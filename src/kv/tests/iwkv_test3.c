#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwcfg.h"

#include <CUnit/Basic.h>
#include <locale.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>

void iwkvd_aln(FILE *f, IWDB db);

typedef struct VN {
  int kn; // key number
  int vs; // value seed
} VN;

typedef struct CTX {
  VN *vn;
  int vnsz;
  pthread_cond_t cond;
  pthread_mutex_t mtx;
  int readynum;
  const int thrnum;
  IWDB db;
} CTX;

typedef struct TASK {
  CTX *ctx;
  int start;
  int cnt;
  pthread_t thr;
} TASK;

int init_suite(void) {
  iwrc rc = iwkv_init();
  return rc;
}

int clean_suite(void) {
  return 0;
}

static int logstage(FILE *f, const char *name, IWDB db) {
  int rci = fprintf(f, "\n#### Stage: %s\n", name);
  iwkvd_db(f, db, /*IWKVD_PRINT_NO_LEVEVELS*/ 0);
  fflush(f);
  return rci < 0 ? rci : 0;
}

static void *iwkv_test1_worker(void *op) {
  TASK *t = op;
  CTX *ctx = t->ctx;
  int mynum;
  int rci = pthread_mutex_lock(&ctx->mtx);
  CU_ASSERT_EQUAL_FATAL(rci, 0);
  ++ctx->readynum;
  mynum = ctx->readynum;
  if (mynum == ctx->thrnum) {
    pthread_cond_broadcast(&ctx->cond);
  } else {
    pthread_cond_wait(&ctx->cond, &ctx->mtx);
  }
  pthread_mutex_unlock(&ctx->mtx);

  IWKV_val key, val;
  for (int i = 0; i < t->cnt; ++i) {
    uint64_t k = t->start + i;
    uint64_t v = k;
    key.size = sizeof(uint64_t);
    key.data = &k;
    val.size = sizeof(uint64_t);
    val.data = &v;
    iwrc rc = iwkv_put(ctx->db, &key, &val, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
  return 0;
}

static void iwkv_test1_impl(int thrnum, int recth) {
  FILE *f = fopen("iwkv_test3_1.log", "w+");
  CU_ASSERT_PTR_NOT_NULL(f);
  const int nrecs = thrnum * recth;
  TASK *tasks = calloc(thrnum, sizeof(*tasks));
  VN *arr = calloc(nrecs, sizeof(*arr));
  CTX ctx = {
    .vn = arr,
    .vnsz = nrecs,
    .mtx = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER,
    .thrnum = thrnum
  };
  for (int i = 0; i < nrecs; ++i) {
    arr[i].kn = i;
    arr[i].vs = iwu_rand_range(256);
  }
  // shuffle
  for (int i = 0; i < nrecs; ++i) {
    uint32_t tgt = iwu_rand_range(nrecs);
    int knt = arr[tgt].kn;
    arr[tgt].kn = arr[i].kn;
    arr[i].kn = knt;
  }
  for (int i = nrecs - 1; i >= 0; --i) {
    uint32_t tgt = iwu_rand_range(nrecs);
    int knt = arr[tgt].kn;
    arr[tgt].kn = arr[i].kn;
    arr[i].kn = knt;
  }

  IWKV_OPTS opts = {
    .path = "iwkv_test3_1.db",
    .oflags = IWKV_TRUNC
  };
  IWKV iwkv;
  IWKV_val key, val;
  iwrc rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_db(iwkv, 1, IWDB_UINT64_KEYS, &ctx.db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  for (int i = 0; i < thrnum; ++i) {
    tasks[i].ctx = &ctx;
    tasks[i].start = i * recth;
    tasks[i].cnt = recth;
    int rci = pthread_create(&tasks[i].thr, 0, iwkv_test1_worker, &tasks[i]);
    CU_ASSERT_EQUAL_FATAL(rci, 0);
  }
  //sleep(3);
  //iwkvd_aln(stderr, ctx.db);
  for (int i = 0; i < thrnum; ++i) {
    int rci = pthread_join(tasks[i].thr, 0);
    CU_ASSERT_EQUAL_FATAL(rci, 0);
  }
  fprintf(stderr, "\nCheking DB");
  // logstage(f, "!!!!!!!", ctx.db);


  pthread_cond_destroy(&ctx.cond);
  pthread_mutex_destroy(&ctx.mtx);
  free(arr);
  free(tasks);
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  fclose(f);
}

static void iwkv_test1(void) {
  iwkv_test1_impl(2, 100000);
}

int main() {
  setlocale(LC_ALL, "en_US.UTF-8");
  CU_pSuite pSuite = NULL;

  /* Initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry()) return CU_get_error();

  /* Add a suite to the registry */
  pSuite = CU_add_suite("iwfs_test1", init_suite, clean_suite);

  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Add the tests to the suite */
  if ((NULL == CU_add_test(pSuite, "iwkv_test1", iwkv_test1))
     )  {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Run all tests using the CUnit Basic interface */
  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  int ret = CU_get_error() || CU_get_number_of_failures();
  CU_cleanup_registry();
  return ret;
}
