#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwcfg.h"

#include "tests.h"
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>

typedef struct VN {
  int kn; // key number
  int vs; // value seed
} VN;

typedef struct CTX {
  struct VN *vn;
  int vnsz;
  pthread_cond_t  cond;
  pthread_mutex_t mtx;
  int       readynum;
  const int thrnum;
  struct iwdb *db;
} CTX;

typedef struct TASK {
  struct CTX *ctx;
  int       start;
  int       cnt;
  pthread_t thr;
} TASK;

int init_suite(void) {
  iwrc rc = iwkv_init();
  return rc;
}

static int logstage(FILE *f, const char *name, struct iwdb *db) {
  int rci = fprintf(f, "\n#### Stage: %s\n", name);
  iwkvd_db(f, db, /*IWKVD_PRINT_NO_LEVEVELS*/ 0, 0);
  fflush(f);
  return rci < 0 ? rci : 0;
}

static void* iwkv_test1_worker(void *op) {
  struct TASK *t = op;
  struct CTX *ctx = t->ctx;
  int mynum;
  int rci = pthread_mutex_lock(&ctx->mtx);
  IW_TEST_ASSERT_EQUAL_FATAL(rci, 0);
  ++ctx->readynum;
  mynum = ctx->readynum;
  if (mynum == ctx->thrnum) {
    pthread_cond_broadcast(&ctx->cond);
  } else {
    pthread_cond_wait(&ctx->cond, &ctx->mtx);
  }
  pthread_mutex_unlock(&ctx->mtx);

  struct iwkv_val key, val;
  for (int i = 0; i < t->cnt; ++i) {
    uint64_t k = t->start + i;
    uint64_t v = k;
    key.size = sizeof(uint64_t);
    key.data = &k;
    val.size = sizeof(uint64_t);
    val.data = &v;
    iwrc rc = iwkv_put(ctx->db, &key, &val, 0);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  }
  return 0;
}

static void iwkv_test3_impl(int thrnum, int recth, bool wal) {
  FILE *f = fopen("iwkv_test3_1.log", "w+");
  IW_TEST_ASSERT_PTR_NOT_NULL(f);
  const int nrecs = thrnum * recth;
  struct TASK *tasks = calloc(thrnum, sizeof(*tasks));
  struct VN *arr = calloc(nrecs, sizeof(*arr));
  struct CTX ctx = {
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

  struct iwkv_opts opts = {
    .path = "iwkv_test3_1.db",
    .oflags = IWKV_TRUNC,
    .wal = {
      .enabled = wal,
      .checkpoint_buffer_sz = 1024 * 1024
    }
  };
  struct iwkv *iwkv;
  struct iwkv_val key, val;
  iwrc rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_db(iwkv, 1, IWDB_VNUM64_KEYS, &ctx.db);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  for (int i = 0; i < thrnum; ++i) {
    tasks[i].ctx = &ctx;
    tasks[i].start = i * recth;
    tasks[i].cnt = recth;
    int rci = pthread_create(&tasks[i].thr, 0, iwkv_test1_worker, &tasks[i]);
    IW_TEST_ASSERT_EQUAL_FATAL(rci, 0);
  }
  for (int i = 0; i < thrnum; ++i) {
    int rci = pthread_join(tasks[i].thr, 0);
    IW_TEST_ASSERT_EQUAL_FATAL(rci, 0);
  }
  fprintf(stderr, "\nChecking DB....");
  for (int i = 0; i < nrecs; ++i) {
    uint64_t k = i, v;
    key.data = &k;
    key.size = sizeof(uint64_t);
    rc = iwkv_get(ctx.db, &key, &val);
    if (rc) {
      fprintf(stderr, "\nwk=%d\n", i);
      iwlog_ecode_error3(rc);
      //break;
    } else {
      IW_TEST_ASSERT_EQUAL_FATAL(val.size, sizeof(uint64_t));
      memcpy(&v, val.data, sizeof(uint64_t));
      IW_TEST_ASSERT_EQUAL_FATAL(v, i);
    }
    iwkv_val_dispose(&val);
  }
  pthread_cond_destroy(&ctx.cond);
  pthread_mutex_destroy(&ctx.mtx);
  free(arr);
  free(tasks);
  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  fclose(f);
}

static void iwkv_test3_1(void) {
  iwkv_test3_impl(4, 30000, false);
}

static void iwkv_test3_2(void) {
  iwkv_test3_impl(4, 30000, true);
}

static const struct iw_test_case cases[] = {
  IW_TEST_CASE(iwkv_test3_1),
  IW_TEST_CASE(iwkv_test3_2),
};

int main(int argc, char *argv[]) {
  return iw_test_run(argc, argv, IW_TEST_SUITE("iwkv_test3", cases, init_suite, 0));
}

