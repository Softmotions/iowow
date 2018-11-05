#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwcfg.h"
#include "iwkv_tests.h"
#include "iwkv_internal.h"

uint32_t g_seed;
uint32_t g_rnd_data_pos;
#define RND_DATA_SZ (10*1048576)
char RND_DATA[RND_DATA_SZ];

static void *rndbuf_next(uint32_t len) {
  assert(len <= RND_DATA_SZ);
  if (g_rnd_data_pos + len > RND_DATA_SZ) {
    g_rnd_data_pos = 0;
  }
  const char *ret = RND_DATA + g_rnd_data_pos;
  g_rnd_data_pos += len;
  return (void *) ret;
}

int init_suite(void) {
  iwrc rc = iwkv_init();
  RCRET(rc);
  uint64_t ts;
  iwp_current_time_ms(&ts, false);
  ts = IW_SWAB64(ts);
  ts >>= 32;
  g_seed = ts;

  fprintf(stderr, "\nRandom seed: %u\n", g_seed);
  iwu_rand_seed(g_seed);
  for (int i = 0; i < RND_DATA_SZ; ++i) {
    RND_DATA[i] = ' ' + iwu_rand_range(95); // ascii space ... ~
  }
  return rc;
}

int clean_suite(void) {
  return 0;
}

static void iwkv_test4(void) {
  char *path = "iwkv_test4_4.db";
  IWKV iwkv;
  IWDB db1;
  IWKV_val key = {0};
  IWKV_val val = {0};
  IWKV_OPTS opts = {
    .path = path,
    .oflags = IWKV_TRUNC,
    .random_seed = g_seed,
    .wal = {
      .enabled = true,
      .savepoint_timeout_sec = 2,
      .checkpoint_timeout_sec = 300
    }
  };
  iwrc rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  key.data = "key00001";
  key.size = strlen(key.data);
  val.data = "value00001";
  val.size = strlen(val.data);
  rc = iwkv_put(db1, &key, &val, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  CU_ASSERT_FALSE(iwal_synched(iwkv));

  sleep(4);

  CU_ASSERT_TRUE(iwal_synched(iwkv));

  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
}

static void iwkv_test3(void) {
  char *path = "iwkv_test4_3.db";
  IWKV iwkv;
  IWDB db1;
  IWKV_val key = {0};
  IWKV_val val = {0};
  IWKV_OPTS opts = {
    .path = path,
    .oflags = IWKV_TRUNC,
    .random_seed = g_seed,
    .wal = {
      .enabled = true,
      .check_crc_on_checkpoint = true,
      .savepoint_timeout_sec = UINT32_MAX
    }
  };
  iwrc rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  key.data = "key00001";
  key.size = strlen(key.data);
  val.data = "value00001";
  val.size = strlen(val.data);
  rc = iwkv_put(db1, &key, &val, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_sync(iwkv, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  key.data = "key00002";
  key.size = strlen(key.data);
  val.data = "value00002";
  val.size = strlen(val.data);
  rc = iwkv_put(db1, &key, &val, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_sync(iwkv, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  key.data = "key00003";
  key.size = strlen(key.data);
  val.data = "value00003";
  val.size = strlen(val.data);
  rc = iwkv_put(db1, &key, &val, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  iwkvd_trigger_xor(IWKVD_WAL_NO_CHECKPOINT_ON_CLOSE);

  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // Now reopen and roll WAL log

  iwkvd_trigger_xor(IWKVD_WAL_NO_CHECKPOINT_ON_CLOSE);

  opts.oflags &= ~IWKV_TRUNC;
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  key.data = "key00001";
  key.size = strlen(key.data);
  rc = iwkv_get(db1, &key, &val);
  CU_ASSERT_EQUAL_FATAL(rc, 0); // !!!!
  CU_ASSERT_NSTRING_EQUAL(val.data, "value00001", val.size);
  iwkv_kv_dispose(0, &val);

  key.data = "key00002";
  key.size = strlen(key.data);
  rc = iwkv_get(db1, &key, &val);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_NSTRING_EQUAL(val.data, "value00002", val.size);
  iwkv_kv_dispose(0, &val);

  key.data = "key00003";
  key.size = strlen(key.data);
  rc = iwkv_get(db1, &key, &val);
  CU_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_NOTFOUND);

  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
}

static void iwkv_test2_impl(char *path, const char *walpath, uint32_t num, uint32_t vrange) {
  g_rnd_data_pos = 0;
  char kbuf[100];
  iwrc rc;
  IWKV iwkv;
  IWDB db1;
  if (walpath) {
    unlink(walpath);
  }
  IWKV_val key = {0};
  IWKV_val val = {0};
  IWKV_OPTS opts = {
    .path = path,
    .oflags = IWKV_TRUNC,
    .random_seed = g_seed,
    .wal = {
      .enabled = (walpath != NULL),
      .check_crc_on_checkpoint = true,
      .savepoint_timeout_sec = UINT32_MAX,
      .wal_buffer_sz = 64 * 1024,
      .checkpoint_buffer_sz = 32 * 1024 * 1024
    }
  };
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_db(iwkv, 1, 0, &db1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  key.data = kbuf;

  for (int i = 0; i < num; ++i) {
    int k = iwu_rand_range(num);
    snprintf(key.data, sizeof(kbuf), "%016d", k);
    key.size = strlen(key.data);
    uint32_t value_size = iwu_rand_range(vrange + 1);
    if (value_size == 0) {
      value_size = 1;
    }
    val.data = rndbuf_next(value_size);
    val.size = value_size;
    rc = iwkv_put(db1, &key, &val, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
}

static void iwkv_test2(void) {
  uint32_t num = 1000;
  uint32_t vrange = 100000;
  iwkv_test2_impl("iwkv_test4_2.db", NULL, num, vrange);
  iwkv_test2_impl("iwkv_test4_2wal.db", "iwkv_test4_2wal.db-wal", num, vrange);
  FILE *iw1 = fopen("iwkv_test4_2.db", "rb");
  CU_ASSERT_PTR_NOT_NULL_FATAL(iw1);
  FILE *iw2 = fopen("iwkv_test4_2wal.db", "rb");
  CU_ASSERT_PTR_NOT_NULL_FATAL(iw2);
  int ret = cmp_files(iw1, iw2);
  CU_ASSERT_FALSE(ret);
  fclose(iw1);
  fclose(iw2);
}


static void iwkv_test1_impl(char *path, const char *walpath)  {
  iwrc rc;
  IWKV iwkv;
  IWDB db1, db2;
  if (walpath) {
    unlink(walpath);
  }
  IWKV_val key = {0};
  IWKV_val val = {0};
  IWKV_OPTS opts = {
    .path = path,
    .oflags = IWKV_TRUNC,
    .wal = {
      .enabled = (walpath != NULL),
      .savepoint_timeout_sec = UINT32_MAX
    }
  };
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_db(iwkv, 1, 0, &db1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_db(iwkv, 2, 0, &db2);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  key.data = "foo";
  key.size = strlen(key.data);
  val.data = "bar";
  val.size = strlen(val.data);
  rc = iwkv_put(db1, &key, &val, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  key.data = "foozz";
  key.size = strlen(key.data);
  val.data = "bazz";
  val.size = strlen(val.data);
  rc = iwkv_put(db2, &key, &val, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  key.data = "foozz2";
  key.size = strlen(key.data);
  val.data = "bazzbazzbazzbazz";
  val.size = strlen(val.data);
  rc = iwkv_put(db2, &key, &val, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  key.data = "foozz";
  key.size = strlen(key.data);
  rc = iwkv_del(db2, &key, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_db_destroy(&db2);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
}

static void iwkv_test1(void) {
  iwkv_test1_impl("iwkv_test4_1.db", NULL);
  iwkv_test1_impl("iwkv_test4_1wal.db", "iwkv_test4_1wal.db-wal");
  FILE *iw1 = fopen("iwkv_test4_1.db", "rb");
  CU_ASSERT_PTR_NOT_NULL_FATAL(iw1);
  FILE *iw2 = fopen("iwkv_test4_1wal.db", "rb");
  CU_ASSERT_PTR_NOT_NULL_FATAL(iw2);
  int ret = cmp_files(iw1, iw2);
  CU_ASSERT_FALSE(ret);
  fclose(iw1);
  fclose(iw2);
}

int main() {
  CU_pSuite pSuite = NULL;

  /* Initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry()) return CU_get_error();

  /* Add a suite to the registry */
  pSuite = CU_add_suite("iwkv_test4", init_suite, clean_suite);

  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Add the tests to the suite */
  if (
    (NULL == CU_add_test(pSuite, "iwkv_test1", iwkv_test1)) ||
    (NULL == CU_add_test(pSuite, "iwkv_test2", iwkv_test2)) ||
    (NULL == CU_add_test(pSuite, "iwkv_test3", iwkv_test3)) ||
    (NULL == CU_add_test(pSuite, "iwkv_test4", iwkv_test4))

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
