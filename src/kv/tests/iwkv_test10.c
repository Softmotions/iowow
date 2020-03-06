#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwkv_tests.h"
#include "iwkv_internal.h"
#include "iwth.h"

#define KBUFSZ 1024
#define VBUFSZ 1024
static char kbuf[KBUFSZ];
static char vbuf[VBUFSZ];

int init_suite(void) {
  return iwkv_init();
}

int clean_suite(void) {
  return 0;
}


static void iwkv_test10_1_impl(int fmt_version) {
  IWKV iwkv;
  IWKV_OPTS opts = {
    .path = fmt_version > 1 ? "iwkv_test10_1_v2.db" : "iwkv_test10_1_v1.db",
    .oflags = IWKV_TRUNC,
    .wal = {
      .enabled = true
    }
  };

  iwrc rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  for (int i = 0; i < 1024; ++i) {
    IWDB db;
    rc = iwkv_db(iwkv, i, 0, &db);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    for (int j = 0; j < 1024; ++j) {
      IWKV_val key, val;
      snprintf(kbuf, KBUFSZ, "%d", j);
      snprintf(vbuf, VBUFSZ, "%03dval", j);
      key.data = kbuf;
      key.size = strlen(key.data);
      val.data = vbuf;
      val.size = strlen(val.data);
      rc = iwkv_put(db, &key, &val, 0);
      CU_ASSERT_EQUAL_FATAL(rc, 0);
    }
  }

  for (int i = 0; i < 1024; ++i) {
    if ((i % 2)) {
      IWDB db;
      rc = iwkv_db(iwkv, i, 0, &db);
      CU_ASSERT_EQUAL_FATAL(rc, 0);
      rc = iwkv_db_destroy(&db);
      CU_ASSERT_EQUAL_FATAL(rc, 0);
    }
  }

  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  opts.oflags = 0;
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  for (int i = 0; i < 1024; ++i) {
    if (!(i % 2)) {
      IWDB db;
      rc = iwkv_db(iwkv, i, 0, &db);
      CU_ASSERT_EQUAL_FATAL(rc, 0);
      for (int j = 0; j < 1024; ++j) {
        IWKV_val key, val;
        int cret = 0;
        snprintf(kbuf, KBUFSZ, "%d", j);
        snprintf(vbuf, VBUFSZ, "%03dval", j);
        key.data = kbuf;
        key.size = strlen(key.data);
        int vlen = strlen(vbuf);
        rc = iwkv_get(db, &key, &val);
        CU_ASSERT_EQUAL_FATAL(rc, 0);
        IW_CMP(cret, vbuf, vlen, val.data, val.size);
        CU_ASSERT_EQUAL_FATAL(cret, 0);
        iwkv_val_dispose(&val);
      }
    }
  }

  for (int i = 0; i < 1024; ++i) {
    if (!(i % 2)) {
      IWDB db;
      rc = iwkv_db(iwkv, i, 0, &db);
      CU_ASSERT_EQUAL_FATAL(rc, 0);
      rc = iwkv_db_destroy(&db);
      CU_ASSERT_EQUAL_FATAL(rc, 0);
    }
  }

  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  IWP_FILE_STAT fs;
  rc = iwp_fstat(opts.path, &fs);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_TRUE(fs.size < 1024 * 1024);
}

static void iwkv_test10_1_v1() {
  iwkv_test10_1_impl(1);
}

static void iwkv_test10_1_v2() {
  iwkv_test10_1_impl(2);
}

int main() {
  CU_pSuite pSuite = NULL;

  /* Initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry()) return CU_get_error();

  /* Add a suite to the registry */
  pSuite = CU_add_suite("iwkv_test8", init_suite, clean_suite);

  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Add the tests to the suite */
  if (
    (NULL == CU_add_test(pSuite, "iwkv_test10_1_v1", iwkv_test10_1_v1)) ||
    (NULL == CU_add_test(pSuite, "iwkv_test10_1_v2", iwkv_test10_1_v2))
  ) {
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
