#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwcfg.h"
#include "iwkv_tests.h"
#include "iwkv_internal.h"

#define KBUFSZ 1024
#define VBUFSZ 1024
char kbuf[KBUFSZ];
char vbuf[VBUFSZ];

static const IWKV_val EMPTY_VAL = {0};

uint32_t g_seed;

int init_suite(void) {
  iwrc rc = iwkv_init();
  RCRET(rc);
  g_seed = 2681089616;
  return rc;
}

int clean_suite(void) {
  return 0;
}





static void iwkv_test7_2_impl(int direction) {
  iwrc rc;
  IWKV iwkv;
  IWDB db;
  IWKV_val key = {0};
  IWKV_val val = {0};
  IWKV_cursor cur1;
  IWKV_OPTS opts = {
    .path = direction > 0 ? "iwkv_test7_2_fwd.db" : "iwkv_test7_2_back.db",
    .oflags = IWKV_TRUNC,
    .random_seed = g_seed

  };
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, IWDB_COMPOUND_KEYS, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  const int nrecords = 50000;

  for (int i = 0; i < nrecords; ++i) {
    snprintf(kbuf, KBUFSZ, "5368fce5-c138-4f0d-bfee-dbce07eb28e1%d", i);
    snprintf(vbuf, VBUFSZ, "%04d", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    key.compound = direction > 0 ? i + 1 : nrecords - i;

    val.data = vbuf;
    val.size = strlen(val.data);
    rc = iwkv_put(db, &key, &val, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }

  for (int i = 0; i < nrecords; ++i) {
    snprintf(kbuf, KBUFSZ, "5368fce5-c138-4f0d-bfee-dbce07eb28e1%d", i);
    snprintf(vbuf, VBUFSZ, "%04d", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    key.compound = direction > 0 ? i + 1 : nrecords - i;
    rc = iwkv_get(db, &key, &val);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
}

static void iwkv_test7_2() {
  iwkv_test7_2_impl(1);
  iwkv_test7_2_impl(-1);
  IWP_FILE_STAT fwd_s = {0};
  IWP_FILE_STAT back_s = {0};
  iwrc rc = iwp_fstat("iwkv_test7_2_fwd.db", &fwd_s);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwp_fstat("iwkv_test7_2_back.db", &back_s);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_TRUE((double)fwd_s.size / back_s.size < 1.1);
}

static void iwkv_test7_1() {
  iwrc rc;
  IWKV iwkv;
  IWDB db;
  IWKV_val key = {0};
  IWKV_val val = {0};
  IWKV_cursor cur1;
  IWKV_OPTS opts = {
    .path = "iwkv_test7_1.db",
    .oflags = IWKV_TRUNC,
    .random_seed = g_seed

  };
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  for (int i = 0; i < 7200; ++i) {
    snprintf(kbuf, KBUFSZ, "5368fce5-c138-4f0d-bfee-dbce07eb28e1%d", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    val.data = vbuf;
    val.size = strlen(val.data);
    rc = iwkv_put(db, &key, &val, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
}

int main() {
  CU_pSuite pSuite = NULL;

  /* Initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry()) return CU_get_error();

  /* Add a suite to the registry */
  pSuite = CU_add_suite("iwkv_test6", init_suite, clean_suite);

  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Add the tests to the suite */
  if (
    //(NULL == CU_add_test(pSuite, "iwkv_test7_1", iwkv_test7_1)) ||
    (NULL == CU_add_test(pSuite, "iwkv_test7_1", iwkv_test7_2))
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
