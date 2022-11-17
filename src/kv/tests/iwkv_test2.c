#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwcfg.h"
#include <CUnit/Basic.h>

#define RND_DATA_SZ (10 * 1048576)
char RND_DATA[RND_DATA_SZ];

int init_suite(void) {
  iwrc rc = iwkv_init();
  return rc;
}

int clean_suite(void) {
  return 0;
}

static void iwkv_test2_1(void) {
  IWKV_OPTS opts = {
    .path   = "iwkv_test2_1.db",
    .oflags = IWKV_TRUNC
  };
  const uint64_t numrec = 1000000; // 1M
  // Test open/close
  IWKV iwkv;
  IWDB db1;
  IWKV_val key, val;
  iwrc rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_db(iwkv, 1, IWDB_VNUM64_KEYS, &db1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  for (uint64_t i = 0; i < numrec; ++i) {
    key.size = sizeof(uint64_t);
    key.data = &i;
    val.size = sizeof(uint64_t);
    val.data = &i;
    rc = iwkv_put(db1, &key, &val, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }

  for (uint64_t v = 0; v < numrec; ++v) {
    uint64_t llv;
    key.data = &v;
    key.size = sizeof(uint64_t);
    rc = iwkv_get(db1, &key, &val);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    memcpy(&llv, val.data, sizeof(llv));
    CU_ASSERT_EQUAL_FATAL(llv, v);
    iwkv_val_dispose(&val);
  }

  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
}

int main(void) {
  CU_pSuite pSuite = NULL;

  /* Initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry()) {
    return CU_get_error();
  }

  /* Add a suite to the registry */
  pSuite = CU_add_suite("iwkv_test2", init_suite, clean_suite);

  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Add the tests to the suite */
  if ((NULL == CU_add_test(pSuite, "iwkv_test2_1", iwkv_test2_1))) {
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
