#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwcfg.h"
#include "iwkv_tests.h"

int init_suite() {
  iwrc rc = iwkv_init();
  return rc;
}

int clean_suite() {
  return 0;
}

static void iwkv_test9_1() {
  IWKV_OPTS opts = {
    .path = "iwkv_test9_1.db",
    .oflags = IWKV_TRUNC
  };
  IWKV kv = NULL;
  iwrc rc = iwkv_open(&opts, &kv);
  assert(rc == 0);
  IWDB db = NULL;
  rc = iwkv_db(kv, 1, 0, &db);
  assert(rc == 0);

  {
    unsigned char ip1[4] = { 1, 0, 142, 235 };
    IWKV_val ikey, ival;
    ikey.data = ip1;
    ikey.size = 4;
    ival.data = (void *)"";
    ival.size = 0;
    iwkv_opflags opflags = IWKV_NO_OVERWRITE;
    iwrc rc = iwkv_put(db, &ikey, &ival, opflags);
    CU_ASSERT_EQUAL(rc, 0);
  }

  {
    unsigned char ip2[4] = { 1, 0, 145, 2 };
    IWKV_val ikey, ival;
    ikey.data = ip2;
    ikey.size = 4;
    ival.data = (void *)"";
    ival.size = 0;
    iwkv_opflags opflags = IWKV_NO_OVERWRITE;
    iwrc rc = iwkv_put(db, &ikey, &ival, opflags);
    CU_ASSERT_EQUAL(rc, 0);
  }
  iwkv_close(&kv);

}


int main() {
  CU_pSuite pSuite = NULL;

  /* Initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry()) return CU_get_error();

  /* Add a suite to the registry */
  pSuite = CU_add_suite("iwkv_test9", init_suite, clean_suite);

  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Add the tests to the suite */
  if (
    (NULL == CU_add_test(pSuite, "iwkv_test9_1", iwkv_test9_1))
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
