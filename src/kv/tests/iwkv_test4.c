#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwcfg.h"

#include <CUnit/Basic.h>

int init_suite(void) {
  iwrc rc = iwkv_init();
  return rc;
}

int clean_suite(void) {
  return 0;
}

static void iwkv_test1_impl(char *path, const char *walpath)  {
  iwrc rc;
  IWKV iwkv;
  IWDB db1;
  if (walpath) {
    unlink(walpath);    
  }
  IWKV_OPTS opts = {
    .path = path,
    .oflags = IWKV_TRUNC,
    .wal = {
      .enabled = (walpath != NULL)
    }
  };
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
}

static void iwkv_test1(void) {
  iwkv_test1_impl("iwkv_test4_1.db", NULL);
  iwkv_test1_impl("iwkv_test4_1wal.db", "iwkv_test4_1wal.db-wal");
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
