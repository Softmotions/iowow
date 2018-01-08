#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwcfg.h"

#include <CUnit/Basic.h>
#include <locale.h>

int init_suite(void) {
  iwrc rc = iwkv_init();
  return rc;
}

int clean_suite(void) {
  return 0;
}

static int logstage(FILE *f, const char *name, IWDB db) {
  int rci = fprintf(f, "\n#### Stage: %s\n", name);
  iwkvd_db(f, db, IWKVD_PRINT_NO_LEVEVELS);
  fflush(f);
  return rci < 0 ? rci : 0;
}

static int logstage2(FILE *f, const char *name, IWDB db) {
  int rci = fprintf(f, "\n#### Stage: %s\n", name);
  iwkvd_db(f, db, IWKVD_PRINT_VALS);
  fflush(f);
  return rci < 0 ? rci : 0;
}

static void iwkv_test1(void) {
  FILE *f = fopen("iwkv_test2_1.log", "w+");
  CU_ASSERT_PTR_NOT_NULL(f);

  IWKV_OPTS opts = {
    .path = "iwkv_test2_1.db",
    .oflags = IWKV_TRUNC
  };
  // Test open/close
  IWKV iwkv;
  IWDB db1;
  IWKV_val key, val;
  iwrc rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_db(iwkv, 1, IWDB_UINT64_KEYS, &db1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  for (uint64_t i = 0; i < 1000000; ++i) {
    key.size = sizeof(uint64_t);
    key.data = &i;
    val.size = sizeof(uint64_t);
    val.data = &i;
    rc = iwkv_put(db1, &key, &val, 0);
    if (rc) {
      iwlog_ecode_error3(rc);
    }
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
  //logstage(f, "first", db1);
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
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

