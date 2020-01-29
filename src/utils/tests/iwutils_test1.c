#include "iowow.h"
#include "iwcfg.h"
#include <CUnit/Basic.h>
#include "iwutils.h"

int init_suite(void) {
  return iw_init();
}

int clean_suite(void) {
  return 0;
}

static const char  *_replace_mapper1(const char *key, void *op) {
  if (!strcmp(key, "{}")) {
    return "Mother";
  } else if (!strcmp(key, "you")) {
    return "I";
  } else if (!strcmp(key, "?")) {
    return "?!!";
  } else {
    return 0;
  }
}

void test_iwu_replace_into(void) {
  IWXSTR *res = 0;
  const char *data = "What you said about my {}?";
  const char *keys[] = {"{}", "$", "?", "you"};
  iwrc rc = iwu_replace(&res, data, strlen(data), keys, 4, _replace_mapper1, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_PTR_NOT_NULL_FATAL(res);
  CU_ASSERT_STRING_EQUAL(iwxstr_ptr(res), "What I said about my Mother?!!");
  iwxstr_destroy(res);
}


int main() {
  CU_pSuite pSuite = NULL;

  /* Initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry())
    return CU_get_error();

  /* Add a suite to the registry */
  pSuite = CU_add_suite("iwutils_test1", init_suite, clean_suite);

  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Add the tests to the suite */
  if ((NULL == CU_add_test(pSuite, "test_iwu_replace_into", test_iwu_replace_into))) {
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
