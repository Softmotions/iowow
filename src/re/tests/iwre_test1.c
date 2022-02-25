#include "iowow.h"
#include <CUnit/Basic.h>
#include "iwre.h"

static int init_suite(void) {
  return iw_init();
}

static int clean_suite(void) {
  return 0;
}

static void iwre_test1(void) {
  struct iwre *re = iwre_create("^(one1)(two)?");
  const char *mpairs[10];
  int rv = iwre_match(re, "one1two", mpairs, 10);
  CU_ASSERT_EQUAL(rv, 3);
  for (int i = 0, j = 0; i < 2 * rv; i += 2, ++j) {
    intptr_t l = mpairs[i + 1] - mpairs[i];
    switch(j)  {
      case 0:
        CU_ASSERT_EQUAL(l, 7);
        CU_ASSERT_EQUAL(strncmp(mpairs[i], "one1two", l), 0);
        break;
      case 1:
        CU_ASSERT_EQUAL(l, 4);
        CU_ASSERT_EQUAL(strncmp(mpairs[i], "one1", l), 0);
        break;
      case 2:
        CU_ASSERT_EQUAL(l, 3);
        CU_ASSERT_EQUAL(strncmp(mpairs[i], "two", l), 0);
        break;
    }
  }
  iwre_destroy(re);
}

int main(int argc, const char *argv[]) {
  CU_pSuite pSuite = NULL;

  /* Initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry()) {
    return CU_get_error();
  }

  /* Add a suite to the registry */
  pSuite = CU_add_suite("iwre_test1", init_suite, clean_suite);

  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Add the tests to the suite */
  if ((NULL == CU_add_test(pSuite, "iwre_test1", iwre_test1))) {
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
