#include "iowow.h"
#include "iwcfg.h"
#include <CUnit/Basic.h>
#include "iwutils.h"
#include "iwpool.h"

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
  const char *keys[] = {"{}", "$", "?", "you", "my"};
  iwrc rc = iwu_replace(&res, data, strlen(data), keys, 5, _replace_mapper1, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_PTR_NOT_NULL_FATAL(res);
  fprintf(stderr, "\n%s", iwxstr_ptr(res));
  CU_ASSERT_STRING_EQUAL(iwxstr_ptr(res), "What I said about my Mother?!!");
  iwxstr_destroy(res);
}


void test_iwpool_split_string() {
  IWPOOL *pool = iwpool_create(128);
  CU_ASSERT_PTR_NOT_NULL_FATAL(pool);
  char **res = iwpool_split_string(pool, " foo , bar:baz,,z,", ",:", true);
  CU_ASSERT_PTR_NOT_NULL_FATAL(res);
  int i = 0;
  for (; res[i]; ++i) {
    switch (i) {
      case 0:
        CU_ASSERT_STRING_EQUAL(res[i], "foo");
        break;
      case 1:
        CU_ASSERT_STRING_EQUAL(res[i], "bar");
        break;
      case 2:
        CU_ASSERT_STRING_EQUAL(res[i], "baz");
        break;
      case 3:
        CU_ASSERT_STRING_EQUAL(res[i], "");
        break;
      case 4:
        CU_ASSERT_STRING_EQUAL(res[i], "z");
        break;
    }
  }
  CU_ASSERT_EQUAL(i, 5);

  res = iwpool_split_string(pool, " foo , bar:baz,,z,", ",:", false);
  CU_ASSERT_PTR_NOT_NULL_FATAL(res);
  i = 0;
  for (; res[i]; ++i) {
    switch (i) {
      case 0:
        CU_ASSERT_STRING_EQUAL(res[i], " foo ");
        break;
      case 1:
        CU_ASSERT_STRING_EQUAL(res[i], " bar");
        break;
      case 2:
        CU_ASSERT_STRING_EQUAL(res[i], "baz");
        break;
      case 3:
        CU_ASSERT_STRING_EQUAL(res[i], "");
        break;
      case 4:
        CU_ASSERT_STRING_EQUAL(res[i], "z");
        break;
    }
  }
  CU_ASSERT_EQUAL(i, 5);

  res = iwpool_split_string(pool, " foo ", ",", false);
  CU_ASSERT_PTR_NOT_NULL_FATAL(res);
  i = 0;
  for (; res[i]; ++i) {
    switch (i) {
      case 0:
        CU_ASSERT_STRING_EQUAL(res[i], " foo ");
        break;
    }
  }
  CU_ASSERT_EQUAL(i, 1);
  iwpool_destroy(pool);
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
  if (
      (NULL == CU_add_test(pSuite, "test_iwu_replace_into", test_iwu_replace_into)) ||
      (NULL == CU_add_test(pSuite, "test_iwpool_split_string", test_iwpool_split_string))
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
