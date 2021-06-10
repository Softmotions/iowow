#include "iowow.h"
#include "iwcfg.h"
#include <CUnit/Basic.h>
#include "iwutils.h"
#include "iwpool.h"
#include "iwrb.h"

int init_suite(void) {
  return iw_init();
}

int clean_suite(void) {
  return 0;
}

static const char* _replace_mapper1(const char *key, void *op) {
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
  const char *keys[] = { "{}", "$", "?", "you", "my" };
  iwrc rc = iwu_replace(&res, data, strlen(data), keys, 5, _replace_mapper1, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_PTR_NOT_NULL_FATAL(res);
  fprintf(stderr, "\n%s", iwxstr_ptr(res));
  CU_ASSERT_STRING_EQUAL(iwxstr_ptr(res), "What I said about my Mother?!!");
  iwxstr_destroy(res);
}

void test_iwpool_split_string(void) {
  IWPOOL *pool = iwpool_create(128);
  CU_ASSERT_PTR_NOT_NULL_FATAL(pool);
  char **res = iwpool_split_string(pool, " foo , bar:baz,,z,", ",:", true);
  CU_ASSERT_PTR_NOT_NULL_FATAL(res);
  int i = 0;
  for ( ; res[i]; ++i) {
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
  for ( ; res[i]; ++i) {
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
  for ( ; res[i]; ++i) {
    switch (i) {
      case 0:
        CU_ASSERT_STRING_EQUAL(res[i], " foo ");
        break;
    }
  }
  CU_ASSERT_EQUAL(i, 1);


  res = iwpool_printf_split(pool, ",", true, "%s,%s", "foo", "bar");
  CU_ASSERT_PTR_NOT_NULL_FATAL(res);
  i = 0;
  for ( ; res[i]; ++i) {
    switch (i) {
      case 0:
        CU_ASSERT_STRING_EQUAL(res[i], "foo");
        break;
      case 1:
        CU_ASSERT_STRING_EQUAL(res[i], "bar");
        break;
    }
  }
  CU_ASSERT_EQUAL(i, 2);


  iwpool_destroy(pool);
}

void test_iwpool_printf(void) {
  IWPOOL *pool = iwpool_create(128);
  CU_ASSERT_PTR_NOT_NULL_FATAL(pool);
  const char *res = iwpool_printf(pool, "%s=%s", "foo", "bar");
  CU_ASSERT_PTR_NOT_NULL_FATAL(pool);
  CU_ASSERT_STRING_EQUAL(res, "foo=bar");
  iwpool_destroy(pool);
}

void test_iwrb1(void) {
  int *p;
  IWRB_ITER iter;
  IWRB *rb = iwrb_create(sizeof(int), 7);
  CU_ASSERT_PTR_NOT_NULL_FATAL(rb);
  CU_ASSERT_EQUAL(iwrb_num_cached(rb), 0);
  int idx = 0;
  int data[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };

  iwrb_put(rb, &data[idx++]);
  CU_ASSERT_EQUAL(iwrb_num_cached(rb), 1);

  iwrb_iter_init(rb, &iter);
  p = iwrb_iter_prev(&iter);
  CU_ASSERT_PTR_NOT_NULL_FATAL(p);
  CU_ASSERT_EQUAL(*p, 1);
  p = iwrb_iter_prev(&iter);
  CU_ASSERT_PTR_NULL(p);
  p = iwrb_peek(rb);
  CU_ASSERT_PTR_NOT_NULL_FATAL(p);
  CU_ASSERT_EQUAL(*p, 1);

  for (int i = 0; i < 6; ++i) {
    iwrb_put(rb, &data[i + 1]);
  }
  p = iwrb_peek(rb);
  CU_ASSERT_PTR_NOT_NULL_FATAL(p);
  CU_ASSERT_EQUAL(*p, 7);

  iwrb_iter_init(rb, &iter);
  for (int i = 7; i > 0; --i) {
    p = iwrb_iter_prev(&iter);
    CU_ASSERT_PTR_NOT_NULL_FATAL(p);
    CU_ASSERT_EQUAL(*p, i);
  }
  CU_ASSERT_PTR_NULL(iwrb_iter_prev(&iter));
  iwrb_put(rb, &data[7]);
  p = iwrb_peek(rb);
  CU_ASSERT_PTR_NOT_NULL_FATAL(p);
  CU_ASSERT_EQUAL(*p, 8);

  iwrb_iter_init(rb, &iter);
  for (int i = 8; i > 1; --i) {
    p = iwrb_iter_prev(&iter);
    CU_ASSERT_PTR_NOT_NULL_FATAL(p);
    CU_ASSERT_EQUAL(*p, i);
  }
  CU_ASSERT_PTR_NULL(iwrb_iter_prev(&iter));

  for (int i = 8; i < 14; ++i) {
    iwrb_put(rb, &data[i]);
  }

  iwrb_iter_init(rb, &iter);
  for (int i = 0; i < 7; ++i) {
    p = iwrb_iter_prev(&iter);
    CU_ASSERT_PTR_NOT_NULL_FATAL(p);
    CU_ASSERT_EQUAL(*p, 14 - i);
  }
  CU_ASSERT_PTR_NULL(iwrb_iter_prev(&iter));

  iwrb_destroy(&rb);
  CU_ASSERT_PTR_NULL(rb);
}

int main() {
  CU_pSuite pSuite = NULL;

  /* Initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry()) {
    return CU_get_error();
  }

  /* Add a suite to the registry */
  pSuite = CU_add_suite("iwutils_test1", init_suite, clean_suite);

  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Add the tests to the suite */
  if (  (NULL == CU_add_test(pSuite, "test_iwu_replace_into", test_iwu_replace_into))
     || (NULL == CU_add_test(pSuite, "test_iwpool_split_string", test_iwpool_split_string))
     || (NULL == CU_add_test(pSuite, "test_iwpool_printf", test_iwpool_printf))
     || (NULL == CU_add_test(pSuite, "test_iwrb1", test_iwrb1))) {
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
