#include "iowow.h"
#include "iwrb.h"
#include <CUnit/Basic.h>

int init_suite(void) {
  return iw_init();
}

int clean_suite(void) {
  return 0;
}

static void test_iwrb1(void) {
  struct iwrb *rb = iwrb_create(1, 6);
  iwrb_put(rb, "A");
  iwrb_put(rb, "B");
  iwrb_put(rb, "C");
  CU_ASSERT_EQUAL(iwrb_num_cached(rb), 3);

  char ch = *(char*) iwrb_peek(rb);
  CU_ASSERT_EQUAL(ch, 'C');

  ch = *(char*) iwrb_begin(rb);
  CU_ASSERT_EQUAL(ch, 'A');

  CU_ASSERT_EQUAL(iwrb_num_cached(rb), 3);

  iwrb_put(rb, "D");
  iwrb_put(rb, "E");
  iwrb_put(rb, "F");

  ch = *(char*) iwrb_peek(rb);
  CU_ASSERT_EQUAL(ch, 'F');

  ch = *(char*) iwrb_begin(rb);
  CU_ASSERT_EQUAL(ch, 'A');

  iwrb_put(rb, "G");

  ch = *(char*) iwrb_peek(rb);
  CU_ASSERT_EQUAL(ch, 'G');

  ch = *(char*) iwrb_begin(rb);
  CU_ASSERT_EQUAL(ch, 'B');

  iwrb_put(rb, "H");
  ch = *(char*) iwrb_begin(rb);
  CU_ASSERT_EQUAL(ch, 'C');

  struct iwrb_iter iter;
  iwrb_iter_init(rb, &iter);

  int i = 0;
  char *p = 0;
  for ( ; (p = iwrb_iter_prev(&iter)); ++i) {
    ch = *p;
    switch (i) {
      case 0:
        CU_ASSERT_EQUAL(ch, 'H');
        break;
      case 1:
        CU_ASSERT_EQUAL(ch, 'G');
        break;
      case 2:
        CU_ASSERT_EQUAL(ch, 'F');
        break;
      case 5:
        CU_ASSERT_EQUAL(ch, 'C');
        break;
    }
  }
  CU_ASSERT_EQUAL(iwrb_num_cached(rb), 6);
  iwrb_destroy(&rb);
}

int main(void) {
  CU_pSuite pSuite = NULL;

  /* Initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry()) {
    return CU_get_error();
  }

  /* Add a suite to the registry */
  pSuite = CU_add_suite("iwrb_test1", init_suite, clean_suite);

  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Add the tests to the suite */
  if ((NULL == CU_add_test(pSuite, "test_iwrb1", test_iwrb1))) {
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
