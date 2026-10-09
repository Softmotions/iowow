#include "iowow.h"
#include <CUnit/Basic.h>
#include "iwarr.h"

int init_suite(void) {
  return iw_init();
}

int clean_suite(void) {
  return 0;
}

static int icmp(const void *v1, const void *v2) {
  int i1, i2;
  memcpy(&i1, v1, sizeof(i1));
  memcpy(&i2, v2, sizeof(i2));
  return i1 < i2 ? -1 : i1 > i2 ? 1 : 0;
}

void test_iwarr1(void) {
#define DSIZE 22
  int data[DSIZE + 1] = { 0 };
  int nc = 0;
  off_t idx;
  for (int i = 0; nc < DSIZE / 2; i += 2, nc++) {
    idx = iwarr_sorted_insert(data, nc, sizeof(int), &i, icmp, false);
  }
  CU_ASSERT_EQUAL_FATAL(idx, 10);
  for (int i = 0, j = 0; i < idx; j += 2, ++i) {
    CU_ASSERT_EQUAL_FATAL(data[i], j);
  }
  for (int i = 1; nc < DSIZE; i += 2, nc++) {
    idx = iwarr_sorted_insert(data, nc, sizeof(int), &i, icmp, false);
  }
  for (int i = 0; i < nc; ++i) {
    CU_ASSERT_EQUAL_FATAL(data[i], i);
  }
}

void test_iwlist1(void) {
  struct iwlist list;
  iwrc rc = iwlist_init(&list, 2); // Small initial capacity to force growth on unshift
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  CU_ASSERT_EQUAL_FATAL(iwlist_push(&list, "p0", 2), 0);
  CU_ASSERT_EQUAL_FATAL(iwlist_push(&list, "p1", 2), 0);
  CU_ASSERT_EQUAL_FATAL(iwlist_push(&list, "p2", 2), 0);
  CU_ASSERT_EQUAL_FATAL(iwlist_length(&list), 3);

  // Exercises the start == 0 shift path and the growth path of iwlist_unshift
  CU_ASSERT_EQUAL_FATAL(iwlist_unshift(&list, "u0", 2), 0);
  CU_ASSERT_EQUAL_FATAL(iwlist_unshift(&list, "u1", 2), 0);
  CU_ASSERT_EQUAL_FATAL(iwlist_unshift(&list, "u2", 2), 0);

  const char *exp[] = { "u2", "u1", "u0", "p0", "p1", "p2" };
  CU_ASSERT_EQUAL_FATAL(iwlist_length(&list), 6);
  for (size_t i = 0; i < 6; ++i) {
    size_t sz = 0;
    char *v = iwlist_at2(&list, i, &sz);
    CU_ASSERT_PTR_NOT_NULL_FATAL(v);
    CU_ASSERT_EQUAL_FATAL(sz, 2);
    CU_ASSERT_STRING_EQUAL(v, exp[i]);
  }

  CU_ASSERT_EQUAL_FATAL(iwlist_insert(&list, 1, "i1", 2), 0);
  CU_ASSERT_EQUAL_FATAL(iwlist_length(&list), 7);
  {
    size_t sz = 0;
    char *v = iwlist_at2(&list, 1, &sz);
    CU_ASSERT_PTR_NOT_NULL_FATAL(v);
    CU_ASSERT_STRING_EQUAL(v, "i1");
    v = iwlist_at2(&list, 6, &sz);
    CU_ASSERT_PTR_NOT_NULL_FATAL(v);
    CU_ASSERT_STRING_EQUAL(v, "p2");
  }

  CU_ASSERT_EQUAL_FATAL(iwlist_set(&list, 0, "u2-long", 7), 0);
  {
    size_t sz = 0;
    char *v = iwlist_at2(&list, 0, &sz);
    CU_ASSERT_PTR_NOT_NULL_FATAL(v);
    CU_ASSERT_EQUAL_FATAL(sz, 7);
    CU_ASSERT_STRING_EQUAL(v, "u2-long");
  }

  iwlist_destroy_keep(&list);
}

int main(void) {
  CU_pSuite pSuite = NULL;

  /* Initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry()) {
    return CU_get_error();
  }

  /* Add a suite to the registry */
  pSuite = CU_add_suite("iwarr_test1", init_suite, clean_suite);

  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Add the tests to the suite */
  if ((NULL == CU_add_test(pSuite, "test_iwarr1", test_iwarr1))) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  if ((NULL == CU_add_test(pSuite, "test_iwlist1", test_iwlist1))) {
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
