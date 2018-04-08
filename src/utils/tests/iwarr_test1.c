#include "iowow.h"
#include "iwcfg.h"
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
  int data[DSIZE + 1] = {0};
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

int main() {
  CU_pSuite pSuite = NULL;

  /* Initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry())
    return CU_get_error();

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

  /* Run all tests using the CUnit Basic interface */
  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  int ret = CU_get_error() || CU_get_number_of_failures();
  CU_cleanup_registry();
  return ret;
}
