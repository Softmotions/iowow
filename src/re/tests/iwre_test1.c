#include "iowow.h"
#include "tests.h"
#include "iwre.h"

static int init_suite(void) {
  return iw_init();
}

static void iwre_test1(void) {
  struct iwre *re = iwre_create("^(one1)(two)?");
  const char *mpairs[10];
  int rv = iwre_match(re, "one1two", mpairs, 10);
  IW_TEST_ASSERT_EQUAL(rv, 3);
  for (int i = 0, j = 0; i < 2 * rv; i += 2, ++j) {
    intptr_t l = mpairs[i + 1] - mpairs[i];
    switch (j) {
      case 0:
        IW_TEST_ASSERT_EQUAL(l, 7);
        IW_TEST_ASSERT_EQUAL(strncmp(mpairs[i], "one1two", l), 0);
        break;
      case 1:
        IW_TEST_ASSERT_EQUAL(l, 4);
        IW_TEST_ASSERT_EQUAL(strncmp(mpairs[i], "one1", l), 0);
        break;
      case 2:
        IW_TEST_ASSERT_EQUAL(l, 3);
        IW_TEST_ASSERT_EQUAL(strncmp(mpairs[i], "two", l), 0);
        break;
    }
  }
  iwre_destroy(re);
}

static const struct iw_test_case cases[] = {
  IW_TEST_CASE(iwre_test1),
};

int main(int argc, char *argv[]) {
  return iw_test_run(argc, argv, IW_TEST_SUITE("iwre_test1", cases, init_suite, 0));
}

