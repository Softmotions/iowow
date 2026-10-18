#include "iowow.h"
#include "iwrb.h"
#include "iwtests.h"

int init_suite(void) {
  return iw_init();
}

static void test_iwrb1(void) {
  struct iwrb *rb = iwrb_create(1, 6);
  iwrb_put(rb, "A");
  iwrb_put(rb, "B");
  iwrb_put(rb, "C");
  IW_TEST_ASSERT_EQUAL(iwrb_num_cached(rb), 3);

  char ch = *(char*) iwrb_peek(rb);
  IW_TEST_ASSERT_EQUAL(ch, 'C');

  ch = *(char*) iwrb_begin(rb);
  IW_TEST_ASSERT_EQUAL(ch, 'A');

  IW_TEST_ASSERT_EQUAL(iwrb_num_cached(rb), 3);

  iwrb_put(rb, "D");
  iwrb_put(rb, "E");
  iwrb_put(rb, "F");

  ch = *(char*) iwrb_peek(rb);
  IW_TEST_ASSERT_EQUAL(ch, 'F');

  ch = *(char*) iwrb_begin(rb);
  IW_TEST_ASSERT_EQUAL(ch, 'A');

  iwrb_put(rb, "G");

  ch = *(char*) iwrb_peek(rb);
  IW_TEST_ASSERT_EQUAL(ch, 'G');

  ch = *(char*) iwrb_begin(rb);
  IW_TEST_ASSERT_EQUAL(ch, 'B');

  iwrb_put(rb, "H");
  ch = *(char*) iwrb_begin(rb);
  IW_TEST_ASSERT_EQUAL(ch, 'C');

  struct iwrb_iter iter;
  iwrb_iter_init(rb, &iter);

  int i = 0;
  char *p = 0;
  for ( ; (p = iwrb_iter_prev(&iter)); ++i) {
    ch = *p;
    switch (i) {
      case 0:
        IW_TEST_ASSERT_EQUAL(ch, 'H');
        break;
      case 1:
        IW_TEST_ASSERT_EQUAL(ch, 'G');
        break;
      case 2:
        IW_TEST_ASSERT_EQUAL(ch, 'F');
        break;
      case 5:
        IW_TEST_ASSERT_EQUAL(ch, 'C');
        break;
    }
  }
  IW_TEST_ASSERT_EQUAL(iwrb_num_cached(rb), 6);
  iwrb_destroy(&rb);
}

static const struct iw_test_case cases[] = {
  IW_TEST_CASE(test_iwrb1),
};

int main(int argc, char *argv[]) {
  return iw_test_run(argc, argv, IW_TEST_SUITE("iwrb_test1", cases, init_suite, 0));
}

