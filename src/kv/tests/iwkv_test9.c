#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwcfg.h"
#include "tests.h"

int init_suite(void) {
  iwrc rc = iwkv_init();
  return rc;
}

static void iwkv_test9_1(void) {
  struct iwkv_opts opts = {
    .path = "iwkv_test9_1.db",
    .oflags = IWKV_TRUNC
  };
  struct iwkv *kv = NULL;
  iwrc rc = iwkv_open(&opts, &kv);
  assert(rc == 0);
  struct iwdb *db = NULL;
  rc = iwkv_db(kv, 1, 0, &db);
  assert(rc == 0);

  {
    unsigned char ip1[4] = { 1, 0, 142, 235 };
    struct iwkv_val ikey, ival;
    ikey.data = ip1;
    ikey.size = 4;
    ival.data = (void*) "";
    ival.size = 0;
    iwkv_opflags opflags = IWKV_NO_OVERWRITE;
    iwrc rc = iwkv_put(db, &ikey, &ival, opflags);
    IW_TEST_ASSERT_EQUAL(rc, 0);
  }

  {
    unsigned char ip2[4] = { 1, 0, 145, 2 };
    struct iwkv_val ikey, ival;
    ikey.data = ip2;
    ikey.size = 4;
    ival.data = (void*) "";
    ival.size = 0;
    iwkv_opflags opflags = IWKV_NO_OVERWRITE;
    iwrc rc = iwkv_put(db, &ikey, &ival, opflags);
    IW_TEST_ASSERT_EQUAL(rc, 0);
  }
  iwkv_close(&kv);
}

static const struct iw_test_case cases[] = {
  IW_TEST_CASE(iwkv_test9_1),
};

int main(int argc, char *argv[]) {
  return iw_test_run(argc, argv, IW_TEST_SUITE("iwkv_test9", cases, init_suite, 0));
}

