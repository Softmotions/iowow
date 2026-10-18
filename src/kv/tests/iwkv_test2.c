#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwcfg.h"
#include "iwtests.h"

#define RND_DATA_SZ (10 * 1048576)
char RND_DATA[RND_DATA_SZ];

int init_suite(void) {
  iwrc rc = iwkv_init();
  return rc;
}

static void iwkv_test2_1(void) {
  struct iwkv_opts opts = {
    .path = "iwkv_test2_1.db",
    .oflags = IWKV_TRUNC
  };
  const uint64_t numrec = 1000000; // 1M
  // Test open/close
  struct iwkv *iwkv;
  struct iwdb *db1;
  struct iwkv_val key, val;
  iwrc rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_db(iwkv, 1, IWDB_VNUM64_KEYS, &db1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  for (uint64_t i = 0; i < numrec; ++i) {
    key.size = sizeof(uint64_t);
    key.data = &i;
    val.size = sizeof(uint64_t);
    val.data = &i;
    rc = iwkv_put(db1, &key, &val, 0);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  }

  for (uint64_t v = 0; v < numrec; ++v) {
    uint64_t llv;
    key.data = &v;
    key.size = sizeof(uint64_t);
    rc = iwkv_get(db1, &key, &val);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
    memcpy(&llv, val.data, sizeof(llv));
    IW_TEST_ASSERT_EQUAL_FATAL(llv, v);
    iwkv_val_dispose(&val);
  }

  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

static const struct iw_test_case cases[] = {
  IW_TEST_CASE(iwkv_test2_1),
};

int main(int argc, char *argv[]) {
  return iw_test_run(argc, argv, IW_TEST_SUITE("iwkv_test2", cases, init_suite, 0));
}

