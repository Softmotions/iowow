#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwcfg.h"
#include "tests.h"
#include "iwkv_internal.h"

int init_suite(void) {
  iwrc rc = iwkv_init();
  return rc;
}

static void iwkv_test6_1_impl(int fmt_version) {
  iwrc rc;
  struct iwkv_val key = { 0 };
  struct iwkv_val val = { 0 };
  struct iwkv *iwkv;
  struct iwdb *db;
  struct iwkv_cursor *cur;

  struct iwkv_opts opts = {
    .path = "iwkv_test6_1.db",
    .oflags = IWKV_TRUNC,
    .fmt_version = fmt_version
  };
  rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, IWDB_VNUM64_KEYS | IWDB_COMPOUND_KEYS, &db);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  for (uint32_t i = 0; i < 100; ++i) {
    key.data = &i;
    key.size = sizeof(i);
    for (uint32_t j = 0; j < 1000; ++j) {
      key.compound = j;
      val.data = &j;
      val.size = sizeof(j);
      rc = iwkv_put(db, &key, &val, 0);
      IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
      rc = iwkv_get(db, &key, &val);
      IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
      IW_TEST_ASSERT_EQUAL_FATAL(key.size, sizeof(i));
      IW_TEST_ASSERT_TRUE_FATAL(!memcmp(key.data, &i, sizeof(i)));
      IW_TEST_ASSERT_TRUE_FATAL(val.size == 4 && val.compound == 0 && !memcmp(val.data, &j, sizeof(j)));
      iwkv_val_dispose(&val);
    }
  }
  for (uint32_t i = 0; i < 10; ++i) {
    key.data = &i;
    key.size = sizeof(i);
    for (uint32_t j = 0; j < 10; ++j) {
      key.compound = j;
      struct iwkv_val ckey;
      rc = iwkv_cursor_open(db, &cur, IWKV_CURSOR_EQ, &key);
      IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
      rc = iwkv_cursor_key(cur, &ckey);
      IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
      int64_t llv;
      IW_TEST_ASSERT_TRUE_FATAL(ckey.size == 8);
      memcpy(&llv, ckey.data, sizeof(llv));
      IW_TEST_ASSERT_TRUE_FATAL(ckey.compound == j && llv == i);
      iwkv_val_dispose(&ckey);
      rc = iwkv_cursor_close(&cur);
      IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
    }
  }
  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

void iwkv_test6_1_v1(void) {
  iwkv_test6_1_impl(1);
}

void iwkv_test6_1_v2(void) {
  iwkv_test6_1_impl(2);
}

static void iwkv_test6_2_impl(int fmt_version) {
  iwrc rc;
  struct iwkv *iwkv;
  struct iwdb *db;
  struct iwkv_val key = { 0 };
  struct iwkv_val val = { 0 };
  char kbuf[PREFIX_KEY_LEN_V2];

  struct iwkv_opts opts = {
    .path = "iwkv_test6_2.db",
    .oflags = IWKV_TRUNC,
    .fmt_version = fmt_version
  };
  rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  for (int i = 0; i < PREFIX_KEY_LEN_V2 - 1; ++i) {
    kbuf[i] = (i % 94) + 33;
  }

  rc = iwkv_db(iwkv, 1, IWDB_COMPOUND_KEYS, &db);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  for (uint32_t i = 0; i < 1000; ++i) {
    key.data = kbuf;
    key.size = PREFIX_KEY_LEN_V2 - 1;
    key.compound = i;
    rc = iwkv_put(db, &key, &val, 0);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
    rc = iwkv_get(db, &key, &val);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  }
  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

static void iwkv_test6_2_v1(void) {
  iwkv_test6_2_impl(1);
}

static void iwkv_test6_2_v2(void) {
  iwkv_test6_2_impl(2);
}

static const struct iw_test_case cases[] = {
  IW_TEST_CASE(iwkv_test6_1_v1),
  IW_TEST_CASE(iwkv_test6_1_v2),
  IW_TEST_CASE(iwkv_test6_2_v1),
  IW_TEST_CASE(iwkv_test6_2_v2),
};

int main(int argc, char *argv[]) {
  return iw_test_run(argc, argv, IW_TEST_SUITE("iwkv_test6", cases, init_suite, 0));
}

