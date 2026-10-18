#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "tests.h"
#include "iwkv_internal.h"
#include "iwth.h"

#define KBUFSZ 1024
#define VBUFSZ 1024
static char kbuf[KBUFSZ];
static char vbuf[VBUFSZ];

int init_suite(void) {
  return iwkv_init();
}

static void iwkv_test10_1_impl(int fmt_version) {
  struct iwkv *iwkv;
  struct iwkv_opts opts = {
    .path = fmt_version > 1 ? "iwkv_test10_1_v2.db" : "iwkv_test10_1_v1.db",
    .oflags = IWKV_TRUNC,
    .wal = {
      .enabled = true
    }
  };

  iwrc rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  for (int i = 0; i < 1024; ++i) {
    struct iwdb *db;
    rc = iwkv_db(iwkv, i, 0, &db);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
    for (int j = 0; j < 1024; ++j) {
      struct iwkv_val key, val;
      snprintf(kbuf, KBUFSZ, "%d", j);
      snprintf(vbuf, VBUFSZ, "%03dval", j);
      key.data = kbuf;
      key.size = strlen(key.data);
      val.data = vbuf;
      val.size = strlen(val.data);
      rc = iwkv_put(db, &key, &val, 0);
      IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
    }
  }

  for (int i = 0; i < 1024; ++i) {
    if ((i % 2)) {
      struct iwdb *db;
      rc = iwkv_db(iwkv, i, 0, &db);
      IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
      rc = iwkv_db_destroy(&db);
      IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
    }
  }

  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  opts.oflags = 0;
  rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  for (int i = 0; i < 1024; ++i) {
    if (!(i % 2)) {
      struct iwdb *db;
      rc = iwkv_db(iwkv, i, 0, &db);
      IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
      for (int j = 0; j < 1024; ++j) {
        struct iwkv_val key, val;
        int cret = 0;
        snprintf(kbuf, KBUFSZ, "%d", j);
        snprintf(vbuf, VBUFSZ, "%03dval", j);
        key.data = kbuf;
        key.size = strlen(key.data);
        int vlen = strlen(vbuf);
        rc = iwkv_get(db, &key, &val);
        IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
        IW_CMP(cret, vbuf, vlen, val.data, val.size);
        IW_TEST_ASSERT_EQUAL_FATAL(cret, 0);
        iwkv_val_dispose(&val);
      }
    }
  }

  for (int i = 0; i < 1024; ++i) {
    if (!(i % 2)) {
      struct iwdb *db;
      rc = iwkv_db(iwkv, i, 0, &db);
      IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
      rc = iwkv_db_destroy(&db);
      IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
    }
  }

  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  // IWP_FILE_STAT fs;
  // rc = iwp_fstat(opts.path, &fs);
  // IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  // IW_TEST_ASSERT_TRUE(fs.size < 1024 * 1024);
}

static void iwkv_test10_1_v1(void) {
  iwkv_test10_1_impl(1);
}

static void iwkv_test10_1_v2(void) {
  iwkv_test10_1_impl(2);
}

static const struct iw_test_case cases[] = {
  IW_TEST_CASE(iwkv_test10_1_v1),
  IW_TEST_CASE(iwkv_test10_1_v2),
};

int main(int argc, char *argv[]) {
  return iw_test_run(argc, argv, IW_TEST_SUITE("iwkv_test10", cases, init_suite, 0));
}

