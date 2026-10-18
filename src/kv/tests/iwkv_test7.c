#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwcfg.h"
#include "tests.h"
#include "iwkv_internal.h"

#define KBUFSZ 1024
#define VBUFSZ 1024
char kbuf[KBUFSZ];
char vbuf[VBUFSZ];

uint32_t g_seed;

int init_suite(void) {
  iwrc rc = iwkv_init();
  RCRET(rc);
  g_seed = 2681089616;
  return rc;
}

static void iwkv_test7_1_impl(int direction) {
  iwrc rc;
  struct iwkv *iwkv;
  struct iwdb *db;
  struct iwkv_val key = { 0 };
  struct iwkv_val val = { 0 };
  struct iwkv_opts opts = {
    .path = direction > 0 ? "iwkv_test7_2_fwd.db" : "iwkv_test7_2_back.db",
    .oflags = IWKV_TRUNC,
    .random_seed = g_seed
  };
  rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, IWDB_COMPOUND_KEYS, &db);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  const int nrecords = 50000;

  for (int i = 0; i < nrecords; ++i) {
    snprintf(kbuf, KBUFSZ, "5368fce5-c138-4f0d-bfee-dbce07eb28e1%d", i);
    snprintf(vbuf, VBUFSZ, "%04d", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    key.compound = direction > 0 ? i + 1 : nrecords - i;

    val.data = vbuf;
    val.size = strlen(val.data);
    rc = iwkv_put(db, &key, &val, 0);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  }

  for (int i = 0; i < nrecords; ++i) {
    snprintf(kbuf, KBUFSZ, "5368fce5-c138-4f0d-bfee-dbce07eb28e1%d", i);
    snprintf(vbuf, VBUFSZ, "%04d", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    key.compound = direction > 0 ? i + 1 : nrecords - i;
    rc = iwkv_get(db, &key, &val);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
    iwkv_val_dispose(&val);
  }
  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

static void iwkv_test7_1(void) {
  iwkv_test7_1_impl(1);
  iwkv_test7_1_impl(-1);
  struct iwp_file_stat fwd_s = { 0 };
  struct iwp_file_stat back_s = { 0 };
  iwrc rc = iwp_fstat("iwkv_test7_2_fwd.db", &fwd_s);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwp_fstat("iwkv_test7_2_back.db", &back_s);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_TRUE((double) fwd_s.size / back_s.size < 1.1);
}

static const struct iw_test_case cases[] = {
  IW_TEST_CASE(iwkv_test7_1),
};

int main(int argc, char *argv[]) {
  return iw_test_run(argc, argv, IW_TEST_SUITE("iwkv_test7", cases, init_suite, 0));
}

