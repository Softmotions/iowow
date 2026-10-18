#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwcfg.h"
#include "tests.h"
#include "iwkv_internal.h"

#define KBUFSZ 128
#define VBUFSZ 128
static char kbuf[KBUFSZ];
static char vbuf[VBUFSZ];

/**
 * Test cursor consistency
 */

int init_suite(void) {
  iwrc rc = iwkv_init();
  return rc;
}

static void iwkv_test5_2(void) {
  iwrc rc;
  struct iwkv *iwkv;
  struct iwdb *db;
  struct iwkv_val key = { 0 };
  struct iwkv_val val = { 0 };
  struct iwkv_cursor *cur1;
  struct iwkv_opts opts = {
    .path = "iwkv_test5_2.db",
    .oflags = IWKV_TRUNC
  };

  rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  for (int i = 1; i <= 64; ++i) {
    snprintf(kbuf, KBUFSZ, "%03dkkk", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    val.data = vbuf;
    val.size = strlen(val.data);
    rc = iwkv_put(db, &key, &val, 0);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  }

  // Remove all data from start
  rc = iwkv_cursor_open(db, &cur1, IWKV_CURSOR_BEFORE_FIRST, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  for (int i = 1; i <= 64; ++i) {
    rc = iwkv_cursor_to(cur1, IWKV_CURSOR_NEXT);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
    rc = iwkv_cursor_del(cur1, 0);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  }
  rc = iwkv_cursor_close(&cur1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_cursor_open(db, &cur1, IWKV_CURSOR_BEFORE_FIRST, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_cursor_to(cur1, IWKV_CURSOR_NEXT);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_NOTFOUND);
  rc = iwkv_cursor_close(&cur1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);


  // Refill
  for (int i = 1; i <= 64; ++i) {
    snprintf(kbuf, KBUFSZ, "%03dkkk", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    val.data = vbuf;
    val.size = strlen(val.data);
    rc = iwkv_put(db, &key, &val, 0);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  }
  // Remove all data from end
  rc = iwkv_cursor_open(db, &cur1, IWKV_CURSOR_AFTER_LAST, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  for (int i = 1; i <= 64; ++i) {
    rc = iwkv_cursor_to(cur1, IWKV_CURSOR_PREV);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
    rc = iwkv_cursor_del(cur1, 0);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  }
  rc = iwkv_cursor_close(&cur1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_cursor_open(db, &cur1, IWKV_CURSOR_BEFORE_FIRST, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_cursor_to(cur1, IWKV_CURSOR_NEXT);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_NOTFOUND);
  rc = iwkv_cursor_close(&cur1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

static void iwkv_test5_1(void) {
  iwrc rc;
  struct iwkv_val key = { 0 };
  struct iwkv_val val = { 0 };
  struct iwkv *iwkv;
  struct iwdb *db;
  struct iwkv_cursor *cur1, *cur2;
  struct iwkv_opts opts = {
    .path = "iwkv_test5_1.db",
    .oflags = IWKV_TRUNC
  };
  rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  int c = 0;
  for (int i = 1; i < 30 * 2; i = i + 2, ++c) {
    snprintf(kbuf, KBUFSZ, "%03dkkk", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    val.data = vbuf;
    val.size = strlen(val.data);
    rc = iwkv_put(db, &key, &val, 0);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  }

  //K: 023kkk
  //K: 025kkk <--
  //K: 027kkk
  //K: 029kkk
  snprintf(kbuf, KBUFSZ, "%03dkkk", 25);
  key.data = kbuf;
  key.size = strlen(key.data);
  rc = iwkv_cursor_open(db, &cur1, IWKV_CURSOR_EQ, &key);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  //K: 023kkk
  //K: 025kkk
  //K: 027kkk
  //K: 029kkk <--
  //K: 031kkk

  snprintf(kbuf, KBUFSZ, "%03dkkk", 29);
  key.data = kbuf;
  key.size = strlen(key.data);
  rc = iwkv_cursor_open(db, &cur2, IWKV_CURSOR_EQ, &key);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  IW_TEST_ASSERT_EQUAL(cur1->cnpos, 17);
  IW_TEST_ASSERT_EQUAL(cur2->cnpos, 15);

  //K: 023kkk
  //K: 025kkk <--
  //K: 026kkk +
  //K: 027kkk
  //K: 029kkk <--
  //K: 031kkk
  snprintf(kbuf, KBUFSZ, "%03dkkk", 26);
  snprintf(vbuf, VBUFSZ, "%03dval", 26);
  key.data = kbuf;
  key.size = strlen(key.data);
  val.data = vbuf;
  val.size = strlen(val.data);
  rc = iwkv_put(db, &key, &val, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  IW_TEST_ASSERT_EQUAL(cur1->cnpos, 18);
  IW_TEST_ASSERT_EQUAL(cur2->cnpos, 15);

  snprintf(kbuf, KBUFSZ, "%03dkkk", 0);
  snprintf(vbuf, VBUFSZ, "%03dval", 0);
  key.data = kbuf;
  key.size = strlen(key.data);
  val.data = vbuf;
  val.size = strlen(val.data);
  rc = iwkv_put(db, &key, &val, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  IW_TEST_ASSERT_EQUAL(cur1->cnpos, 18);
  IW_TEST_ASSERT_EQUAL(cur2->cnpos, 15);

  //K: 023kkk
  //K: 025kkk <--
  //K: 026kkk +
  //K: 027kkk
  //K: 028kkk +
  //K: 029kkk <--
  //K: 031kkk

  // FORCE SPLIT:
  snprintf(kbuf, KBUFSZ, "%03dkkk", 28);
  snprintf(vbuf, VBUFSZ, "%03dval", 28);
  key.data = kbuf;
  key.size = strlen(key.data);
  val.data = vbuf;
  val.size = strlen(val.data);
  rc = iwkv_put(db, &key, &val, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  IW_TEST_ASSERT_EQUAL(cur1->cnpos, 1);
  IW_TEST_ASSERT_EQUAL(cur2->cnpos, 15);

  rc = iwkv_cursor_get(cur1, &key, &val);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_FALSE(strncmp((char*) key.data, "025kkk", strlen("025kkk")));
  IW_TEST_ASSERT_FALSE(strncmp((char*) val.data, "025val", strlen("025val")));
  iwkv_kv_dispose(&key, &val);

  rc = iwkv_cursor_to(cur1, IWKV_CURSOR_NEXT);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_cursor_get(cur1, &key, &val);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_FALSE(strncmp((char*) key.data, "023kkk", strlen("023kkk")));
  IW_TEST_ASSERT_FALSE(strncmp((char*) val.data, "023val", strlen("023val")));
  iwkv_kv_dispose(&key, &val);

  rc = iwkv_cursor_to(cur1, IWKV_CURSOR_PREV);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_cursor_to(cur1, IWKV_CURSOR_PREV);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_cursor_get(cur1, &key, &val);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_FALSE(strncmp((char*) key.data, "026kkk", strlen("026kkk")));
  IW_TEST_ASSERT_FALSE(strncmp((char*) val.data, "026val", strlen("026val")));
  iwkv_kv_dispose(&key, &val);

  rc = iwkv_cursor_to(cur1, IWKV_CURSOR_PREV);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_cursor_get(cur1, &key, &val);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_FALSE(strncmp((char*) key.data, "027kkk", strlen("027kkk")));
  IW_TEST_ASSERT_FALSE(strncmp((char*) val.data, "027val", strlen("027val")));
  iwkv_kv_dispose(&key, &val);

  IW_TEST_ASSERT_EQUAL(cur1->cnpos, 17);

  rc = iwkv_cursor_close(&cur1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_cursor_close(&cur2);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

static const struct iw_test_case cases[] = {
  IW_TEST_CASE(iwkv_test5_1),
  IW_TEST_CASE(iwkv_test5_2),
};

int main(int argc, char *argv[]) {
  return iw_test_run(argc, argv, IW_TEST_SUITE("iwkv_test5", cases, init_suite, 0));
}

