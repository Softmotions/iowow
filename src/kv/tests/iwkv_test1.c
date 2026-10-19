#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwtests.h"

#define KBUFSZ 128
#define VBUFSZ 128
char kbuf[KBUFSZ];
char vbuf[VBUFSZ];

extern int8_t iwkv_next_level;

static int logstage(FILE *f, const char *name, struct iwdb *db) {
  int rci = fprintf(f, "\n#### Stage: %s\n", name);
  iwkvd_db(f, db, IWKVD_PRINT_NO_LEVEVELS | IWKVD_PRINT_VALS, 0);
  fflush(f);
  return rci < 0 ? rci : 0;
}

static int logstage2(FILE *f, const char *name, struct iwdb *db) {
  int rci = fprintf(f, "\n#### Stage: %s\n", name);
  iwkvd_db(f, db, IWKVD_PRINT_NO_LEVEVELS | IWKVD_PRINT_VALS, 0);
  fflush(f);
  return rci < 0 ? rci : 0;
}

int init_suite(void) {
  iwrc rc = iwkv_init();
  return rc;
}

// Test5 staff
struct Test5DUP1 {
  bool _mv;
  bool _1v;
  bool _10v;
};

static int64_t _test5dup5visitor(uint64_t dv, int64_t idx, void *op) {
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(op);
  struct Test5DUP1 *s = op;
  switch (dv) {
    case -1ULL:
      s->_mv = true;
      break;
    case 1ULL:
      s->_1v = true;
      break;
    case 10ULL:
      s->_10v = true;
      break;
    default:
      IW_TEST_FAIL("Invalid dup value");
      break;
  }
  return 1;
}

// Test Slides
static void iwkv_test3_impl(int fmt_version) {
  FILE *f = fmt_version > 1 ? fopen("iwkv_test1_3_v2.log", "w+") : fopen("iwkv_test1_3.log", "w+");
  IW_TEST_ASSERT_PTR_NOT_NULL(f);

  iwrc rc;
  struct iwkv_val key = { 0 };
  struct iwkv_val val = { 0 };
  struct iwkv *iwkv;
  struct iwdb *db1;
  struct iwkv_opts opts = {
    .path = "iwkv_test1_3.db",
    .oflags = IWKV_TRUNC,
    .fmt_version = fmt_version
  };

  rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  for (int i = -23, c = 0; i <= 23; ++i) {
    for (int j = 0; j < 63; ++j, ++c) {
      iwkv_next_level = i < 0 ? -i : i;
      snprintf(kbuf, KBUFSZ, "%05dkkk", c);
      snprintf(vbuf, VBUFSZ, "%05dval", c);
      key.data = kbuf;
      key.size = strlen(key.data);
      val.data = vbuf;
      val.size = strlen(val.data);
      rc = iwkv_put(db1, &key, &val, 0);
      IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
    }
  }
  //       middle
  // 23 \    |    / 23
  //     \   |   /
  //    0 \__|__/ 0
  iwkv_next_level = 23;
  // put: 01858aaa in order to split middle zero sblk
  snprintf(kbuf, KBUFSZ, "%05daaa", 1858);
  snprintf(vbuf, VBUFSZ, "%05dval", 1858);
  rc = iwkv_put(db1, &key, &val, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  logstage2(f, "iwkv_test3", db1);

  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  // Compare logs with referenced
#ifndef _WIN32
  FILE *r = fmt_version > 1 ? fopen("iwkv_test1_3_v2.ref", "r+") : fopen("iwkv_test1_3.ref", "r+");
#else
  FILE *r = fmt_version > 1 ? fopen("iwkv_test1_3w_v2.ref", "r+") : fopen("iwkv_test1_3w.ref", "r+");
#endif
  IW_TEST_ASSERT_PTR_NOT_NULL(r);
  int rci = iw_test_cmp_files(r, f);
  IW_TEST_ASSERT_EQUAL_FATAL(rci, 0);
  fclose(f);
  fclose(r);
}

static void iwkv_test3_v2(void) {
  iwkv_test3_impl(2);
}

static void iwkv_test2_impl(int fmt_version) {
  FILE *f = fmt_version > 1 ? fopen("iwkv_test1_2_v2.log", "w+") : fopen("iwkv_test1_2.log", "w+");
  IW_TEST_ASSERT_PTR_NOT_NULL(f);

  iwrc rc;
  struct iwkv_val key = { 0 };
  struct iwkv_val val = { 0 };
  struct iwkv *iwkv;
  struct iwdb *db1;
  struct iwkv_opts opts = {
    .path = "iwkv_test1_2.db",
    .oflags = IWKV_TRUNC,
    .fmt_version = fmt_version
  };

  rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  for (int i = 252 * 2; i >= 0; --i) { // 189
    snprintf(kbuf, KBUFSZ, "%03dkkk", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    val.data = vbuf;
    val.size = strlen(val.data);
    rc = iwkv_put(db1, &key, &val, 0);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  }
  logstage(f, "desc sorted keys inserted", db1);

  for (int i = 0; i <= 252 * 2; ++i) {
    int cret;
    snprintf(kbuf, KBUFSZ, "%03dkkk", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    int vsize = strlen(vbuf);
    key.data = kbuf;
    key.size = strlen(key.data);
    rc = iwkv_get(db1, &key, &val);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
    IW_CMP(cret, vbuf, vsize, val.data, val.size);
    IW_TEST_ASSERT_EQUAL_FATAL(cret, 0);
    iwkv_kv_dispose(0, &val);
  }

  //  snprintf(kbuf, KBUFSZ, "%03dkkk", 64);
  //  key.data = kbuf;
  //  key.size = strlen(key.data);
  //  rc = iwkv_del(db1, &key);
  //  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  //  logstage(f, "removed 064kkk", db1);
  //
  //
  //  snprintf(kbuf, KBUFSZ, "%03dkkk", 126);
  //  key.data = kbuf;
  //  key.size = strlen(key.data);
  //  rc = iwkv_del(db1, &key);
  //  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  //  logstage(f, "removed 126kkk", db1);
  //
  //
  //  // Now delete more than half of block records
  //  // 126
  //  for (int i = 64; i <= 99; ++i) {
  //    snprintf(kbuf, KBUFSZ, "%03dkkk", i);
  //    key.data = kbuf;
  //    key.size = strlen(key.data);
  //    rc = iwkv_del(db1, &key);
  //    if (i == 64) {
  //      IW_TEST_ASSERT_EQUAL(rc, IWKV_ERROR_NOTFOUND);
  //      rc = 0;
  //      continue;
  //    }
  //    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  //  }
  //  logstage(f, "removed 065kkk - 099kkk", db1); // 125
  //
  //  for (int i = 100; i <= 125; ++i) {
  //    snprintf(kbuf, KBUFSZ, "%03dkkk", i);
  //    key.data = kbuf;
  //    key.size = strlen(key.data);
  //    rc = iwkv_del(db1, &key);
  //    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  //  }
  //  logstage(f, "removed all keys in SBLK[54]", db1); // 125

  rc = iwkv_db_destroy(&db1);      // Destroy DB and remove all db blocks
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  // Reopen DB then check db1
  rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_db(iwkv, 1, 0, &db1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  logstage(f, "db1 destroyed", db1);
  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  // Compare logs with referenced
#ifndef _WIN32
  FILE *r = fmt_version > 1 ? fopen("iwkv_test1_2_v2.ref", "r+") : fopen("iwkv_test1_2.ref", "r+");
#else
  FILE *r = fmt_version > 1 ? fopen("iwkv_test1_2w_v2.ref", "r+") : fopen("iwkv_test1_2w.ref", "r+");
#endif
  IW_TEST_ASSERT_PTR_NOT_NULL(r);
  int rci = iw_test_cmp_files(r, f);
  IW_TEST_ASSERT_EQUAL_FATAL(rci, 0);
  fclose(f);
  fclose(r);
}

static void iwkv_test2_v2(void) {
  iwkv_test2_impl(2);
}

static void iwkv_test1_impl(int fmt_version) {
  FILE *f = fmt_version > 1 ? fopen("iwkv_test1_1_v2.log", "w+") : fopen("iwkv_test1_1.log", "w+");
  IW_TEST_ASSERT_PTR_NOT_NULL(f);
  char buf[128];
  size_t vsize;

  struct iwkv_opts opts = {
    .path = "iwkv_test1.db",
    .oflags = IWKV_TRUNC,
    .fmt_version = fmt_version
  };
  // Test open/close
  struct iwkv *iwkv;
  struct iwdb *db1, *db2, *db3;
  iwrc rc;
  struct iwkv_val key = { .data = "foo" };
  key.size = strlen(key.data);
  struct iwkv_val val = { .data = "bar" };
  val.size = strlen(val.data);

  rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  // Test open/close existing db
  opts.oflags = 0;
  rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  // Test create/destroy db
  rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 2, 0, &db2); // destroyed
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 3, 0, &db3);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db_destroy(&db2);     // destroyed
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  // Test one in read-only mode
  opts.oflags = IWKV_RDONLY;
  opts.path = "not-existing.db";
  rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_TRUE_FATAL(rc);
  iwrc_strip_errno(&rc);
#ifdef _WIN32
  iwrc_strip_werror(&rc);
#endif
  IW_TEST_ASSERT_EQUAL(rc, IW_ERROR_NOT_EXISTS);

  // Open in read-only mode and acquire not existing db
  opts.path = "iwkv_test1.db";
  rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_db(iwkv, 2, 0, &db2);
  IW_TEST_ASSERT_EQUAL(rc, IW_ERROR_READONLY);

  rc = iwkv_db(iwkv, 1, 0, &db1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_db(iwkv, 3, 0, &db3);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  logstage(f, "empty db", db1);

  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  // Open in write mode, then put a simple kv
  opts.oflags = 0;
  rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  // iwkv_next_level = 3;
  rc = iwkv_put(db1, &key, &val, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  logstage(f, "put foo:bar", db1);

  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  // Open db and get out single record
  rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  val.size = 0;
  val.data = 0;

  rc = iwkv_get(db1, &key, &val);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_NSTR_EQUAL(key.data, "foo", key.size);
  IW_TEST_ASSERT_NSTR_EQUAL(val.data, "bar", val.size);
  iwkv_kv_dispose(0, &val);

  rc = iwkv_get_copy(db1, &key, buf, sizeof(buf), &vsize);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(3, vsize);
  IW_TEST_ASSERT_NSTR_EQUAL(buf, "bar", vsize);

  rc = iwkv_get_copy(db1, &key, buf, 1, &vsize);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(3, vsize);
  IW_TEST_ASSERT_NSTR_EQUAL(buf, "b", 1);

  // put foo->bazzz
  key.data = "foo";
  key.size = strlen(key.data);
  val.data = "bazzz";
  val.size = strlen(val.data);
  rc = iwkv_put(db1, &key, &val, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  // put foo->zzz with IWKV_NO_OVERWRITE
  val.data = "zzz";
  val.size = strlen(val.data);
  rc = iwkv_put(db1, &key, &val, IWKV_NO_OVERWRITE);

  IW_TEST_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_KEY_EXISTS);
  rc = iwkv_get(db1, &key, &val);
  IW_TEST_ASSERT_NSTR_EQUAL(key.data, "foo", key.size);
  IW_TEST_ASSERT_NSTR_EQUAL(val.data, "bazzz", val.size);
  iwkv_kv_dispose(0, &val);

  logstage(f, "put foo:bazz", db1);

  // put foo->''
  val.data = "";
  val.size = strlen(val.data);
  rc = iwkv_put(db1, &key, &val, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_get(db1, &key, &val);
  IW_TEST_ASSERT_NSTR_EQUAL(key.data, "foo", key.size);
  if (val.data) {
    IW_TEST_ASSERT_NSTR_EQUAL(val.data, "", val.size);
  }
  iwkv_kv_dispose(0, &val);

  logstage(f, "put foo:", db1);

  val.data = "bar";
  val.size = strlen(val.data);
  rc = iwkv_put(db1, &key, &val, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_get(db1, &key, &val);
  IW_TEST_ASSERT_NSTR_EQUAL(key.data, "foo", key.size);
  IW_TEST_ASSERT_NSTR_EQUAL(val.data, "bar", val.size);
  iwkv_kv_dispose(0, &val);

  logstage(f, "put foo:bar", db1);

  // remove key/value
  rc = iwkv_del(db1, &key, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_get(db1, &key, &val);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_NOTFOUND);

  logstage(f, "remove foo:bar", db1);

  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_get(db1, &key, &val);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_NOTFOUND);

  // iwkv_next_level = 0;

  for (int i = 0; i < 127 * 2; i += 2) {
    snprintf(kbuf, KBUFSZ, "%03dkkk", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    val.data = vbuf;
    val.size = strlen(val.data);
    rc = iwkv_put(db1, &key, &val, 0);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  }

  logstage(f, "fill up first block", db1);

  // iwkv_next_level = 0;
  for (int i = 0; i < 127 * 2; i += 2) {
    snprintf(kbuf, KBUFSZ, "%03dkkk", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    rc = iwkv_get(db1, &key, &val);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
    IW_TEST_ASSERT_EQUAL_FATAL(strncmp(val.data, vbuf, val.size), 0);
    iwkv_kv_dispose(0, &val);
  }

  for (int i = 1; i < 127 * 2; i += 2) {
    snprintf(kbuf, KBUFSZ, "%03dkkk", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    val.data = vbuf;
    val.size = strlen(val.data);
    //logstage(stderr, "!!!!!!", db1);
    rc = iwkv_put(db1, &key, &val, 0);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
    //logstage(stderr, "??????", db1);
  }

  logstage(f, "fill up second block", db1);

  // Check basic cursor operations
  struct iwkv_cursor *cur1;

  rc = iwkv_cursor_open(db1, &cur1, IWKV_CURSOR_BEFORE_FIRST, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_cursor_to(cur1, IWKV_CURSOR_PREV);
  IW_TEST_ASSERT_EQUAL(rc, IWKV_ERROR_NOTFOUND);
  rc = iwkv_cursor_close(&cur1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_cursor_open(db1, &cur1, IWKV_CURSOR_AFTER_LAST, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_cursor_get(cur1, &key, &val);
  IW_TEST_ASSERT_EQUAL(rc, IWKV_ERROR_NOTFOUND);
  rc = iwkv_cursor_to(cur1, IWKV_CURSOR_NEXT);
  IW_TEST_ASSERT_EQUAL(rc, IWKV_ERROR_NOTFOUND);
  rc = iwkv_cursor_close(&cur1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_cursor_open(db1, &cur1, IWKV_CURSOR_AFTER_LAST, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_cursor_to(cur1, IWKV_CURSOR_PREV);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  int i = 0;
  do {
    struct iwkv_val key;
    struct iwkv_val val;
    iwrc rc2 = iwkv_cursor_get(cur1, &key, &val);
    IW_TEST_ASSERT_EQUAL_FATAL(rc2, 0);
    snprintf(kbuf, KBUFSZ, "%03dkkk", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    IW_TEST_ASSERT_EQUAL(strncmp(key.data, kbuf, key.size), 0);
    IW_TEST_ASSERT_EQUAL(strncmp(val.data, vbuf, val.size), 0);
    iwkv_kv_dispose(&key, &val);
    if (i == 2) {
      rc2 = iwkv_cursor_to(cur1, IWKV_CURSOR_PREV);
      IW_TEST_ASSERT_EQUAL_FATAL(rc2, 0);
      rc2 = iwkv_cursor_get(cur1, &key, &val);
      IW_TEST_ASSERT_EQUAL_FATAL(rc2, 0);
      snprintf(kbuf, KBUFSZ, "%03dkkk", i + 1);
      snprintf(vbuf, VBUFSZ, "%03dval", i + 1);
      IW_TEST_ASSERT_EQUAL(strncmp(key.data, kbuf, key.size), 0);
      IW_TEST_ASSERT_EQUAL(strncmp(val.data, vbuf, val.size), 0);
      rc2 = iwkv_cursor_to(cur1, IWKV_CURSOR_NEXT);
      IW_TEST_ASSERT_EQUAL_FATAL(rc2, 0);
      iwkv_kv_dispose(&key, &val);
    }
    ++i;
  } while (!(rc = iwkv_cursor_to(cur1, IWKV_CURSOR_PREV)));
  IW_TEST_ASSERT_EQUAL(rc, IWKV_ERROR_NOTFOUND);
  rc = iwkv_cursor_close(&cur1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  --i;
  rc = iwkv_cursor_open(db1, &cur1, IWKV_CURSOR_BEFORE_FIRST, 0);
  while (!(rc = iwkv_cursor_to(cur1, IWKV_CURSOR_NEXT))) {
    struct iwkv_val key;
    struct iwkv_val val;
    iwrc rc2 = iwkv_cursor_get(cur1, &key, &val);
    IW_TEST_ASSERT_EQUAL_FATAL(rc2, 0);
    snprintf(kbuf, KBUFSZ, "%03dkkk", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    --i;
    IW_TEST_ASSERT_EQUAL(strncmp(key.data, kbuf, key.size), 0);
    IW_TEST_ASSERT_EQUAL(strncmp(val.data, vbuf, val.size), 0);
    iwkv_kv_dispose(&key, &val);
  }
  IW_TEST_ASSERT_EQUAL(rc, IWKV_ERROR_NOTFOUND);
  rc = iwkv_cursor_close(&cur1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  // Set cursor to key
  do {
    struct iwkv_val key;
    struct iwkv_val val;
    snprintf(kbuf, KBUFSZ, "%03dkkk", 30);
    snprintf(vbuf, VBUFSZ, "%03dval", 30);
    key.data = kbuf;
    key.size = strlen(kbuf);
    rc = iwkv_cursor_open(db1, &cur1, IWKV_CURSOR_EQ, &key);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
    iwrc rc2 = iwkv_cursor_get(cur1, &key, &val);
    IW_TEST_ASSERT_EQUAL_FATAL(rc2, 0);
    IW_TEST_ASSERT_EQUAL(strncmp(key.data, kbuf, key.size), 0);
    IW_TEST_ASSERT_EQUAL(strncmp(val.data, vbuf, val.size), 0);
    iwkv_kv_dispose(&key, &val);

    // Move to GE 000
    snprintf(kbuf, KBUFSZ, "%03d", 0);
    snprintf(vbuf, VBUFSZ, "%03dval", 0);
    key.data = kbuf;
    key.size = strlen(kbuf);
    rc2 = iwkv_cursor_to_key(cur1, IWKV_CURSOR_GE, &key);
    if (rc2) {
      iwlog_ecode_error3(rc2);
    }
    IW_TEST_ASSERT_EQUAL_FATAL(rc2, 0);
    rc2 = iwkv_cursor_get(cur1, &key, &val);
    IW_TEST_ASSERT_EQUAL_FATAL(rc2, 0);
    snprintf(kbuf, KBUFSZ, "%03dkkk", 0);
    snprintf(vbuf, VBUFSZ, "%03dval", 0);
    IW_TEST_ASSERT_EQUAL(strncmp(key.data, kbuf, key.size), 0);
    IW_TEST_ASSERT_EQUAL(strncmp(val.data, vbuf, val.size), 0);
    iwkv_kv_dispose(&key, &val);

    // Move to EQ 000
    snprintf(kbuf, KBUFSZ, "%03d", 0);
    snprintf(vbuf, VBUFSZ, "%03dval", 0);
    key.data = kbuf;
    key.size = strlen(kbuf);
    rc2 = iwkv_cursor_to_key(cur1, IWKV_CURSOR_EQ, &key);
    IW_TEST_ASSERT_EQUAL(rc2, IWKV_ERROR_NOTFOUND);

    rc = iwkv_cursor_close(&cur1);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  } while (0);

  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  logstage(f, "state after reopen", db1);

  // Put a big key
  snprintf(kbuf, KBUFSZ, "abracadabrabracadabrabracadabrabracadabrabracadabrabracadabrabracadabr1");
  key.size = strlen(kbuf);
  snprintf(vbuf, VBUFSZ, "vabracadabrabracadabrabracadabrabracadabrabracadabrabracadabrabracadabr");
  val.size = strlen(vbuf);
  rc = iwkv_db(iwkv, 1, 0, &db1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_put(db1, &key, &val, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_get(db1, &key, &val);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(strncmp(val.data, vbuf, val.size), 0);
  iwkv_kv_dispose(0, &val);

  logstage(f, "a big key", db1);

  // 061kkk:061val
  // Set value with cursor
  snprintf(kbuf, KBUFSZ, "%03dkkk", 61);
  snprintf(vbuf, VBUFSZ, "%03dval2", 61);
  key.data = kbuf;
  key.size = strlen(kbuf);
  val.data = vbuf;
  val.size = strlen(vbuf);

  // Cursor set
  rc = iwkv_cursor_open(db1, &cur1, IWKV_CURSOR_EQ, &key);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_cursor_set(cur1, &val, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  key.data = 0;
  val.data = 0;
  rc = iwkv_cursor_get(cur1, &key, &val);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(strncmp(key.data, kbuf, key.size), 0);
  IW_TEST_ASSERT_EQUAL(strncmp(val.data, vbuf, val.size), 0);
  iwkv_kv_dispose(&key, &val);
  rc = iwkv_cursor_close(&cur1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  // Set in write mode
  snprintf(kbuf, KBUFSZ, "%03dkkk", 61);
  snprintf(vbuf, VBUFSZ, "%03dval3", 61);
  key.data = kbuf;
  key.size = strlen(kbuf);
  val.data = vbuf;
  val.size = strlen(vbuf);
  rc = iwkv_cursor_open(db1, &cur1, IWKV_CURSOR_EQ, &key);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_cursor_set(cur1, &val, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  key.data = 0;
  val.data = 0;
  rc = iwkv_cursor_get(cur1, &key, &val);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(strncmp(key.data, kbuf, key.size), 0);
  IW_TEST_ASSERT_EQUAL(strncmp(val.data, vbuf, val.size), 0);
  iwkv_kv_dispose(&key, &val);
  rc = iwkv_cursor_close(&cur1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  // Compare logs with referenced
#ifndef _WIN32
  FILE *r = fmt_version > 1 ? fopen("iwkv_test1_1_v2.ref", "r+") : fopen("iwkv_test1_1.ref", "r+");
#else
  FILE *r = fmt_version > 1 ? fopen("iwkv_test1_1w_v2.ref", "r+") : fopen("iwkv_test1_1w.ref", "r+");
#endif
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(r);
  int rci = iw_test_cmp_files(r, f);
  IW_TEST_ASSERT_EQUAL_FATAL(rci, 0);
  fclose(r);
  fclose(f);
}

static void iwkv_test1_v2(void) {
  iwkv_test1_impl(2);
}

static void iwkv_test8_impl(int fmt_version) {
  struct iwkv_opts opts = {
    .path = "iwkv_test1_8.db",
    .oflags = IWKV_TRUNC,
    .fmt_version = fmt_version
  };
  struct iwkv *iwkv;
  struct iwdb *db1;
  struct iwkv_cursor *cur;
  struct iwkv_val key;
  struct iwkv_val val = {
    .data = "foo",
    .size = sizeof("foo") - 1
  };
  struct iwkv_val oval;
  size_t ksz;
  uint64_t llv = 1;
  uint64_t llv2;

  iwrc rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_db(iwkv, 1, IWDB_VNUM64_KEYS, &db1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  key.data = &llv;
  key.size = sizeof(llv);

  rc = iwkv_put(db1, &key, &val, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_get(db1, &key, &oval);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  iwkv_val_dispose(&oval);

  llv = 0xffffffffffffffe;
  key.data = &llv;

  rc = iwkv_put(db1, &key, &val, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_get(db1, &key, &oval);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  iwkv_val_dispose(&oval);

  rc = iwkv_get_copy(db1, &key, &llv2, sizeof(llv2), &ksz);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_cursor_open(db1, &cur, IWKV_CURSOR_EQ, &key);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  llv = 0xffffffffffffffffULL;
  rc = iwkv_put(db1, &key, &val, 0);
  IW_TEST_ASSERT_EQUAL(rc, IW_ERROR_OVERFLOW);


  llv = 0;
  int64_t compound;
  rc = iwkv_cursor_copy_key(cur, &llv, sizeof(llv), &ksz, &compound);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(llv, 0xffffffffffffffe);

  llv = 0;
  rc = iwkv_cursor_get(cur, &oval, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(oval.size, sizeof(llv));
  memcpy(&llv, oval.data, sizeof(llv));
  IW_TEST_ASSERT_EQUAL(llv, 0xffffffffffffffe);
  iwkv_val_dispose(&oval);

  rc = iwkv_cursor_to(cur, IWKV_CURSOR_NEXT);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  llv = 0;
  rc = iwkv_cursor_copy_key(cur, &llv, sizeof(llv), &ksz, &compound);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(llv, 1);

  iwkv_cursor_close(&cur);

  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

static void iwkv_test8_v2(void) {
  iwkv_test1_impl(2);
}

static void iwkv_test7_impl(int fmt_version) {
  struct iwkv_opts opts = {
    .path = "iwkv_test1_7.db",
    .oflags = IWKV_TRUNC,
    .fmt_version = fmt_version
  };
  struct iwkv *iwkv;
  struct iwdb *db1;
  struct iwkv_val key, val;
  int64_t llv;
  key.data = "foo";
  key.size = strlen(key.data);

  iwrc rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_db(iwkv, 1, 0, &db1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  llv = 1;
  val.data = &llv;
  val.size = sizeof(llv);

  rc = iwkv_put(db1, &key, &val, IWKV_VAL_INCREMENT);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_put(db1, &key, &val, IWKV_VAL_INCREMENT);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_put(db1, &key, &val, IWKV_VAL_INCREMENT);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  llv = 0;
  val.data = 0;
  val.size = 0;
  rc = iwkv_get(db1, &key, &val);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(val.size, sizeof(llv));
  memcpy(&llv, val.data, sizeof(llv));
  llv = IW_ITOHLL(llv);
  IW_TEST_ASSERT_EQUAL(llv, 3);
  iwkv_val_dispose(&val);

  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

static void iwkv_test7_v2(void) {
  iwkv_test7_impl(2);
}

static void iwkv_test6_impl(int fmt_version) {
  struct iwkv_opts opts = {
    .path = "iwkv_test1_6.db",
    .oflags = IWKV_TRUNC,
    .fmt_version = fmt_version
  };
  const int vbsiz = 1000 * 1000;
  // Test open/close
  char kbuf[100];
  char *vbuf = malloc(vbsiz);
  struct iwkv *iwkv;
  struct iwdb *db1;
  struct iwkv_val key, val;

  iwrc rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_db(iwkv, 1, 0, &db1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  key.data = kbuf;
  val.data = vbuf;
  val.size = vbsiz;
  for (int i = 0; i < 20; ++i) {
    memset(vbuf, ' ' + i + 1, vbsiz);
    snprintf(kbuf, sizeof(kbuf), "%016d", i);
    key.size = strlen(kbuf);
    rc = iwkv_put(db1, &key, &val, 0);
    if (rc) {
      iwlog_ecode_error3(rc);
    }
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  }
  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  free(vbuf);
}

static void iwkv_test6_v2(void) {
  iwkv_test6_impl(2);
}

static void iwkv_test9(void) {
  struct iwkv_opts opts = {
    .path = "garbage.data",
  };
  // Test open/close
  struct iwkv *iwkv;
  iwrc rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL(rc, IWFS_ERROR_INVALID_FILEMETA);
  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL(rc, IW_ERROR_INVALID_STATE);
}

/* Key peek without a destination buffer: `kbuf` can be zero when `kbufsz` is
 * zero too, in this case only the key size is reported. */
static void iwkv_test_cursor_copy_key_size_only(void) {
  struct iwkv_opts opts = {
    .path = "iwkv_test1_copysize.db",
    .oflags = IWKV_TRUNC,
    .fmt_version = 2
  };
  struct iwkv *iwkv;
  struct iwdb *db1, *db2;
  struct iwkv_cursor *cur;
  struct iwkv_val key, val;
  size_t ksz;
  int64_t compound;
  uint64_t vkey = 0x0123456789abcdefULL;
  char kbuf[4];

  memset(kbuf, 0, sizeof(kbuf));
  val.data = (void*) "bar";
  val.size = 3;

  iwrc rc = iwkv_open(&opts, &iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_db(iwkv, 1, 0, &db1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  key.data = (void*) "foo";
  key.size = 3;
  rc = iwkv_put(db1, &key, &val, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_cursor_open(db1, &cur, IWKV_CURSOR_BEFORE_FIRST, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_cursor_to(cur, IWKV_CURSOR_NEXT);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  ksz = 0;
  compound = 0;
  rc = iwkv_cursor_copy_key(cur, 0, 0, &ksz, &compound);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(ksz, 3);
  IW_TEST_ASSERT_EQUAL(compound, 0);

  ksz = 0;
  rc = iwkv_cursor_copy_key(cur, kbuf, 0, &ksz, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(ksz, 3);
  IW_TEST_ASSERT_MEM_EQUAL(kbuf, "\0\0\0\0", sizeof(kbuf));

  ksz = 0;
  rc = iwkv_cursor_copy_key(cur, kbuf, sizeof(kbuf), &ksz, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(ksz, 3);
  IW_TEST_ASSERT_MEM_EQUAL(kbuf, "foo", 3);
  iwkv_cursor_close(&cur);

  // VNUM64 (compound) keys
  rc = iwkv_db(iwkv, 2, IWDB_VNUM64_KEYS, &db2);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  key.data = &vkey;
  key.size = sizeof(vkey);
  rc = iwkv_put(db2, &key, &val, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_cursor_open(db2, &cur, IWKV_CURSOR_BEFORE_FIRST, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_cursor_to(cur, IWKV_CURSOR_NEXT);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  ksz = 0;
  rc = iwkv_cursor_copy_key(cur, 0, 0, &ksz, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(ksz, sizeof(vkey));
  iwkv_cursor_close(&cur);

  rc = iwkv_close(&iwkv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

static const struct iw_test_case cases[] = {
  IW_TEST_CASE_AS("iwkv_test1_v1", iwkv_test1_v2),
  IW_TEST_CASE(iwkv_test2_v2),
  IW_TEST_CASE(iwkv_test3_v2),
  IW_TEST_CASE(iwkv_test6_v2),
  IW_TEST_CASE(iwkv_test7_v2),
  IW_TEST_CASE(iwkv_test8_v2),
  IW_TEST_CASE(iwkv_test9),
  IW_TEST_CASE(iwkv_test_cursor_copy_key_size_only),
};

int main(int argc, char *argv[]) {
  return iw_test_run(argc, argv, IW_TEST_SUITE("iwkv_test1", cases, init_suite, 0));
}

