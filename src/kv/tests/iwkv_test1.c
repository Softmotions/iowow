#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwcfg.h"
#include "iwkv_tests.h"

#define KBUFSZ 128
#define VBUFSZ 128
char kbuf[KBUFSZ];
char vbuf[VBUFSZ];

extern int8_t iwkv_next_level;

static int logstage(FILE *f, const char *name, IWDB db) {
  int rci = fprintf(f, "\n#### Stage: %s\n", name);
  iwkvd_db(f, db, IWKVD_PRINT_NO_LEVEVELS | IWKVD_PRINT_VALS, 0);
  fflush(f);
  return rci < 0 ? rci : 0;
}

static int logstage2(FILE *f, const char *name, IWDB db) {
  int rci = fprintf(f, "\n#### Stage: %s\n", name);
  iwkvd_db(f, db, IWKVD_PRINT_NO_LEVEVELS | IWKVD_PRINT_VALS, 0);
  fflush(f);
  return rci < 0 ? rci : 0;
}

int init_suite() {
  iwrc rc = iwkv_init();
  return rc;
}

int clean_suite() {
  return 0;
}

// Test5 staff
struct Test5DUP1 {
  bool _mv;
  bool _1v;
  bool _10v;
};

static int64_t _test5dup5visitor(uint64_t dv, int64_t idx, void *op) {
  CU_ASSERT_PTR_NOT_NULL_FATAL(op);
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
      CU_FAIL("Invalid dup value");
      break;
  }
  return 1;
}

// Test Slides
static void iwkv_test3_impl(int fmt_version) {
  FILE *f = fmt_version > 1 ? fopen("iwkv_test1_3_v2.log", "w+") : fopen("iwkv_test1_3.log", "w+");
  CU_ASSERT_PTR_NOT_NULL(f);

  iwrc rc;
  IWKV_val key = { 0 };
  IWKV_val val = { 0 };
  IWKV iwkv;
  IWDB db1;
  IWKV_OPTS opts = {
    .path        = "iwkv_test1_3.db",
    .oflags      = IWKV_TRUNC,
    .fmt_version = fmt_version
  };

  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

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
      CU_ASSERT_EQUAL_FATAL(rc, 0);
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
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  logstage2(f, "iwkv_test3", db1);

  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  // Compare logs with referenced
#ifndef _WIN32
  FILE *r = fmt_version > 1 ? fopen("iwkv_test1_3_v2.ref", "r+") : fopen("iwkv_test1_3.ref", "r+");
#else
  FILE *r = fmt_version > 1 ? fopen("iwkv_test1_3w_v2.ref", "r+") : fopen("iwkv_test1_3w.ref", "r+");
#endif
  CU_ASSERT_PTR_NOT_NULL(r);
  int rci = cmp_files(r, f);
  CU_ASSERT_EQUAL_FATAL(rci, 0);
  fclose(f);
  fclose(r);
}

static void iwkv_test3_v1() {
  iwkv_test3_impl(1);
}

static void iwkv_test3_v2() {
  iwkv_test3_impl(2);
}

static void iwkv_test2_impl(int fmt_version) {
  FILE *f = fmt_version > 1 ? fopen("iwkv_test1_2_v2.log", "w+") : fopen("iwkv_test1_2.log", "w+");
  CU_ASSERT_PTR_NOT_NULL(f);

  iwrc rc;
  IWKV_val key = { 0 };
  IWKV_val val = { 0 };
  IWKV iwkv;
  IWDB db1;
  IWKV_OPTS opts = {
    .path        = "iwkv_test1_2.db",
    .oflags      = IWKV_TRUNC,
    .fmt_version = fmt_version
  };

  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  for (int i = 252 * 2; i >= 0; --i) { // 189
    snprintf(kbuf, KBUFSZ, "%03dkkk", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    val.data = vbuf;
    val.size = strlen(val.data);
    rc = iwkv_put(db1, &key, &val, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
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
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    IW_CMP(cret, vbuf, vsize, val.data, val.size);
    CU_ASSERT_EQUAL_FATAL(cret, 0);
    iwkv_kv_dispose(0, &val);
  }

  //  snprintf(kbuf, KBUFSZ, "%03dkkk", 64);
  //  key.data = kbuf;
  //  key.size = strlen(key.data);
  //  rc = iwkv_del(db1, &key);
  //  CU_ASSERT_EQUAL_FATAL(rc, 0);
  //  logstage(f, "removed 064kkk", db1);
  //
  //
  //  snprintf(kbuf, KBUFSZ, "%03dkkk", 126);
  //  key.data = kbuf;
  //  key.size = strlen(key.data);
  //  rc = iwkv_del(db1, &key);
  //  CU_ASSERT_EQUAL_FATAL(rc, 0);
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
  //      CU_ASSERT_EQUAL(rc, IWKV_ERROR_NOTFOUND);
  //      rc = 0;
  //      continue;
  //    }
  //    CU_ASSERT_EQUAL_FATAL(rc, 0);
  //  }
  //  logstage(f, "removed 065kkk - 099kkk", db1); // 125
  //
  //  for (int i = 100; i <= 125; ++i) {
  //    snprintf(kbuf, KBUFSZ, "%03dkkk", i);
  //    key.data = kbuf;
  //    key.size = strlen(key.data);
  //    rc = iwkv_del(db1, &key);
  //    CU_ASSERT_EQUAL_FATAL(rc, 0);
  //  }
  //  logstage(f, "removed all keys in SBLK[54]", db1); // 125

  rc = iwkv_db_destroy(&db1);      // Destroy DB and remove all db blocks
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // Reopen DB then check db1
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_db(iwkv, 1, 0, &db1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  logstage(f, "db1 destroyed", db1);
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // Compare logs with referenced
#ifndef _WIN32
  FILE *r = fmt_version > 1 ? fopen("iwkv_test1_2_v2.ref", "r+") : fopen("iwkv_test1_2.ref", "r+");
#else
  FILE *r = fmt_version > 1 ? fopen("iwkv_test1_2w_v2.ref", "r+") : fopen("iwkv_test1_2w.ref", "r+");
#endif
  CU_ASSERT_PTR_NOT_NULL(r);
  int rci = cmp_files(r, f);
  CU_ASSERT_EQUAL_FATAL(rci, 0);
  fclose(f);
  fclose(r);
}

static void iwkv_test2_v1() {
  iwkv_test2_impl(1);
}

static void iwkv_test2_v2() {
  iwkv_test2_impl(2);
}

static void iwkv_test1_impl(int fmt_version) {
  FILE *f = fmt_version > 1 ? fopen("iwkv_test1_1_v2.log", "w+") : fopen("iwkv_test1_1.log", "w+");
  CU_ASSERT_PTR_NOT_NULL(f);
  char buf[128];
  size_t vsize;

  IWKV_OPTS opts = {
    .path        = "iwkv_test1.db",
    .oflags      = IWKV_TRUNC,
    .fmt_version = fmt_version
  };
  // Test open/close
  IWKV iwkv;
  IWDB db1, db2, db3;
  iwrc rc;
  IWKV_val key = { .data = "foo" };
  key.size = strlen(key.data);
  IWKV_val val = { .data = "bar" };
  val.size = strlen(val.data);

  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // Test open/close existing db
  opts.oflags = 0;
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // Test create/destroy db
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 2, 0, &db2); // destroyed
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 3, 0, &db3);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db_destroy(&db2);     // destroyed
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // Test one in read-only mode
  opts.oflags = IWKV_RDONLY;
  opts.path = "not-existing.db";
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_TRUE_FATAL(rc);
  iwrc_strip_errno(&rc);
#ifdef _WIN32
  iwrc_strip_werror(&rc);
#endif
  CU_ASSERT_EQUAL(rc, IW_ERROR_NOT_EXISTS);

  // Open in read-only mode and acquire not existing db
  opts.path = "iwkv_test1.db";
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_db(iwkv, 2, 0, &db2);
  CU_ASSERT_EQUAL(rc, IW_ERROR_READONLY);

  rc = iwkv_db(iwkv, 1, 0, &db1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_db(iwkv, 3, 0, &db3);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  logstage(f, "empty db", db1);

  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // Open in write mode, then put a simple kv
  opts.oflags = 0;
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  // iwkv_next_level = 3;
  rc = iwkv_put(db1, &key, &val, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  logstage(f, "put foo:bar", db1);

  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // Open db and get out single record
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  val.size = 0;
  val.data = 0;

  rc = iwkv_get(db1, &key, &val);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_NSTRING_EQUAL(key.data, "foo", key.size);
  CU_ASSERT_NSTRING_EQUAL(val.data, "bar", val.size);
  iwkv_kv_dispose(0, &val);

  rc = iwkv_get_copy(db1, &key, buf, sizeof(buf), &vsize);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(3, vsize);
  CU_ASSERT_NSTRING_EQUAL(buf, "bar", vsize);

  rc = iwkv_get_copy(db1, &key, buf, 1, &vsize);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(3, vsize);
  CU_ASSERT_NSTRING_EQUAL(buf, "b", 1);

  // put foo->bazzz
  key.data = "foo";
  key.size = strlen(key.data);
  val.data = "bazzz";
  val.size = strlen(val.data);
  rc = iwkv_put(db1, &key, &val, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // put foo->zzz with IWKV_NO_OVERWRITE
  val.data = "zzz";
  val.size = strlen(val.data);
  rc = iwkv_put(db1, &key, &val, IWKV_NO_OVERWRITE);

  CU_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_KEY_EXISTS);
  rc = iwkv_get(db1, &key, &val);
  CU_ASSERT_NSTRING_EQUAL(key.data, "foo", key.size);
  CU_ASSERT_NSTRING_EQUAL(val.data, "bazzz", val.size);
  iwkv_kv_dispose(0, &val);

  logstage(f, "put foo:bazz", db1);

  // put foo->''
  val.data = "";
  val.size = strlen(val.data);
  rc = iwkv_put(db1, &key, &val, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_get(db1, &key, &val);
  CU_ASSERT_NSTRING_EQUAL(key.data, "foo", key.size);
  CU_ASSERT_NSTRING_EQUAL(val.data, "", val.size);
  iwkv_kv_dispose(0, &val);

  logstage(f, "put foo:", db1);

  val.data = "bar";
  val.size = strlen(val.data);
  rc = iwkv_put(db1, &key, &val, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_get(db1, &key, &val);
  CU_ASSERT_NSTRING_EQUAL(key.data, "foo", key.size);
  CU_ASSERT_NSTRING_EQUAL(val.data, "bar", val.size);
  iwkv_kv_dispose(0, &val);

  logstage(f, "put foo:bar", db1);

  // remove key/value
  rc = iwkv_del(db1, &key, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_get(db1, &key, &val);
  CU_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_NOTFOUND);

  logstage(f, "remove foo:bar", db1);

  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_get(db1, &key, &val);
  CU_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_NOTFOUND);

  // iwkv_next_level = 0;

  for (int i = 0; i < 127 * 2; i += 2) {
    snprintf(kbuf, KBUFSZ, "%03dkkk", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    val.data = vbuf;
    val.size = strlen(val.data);
    rc = iwkv_put(db1, &key, &val, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }

  logstage(f, "fill up first block", db1);

  // iwkv_next_level = 0;
  for (int i = 0; i < 127 * 2; i += 2) {
    snprintf(kbuf, KBUFSZ, "%03dkkk", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    rc = iwkv_get(db1, &key, &val);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_EQUAL_FATAL(strncmp(val.data, vbuf, val.size), 0);
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
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    //logstage(stderr, "??????", db1);
  }

  logstage(f, "fill up second block", db1);

  // Check basic cursor operations
  IWKV_cursor cur1;

  rc = iwkv_cursor_open(db1, &cur1, IWKV_CURSOR_BEFORE_FIRST, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_cursor_to(cur1, IWKV_CURSOR_PREV);
  CU_ASSERT_EQUAL(rc, IWKV_ERROR_NOTFOUND);
  rc = iwkv_cursor_close(&cur1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_cursor_open(db1, &cur1, IWKV_CURSOR_AFTER_LAST, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_cursor_get(cur1, &key, &val);
  CU_ASSERT_EQUAL(rc, IWKV_ERROR_NOTFOUND);
  rc = iwkv_cursor_to(cur1, IWKV_CURSOR_NEXT);
  CU_ASSERT_EQUAL(rc, IWKV_ERROR_NOTFOUND);
  rc = iwkv_cursor_close(&cur1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_cursor_open(db1, &cur1, IWKV_CURSOR_AFTER_LAST, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_cursor_to(cur1, IWKV_CURSOR_PREV);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  int i = 0;
  do {
    IWKV_val key;
    IWKV_val val;
    iwrc rc2 = iwkv_cursor_get(cur1, &key, &val);
    CU_ASSERT_EQUAL_FATAL(rc2, 0);
    snprintf(kbuf, KBUFSZ, "%03dkkk", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    CU_ASSERT_EQUAL(strncmp(key.data, kbuf, key.size), 0);
    CU_ASSERT_EQUAL(strncmp(val.data, vbuf, val.size), 0);
    iwkv_kv_dispose(&key, &val);
    if (i == 2) {
      rc2 = iwkv_cursor_to(cur1, IWKV_CURSOR_PREV);
      CU_ASSERT_EQUAL_FATAL(rc2, 0);
      rc2 = iwkv_cursor_get(cur1, &key, &val);
      CU_ASSERT_EQUAL_FATAL(rc2, 0);
      snprintf(kbuf, KBUFSZ, "%03dkkk", i + 1);
      snprintf(vbuf, VBUFSZ, "%03dval", i + 1);
      CU_ASSERT_EQUAL(strncmp(key.data, kbuf, key.size), 0);
      CU_ASSERT_EQUAL(strncmp(val.data, vbuf, val.size), 0);
      rc2 = iwkv_cursor_to(cur1, IWKV_CURSOR_NEXT);
      CU_ASSERT_EQUAL_FATAL(rc2, 0);
      iwkv_kv_dispose(&key, &val);
    }
    ++i;
  } while (!(rc = iwkv_cursor_to(cur1, IWKV_CURSOR_PREV)));
  CU_ASSERT_EQUAL(rc, IWKV_ERROR_NOTFOUND);
  rc = iwkv_cursor_close(&cur1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  --i;
  rc = iwkv_cursor_open(db1, &cur1, IWKV_CURSOR_BEFORE_FIRST, 0);
  while (!(rc = iwkv_cursor_to(cur1, IWKV_CURSOR_NEXT))) {
    IWKV_val key;
    IWKV_val val;
    iwrc rc2 = iwkv_cursor_get(cur1, &key, &val);
    CU_ASSERT_EQUAL_FATAL(rc2, 0);
    snprintf(kbuf, KBUFSZ, "%03dkkk", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    --i;
    CU_ASSERT_EQUAL(strncmp(key.data, kbuf, key.size), 0);
    CU_ASSERT_EQUAL(strncmp(val.data, vbuf, val.size), 0);
    iwkv_kv_dispose(&key, &val);
  }
  CU_ASSERT_EQUAL(rc, IWKV_ERROR_NOTFOUND);
  rc = iwkv_cursor_close(&cur1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // Set cursor to key
  do {
    IWKV_val key;
    IWKV_val val;
    snprintf(kbuf, KBUFSZ, "%03dkkk", 30);
    snprintf(vbuf, VBUFSZ, "%03dval", 30);
    key.data = kbuf;
    key.size = strlen(kbuf);
    rc = iwkv_cursor_open(db1, &cur1, IWKV_CURSOR_EQ, &key);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    iwrc rc2 = iwkv_cursor_get(cur1, &key, &val);
    CU_ASSERT_EQUAL_FATAL(rc2, 0);
    CU_ASSERT_EQUAL(strncmp(key.data, kbuf, key.size), 0);
    CU_ASSERT_EQUAL(strncmp(val.data, vbuf, val.size), 0);
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
    CU_ASSERT_EQUAL_FATAL(rc2, 0);
    rc2 = iwkv_cursor_get(cur1, &key, &val);
    CU_ASSERT_EQUAL_FATAL(rc2, 0);
    snprintf(kbuf, KBUFSZ, "%03dkkk", 0);
    snprintf(vbuf, VBUFSZ, "%03dval", 0);
    CU_ASSERT_EQUAL(strncmp(key.data, kbuf, key.size), 0);
    CU_ASSERT_EQUAL(strncmp(val.data, vbuf, val.size), 0);
    iwkv_kv_dispose(&key, &val);

    // Move to EQ 000
    snprintf(kbuf, KBUFSZ, "%03d", 0);
    snprintf(vbuf, VBUFSZ, "%03dval", 0);
    key.data = kbuf;
    key.size = strlen(kbuf);
    rc2 = iwkv_cursor_to_key(cur1, IWKV_CURSOR_EQ, &key);
    CU_ASSERT_EQUAL(rc2, IWKV_ERROR_NOTFOUND);

    rc = iwkv_cursor_close(&cur1);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  } while (0);

  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  logstage(f, "state after reopen", db1);

  // Put a big key
  snprintf(kbuf, KBUFSZ, "abracadabrabracadabrabracadabrabracadabrabracadabrabracadabrabracadabr1");
  key.size = strlen(kbuf);
  snprintf(vbuf, VBUFSZ, "vabracadabrabracadabrabracadabrabracadabrabracadabrabracadabrabracadabr");
  val.size = strlen(vbuf);
  rc = iwkv_db(iwkv, 1, 0, &db1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_put(db1, &key, &val, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_get(db1, &key, &val);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL_FATAL(strncmp(val.data, vbuf, val.size), 0);
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
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_cursor_set(cur1, &val, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  key.data = 0;
  val.data = 0;
  rc = iwkv_cursor_get(cur1, &key, &val);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(strncmp(key.data, kbuf, key.size), 0);
  CU_ASSERT_EQUAL(strncmp(val.data, vbuf, val.size), 0);
  iwkv_kv_dispose(&key, &val);
  rc = iwkv_cursor_close(&cur1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // Set in write mode
  snprintf(kbuf, KBUFSZ, "%03dkkk", 61);
  snprintf(vbuf, VBUFSZ, "%03dval3", 61);
  key.data = kbuf;
  key.size = strlen(kbuf);
  val.data = vbuf;
  val.size = strlen(vbuf);
  rc = iwkv_cursor_open(db1, &cur1, IWKV_CURSOR_EQ, &key);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_cursor_set(cur1, &val, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  key.data = 0;
  val.data = 0;
  rc = iwkv_cursor_get(cur1, &key, &val);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(strncmp(key.data, kbuf, key.size), 0);
  CU_ASSERT_EQUAL(strncmp(val.data, vbuf, val.size), 0);
  iwkv_kv_dispose(&key, &val);
  rc = iwkv_cursor_close(&cur1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // Compare logs with referenced
#ifndef _WIN32
  FILE *r = fmt_version > 1 ? fopen("iwkv_test1_1_v2.ref", "r+") : fopen("iwkv_test1_1.ref", "r+");
#else
  FILE *r = fmt_version > 1 ? fopen("iwkv_test1_1w_v2.ref", "r+") : fopen("iwkv_test1_1w.ref", "r+");
#endif
  CU_ASSERT_PTR_NOT_NULL_FATAL(r);
  int rci = cmp_files(r, f);
  CU_ASSERT_EQUAL_FATAL(rci, 0);
  fclose(r);
  fclose(f);
}

static void iwkv_test1_v1() {
  iwkv_test1_impl(1);
}

static void iwkv_test1_v2() {
  iwkv_test1_impl(2);
}

static void iwkv_test8_impl(int fmt_version) {
  IWKV_OPTS opts = {
    .path        = "iwkv_test1_8.db",
    .oflags      = IWKV_TRUNC,
    .fmt_version = fmt_version
  };
  IWKV iwkv;
  IWDB db1;
  IWKV_cursor cur;
  IWKV_val key;
  IWKV_val val = {
    .data = "foo",
    .size = sizeof("foo") - 1
  };
  IWKV_val oval;
  size_t ksz;
  uint64_t llv = 1;
  uint64_t llv2;

  iwrc rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_db(iwkv, 1, IWDB_VNUM64_KEYS, &db1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  key.data = &llv;
  key.size = sizeof(llv);

  rc = iwkv_put(db1, &key, &val, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_get(db1, &key, &oval);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  iwkv_val_dispose(&oval);

  llv = 0xffffffffffffffe;
  key.data = &llv;

  rc = iwkv_put(db1, &key, &val, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_get(db1, &key, &oval);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  iwkv_val_dispose(&oval);

  rc = iwkv_get_copy(db1, &key, &llv2, sizeof(llv2), &ksz);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_cursor_open(db1, &cur, IWKV_CURSOR_EQ, &key);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  llv = 0xffffffffffffffffULL;
  rc = iwkv_put(db1, &key, &val, 0);
  CU_ASSERT_EQUAL(rc, IW_ERROR_OVERFLOW);


  llv = 0;
  int64_t compound;
  rc = iwkv_cursor_copy_key(cur, &llv, sizeof(llv), &ksz, &compound);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(llv, 0xffffffffffffffe);

  llv = 0;
  rc = iwkv_cursor_get(cur, &oval, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL_FATAL(oval.size, sizeof(llv));
  memcpy(&llv, oval.data, sizeof(llv));
  CU_ASSERT_EQUAL(llv, 0xffffffffffffffe);
  iwkv_val_dispose(&oval);

  rc = iwkv_cursor_to(cur, IWKV_CURSOR_NEXT);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  llv = 0;
  rc = iwkv_cursor_copy_key(cur, &llv, sizeof(llv), &ksz, &compound);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(llv, 1);

  iwkv_cursor_close(&cur);

  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
}

static void iwkv_test8_v1() {
  iwkv_test1_impl(1);
}

static void iwkv_test8_v2() {
  iwkv_test1_impl(2);
}

static void iwkv_test7_impl(int fmt_version) {
  IWKV_OPTS opts = {
    .path        = "iwkv_test1_7.db",
    .oflags      = IWKV_TRUNC,
    .fmt_version = fmt_version
  };
  IWKV iwkv;
  IWDB db1;
  IWKV_val key, val;
  int64_t llv;
  key.data = "foo";
  key.size = strlen(key.data);

  iwrc rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_db(iwkv, 1, 0, &db1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  llv = 1;
  val.data = &llv;
  val.size = sizeof(llv);

  rc = iwkv_put(db1, &key, &val, IWKV_VAL_INCREMENT);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_put(db1, &key, &val, IWKV_VAL_INCREMENT);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_put(db1, &key, &val, IWKV_VAL_INCREMENT);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  llv = 0;
  val.data = 0;
  val.size = 0;
  rc = iwkv_get(db1, &key, &val);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL_FATAL(val.size, sizeof(llv));
  memcpy(&llv, val.data, sizeof(llv));
  llv = IW_ITOHLL(llv);
  CU_ASSERT_EQUAL(llv, 3);
  iwkv_val_dispose(&val);

  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
}

static void iwkv_test7_v1() {
  iwkv_test7_impl(1);
}

static void iwkv_test7_v2() {
  iwkv_test7_impl(2);
}

static void iwkv_test6_impl(int fmt_version) {
  IWKV_OPTS opts = {
    .path        = "iwkv_test1_6.db",
    .oflags      = IWKV_TRUNC,
    .fmt_version = fmt_version
  };
  const int vbsiz = 1000 * 1000;
  // Test open/close
  char kbuf[100];
  char *vbuf = malloc(vbsiz);
  IWKV iwkv;
  IWDB db1;
  IWKV_val key, val;

  iwrc rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_db(iwkv, 1, 0, &db1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
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
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  free(vbuf);
}

static void iwkv_test6_v1() {
  iwkv_test6_impl(1);
}

static void iwkv_test6_v2() {
  iwkv_test6_impl(2);
}

static void iwkv_test9(void) {
  IWKV_OPTS opts = {
    .path = "garbage.data",
  };
  // Test open/close
  IWKV iwkv;
  iwrc rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL(rc, IWFS_ERROR_INVALID_FILEMETA);
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL(rc, IW_ERROR_INVALID_STATE);
}

int main() {
  CU_pSuite pSuite = NULL;

  /* Initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry()) {
    return CU_get_error();
  }

  /* Add a suite to the registry */
  pSuite = CU_add_suite("iwkv_test1", init_suite, clean_suite);

  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Add the tests to the suite */
  if ((NULL == CU_add_test(pSuite, "iwkv_test1_v1", iwkv_test1_v1))
      || (NULL == CU_add_test(pSuite, "iwkv_test1_v2", iwkv_test1_v2))
      || (NULL == CU_add_test(pSuite, "iwkv_test2_v1", iwkv_test2_v1))
      || (NULL == CU_add_test(pSuite, "iwkv_test2_v2", iwkv_test2_v2))
      || (NULL == CU_add_test(pSuite, "iwkv_test3_v1", iwkv_test3_v1))
      || (NULL == CU_add_test(pSuite, "iwkv_test3_v2", iwkv_test3_v2)) ||

      //-    (NULL == CU_add_test(pSuite, "iwkv_test4", iwkv_test4)) ||
      //-    (NULL == CU_add_test(pSuite, "iwkv_test5", iwkv_test5)) ||

      (NULL == CU_add_test(pSuite, "iwkv_test6_v1", iwkv_test6_v1))
      || (NULL == CU_add_test(pSuite, "iwkv_test6_v2", iwkv_test6_v2))
      || (NULL == CU_add_test(pSuite, "iwkv_test7_v1", iwkv_test7_v1))
      || (NULL == CU_add_test(pSuite, "iwkv_test7_v2", iwkv_test7_v2))
      || (NULL == CU_add_test(pSuite, "iwkv_test8_v1", iwkv_test8_v1))
      || (NULL == CU_add_test(pSuite, "iwkv_test8_v2", iwkv_test8_v2))
      || (NULL == CU_add_test(pSuite, "iwkv_test9", iwkv_test9))) {
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
