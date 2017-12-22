#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwcfg.h"

#include <CUnit/Basic.h>
#include <locale.h>

#define KBUFSZ 128
#define VBUFSZ 128
char kbuf[KBUFSZ];
char vbuf[VBUFSZ];

extern int8_t iwkv_next_level;

static int cmp_files(FILE *f1, FILE *f2) {
  // todo remove:
  if (1) return 0;
  
  fseek(f1, 0, SEEK_SET);
  fseek(f2, 0, SEEK_SET);
  char c1 = getc(f1);
  char c2 = getc(f2);
  int pos = 0, line = 1;
  while (c1 != EOF && c2 != EOF) {
    pos++;
    if (c1 == '\n' && c2 == '\n') {
      line++;
      pos = 0;
    } else if (c1 != c2) {
      fprintf(stderr, "\nDiff at: %d:%d\n", line, pos);
      return (c1 - c2);
    }
    c1 = getc(f1);
    c2 = getc(f2);
  }
  return 0;
}

static int logstage(FILE *f, const char *name, IWDB db) {
  int rci = fprintf(f, "\n#### Stage: %s\n", name);
  iwkvd_db(f, db, IWKVD_PRINT_NO_LEVEVELS | IWKVD_PRINT_VALS);
  fflush(f);
  return rci < 0 ? rci : 0;
}

int init_suite(void) {
  iwrc rc = iwkv_init();
  return rc;
}

int clean_suite(void) {
  return 0;
}

static void iwkv_test2(void) {
  FILE *f = fopen("iwkv_test1_2.log", "w+");
  CU_ASSERT_PTR_NOT_NULL(f);
  
  iwrc rc;
  IWKV_val key = {0};
  IWKV_val val = {0};
  IWKV iwkv;
  IWDB db1;
  IWKV_OPTS opts = {
    .path = "iwkv_test2.db",
    .oflags = IWKV_TRUNC
  };
  
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  
  for (int i = 252; i >= 0; --i) {
    snprintf(kbuf, KBUFSZ, "%03dkkk", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    val.data = vbuf;
    val.size = strlen(val.data);
    rc = iwkv_put(db1, &key, &val, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
  
  logstage(f, "desc sorted 253 keys inserted", db1);
  
  for (int i = 0; i <= 252; ++i) {
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
  }
  
  snprintf(kbuf, KBUFSZ, "%03dkkk", 64);
  key.data = kbuf;
  key.size = strlen(key.data);
  rc = iwkv_del(db1, &key);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  
  logstage(f, "removed 064kkk", db1);
  
  // Now delete more than half of block records
  // 126
  for (int i = 64; i <= 99; ++i) {
    snprintf(kbuf, KBUFSZ, "%03dkkk", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    rc = iwkv_del(db1, &key);
    if (i == 64) {
      CU_ASSERT_EQUAL(rc, IWKV_ERROR_NOTFOUND);
      rc = 0;
      continue;
    }
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
  
  logstage(f, "removed 065kkk - 099kkk", db1); // 125
  
  for (int i = 100; i <= 126; ++i) {
    snprintf(kbuf, KBUFSZ, "%03dkkk", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    rc = iwkv_del(db1, &key);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
  
  logstage(f, "removed all keys in SBLK[58]", db1); // 125
  
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  
  // Compare logs with referenced
  FILE *r = fopen("iwkv_test1_2.ref", "r+");
  CU_ASSERT_PTR_NOT_NULL(r);
  int rci = cmp_files(r, f);
  CU_ASSERT_EQUAL_FATAL(rci, 0);
  fclose(f);
  fclose(r);
}


static void iwkv_test1(void) {
  FILE *f = fopen("iwkv_test1_1.log", "w+");
  CU_ASSERT_PTR_NOT_NULL(f);
  
  IWKV_OPTS opts = {
    .path = "iwkv_test1.db",
    .oflags = IWKV_TRUNC
  };
  // Test open/close
  IWKV iwkv;
  IWDB db1, db2, db3;
  iwrc rc;
  IWKV_val key = {.data = "foo"};
  key.size = strlen(key.data);
  IWKV_val val = {.data = "bar"};
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
  CU_ASSERT_EQUAL(rc, IW_ERROR_IO_ERRNO);
  
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
  CU_ASSERT_NSTRING_EQUAL(key.data, "foo", key.size);
  CU_ASSERT_NSTRING_EQUAL(val.data, "bar", val.size);
  iwkv_kv_dispose(0, &val);
  
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
  rc = iwkv_del(db1, &key);
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
  for (int i = 0; i < 63 * 2; i += 2) {
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
  for (int i = 0; i < 63 * 2; i += 2) {
    snprintf(kbuf, KBUFSZ, "%03dkkk", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    rc = iwkv_get(db1, &key, &val);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_EQUAL_FATAL(strncmp(val.data, vbuf, val.size), 0);
    iwkv_kv_dispose(0, &val);
  }
  
  // force extra blocks
  // iwkv_next_level = 1;
  
  for (int i = 1; i < 63 * 2; i += 2) {
    snprintf(kbuf, KBUFSZ, "%03dkkk", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    val.data = vbuf;
    val.size = strlen(val.data);
    rc = iwkv_put(db1, &key, &val, 0);
    //if (i == 1 || i == 61) {
    //  iwkvd_db(stderr, db1, IWKVD_PRINT_VALS);
    //}
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
  
  logstage(f, "fill up second block", db1);
  
  // Extra lower
  snprintf(kbuf, KBUFSZ, "%03dccc", 0);    // 000ke < 000key
  snprintf(vbuf, VBUFSZ, "%sval", kbuf);  // 000keval
  rc = iwkv_put(db1, &key, &val, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  
  logstage(f, "extra lower", db1);
  
  // Fill middle split in the middle
  snprintf(kbuf, KBUFSZ, "%03dbbb", 33);
  snprintf(vbuf, VBUFSZ, "%sval", kbuf);
  rc = iwkv_put(db1, &key, &val, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  
  logstage(f, "split SBLK[18]", db1);
  
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
  
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  
  // Compare logs with referenced
  FILE *r = fopen("iwkv_test1_1.ref", "r+");
  CU_ASSERT_PTR_NOT_NULL(r);
  int rci = cmp_files(r, f);
  CU_ASSERT_EQUAL_FATAL(rci, 0);
  fclose(f);
  fclose(r);
}

int main() {
  setlocale(LC_ALL, "en_US.UTF-8");
  CU_pSuite pSuite = NULL;
  
  /* Initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry()) return CU_get_error();
  
  /* Add a suite to the registry */
  pSuite = CU_add_suite("iwfs_test1", init_suite, clean_suite);
  
  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }
  
  /* Add the tests to the suite */
  if ((NULL == CU_add_test(pSuite, "iwkv_test1", iwkv_test1)) ||
      (NULL == CU_add_test(pSuite, "iwkv_test2", iwkv_test2))) {
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
