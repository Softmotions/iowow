#include "iwkv.h"
#include "iwlog.h"
#include "iwcfg.h"

#include <CUnit/Basic.h>
#include <locale.h>


int init_suite(void) {
  iwrc rc = iwkv_init();
  return rc;
}

int clean_suite(void) {
  return 0;
}

static void iwkv_test1(void) {
  IWKV_OPTS opts = {
    .path = "iwkv_test1.db",
    .oflags = IWKV_TRUNC
  };
#define KBUFSZ 128
#define VBUFSZ 128
  char kbuf[KBUFSZ];
  char vbuf[VBUFSZ];
  
  // Test open/close
  IWKV iwkv;
  IWDB db1, db2, db3;
  iwrc rc = iwkv_open(&opts, &iwkv);
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
  
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  
  // Open in write mode, then put a simple kv
  opts.oflags = 0;
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  IWKV_val key = {.data = "foo"};
  key.size = strlen(key.data);
  IWKV_val val = {.data = "bar"};
  val.size = strlen(val.data);
  rc = iwkv_put(db1, &key, &val, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
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
  
  // put foo->''
  val.data = "";
  val.size = strlen(val.data);
  rc = iwkv_put(db1, &key, &val, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_get(db1, &key, &val);
  CU_ASSERT_NSTRING_EQUAL(key.data, "foo", key.size);
  CU_ASSERT_NSTRING_EQUAL(val.data, "", val.size);
  
  val.data = "bar";
  val.size = strlen(val.data);
  rc = iwkv_put(db1, &key, &val, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_get(db1, &key, &val);
  CU_ASSERT_NSTRING_EQUAL(key.data, "foo", key.size);
  CU_ASSERT_NSTRING_EQUAL(val.data, "bar", val.size);
  iwkv_kv_dispose(0, &val);
  
  // remove key/value
  rc = iwkv_del(db1, &key);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_get(db1, &key, &val);
  CU_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_NOTFOUND);
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  
  
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_get(db1, &key, &val);
  CU_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_NOTFOUND);
  
  
  for (int i = 0; i < 63 * 2; i += 2) {
    snprintf(kbuf, KBUFSZ, "%03dkey", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    val.data = vbuf;
    val.size = strlen(val.data);
    rc = iwkv_put(db1, &key, &val, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
  
  for (int i = 0; i < 63 * 2; i += 2) {
    snprintf(kbuf, KBUFSZ, "%03dkey", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    rc = iwkv_get(db1, &key, &val);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_EQUAL_FATAL(strncmp(val.data, vbuf, val.size), 0);
    iwkv_kv_dispose(0, &val);
  }
  
  // force extra block
  for (int i = 1; i < 63 * 2; i += 2) {
    snprintf(kbuf, KBUFSZ, "%03dkey", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    val.data = vbuf;
    val.size = strlen(val.data);
    rc = iwkv_put(db1, &key, &val, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
  
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  
#undef KBUFSZ
#undef VBUFSZ
}


static void iwkv_test2(void) {

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
