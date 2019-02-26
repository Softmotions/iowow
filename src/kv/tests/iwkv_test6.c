#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwcfg.h"
#include "iwkv_tests.h"
#include "iwkv_internal.h"

int init_suite(void) {
  iwrc rc = iwkv_init();
  return rc;
}

int clean_suite(void) {
  return 0;
}

static void iwkv_test6_1() {
  iwrc rc;
  IWKV_val key = {0};
  IWKV_val val = {0};
  IWKV iwkv;
  IWDB db;
  IWKV_cursor cur;

  IWKV_OPTS opts = {
    .path = "iwkv_test6_1.db",
    .oflags = IWKV_TRUNC
  };
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, IWDB_VNUM64_KEYS | IWDB_COMPOUND_KEYS, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  for (uint32_t i = 0; i < 100; ++i) {
    key.data = &i;
    key.size = sizeof(i);
    for (uint32_t j = 0; j < 1000; ++j) {
      key.compound = j;
      val.data = &j;
      val.size = sizeof(j);
      rc = iwkv_put(db, &key, &val, 0);
      CU_ASSERT_EQUAL_FATAL(rc, 0);
      rc = iwkv_get(db, &key, &val);
      CU_ASSERT_EQUAL_FATAL(rc, 0);
      CU_ASSERT_EQUAL_FATAL(key.size, sizeof(i));
      CU_ASSERT_TRUE_FATAL(!memcmp(key.data, &i, sizeof(i)));
      CU_ASSERT_TRUE_FATAL(val.size == 4 && val.compound == 0 && !memcmp(val.data, &j, sizeof(j)));
      iwkv_val_dispose(&val);
    }
  }
  for (uint32_t i = 0; i < 10; ++i) {
    key.data = &i;
    key.size = sizeof(i);
    for (uint32_t j = 0; j < 10; ++j) {
      key.compound = j;
      IWKV_val ckey;
      rc = iwkv_cursor_open(db, &cur, IWKV_CURSOR_EQ, &key);
      CU_ASSERT_EQUAL_FATAL(rc, 0);
      rc = iwkv_cursor_key(cur, &ckey);
      CU_ASSERT_EQUAL_FATAL(rc, 0);
      CU_ASSERT_TRUE_FATAL(ckey.size == 4 && ckey.compound == j && !memcmp(ckey.data, &i, sizeof(i)));
      iwkv_val_dispose(&ckey);
      rc = iwkv_cursor_close(&cur);
      CU_ASSERT_EQUAL_FATAL(rc, 0);
    }
  }
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
}

static void iwkv_test6_2() {
  iwrc rc;
  IWKV iwkv;
  IWDB db;
  IWKV_val key = {0};
  IWKV_val val = {0};
  char kbuf[PREFIX_KEY_LEN - 1];
  for (int i = 0; i < sizeof(kbuf); ++i) {
    kbuf[i] = (i % 94) + 33;
  }
  IWKV_OPTS opts = {
    .path = "iwkv_test6_2.db",
    .oflags = IWKV_TRUNC
  };
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, IWDB_COMPOUND_KEYS, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  for (uint32_t i = 0; i < 1000; ++i) {
    key.data = kbuf;
    key.size = sizeof(kbuf);
    key.compound = i;
    rc = iwkv_put(db, &key, &val, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    rc = iwkv_get(db, &key, &val);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
}

int main() {
  CU_pSuite pSuite = NULL;

  /* Initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry()) return CU_get_error();

  /* Add a suite to the registry */
  pSuite = CU_add_suite("iwkv_test6", init_suite, clean_suite);

  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Add the tests to the suite */
  if (
    (NULL == CU_add_test(pSuite, "iwkv_test6_1", iwkv_test6_1)) ||
    (NULL == CU_add_test(pSuite, "iwkv_test6_2", iwkv_test6_2))
    ) {
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
