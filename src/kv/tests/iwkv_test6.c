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

int cmp_uint64(const void *v1, const void *v2) {
  uint64_t u1, u2;
  memcpy(&u1, v1, sizeof(u1));
  memcpy(&u2, v2, sizeof(u2));
  return u1 < u2 ? -1 : u1 > u2 ? 1 : 0;
}

static void swap(uint64_t *v1, uint64_t *v2) {
  uint64_t tmp = *v1;
  *v1 = *v2;
  *v2 = tmp;
}

void process_put(IWDB db, uint32_t id2) {
  iwrc rc;
  uint32_t id1 = id2 - 1;
  uint64_t u1, u2;
  IWKV_val v1, v2;
  IWKV_val k1 = {.data = &id1, .size = sizeof(id1)};
  IWKV_val k2 = {.data = &id2, .size = sizeof(id2)};

  rc = iwkv_get(db, &k1, &v1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_get(db, &k2, &v2);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  memcpy(&u1, v1.data, sizeof(u1));
  memcpy(&u2, v2.data, sizeof(u2));
  iwkv_kv_dispose(&v1, &v2);

  if (u1 > u2) {
    v1.data = &u2;
    v1.size = sizeof(u2);
    v2.data = &u1;
    v2.size = sizeof(u1);
    rc = iwkv_put(db, &k1, &v1, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    rc = iwkv_put(db, &k2, &v2, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
}

static void iwkv_test6_impl(int dbid, int num, bool wal) {
  iwrc rc;
  IWKV iwkv;
  IWDB db;

  uint64_t *data = calloc(num, sizeof(uint64_t));
  CU_ASSERT_PTR_NOT_NULL_FATAL(data);
  for (int i = 0; i < num; ++i) {
    uint64_t v = iwu_rand_u32();
    v <<= 32;
    v |= iwu_rand_u32();
    data[i] = v;
  }
  IWKV_OPTS opts = {
    .path = "iwkv_test6_1.db",
    .oflags = IWKV_TRUNC,
    .wal = {
      .enabled = wal,
      .checkpoint_buffer_sz = 10 * 1024 * 1024 // 10M
    }
  };
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, dbid, IWDB_UINT32_KEYS, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  for (uint32_t i = 0; i < num; ++i) {
    IWKV_val key, val;
    key.data = &i;
    key.size = sizeof(i);
    val.data = &data[i];
    val.size = sizeof(data[0]);
    rc = iwkv_put(db, &key, &val, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }

  qsort(data, num, sizeof(data[0]), cmp_uint64);

  int i = 0;
  for (int n = 0; n < num; ++n) {
    if (n & 1) {
      #pragma omp parallel for private(i) shared(data)
      for (i = 2; i < num; i += 2) {
        process_put(db, i);
      }
    } else {
      #pragma omp parallel for private(i) shared(data)
      for (i = 1; i < num; i += 2) {
        process_put(db, i);
      }
    }
  }

  IWKV_cursor cur;
  rc = iwkv_cursor_open(db, &cur, IWKV_CURSOR_AFTER_LAST, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  for (int i = 0; !(rc = iwkv_cursor_to(cur, IWKV_CURSOR_PREV)); ++i) {
    CU_ASSERT_TRUE_FATAL(i < num);
    uint32_t id;
    uint64_t num;
    IWKV_val key, val;
    rc = iwkv_cursor_get(cur, &key, &val);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_EQUAL_FATAL(key.size, sizeof(id));
    CU_ASSERT_EQUAL_FATAL(val.size, sizeof(num));
    memcpy(&id, key.data, sizeof(id));
    memcpy(&num, val.data, sizeof(num));

    CU_ASSERT_EQUAL(num, data[i]);
    iwkv_kv_dispose(&key, &val);
  }
  if (rc == IWKV_ERROR_NOTFOUND) {
    rc = 0;
  }
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_cursor_close(&cur);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  free(data);
}

static void iwkv_test6_1(void) {
  iwkv_test6_impl(1, 2000, false);
}

static void iwkv_test6_2(void) {
  iwkv_test6_impl(1, 2000, true);
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

  )  {
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
