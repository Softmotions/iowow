#include "iowow.h"
#include "iwcfg.h"
#include "iwhmap.h"
#include <CUnit/Basic.h>

static int init_suite(void) {
  return iw_init();
}

static int clean_suite(void) {
  return 0;
}

static void hex32(uint32_t *hash, char *buf) {
  sprintf(buf, "%08x", *hash);
}

static void hex128(uint32_t hash[4], char *buf) {
  sprintf(buf, "%08x%08x%08x%08x", hash[0], hash[1], hash[2], hash[3]);
}

void murmur3_x86_32(const void *key, size_t len, uint32_t seed, void *out);
void murmur3_x86_128(const void *key, const size_t len, uint32_t seed, void *out);
void murmur3_x64_128(const void *key, const size_t len, const uint32_t seed, void *out);

static void test_murmur_hash(void) {
#define TESTHASH(arch, nbytes, seed, str, expected) {                          \
          char *input = str;                                                   \
          uint32_t hash[4];                                                    \
          char buf[33];                                                        \
          murmur3_ ## arch ## _ ## nbytes(input, strlen(input), (seed), hash); \
          hex ## nbytes(hash, buf);                                            \
          CU_ASSERT_STRING_EQUAL(buf, expected)                                \
}

  TESTHASH(x86, 32, 1234, "Hello, world!", "faf6cdb3");
  TESTHASH(x86, 32, 4321, "Hello, world!", "bf505788");
  TESTHASH(x86, 32, 1234, "xxxxxxxxxxxxxxxxxxxxxxxxxxxx", "8905ac28");
  TESTHASH(x86, 32, 1234, "", "0f2cc00b");

  TESTHASH(x86, 128, 123, "Hello, world!", "61c9129e5a1aacd7a41621629e37c886");
  TESTHASH(x86, 128, 321, "Hello, world!", "d5fbdcb3c26c4193045880c5a7170f0f");
  TESTHASH(x86, 128, 123, "xxxxxxxxxxxxxxxxxxxxxxxxxxxx", "5e40bab278825a164cf929d31fec6047");
  TESTHASH(x86, 128, 123, "", "fedc524526f3e79926f3e79926f3e799");

  TESTHASH(x64, 128, 123, "Hello, world!", "8743acad421c8c73d373c3f5f19732fd");
  TESTHASH(x64, 128, 321, "Hello, world!", "f86d4004ca47f42bb9546c7979200aee");
  TESTHASH(x64, 128, 123, "xxxxxxxxxxxxxxxxxxxxxxxxxxxx", "becf7e04dbcf74637751664ef66e73e0");
  TESTHASH(x64, 128, 123, "", "4cd9597081679d1abd92f8784bace33d");
}

static void test_basic_crud_str(void) {
  char kbuf[64];
  char vbuf[64];
  IWHMAP *hm = iwhmap_create_str(iwhmap_kv_free);
  CU_ASSERT_PTR_NOT_NULL_FATAL(hm);
  for (int i = 0; i < 10000; ++i) {
    snprintf(kbuf, sizeof(kbuf), "key%d", i);
    snprintf(vbuf, sizeof(vbuf), "value%d", i);
    iwrc rc = iwhmap_put(hm, strdup(kbuf), strdup(vbuf));
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
  for (int i = 0; i < 10000; ++i) {
    snprintf(kbuf, sizeof(kbuf), "key%d", i);
    snprintf(vbuf, sizeof(vbuf), "value%d", i);
    const char *vp = iwhmap_get(hm, kbuf);
    CU_ASSERT_PTR_NOT_NULL_FATAL(vp);
    CU_ASSERT_STRING_EQUAL(vbuf, vp);
    if (i % 2 == 0) {
      iwhmap_remove(hm, kbuf);
    }
  }
  CU_ASSERT_EQUAL(iwhmap_count(hm), 5000);
  for (int i = 0; i < 10000; ++i) {
    if ((i % 2) == 0) {
      continue;
    }
    snprintf(kbuf, sizeof(kbuf), "key%d", i);
    snprintf(vbuf, sizeof(vbuf), "value%d", i);
    const char *vp = iwhmap_get(hm, kbuf);
    CU_ASSERT_PTR_NOT_NULL_FATAL(vp);
    CU_ASSERT_STRING_EQUAL(vbuf, vp);
    if (i % 3 == 0) {
      iwhmap_remove(hm, kbuf);
    }
  }
  CU_ASSERT_EQUAL(iwhmap_count(hm), 3333);

  // TODO: finish tests
  iwhmap_destroy(hm);
}

static void test_lru1(void) {
  IWHMAP *hm = iwhmap_create_u32(0);
  CU_ASSERT_PTR_NOT_NULL_FATAL(hm);

  // Init LRU mode max 2 records in map
  iwhmap_lru_init(hm, iwhmap_lru_eviction_max_count, (void*) (uintptr_t) 2UL);

  iwrc rc = iwhmap_put_u32(hm, 1, (void*) 1L);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  long val = (intptr_t) iwhmap_get_u64(hm, 1);
  CU_ASSERT_EQUAL(val, 1L);

  rc -= iwhmap_put_u32(hm, 2, (void*) 2L);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  val = (intptr_t) iwhmap_get_u64(hm, 1);
  CU_ASSERT_EQUAL(val, 1L);
  val = (intptr_t) iwhmap_get_u64(hm, 2);
  CU_ASSERT_EQUAL(val, 2L);

  rc = iwhmap_put_u32(hm, 3, (void*) 3L);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  val = (intptr_t) iwhmap_get_u64(hm, 1);
  CU_ASSERT_EQUAL(val, 0L);
  val = (intptr_t) iwhmap_get_u64(hm, 3);
  CU_ASSERT_EQUAL(val, 3L);
  val = (intptr_t) iwhmap_get_u64(hm, 2);
  CU_ASSERT_EQUAL(val, 2L);

  rc = iwhmap_put_u32(hm, 4, (void*) 4L);
  val = (intptr_t) iwhmap_get_u64(hm, 3);
  CU_ASSERT_EQUAL(val, 0);
  CU_ASSERT_EQUAL(iwhmap_count(hm), 2);

  iwhmap_destroy(hm);
}

static void test_lru2(void) {
  iwrc rc = 0;
  IWHMAP *hm = iwhmap_create_u32(0);
  CU_ASSERT_PTR_NOT_NULL_FATAL(hm);
  iwhmap_lru_init(hm, iwhmap_lru_eviction_max_count, (void*) (uintptr_t) 1024UL);
  for (int i = 0; i < 2048; ++i) {
    rc = iwhmap_put_u32(hm, i + 1, (void*) (intptr_t) i);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
  uint32_t val = iwhmap_count(hm);
  CU_ASSERT_EQUAL(val, 1024);

  iwhmap_destroy(hm);
}

int main(void) {
  CU_pSuite pSuite = NULL;

  /* Initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry()) {
    return CU_get_error();
  }

  /* Add a suite to the registry */
  pSuite = CU_add_suite("iwhmap_test1", init_suite, clean_suite);

  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Add the tests to the suite */
  if (  (NULL == CU_add_test(pSuite, "test_murmur_hash", test_murmur_hash))
     || (NULL == CU_add_test(pSuite, "test_basic_crud_str", test_basic_crud_str))
     || (NULL == CU_add_test(pSuite, "test_lru1", test_lru1))
     || (NULL == CU_add_test(pSuite, "test_lru2", test_lru2))) {
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
