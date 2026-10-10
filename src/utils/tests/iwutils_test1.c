#include "iowow.h"
#include "iwcfg.h"
#include <CUnit/Basic.h>
#include "iwutils.h"
#include "iwpool.h"
#include "iwrb.h"
#include "iwconv.h"

static int init_suite(void) {
  return iw_init();
}

// Defined in src/utils/iwutils.c (IW_TESTS only)
uint32_t iwu_crc32_sw(const uint8_t *buf, int len, uint32_t init);
uint32_t iwu_crc32_hw(const uint8_t *buf, int len, uint32_t init);
bool iwu_crc32_hw_available(void);

static int clean_suite(void) {
  return 0;
}

static const char* _replace_mapper1(const char *key, void *op) {
  if (!strcmp(key, "{}")) {
    return "Mother";
  } else if (!strcmp(key, "you")) {
    return "I";
  } else if (!strcmp(key, "?")) {
    return "?!!";
  } else {
    return 0;
  }
}

static void test_iwu_replace_into(void) {
  struct iwxstr *res = 0;
  const char *data = "What you said about my {}?";
  const char *keys[] = { "{}", "$", "?", "you", "my" };
  iwrc rc = iwu_replace(&res, data, strlen(data), keys, 5, _replace_mapper1, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_PTR_NOT_NULL_FATAL(res);
  fprintf(stderr, "\n%s", iwxstr_ptr(res));
  CU_ASSERT_STRING_EQUAL(iwxstr_ptr(res), "What I said about my Mother?!!");
  iwxstr_destroy(res);
}

static void test_iwpool_split_string(void) {
  struct iwpool *pool = iwpool_create(128);
  CU_ASSERT_PTR_NOT_NULL_FATAL(pool);
  const char **res = iwpool_split_string(pool, " foo , bar:baz,,z,", ",:", true);
  CU_ASSERT_PTR_NOT_NULL_FATAL(res);
  int i = 0;
  for ( ; res[i]; ++i) {
    switch (i) {
      case 0:
        CU_ASSERT_STRING_EQUAL(res[i], "foo");
        break;
      case 1:
        CU_ASSERT_STRING_EQUAL(res[i], "bar");
        break;
      case 2:
        CU_ASSERT_STRING_EQUAL(res[i], "baz");
        break;
      case 3:
        CU_ASSERT_STRING_EQUAL(res[i], "");
        break;
      case 4:
        CU_ASSERT_STRING_EQUAL(res[i], "z");
        break;
    }
  }
  CU_ASSERT_EQUAL(i, 5);

  res = iwpool_split_string(pool, " foo , bar:baz,,z,", ",:", false);
  CU_ASSERT_PTR_NOT_NULL_FATAL(res);
  i = 0;
  for ( ; res[i]; ++i) {
    switch (i) {
      case 0:
        CU_ASSERT_STRING_EQUAL(res[i], " foo ");
        break;
      case 1:
        CU_ASSERT_STRING_EQUAL(res[i], " bar");
        break;
      case 2:
        CU_ASSERT_STRING_EQUAL(res[i], "baz");
        break;
      case 3:
        CU_ASSERT_STRING_EQUAL(res[i], "");
        break;
      case 4:
        CU_ASSERT_STRING_EQUAL(res[i], "z");
        break;
    }
  }
  CU_ASSERT_EQUAL(i, 5);

  res = iwpool_split_string(pool, " foo ", ",", false);
  CU_ASSERT_PTR_NOT_NULL_FATAL(res);
  i = 0;
  for ( ; res[i]; ++i) {
    switch (i) {
      case 0:
        CU_ASSERT_STRING_EQUAL(res[i], " foo ");
        break;
    }
  }
  CU_ASSERT_EQUAL(i, 1);


  res = iwpool_printf_split(pool, ",", true, "%s,%s", "foo", "bar");
  CU_ASSERT_PTR_NOT_NULL_FATAL(res);
  i = 0;
  for ( ; res[i]; ++i) {
    switch (i) {
      case 0:
        CU_ASSERT_STRING_EQUAL(res[i], "foo");
        break;
      case 1:
        CU_ASSERT_STRING_EQUAL(res[i], "bar");
        break;
    }
  }
  CU_ASSERT_EQUAL(i, 2);


  iwpool_destroy(pool);
}

static void test_iwpool_printf(void) {
  struct iwpool *pool = iwpool_create(128);
  CU_ASSERT_PTR_NOT_NULL_FATAL(pool);
  const char *res = iwpool_printf(pool, "%s=%s", "foo", "bar");
  CU_ASSERT_PTR_NOT_NULL_FATAL(pool);
  CU_ASSERT_STRING_EQUAL(res, "foo=bar");
  iwpool_destroy(pool);
}

static void test_iwrb1(void) {
  int *p;
  struct iwrb_iter iter;
  struct iwrb *rb = iwrb_create(sizeof(int), 7);
  CU_ASSERT_PTR_NOT_NULL_FATAL(rb);
  CU_ASSERT_EQUAL(iwrb_num_cached(rb), 0);
  int idx = 0;
  int data[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };

  iwrb_put(rb, &data[idx++]);
  CU_ASSERT_EQUAL(iwrb_num_cached(rb), 1);

  iwrb_iter_init(rb, &iter);
  p = iwrb_iter_prev(&iter);
  CU_ASSERT_PTR_NOT_NULL_FATAL(p);
  CU_ASSERT_EQUAL(*p, 1);
  p = iwrb_iter_prev(&iter);
  CU_ASSERT_PTR_NULL(p);
  p = iwrb_peek(rb);
  CU_ASSERT_PTR_NOT_NULL_FATAL(p);
  CU_ASSERT_EQUAL(*p, 1);

  for (int i = 0; i < 6; ++i) {
    iwrb_put(rb, &data[i + 1]);
  }
  p = iwrb_peek(rb);
  CU_ASSERT_PTR_NOT_NULL_FATAL(p);
  CU_ASSERT_EQUAL(*p, 7);

  iwrb_iter_init(rb, &iter);
  for (int i = 7; i > 0; --i) {
    p = iwrb_iter_prev(&iter);
    CU_ASSERT_PTR_NOT_NULL_FATAL(p);
    CU_ASSERT_EQUAL(*p, i);
  }
  CU_ASSERT_PTR_NULL(iwrb_iter_prev(&iter));
  iwrb_put(rb, &data[7]);
  p = iwrb_peek(rb);
  CU_ASSERT_PTR_NOT_NULL_FATAL(p);
  CU_ASSERT_EQUAL(*p, 8);

  iwrb_iter_init(rb, &iter);
  for (int i = 8; i > 1; --i) {
    p = iwrb_iter_prev(&iter);
    CU_ASSERT_PTR_NOT_NULL_FATAL(p);
    CU_ASSERT_EQUAL(*p, i);
  }
  CU_ASSERT_PTR_NULL(iwrb_iter_prev(&iter));

  for (int i = 8; i < 14; ++i) {
    iwrb_put(rb, &data[i]);
  }

  iwrb_iter_init(rb, &iter);
  for (int i = 0; i < 7; ++i) {
    p = iwrb_iter_prev(&iter);
    CU_ASSERT_PTR_NOT_NULL_FATAL(p);
    CU_ASSERT_EQUAL(*p, 14 - i);
  }
  CU_ASSERT_PTR_NULL(iwrb_iter_prev(&iter));

  iwrb_destroy(&rb);
  CU_ASSERT_PTR_NULL(rb);
}

static void iwitoa_issue48(void) {
  char buf[IWNUMBUF_SIZE];
  int len = iwitoa(INT64_MIN, buf, sizeof(buf));
  CU_ASSERT_EQUAL(len, 20);
  CU_ASSERT_STRING_EQUAL("-9223372036854775808", buf);
}

// Independent bit-at-a-time CRC-32C reference implementation.
static uint32_t crc32c_ref(const uint8_t *buf, int len, uint32_t init) {
  uint32_t crc = init;
  for (int i = 0; i < len; ++i) {
    crc ^= buf[i];
    for (int b = 0; b < 8; ++b) {
      crc = (crc >> 1) ^ (0x82F63B78U & (uint32_t) -(int32_t) (crc & 1));
    }
  }
  return crc;
}

// Verifies that the portable software implementation, the hardware accelerated
// implementation and an independent reference all produce the same CRC-32C
// value for every length, init and split point.
static void test_iwu_crc32(void) {
  // Standard CRC-32C check value for "123456789".
  const uint8_t check[] = "123456789";
  CU_ASSERT_EQUAL(iwu_crc32(check, 9, 0xFFFFFFFFU) ^ 0xFFFFFFFFU, 0xE3069283U);

  uint8_t buf[512];
  for (int i = 0; i < (int) sizeof(buf); ++i) {
    buf[i] = (uint8_t) (i * 131 + 7);
  }
  static const uint32_t inits[] = { 0U, 0xFFFFFFFFU, 0x12345678U, 0xA5A5A5A5U };
  const bool hw = iwu_crc32_hw_available();

  for (size_t ii = 0; ii < sizeof(inits) / sizeof(inits[0]); ++ii) {
    const uint32_t init = inits[ii];
    for (int len = 0; len <= (int) sizeof(buf); ++len) {
      const uint32_t ref = crc32c_ref(buf, len, init);
      CU_ASSERT_EQUAL_FATAL(iwu_crc32(buf, len, init), ref);
      CU_ASSERT_EQUAL_FATAL(iwu_crc32_sw(buf, len, init), ref);
      if (hw) {
        CU_ASSERT_EQUAL_FATAL(iwu_crc32_hw(buf, len, init), ref);
        for (int split = 0; split <= len; split += 13) {
          uint32_t c = iwu_crc32_hw(buf, split, init);
          c = iwu_crc32_hw(buf + split, len - split, c);
          CU_ASSERT_EQUAL_FATAL(c, ref);
        }
      }
    }
  }

  // Incremental (chained) evaluation must match a single-shot computation.
  for (int split = 0; split <= 64; ++split) {
    uint32_t c = iwu_crc32(buf, split, 0);
    c = iwu_crc32(buf + split, 64 - split, c);
    CU_ASSERT_EQUAL_FATAL(c, iwu_crc32(buf, 64, 0));
  }
}

int main(void) {
  CU_pSuite pSuite = NULL;

  /* Initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry()) {
    return CU_get_error();
  }

  /* Add a suite to the registry */
  pSuite = CU_add_suite("iwutils_test1", init_suite, clean_suite);

  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Add the tests to the suite */
  if (  (NULL == CU_add_test(pSuite, "test_iwu_replace_into", test_iwu_replace_into))
     || (NULL == CU_add_test(pSuite, "test_iwpool_split_string", test_iwpool_split_string))
     || (NULL == CU_add_test(pSuite, "test_iwpool_printf", test_iwpool_printf))
     || (NULL == CU_add_test(pSuite, "test_iwrb1", test_iwrb1))
     || (NULL == CU_add_test(pSuite, "iwitoa_issue48", iwitoa_issue48))
     || (NULL == CU_add_test(pSuite, "test_iwu_crc32", test_iwu_crc32))) {
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
