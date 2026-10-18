#include "iowow.h"
#include "iwcfg.h"
#include "tests.h"
#include "iwutils.h"
#include "iwpool.h"
#include "iwrb.h"
#include "iwconv.h"
#include "iwlog.h"

#include <errno.h>
#include <math.h>
#include <locale.h>

static int init_suite(void) {
  return iw_init();
}

// Defined in src/utils/iwutils.c (IW_TESTS only)
uint32_t iwu_crc32_sw(const uint8_t *buf, int len, uint32_t init);
uint32_t iwu_crc32_hw(const uint8_t *buf, int len, uint32_t init);
bool iwu_crc32_hw_available(void);

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
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(res);
  fprintf(stderr, "\n%s", iwxstr_ptr(res));
  IW_TEST_ASSERT_STR_EQUAL(iwxstr_ptr(res), "What I said about my Mother?!!");
  iwxstr_destroy(res);
}

static void test_iwpool_split_string(void) {
  struct iwpool *pool = iwpool_create(128);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);
  const char **res = iwpool_split_string(pool, " foo , bar:baz,,z,", ",:", true);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(res);
  int i = 0;
  for ( ; res[i]; ++i) {
    switch (i) {
      case 0:
        IW_TEST_ASSERT_STR_EQUAL(res[i], "foo");
        break;
      case 1:
        IW_TEST_ASSERT_STR_EQUAL(res[i], "bar");
        break;
      case 2:
        IW_TEST_ASSERT_STR_EQUAL(res[i], "baz");
        break;
      case 3:
        IW_TEST_ASSERT_STR_EQUAL(res[i], "");
        break;
      case 4:
        IW_TEST_ASSERT_STR_EQUAL(res[i], "z");
        break;
    }
  }
  IW_TEST_ASSERT_EQUAL(i, 5);

  res = iwpool_split_string(pool, " foo , bar:baz,,z,", ",:", false);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(res);
  i = 0;
  for ( ; res[i]; ++i) {
    switch (i) {
      case 0:
        IW_TEST_ASSERT_STR_EQUAL(res[i], " foo ");
        break;
      case 1:
        IW_TEST_ASSERT_STR_EQUAL(res[i], " bar");
        break;
      case 2:
        IW_TEST_ASSERT_STR_EQUAL(res[i], "baz");
        break;
      case 3:
        IW_TEST_ASSERT_STR_EQUAL(res[i], "");
        break;
      case 4:
        IW_TEST_ASSERT_STR_EQUAL(res[i], "z");
        break;
    }
  }
  IW_TEST_ASSERT_EQUAL(i, 5);

  res = iwpool_split_string(pool, " foo ", ",", false);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(res);
  i = 0;
  for ( ; res[i]; ++i) {
    switch (i) {
      case 0:
        IW_TEST_ASSERT_STR_EQUAL(res[i], " foo ");
        break;
    }
  }
  IW_TEST_ASSERT_EQUAL(i, 1);


  res = iwpool_printf_split(pool, ",", true, "%s,%s", "foo", "bar");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(res);
  i = 0;
  for ( ; res[i]; ++i) {
    switch (i) {
      case 0:
        IW_TEST_ASSERT_STR_EQUAL(res[i], "foo");
        break;
      case 1:
        IW_TEST_ASSERT_STR_EQUAL(res[i], "bar");
        break;
    }
  }
  IW_TEST_ASSERT_EQUAL(i, 2);


  iwpool_destroy(pool);
}

static void test_iwpool_printf(void) {
  struct iwpool *pool = iwpool_create(128);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);
  const char *res = iwpool_printf(pool, "%s=%s", "foo", "bar");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);
  IW_TEST_ASSERT_STR_EQUAL(res, "foo=bar");
  iwpool_destroy(pool);
}

static void test_iwrb1(void) {
  int *p;
  struct iwrb_iter iter;
  struct iwrb *rb = iwrb_create(sizeof(int), 7);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(rb);
  IW_TEST_ASSERT_EQUAL(iwrb_num_cached(rb), 0);
  int idx = 0;
  int data[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };

  iwrb_put(rb, &data[idx++]);
  IW_TEST_ASSERT_EQUAL(iwrb_num_cached(rb), 1);

  iwrb_iter_init(rb, &iter);
  p = iwrb_iter_prev(&iter);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(p);
  IW_TEST_ASSERT_EQUAL(*p, 1);
  p = iwrb_iter_prev(&iter);
  IW_TEST_ASSERT_PTR_NULL(p);
  p = iwrb_peek(rb);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(p);
  IW_TEST_ASSERT_EQUAL(*p, 1);

  for (int i = 0; i < 6; ++i) {
    iwrb_put(rb, &data[i + 1]);
  }
  p = iwrb_peek(rb);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(p);
  IW_TEST_ASSERT_EQUAL(*p, 7);

  iwrb_iter_init(rb, &iter);
  for (int i = 7; i > 0; --i) {
    p = iwrb_iter_prev(&iter);
    IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(p);
    IW_TEST_ASSERT_EQUAL(*p, i);
  }
  IW_TEST_ASSERT_PTR_NULL(iwrb_iter_prev(&iter));
  iwrb_put(rb, &data[7]);
  p = iwrb_peek(rb);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(p);
  IW_TEST_ASSERT_EQUAL(*p, 8);

  iwrb_iter_init(rb, &iter);
  for (int i = 8; i > 1; --i) {
    p = iwrb_iter_prev(&iter);
    IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(p);
    IW_TEST_ASSERT_EQUAL(*p, i);
  }
  IW_TEST_ASSERT_PTR_NULL(iwrb_iter_prev(&iter));

  for (int i = 8; i < 14; ++i) {
    iwrb_put(rb, &data[i]);
  }

  iwrb_iter_init(rb, &iter);
  for (int i = 0; i < 7; ++i) {
    p = iwrb_iter_prev(&iter);
    IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(p);
    IW_TEST_ASSERT_EQUAL(*p, 14 - i);
  }
  IW_TEST_ASSERT_PTR_NULL(iwrb_iter_prev(&iter));

  iwrb_destroy(&rb);
  IW_TEST_ASSERT_PTR_NULL(rb);
}

static void iwitoa_issue48(void) {
  char buf[IWNUMBUF_SIZE];
  int len = iwitoa(INT64_MIN, buf, sizeof(buf));
  IW_TEST_ASSERT_EQUAL(len, 20);
  IW_TEST_ASSERT_STR_EQUAL("-9223372036854775808", buf);
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
  IW_TEST_ASSERT_EQUAL(iwu_crc32(check, 9, 0xFFFFFFFFU) ^ 0xFFFFFFFFU, 0xE3069283U);

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
      IW_TEST_ASSERT_EQUAL_FATAL(iwu_crc32(buf, len, init), ref);
      IW_TEST_ASSERT_EQUAL_FATAL(iwu_crc32_sw(buf, len, init), ref);
      if (hw) {
        IW_TEST_ASSERT_EQUAL_FATAL(iwu_crc32_hw(buf, len, init), ref);
        for (int split = 0; split <= len; split += 13) {
          uint32_t c = iwu_crc32_hw(buf, split, init);
          c = iwu_crc32_hw(buf + split, len - split, c);
          IW_TEST_ASSERT_EQUAL_FATAL(c, ref);
        }
      }
    }
  }

  // Incremental (chained) evaluation must match a single-shot computation.
  for (int split = 0; split <= 64; ++split) {
    uint32_t c = iwu_crc32(buf, split, 0);
    c = iwu_crc32(buf + split, 64 - split, c);
    IW_TEST_ASSERT_EQUAL_FATAL(c, iwu_crc32(buf, 64, 0));
  }
}


//--- iw_strtod_c() / iw_strtold_c()

/* Asserts that iw_strtod_c() and libc strtod() (C locale) produce the same value and end position. */
static void _assert_strtod_same(const char *s) {
  char *e1 = 0, *e2 = 0;
  double d1 = iw_strtod_c(s, &e1);
  double d2 = strtod(s, &e2);
  IW_TEST_ASSERT_EQUAL((long) (e1 - s), (long) (e2 - s));
  // Bit exact comparison, it also catches the -0.0 vs 0.0 difference
  IW_TEST_ASSERT_MEM_EQUAL(&d1, &d2, sizeof(d1));
}

// Generates a random decimal number token: [-][0..][digits[.digits]][0..][e[-]exp][garbage]
static void _gen_number_token(char *buf, size_t bufsz, uint64_t *state) {
  uint64_t x = *state;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  *state = x;

  int ndig = 1 + (int) (x % 19);
  int dot = (int) ((x >> 3) % 21);      // Decimal point position, may be out of the digits
  int lead = (int) ((x >> 7) % 4);      // Leading zeroes
  int trail = (int) ((x >> 9) % 3);     // Trailing zeroes
  int exp = (int) ((x >> 11) % 61) - 30;
  bool with_exp = ((x >> 15) & 1U) != 0;
  bool garbage = ((x >> 16) % 8U) == 0;

  size_t off = 0;
#define _PUT(ch_) do { if (off < bufsz - 1) { buf[off++] = (ch_); } } while (0)
  if ((x >> 17) & 1U) {
    _PUT('-');
  }
  for (int i = 0; i < lead; ++i) {
    _PUT('0');
  }
  for (int i = 0; i < ndig; ++i) {
    if (i == dot) {
      _PUT('.');
    }
    _PUT((char) ('0' + (int) ((x >> (20 + (i % 24))) % 10U)));
  }
  if (dot >= ndig) {
    _PUT('.');
  }
  for (int i = 0; i < trail; ++i) {
    _PUT('0');
  }
  if (with_exp) {
    char ebuf[8];
    int elen = snprintf(ebuf, sizeof(ebuf), "%c%s%d", ((x >> 18) & 1U) ? 'E' : 'e',
                        (exp < 0) ? "-" : (((x >> 19) & 1U) ? "+" : ""), (exp < 0) ? -exp : exp);
    for (int i = 0; (i < elen) && (ebuf[i] != '\0'); ++i) {
      _PUT(ebuf[i]);
    }
  }
  if (garbage) {
    _PUT('x');
  }
  buf[off] = '\0';
#undef _PUT
}

static void test_iwconv_strtod(void) {
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(setlocale(LC_NUMERIC, "C"));

  static const char *cases[] = {
    // Plain numbers
    "0", "-0", "0.0", "-0.0", "1", "-1", "42", "1.5", "-1.5", "0.1", "-0.125", "123.456",
    "0.000006", "6E-06", "1e3", "1E3", "1e+3", "1e-3", "1.5e2", "1.5E-2", "1e000022",
    "000123", "0.000", "-0.000", "0.000123", "1234.5678",
    // Values around the fast path limits
    "9007199254740991", "9007199254740992", "9007199254740993", "18446744073709551615",
    // Leading/trailing zeroes, significant digit counting
    "000.5", "000.000123", "0000", "-000.000", "0.12345678901234567",
    "0.00000000000000012345678901234567", "0.000000000000000123456789",
    "1.0000000000000000000", "123.4500", "0.10000000000000000000000",
    "0.0000000000000000000000001", "0.0000000000000000000012345678901234567",
    "1e22", "1e23", "1e-22", "1e-23", "9007199254740991e22", "9007199254740991e-22",
    "123456789012345678901234567890", "0.30000000000000004", "1.0000000000000002",
    // Extreme/special values
    "1e400", "1e-400", "1e1000", "1e-1000", "4.9406564584124654e-324",
    "1.7976931348623157e+308", "2.2250738585072014e-308",
    // Not a decimal number: the strtod() fallback has to handle these
    ".5", "1.", "-.5", "1e", "1e+", "1e-", "-", "+1", " 1.5", "0x10", "0X1p3", "0x1.8p1",
    "inf", "-inf", "INFINITY", "nan", "-nan", "NaN",
    // Trailing garbage: the end position must match strtod()
    "1.5x", "1e5x", "12abc", "1.5.5", "1..2", "0x", "-.e1",
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    _assert_strtod_same(cases[i]);
  }

  // Generated corpus covering the fast path and its fallbacks
  char tok[64];
  uint64_t state = 0x243F6A8885A308D3ULL;
  for (int i = 0; i < 20000; ++i) {
    _gen_number_token(tok, sizeof(tok), &state);
    _assert_strtod_same(tok);
  }

  // Long fractional parts and long digit runs (slow path)
  char longtok[512];
  memset(longtok, '0', sizeof(longtok));
  longtok[0] = '0';
  longtok[1] = '.';
  for (int n = 1; n < 400; n += 7) {
    memset(longtok + 2, '0', (size_t) n);
    longtok[2 + n] = '1';
    longtok[3 + n] = '\0';
    _assert_strtod_same(longtok);
  }
  memset(longtok, '9', 100);
  longtok[100] = '\0';
  _assert_strtod_same(longtok);

  // iw_strtold_c()
  static const char *lcases[] = { "0", "-0.0", "1.5", "-1234.25", "0.1", "1e-9", "1e300", ".5", "1.", "0x10" };
  for (size_t i = 0; i < sizeof(lcases) / sizeof(lcases[0]); ++i) {
    char *e1 = 0, *e2 = 0;
    long double d1 = iw_strtold_c(lcases[i], &e1);
    long double d2 = strtold(lcases[i], &e2);
    IW_TEST_ASSERT_EQUAL((long) (e1 - lcases[i]), (long) (e2 - lcases[i]));
    // A `long double` may contain padding bytes, so compare the values (and the zero sign)
    IW_TEST_ASSERT_TRUE((d1 == d2) && (signbit(d1) == signbit(d2)));
  }
}

static void test_iwconv_strtod_wrappers(void) {
  // A stale ERANGE must not turn a successful conversion into an error
  errno = ERANGE;
  iwrc rc = 0;
  IW_TEST_ASSERT_DOUBLE_EQUAL(iw_strtod("2.5", &rc), 2.5, 0.0);
  IW_TEST_ASSERT_EQUAL(rc, 0);
  errno = ERANGE;
  rc = 0;
  IW_TEST_ASSERT_DOUBLE_EQUAL((double) iw_strtold("2.5", &rc), 2.5, 0.0);
  IW_TEST_ASSERT_EQUAL(rc, 0);
  errno = ERANGE;
  rc = 0;
  IW_TEST_ASSERT_EQUAL(iw_strtoll("12", 10, &rc), 12);
  IW_TEST_ASSERT_EQUAL(rc, 0);

  // Errors are still reported
  rc = 0;
  IW_TEST_ASSERT_EQUAL(iw_strtod("2.5x", &rc), 0);
  IW_TEST_ASSERT_EQUAL(rc, IW_ERROR_INVALID_ARGS);
  rc = 0;
  IW_TEST_ASSERT_EQUAL(iw_strtod("1e400", &rc), 0);
  IW_TEST_ASSERT_EQUAL(rc, IW_ERROR_INVALID_ARGS);

  // The text produced by the C locale formatter is parsed back to the same double
  char buf[IWNUMBUF_SIZE];
  uint64_t state = 0x13198A2E03707344ULL;
  for (int i = 0; i < 5000; ++i) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    double d;
    memcpy(&d, &state, sizeof(d));
    if (isnan(d) || isinf(d)) {
      continue; // JSON has no representation for non finite numbers
    }
    iw_snprintf_c(buf, sizeof(buf), "%.17g", d);
    char *ep = 0;
    double rv = iw_strtod_c(buf, &ep);
    IW_TEST_ASSERT_TRUE(ep && (*ep == '\0'));
    IW_TEST_ASSERT_MEM_EQUAL(&rv, &d, sizeof(rv));
  }
}

static const struct iw_test_case cases[] = {
  IW_TEST_CASE(test_iwu_replace_into),
  IW_TEST_CASE(test_iwpool_split_string),
  IW_TEST_CASE(test_iwpool_printf),
  IW_TEST_CASE(test_iwrb1),
  IW_TEST_CASE(iwitoa_issue48),
  IW_TEST_CASE(test_iwu_crc32),
  IW_TEST_CASE(test_iwconv_strtod),
  IW_TEST_CASE(test_iwconv_strtod_wrappers),
};

int main(int argc, char *argv[]) {
  return iw_test_run(argc, argv, IW_TEST_SUITE("iwutils_test1", cases, init_suite, 0));
}

