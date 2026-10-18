#include "iwconv.h"
#include "iwchars.h"
#include "iwlog.h"

#include <math.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __APPLE__
#include <xlocale.h>
#else
#include <locale.h>
#endif

// mapping of ASCII characters to hex values
static const uint8_t ascii2hex[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  !"#$%&'
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ()*+,-./
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
  0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
  0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PQRSTUVW
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // XYZ[\]^_
  0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // `abcdefg
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hijklmno
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // pqrstuvw
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // xyz{|}~.
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // ........
};

size_t iwhex2bin(const char *hex, int hexlen, char *out, int max) {
  size_t pos = 0, vpos = 0;
  uint8_t idx0, idx1;
  while (pos < hexlen) {
    if (!pos && (hexlen % 2)) { // first iteration + odd chars in hex
      idx0 = '0';               // add '0' prefix
      idx1 = hex[0];
      pos += 1;
    } else {                    // even chars in hex
      idx0 = hex[pos];
      idx1 = hex[pos + 1];
      pos += 2;
    }
    out[vpos++] = (uint8_t) (ascii2hex[idx0] << 4) | ascii2hex[idx1];
    if (vpos >= max) {
      return vpos;
    }
  }
  return vpos;
}

char* iwbin2hex(
  char* const                hex,
  const size_t               hex_maxlen,
  const unsigned char* const bin,
  const size_t               bin_len) {
  size_t i = (size_t) 0U;
  unsigned int x;
  int b;
  int c;

  if ((bin_len >= SIZE_MAX / 2) || (hex_maxlen <= bin_len * 2U)) {
    //errx(2, "bin2hex length wrong");
    return 0;
  }
  while (i < bin_len) {
    c = bin[i] & 0xf;
    b = bin[i] >> 4;
    x = (unsigned char) (87U + c + (((c - 10U) >> 8) & ~38U)) << 8
        | (unsigned char) (87U + b + (((b - 10U) >> 8) & ~38U));
    hex[i * 2U] = (char) x;
    x >>= 8;
    hex[i * 2U + 1U] = (char) x;
    i++;
  }
  hex[i * 2U] = 0U;
  return hex;
}

int iwitoa(int64_t v, char *buf, int max) {
#define ITOA_SZSTEP(_step) if ((ret += (_step)) >= max) { \
          *ptr = 0;                                       \
          return ret;                                     \
}
  int ret = 0;
  char c, *ptr = buf, *p, *p1;
  if (!v) {
    ITOA_SZSTEP(1);
    *ptr++ = '0';
    *ptr = 0;
    return ret;
  }
  // sign stuff
  if (v < 0) {
    if (IW_UNLIKELY(v == INT64_MIN)) {
      return snprintf(buf, max, "-9223372036854775808");
    } else {
      v = -v;
      ITOA_SZSTEP(1)
      * ptr++ = '-';
    }
  }
  // save start pointer
  p = ptr;
  while (v) {
    if (++ret >= max) { //overflow condition
      memmove(ptr, ptr + 1, p - ptr);
      p--;
    }
    *p++ = '0' + v % 10;
    v /= 10;
  }
  // save end pos
  p1 = p;
  // reverse result
  while (p > ptr) {
    c = *--p;
    *p = *ptr;
    *ptr++ = c;
  }
  ptr = p1;
  *ptr = 0;
  return ret;

#undef ITOA_SZSTEP
}

char* iwftoa(long double n, char s[static IWNUMBUF_SIZE]) {
  static double PRECISION = 0.00000000000001;
  // handle special cases
  if (isnan(n)) {
    strcpy(s, "nan");
  } else if (isinf(n)) {
    strcpy(s, "inf");
  } else if (n == 0.0) {
    strcpy(s, "0");
  } else {
    int digit, m, m1;
    char *c = s;
    int neg = (n < 0);
    if (neg) {
      n = -n;
    }
    // calculate magnitude
    m = (int) log10l(n);
    int useExp = (m >= 14 || (neg && m >= 9) || m <= -9);
    if (neg) {
      *(c++) = '-';
    }
    // set up for scientific notation
    if (useExp) {
      if (m < 0) {
        m -= 1;
      }
      n = n / pow(10.0, m);
      m1 = m;
      m = 0;
    }
    if (m < 1) {
      m = 0;
    }
    // convert the number
    while (n > PRECISION || m >= 0) {
      double weight = pow(10.0, m);
      if ((weight > 0) && !isinf(weight)) {
        digit = (int) floorl(n / weight);
        n -= (digit * weight);
        *(c++) = '0' + digit;
      }
      if ((m == 0) && (n > 0)) {
        *(c++) = '.';
      }
      m--;
    }
    if (useExp) {
      // convert the exponent
      int i, j;
      *(c++) = 'e';
      if (m1 > 0) {
        *(c++) = '+';
      } else {
        *(c++) = '-';
        m1 = -m1;
      }
      m = 0;
      while (m1 > 0) {
        *(c++) = '0' + m1 % 10;
        m1 /= 10;
        m++;
      }
      c -= m;
      for (i = 0, j = m - 1; i < j; i++, j--) {
        c[i] ^= c[j];
        c[j] ^= c[i];
        c[i] ^= c[j];
      }
      c += m;
    }
    *(c) = '\0';
  }
  return s;
}

int64_t iwatoi(const char *str) {
  assert(str);
  while (*str > '\0' && *str <= ' ') {
    str++;
  }
  int sign = 1;
  int64_t num = 0;
  if (*str == '-') {
    str++;
    sign = -1;
  } else if (*str == '+') {
    str++;
  }
  if (!strcmp(str, "inf")) {
    return (INT64_MAX * sign);
  }
  while (*str != '\0') {
    if ((*str < '0') || (*str > '9')) {
      break;
    }
    num = num * 10 + *str - '0';
    str++;
  }
  return num * sign;
}

int64_t iwatoi2(const char *str, size_t len) {
  while (len > 0 && *str > '\0' && *str <= ' ') {
    str++;
    len--;
  }
  if (len == 0) {
    return 0;
  }
  int sign = 1;
  int64_t num = 0;
  if (*str == '-') {
    str++;
    len--;
    sign = -1;
  } else if (*str == '+') {
    str++;
    len--;
  }
  if (!strcmp(str, "inf")) {
    return (INT64_MAX * sign);
  }
  while (len > 0 && *str != '\0') {
    if ((*str < '0') || (*str > '9')) {
      break;
    }
    num = num * 10 + *str - '0';
    str++;
    len--;
  }
  return num * sign;
}

long double iwatof(const char *str) {
  assert(str);
  while (*str > '\0' && *str <= ' ') {
    str++;
  }
  int sign = 1;
  if (*str == '-') {
    str++;
    sign = -1;
  } else if (*str == '+') {
    str++;
  }
  if (!strcmp(str, "inf")) {
    return HUGE_VAL * sign;
  }
  long double num = 0;
  while (*str != '\0') {
    if ((*str < '0') || (*str > '9')) {
      break;
    }
    num = num * 10 + *str - '0';
    str++;
  }
  if (*str == '.') {
    str++;
    long double fract = 0.0;
    long double base = 10;
    while (*str != '\0') {
      if ((*str < '0') || (*str > '9')) {
        break;
      }
      fract += (*str - '0') / base;
      str++;
      base *= 10;
    }
    num += fract;
  }
  if ((*str == 'e') || (*str == 'E')) {
    str++;
    num *= pow(10, iwatoi(str));
  }
  return num * sign;
}

/**
 * Compare two strings as real numbers
 */
int iwafcmp(const char *aptr, int asiz, const char *bptr, int bsiz) {
  const unsigned char *arp = (const unsigned char*) aptr;
  const unsigned char *brp = (const unsigned char*) bptr;
  int alen = asiz, blen = bsiz;
  int64_t anum = 0, bnum = 0;
  int asign = 1, bsign = 1;

  // A part
  while (alen > 0 && (*arp <= ' ' || *arp == 0x7f)) {
    arp++;
    alen--;
  }
  if ((alen > 0) && (*arp == '-')) {
    arp++;
    alen--;
    asign = -1;
  }
  while (alen > 0) {
    int c = *arp;
    if ((c < '0') || (c > '9')) {
      break;
    }
    anum = anum * 10 + c - '0';
    arp++;
    alen--;
  }
  anum *= asign;

  // B part
  while (blen > 0 && (*brp <= ' ' || *brp == 0x7f)) {
    brp++;
    blen--;
  }
  if ((blen > 0) && (*brp == '-')) {
    brp++;
    blen--;
    bsign = -1;
  }
  while (blen > 0) {
    int c = *brp;
    if ((c < '0') || (c > '9')) {
      break;
    }
    bnum = bnum * 10 + c - '0';
    brp++;
    blen--;
  }
  bnum *= bsign;
  if (anum < bnum) {
    return -1;
  }
  if (anum > bnum) {
    return 1;
  }
  if (((alen > 1) && (*arp == '.')) || ((blen > 1) && (*brp == '.'))) {
    long double aflt = 0;
    long double bflt = 0;
    if ((alen > 1) && (*arp == '.')) {
      arp++;
      alen--;
      if (alen > IWNUMBUF_SIZE) {
        alen = IWNUMBUF_SIZE;
      }
      long double base = 10;
      while (alen > 0) {
        if ((*arp < '0') || (*arp > '9')) {
          break;
        }
        aflt += (*arp - '0') / base;
        arp++;
        alen--;
        base *= 10;
      }
      aflt *= asign;
    }
    if ((blen > 1) && (*brp == '.')) {
      brp++;
      blen--;
      if (blen > IWNUMBUF_SIZE) {
        blen = IWNUMBUF_SIZE;
      }
      long double base = 10;
      while (blen > 0) {
        if ((*brp < '0') || (*brp > '9')) {
          break;
        }
        bflt += (*brp - '0') / base;
        brp++;
        blen--;
        base *= 10;
      }
      bflt *= bsign;
    }
    if (aflt < bflt) {
      return -1;
    }
    if (aflt > bflt) {
      return 1;
    }
  }
  int rv = strncmp(aptr, bptr, MIN(asiz, bsiz));
  if (!rv) {
    return (asiz - bsiz);
  } else {
    return rv;
  }
}

/// MIT Licensed
/// Taken https://github.com/mattn/strtod/blob/master/strtod.c

static const char* skipwhite(const char *q) {
  const char *p = q;
  while (iwchars_is_space(*p)) {
    ++p;
  }
  return p;
}

//--- Locale independent numeric conversions

#ifdef _WIN32
typedef _locale_t iw_c_locale_t;
#else
typedef locale_t iw_c_locale_t;
#endif

#define _IWC_LOCALE_UNINIT 0
#define _IWC_LOCALE_BUSY   1
#define _IWC_LOCALE_READY  2

static iw_c_locale_t _iwc_locale_handle;
static int _iwc_locale_status = _IWC_LOCALE_UNINIT;

static iw_c_locale_t _iwc_locale_create(void) {
#ifdef _WIN32
  return _create_locale(LC_NUMERIC, "C");
#else
  return newlocale(LC_NUMERIC_MASK, "C", (locale_t) 0);
#endif
}

/**
 * Returns the cached C numeric locale, or zero if it cannot be created.
 * In the latter case the current (process) locale is used as a fallback.
 */
static iw_c_locale_t _iwc_locale(void) {
  if (!__sync_bool_compare_and_swap(&_iwc_locale_status, _IWC_LOCALE_READY, _IWC_LOCALE_READY)) {
    if (__sync_bool_compare_and_swap(&_iwc_locale_status, _IWC_LOCALE_UNINIT, _IWC_LOCALE_BUSY)) {
      _iwc_locale_handle = _iwc_locale_create();
      __sync_bool_compare_and_swap(&_iwc_locale_status, _IWC_LOCALE_BUSY, _IWC_LOCALE_READY);
    } else {
      // Another thread is creating the locale, the initialization is instantaneous
      while (!__sync_bool_compare_and_swap(&_iwc_locale_status, _IWC_LOCALE_READY, _IWC_LOCALE_READY)) { }
    }
  }
  return _iwc_locale_handle;
}

// Powers of ten which are exactly representable as double
static const double _iwc_pow10[] = {
  1e0,  1e1,  1e2,  1e3,  1e4,  1e5,  1e6,  1e7,
  1e8,  1e9,  1e10, 1e11, 1e12, 1e13, 1e14, 1e15,
  1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22
};

#define _IWC_POW10_MAX  ((int) (sizeof(_iwc_pow10) / sizeof(_iwc_pow10[0])) - 1)
#define _IWC_MANT_MAX   ((uint64_t) 1 << 53) // Largest integer exactly representable as double
#define _IWC_EXP_LIMIT  1000                 // Exponent overflow guard

/**
 * Fast path for the decimal numbers: `[-]digits[.digits][(e|E)[+|-]digits]`.
 *
 * The value is computed by a single IEEE multiplication or division, which is correctly rounded
 * (Clinger's fast path), therefore the fast path is used only when the integer mantissa fits into
 * 53 bits and the decimal exponent is within `[-22, 22]`. Anything else is left to `strtod()`.
 *
 * The structure of the number is scanned first, so the numbers which cannot be handled by the fast
 * path (for example, with more than 16 significant digits) are rejected without the mantissa
 * accumulation.
 *
 * @return `true` if the number is parsed, `*end` is set only on success.
 */
static bool _iwc_strtod_fast(const char *str, double *out, char **end) {
  const char *p = str;
  int sign = 1;
  int exp10;

  if (*p == '-') {
    sign = -1;
    ++p;
  }
  if ((*p < '0') || (*p > '9')) {
    return false; // ' ', '+', '.', 'i'/'n' (inf/nan) and so on are left to strtod()
  }
  if ((p[0] == '0') && ((p[1] == 'x') || (p[1] == 'X'))) {
    return false; // Hexadecimal float, strtod() is the only one who knows how to parse it
  }

  // Scan the structure of the number
  const char *int_start = p;
  while ((*p >= '0') && (*p <= '9')) {
    ++p;
  }
  const char *int_end = p;
  const char *frac_start = p, *frac_end = p;
  if (*p == '.') {
    ++p;
    frac_start = p;
    while ((*p >= '0') && (*p <= '9')) {
      ++p;
    }
    frac_end = p;
    // Trailing zeroes of the fractional part do not change the value
    while ((frac_end > frac_start) && (frac_end[-1] == '0')) {
      --frac_end;
    }
    if ((frac_end - frac_start) > _IWC_EXP_LIMIT) {
      return false;
    }
  }

  // Find the first significant digit. 17 significant digits are always greater than 2^53,
  // such numbers are left to strtod().
  const char *sig_start = int_start;
  while ((sig_start < int_end) && (*sig_start == '0')) {
    ++sig_start;
  }
  int sig;
  if (sig_start < int_end) {
    sig = (int) ((int_end - sig_start) + (frac_end - frac_start));
  } else {
    sig_start = frac_start;
    while ((sig_start < frac_end) && (*sig_start == '0')) {
      ++sig_start;
    }
    sig = (int) (frac_end - sig_start);
  }
  if (sig > 16) {
    return false;
  }
  exp10 = -(int) (frac_end - frac_start);
  if ((*p == 'e') || (*p == 'E')) {
    int esign = 1, e = 0;
    ++p;
    if (*p == '-') {
      esign = -1;
      ++p;
    } else if (*p == '+') {
      ++p;
    }
    if ((*p < '0') || (*p > '9')) {
      return false; // Incomplete exponent, strtod() will stop before `e`
    }
    for (; (*p >= '0') && (*p <= '9'); ++p) {
      if (e > _IWC_EXP_LIMIT) {
        return false;
      }
      e = e * 10 + (*p - '0');
    }
    exp10 += esign * e;
  }
  if ((exp10 < -_IWC_POW10_MAX) || (exp10 > _IWC_POW10_MAX)) {
    return false;
  }

  // Accumulate the significant digits
  uint64_t mant = 0;
  if (sig_start < int_end) {
    for (const char *c = sig_start; c < int_end; ++c) {
      mant = mant * 10 + (uint64_t) (*c - '0');
    }
    for (const char *c = frac_start; c < frac_end; ++c) {
      mant = mant * 10 + (uint64_t) (*c - '0');
    }
  } else {
    for (const char *c = sig_start; c < frac_end; ++c) {
      mant = mant * 10 + (uint64_t) (*c - '0');
    }
  }
  if (mant > _IWC_MANT_MAX) {
    return false;
  }
  double d = (double) mant;
  if (exp10 < 0) {
    d /= _iwc_pow10[-exp10];
  } else if (exp10 > 0) {
    d *= _iwc_pow10[exp10];
  }
  *out = (sign < 0) ? -d : d;
  if (end) {
    *end = (char*) p;
  }
  return true;
}

double iw_strtod_c(const char *str, char **end) {
  double d;
  if (_iwc_strtod_fast(str, &d, end)) {
    return d;
  }
#ifdef _WIN32
  iw_c_locale_t cl = _iwc_locale();
  return cl ? _strtod_l(str, end, cl) : strtod(str, end);
#else
  iw_c_locale_t cl = _iwc_locale(), prev = (locale_t) 0;
  if (cl) {
    prev = uselocale(cl);
  }
  double ret = strtod(str, end);
  if (prev) {
    uselocale(prev);
  }
  return ret;
#endif
}

long double iw_strtold_c(const char *str, char **end) {
#ifdef _WIN32
  iw_c_locale_t cl = _iwc_locale();
  return cl ? (long double) _strtod_l(str, end, cl) : (long double) strtod(str, end);
#else
  iw_c_locale_t cl = _iwc_locale(), prev = (locale_t) 0;
  if (cl) {
    prev = uselocale(cl);
  }
  long double ret = strtold(str, end);
  if (prev) {
    uselocale(prev);
  }
  return ret;
#endif
}

int iw_snprintf_c(char *buf, size_t size, const char *format, ...) {
  va_list ap;
  int ret;
  va_start(ap, format);
#ifdef _WIN32
  iw_c_locale_t cl = _iwc_locale();
  if (cl) {
    ret = _vsnprintf_l(buf, size, format, cl, ap);
  } else {
    ret = vsnprintf(buf, size, format, ap);
  }
#else
  iw_c_locale_t cl = _iwc_locale(), prev = (locale_t) 0;
  if (cl) {
    prev = uselocale(cl);
  }
  ret = vsnprintf(buf, size, format, ap);
  if (prev) {
    uselocale(prev);
  }
#endif
  va_end(ap);
  return ret;
}

long double iw_strtold(const char *v, iwrc *rcp) {
  char *ep = 0;
  errno = 0;
  long double ret = iw_strtold_c(v, &ep);
  if (*ep != '\0' || errno == ERANGE) {
    *rcp = IW_ERROR_INVALID_ARGS;
    return 0;
  }
  return ret;
}

double iw_strtod(const char *v, iwrc *rcp) {
  char *ep = 0;
  errno = 0;
  double ret = iw_strtod_c(v, &ep);
  if (*ep != '\0' || errno == ERANGE) {
    *rcp = IW_ERROR_INVALID_ARGS;
    return 0;
  }
  return ret;
}

long int iw_strtol(const char *v, int base, iwrc *rcp) {
  errno = 0;
  char *ep = 0;
  long int ret = strtol(v, &ep, base);
  if (*ep != '\0' || errno == ERANGE) {
    *rcp = IW_ERROR_INVALID_ARGS;
    return 0;
  }
  return ret;
}

long long iw_strtoll(const char *v, int base, iwrc *rcp) {
  errno = 0;
  char *ep = 0;
  long long ret = strtoll(v, &ep, base);
  if (*ep != '\0' || errno == ERANGE) {
    *rcp = IW_ERROR_INVALID_ARGS;
    return 0;
  }
  return ret;
}

unsigned long int iw_strtoul(const char *v, int base, iwrc *rcp) {
  errno = 0;
  char *ep = 0;
  unsigned long int ret = strtoul(v, &ep, base);
  if (*ep != '\0' || errno == ERANGE) {
    *rcp = IW_ERROR_INVALID_ARGS;
    return 0;
  }
  return ret;
}

unsigned long long iw_strtoull(const char *v, int base, iwrc *rcp) {
  errno = 0;
  char *ep = 0;
  unsigned long long ret = strtoull(v, &ep, base);
  if (*ep != '\0' || errno == ERANGE) {
    *rcp = IW_ERROR_INVALID_ARGS;
    return 0;
  }
  return ret;
}

static inline int _hexval(unsigned char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

iwrc iw_decode_percent_inplace(char *buf, size_t len, size_t *out_len) {
  if (!buf || !out_len) {
    return IW_ERROR_INVALID_ARGS;
  }
  size_t si = 0;
  size_t di = 0;

  while (si < len) {
    unsigned char c = (unsigned char) buf[si];
    if (c == '%') {
      if (si + 2 >= len) {
        return IW_ERROR_INVALID_VALUE;
      }
      int hi = ascii2hex[(uint8_t) buf[si + 1]];
      int lo = ascii2hex[(uint8_t) buf[si + 2]];
      if (hi < 0 || lo < 0) {
        return IW_ERROR_INVALID_VALUE;
      }
      buf[di++] = (char) ((hi << 4) | lo);
      si += 3;
    } else {
      buf[di++] = buf[si++];
    }
  }
  buf[di] = '\0';
  *out_len = di;
  return 0;
}
