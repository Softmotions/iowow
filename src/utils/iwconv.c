#include "iwconv.h"
#include <math.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>

// mapping of ASCII characters to hex values
const uint8_t ascii2hex[] = {
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
  ;
  return vpos;
}

char* iwbin2hex(
  char* const                hex,
  const size_t               hex_maxlen,
  const unsigned char* const bin,
  const size_t               bin_len
  ) {
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
    *ptr = 0; \
    return ret; \
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
    v = -v;
    ITOA_SZSTEP(1)
    * ptr++ = '-';
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

char* iwftoa(long double n, char s[static IWFTOA_BUFSIZE]) {
  static double PRECISION = 0.00000000000001;
  // handle special cases
  if (isnan(n)) {
    strcpy(s, "nan");
  } else if (isinf(n)) {
    strcpy(s, "inf");
  } else if (n == 0.0) { // -V550
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
      if (alen > IWFTOA_BUFSIZE) {
        alen = IWFTOA_BUFSIZE;
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
      if (blen > IWFTOA_BUFSIZE) {
        blen = IWFTOA_BUFSIZE;
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
  while (isspace(*p)) {
    ++p;
  }
  return p;
}

double iwstrtod(const char *str, char **end) {
  double d = 0.0;
  int sign;
  int n = 0;
  const char *p, *a;

  a = p = str;
  p = skipwhite(p);

  /* decimal part */
  sign = 1;
  if (*p == '-') {
    sign = -1;
    ++p;
  } else if (*p == '+') {
    ++p;
  }
  if (isdigit(*p)) {
    d = (double) (*p++ - '0');
    while (*p && isdigit(*p)) {
      d = d * 10.0 + (double) (*p - '0');
      ++p;
      ++n;
    }
    a = p;
  } else if (*p != '.') {
    goto done;
  }
  d *= sign;

  /* fraction part */
  if (*p == '.') {
    double f = 0.0;
    double base = 0.1;
    ++p;

    if (isdigit(*p)) {
      while (*p && isdigit(*p)) {
        f += base * (*p - '0');
        base /= 10.0;
        ++p;
        ++n;
      }
    }
    d += f * sign;
    a = p;
  }

  /* exponential part */
  if ((*p == 'E') || (*p == 'e')) {
    int e = 0;
    ++p;

    sign = 1;
    if (*p == '-') {
      sign = -1;
      ++p;
    } else if (*p == '+') {
      ++p;
    }

    if (isdigit(*p)) {
      while (*p == '0') {
        ++p;
      }
      if (*p == '\0') {
        --p;
      }
      e = (*p++ - '0');
      while (*p && isdigit(*p)) {
        e = e * 10 + (*p - '0');
        ++p;
      }
      e *= sign;
    } else if (!isdigit(*(a - 1))) {
      a = str;
      goto done;
    } else if (*p == 0) {
      goto done;
    }

    if (d == 2.2250738585072011 && e == -308) {
      d = 0.0;
      a = p;
      errno = ERANGE;
      goto done;
    }
    if (d == 2.2250738585072012 && e <= -308) {
      d *= 1.0e-308;
      a = p;
      goto done;
    }
    d *= pow(10.0, (double) e);
    a = p;
  } else if (p > str && !isdigit(*(p - 1))) {
    a = str;
    goto done;
  }

done:
  if (end) {
    *end = (char*) a;
  }
  return d;
}
