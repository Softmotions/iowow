#include "iwconv.h"
#include <math.h>
#include <string.h>
#include <assert.h>

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
  int  pos = 0, vpos = 0;
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
    out[vpos++] = (uint8_t)(ascii2hex[idx0] << 4) | ascii2hex[idx1];
    if (vpos >= max) {
      return vpos;
    }
  };
  return vpos;
}

int iwitoa(int64_t v, char *buf, int max) {
#define ITOA_SZSTEP(_step) if ((ret += (_step)) >= max) { \
    *ptr = 0; \
    return ret; \
  }
  int ret = 0;
  char *ptr = buf, *p = ptr, *p1;
  char c;

  if (!v) {
    ITOA_SZSTEP(1);
    *ptr++ = '0';
    return ret;
  }
  // sign stuff
  if (v < 0) {
    v = -v;
    ITOA_SZSTEP(1)
    *ptr++ = '-';
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

// Basic code of `ftoa()' from scmRTOS https://sourceforge.net/projects/scmrtos
// Copyright (c) 2009-2012by Anton Gusev aka AHTOXA
#define FTOA_MAX_PRECISION  (10)
static const double rounders[FTOA_MAX_PRECISION + 1] = {
  0.5, // 0
  0.05, // 1
  0.005, // 2
  0.0005, // 3
  0.00005, // 4
  0.000005, // 5
  0.0000005, // 6
  0.00000005, // 7
  0.000000005, // 8
  0.0000000005, // 9
  0.00000000005 // 10
};

int iwftoa(long double f, char *buf, int max, int precision) {

#define FTOA_SZSTEP(_step) if ((ret += (_step)) >= max) { \
    *ptr = 0; \
    return ret; \
  }
  if (max <= 0) {
    return 0;
  }

  char *ptr = buf, *p = ptr, *p1;
  char c;
  long int intPart;
  int ret = 0;

  // check precision bounds
  if (precision > FTOA_MAX_PRECISION) {
    precision = FTOA_MAX_PRECISION;
  }

  // sign stuff
  if (f < 0) {
    f = -f;
    FTOA_SZSTEP(1)
    *ptr++ = '-';
  }
  if (precision == -1) {
    if (f < 1.0) precision = 6;
    else if (f < 10.0) precision = 5;
    else if (f < 100.0) precision = 4;
    else if (f < 1000.0) precision = 3;
    else if (f < 10000.0) precision = 2;
    else if (f < 100000.0) precision = 1;
    else precision = 0;
  }
  if (precision) {
    // round value according the precision
    f += rounders[precision];
  }
  // integer part...
  intPart = f;
  f -= intPart;

  if (!intPart) {
    FTOA_SZSTEP(1)
    *ptr++ = '0';
  } else {
    // save start pointer
    p = ptr;
    while (intPart) {
      if (++ret >= max) { //overflow condition
        memmove(ptr, ptr + 1, p - ptr);
        p--;
      }
      *p++ = '0' + intPart % 10;
      intPart /= 10;
    }
    // save end pos
    p1 = p;
    // reverse result
    while (p > ptr) {
      c = *--p;
      *p = *ptr;
      *ptr++ = c;
    }
    if (ret >= max) {
      ptr = p1;
      *ptr = 0;
      return ret;
    }
    // restore end pos
    ptr = p1;
  }

  // decimal part
  if (precision) {
    // place decimal point
    if ((ret += 1) + 1 >= max) { //reserve one more after dot
      *ptr = 0;
      return ret;
    }
    *ptr++ = '.';
    // convert
    while (precision--) {
      f *= 10.0;
      c = f;
      FTOA_SZSTEP(1)
      *ptr++ = '0' + c;
      f -= c;
    }
  }
  // terminating zero
  *ptr = 0;
  return ret;

#undef FTOA_SZSTEP
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
  if (!strcmp(str, "inf")) return (INT64_MAX * sign);
  while (*str != '\0') {
    if (*str < '0' || *str > '9') break;
    num = num * 10 + *str - '0';
    str++;
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
    if (*str < '0' || *str > '9') {
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
      if (*str < '0' || *str > '9') {
        break;
      }
      fract += (*str - '0') / base;
      str++;
      base *= 10;
    }
    num += fract;
  }
  if (*str == 'e' || *str == 'E') {
    str++;
    num *= pow(10, iwatoi(str));
  }
  return num * sign;
}

