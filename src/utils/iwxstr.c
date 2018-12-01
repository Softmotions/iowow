#include "iwxstr.h"
#include "iwlog.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

// Default IWXSTR initial size
#ifndef IWXSTR_AUNIT
#define IWXSTR_AUNIT 16
#endif

struct _IWXSTR {
  char *ptr;      /**< Data buffer */
  int size;       /**< Actual data size */
  int asize;      /**< Allocated buffer size */
};

IWXSTR *iwxstr_new2(int siz) {
  IWXSTR *xstr = malloc(sizeof(*xstr));
  if (!xstr) return 0;
  xstr->ptr = malloc(siz);
  if (!xstr->ptr) {
    free(xstr);
    return 0;
  }
  xstr->size = 0;
  xstr->asize = siz;
  xstr->ptr[0] = '\0';
  return xstr;
}

IWXSTR *iwxstr_new(void) {
  return iwxstr_new2(IWXSTR_AUNIT);
}

void iwxstr_destroy(IWXSTR *xstr) {
  if (!xstr) return;
  free(xstr->ptr);
  free(xstr);
}

void iwxstr_clear(IWXSTR *xstr) {
  assert(xstr);
  xstr->size = 0;
}

iwrc iwxstr_cat(IWXSTR *xstr, const void *buf, int size) {
  int nsize = xstr->size + size + 1;
  if (xstr->asize < nsize) {
    while (xstr->asize < nsize) {
      xstr->asize <<= 1;
      if (xstr->asize < nsize) {
        xstr->asize = nsize;
      }
    }
    xstr->ptr = realloc(xstr->ptr, xstr->asize);
    if (!xstr->ptr) {
      return IW_ERROR_ERRNO;
    }
  }
  memcpy(xstr->ptr + xstr->size, buf, size);
  xstr->size += size;
  xstr->ptr[xstr->size] = '\0';
  return IW_OK;
}

iwrc iwxstr_unshift(IWXSTR *xstr, const void *buf, int size) {
  int nsize = xstr->size + size + 1;
  if (xstr->asize < nsize) {
    while (xstr->asize < nsize) {
      xstr->asize <<= 1;
      if (xstr->asize < nsize) {
        xstr->asize = nsize;
      }
    }
    xstr->ptr = realloc(xstr->ptr, xstr->asize);
    if (!xstr->ptr) {
      return IW_ERROR_ERRNO;
    }
  }
  if (xstr->size) {
    // shift to right
    memmove(xstr->ptr + size, xstr->ptr, xstr->size);
  }
  memcpy(xstr->ptr, buf, size);
  xstr->size += size;
  xstr->ptr[xstr->size] = '\0';
  return IW_OK;
}

static iwrc iwxstr_vaprintf(IWXSTR *xstr, const char *format, va_list ap) {
  iwrc rc = 0;
  while (*format) {
    if (*format == '%') {
      char cbuf[32];
      cbuf[0] = '%';
      int cblen = 1;
      int lnum = 0;
      ++format;
      while (strchr("0123456789 .+-hlLzI", *format) && *format && cblen < sizeof(cbuf) - 1) {
        if (*format == 'l' || *format == 'L') {
          lnum++;
        }
        cbuf[cblen++] = *(format++);
      }
      cbuf[cblen++] = *format;
      cbuf[cblen] = '\0';
      int tlen;
      char *tmp, tbuf[128];
      switch (*format) {
        case 's':
          tmp = va_arg(ap, char *);
          if (!tmp) tmp = "(null)";
          rc = iwxstr_cat(xstr, tmp, strlen(tmp));
          break;
        case 'd':
          if (lnum >= 2) {
            tlen = sprintf(tbuf, cbuf, va_arg(ap, long long));
          } else if (lnum >= 1) {
            tlen = sprintf(tbuf, cbuf, va_arg(ap, long));
          } else {
            tlen = sprintf(tbuf, cbuf, va_arg(ap, int));
          }
          rc = iwxstr_cat(xstr, tbuf, tlen);
          break;
        case 'o':
        case 'u':
        case 'x':
        case 'X':
        case 'c':
          if (lnum >= 2) {
            tlen = sprintf(tbuf, cbuf, va_arg(ap, unsigned long long));
          } else if (lnum >= 1) {
            tlen = sprintf(tbuf, cbuf, va_arg(ap, unsigned long));
          } else {
            tlen = sprintf(tbuf, cbuf, va_arg(ap, unsigned int));
          }
          rc = iwxstr_cat(xstr, tbuf, tlen);
          break;
        case 'e':
        case 'E':
        case 'f':
        case 'g':
        case 'G':
          if (lnum > 1) {
            tlen = snprintf(tbuf, sizeof(tbuf), cbuf, va_arg(ap, long double));
          } else {
            tlen = snprintf(tbuf, sizeof(tbuf), cbuf, va_arg(ap, double));
          }
          if (tlen < 0 || tlen >= sizeof(tbuf)) {
            tbuf[sizeof(tbuf) - 1] = '*';
            tlen = sizeof(tbuf);
          }
          rc = iwxstr_cat(xstr, tbuf, tlen);
          break;
        case '%':
          rc = iwxstr_cat(xstr, "%", 1);
          break;
      }
      RCBREAK(rc);
    } else {
      rc = iwxstr_cat(xstr, format, 1);
      RCRET(rc);
    }
    format++;
  }
  return rc;
}

iwrc iwxstr_printf(IWXSTR *xstr, const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  iwrc rc  = iwxstr_vaprintf(xstr, format, ap);
  va_end(ap);
  return rc;
}

char *iwxstr_ptr(IWXSTR *xstr) {
  return xstr->ptr;
}

int iwxstr_size(IWXSTR *xstr) {
  return xstr->size;
}

