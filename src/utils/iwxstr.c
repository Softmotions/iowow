#include "iwxstr.h"
#include "iwlog.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

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

char *iwxstr_ptr(IWXSTR *xstr) {
  return xstr->ptr;
}

int iwxstr_size(IWXSTR *xstr) {
  return xstr->size;
}

