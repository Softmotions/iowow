#include "iwarr.h"

#include <string.h>
#include <assert.h>
#include "iwlog.h"

// Default IWALIST initial size
#ifndef IWALIST_AUNIT
#define IWALIST_AUNIT 64
#endif

off_t iwarr_sorted_insert(void *els,
                          size_t nels,
                          size_t elsize,
                          void *eptr,
                          int (*cmp)(const void *, const void *),
                          bool skipeq) {

#define EL(idx_) (elsptr + (idx_) * elsize)

  off_t idx = 0,
        lb = 0,
        ub = nels - 1;
  char *elsptr = els;
  if (nels == 0) {
    memcpy(els, eptr, elsize);
    return idx;
  }
  while (1) {
    int cr;
    idx = (ub + lb) / 2;
    cr = cmp(EL(idx), eptr);
    if (!cr) {
      if (skipeq) {
        return -1;
      }
      break;
    } else if (cr < 0) {
      lb = idx + 1;
      if (lb > ub) {
        idx = lb;
        break;
      }
    } else {
      ub = idx - 1;
      if (lb > ub) {
        break;
      }
    }
  }
  memmove(EL(idx + 1), EL(idx), (nels - idx) * elsize);
  memcpy(EL(idx), eptr, elsize);
#undef EL
  return idx;
}

bool iwarr_sorted_remove(void *els,
                         size_t nels,
                         size_t elsize,
                         void *eptr,
                         int (*cmp)(const void *, const void *)) {

#define EL(idx_) (elsptr + (idx_) * elsize)

  off_t idx = 0,
        lb = 0,
        ub = nels - 1;
  char *elsptr = els;
  if (nels == 0) {
    return false;
  }
  while (1) {
    int cr;
    idx = (ub + lb) / 2;
    cr = cmp(EL(idx), eptr);
    if (!cr) {
      if (idx < nels - 1) {
        memmove(EL(idx), EL(idx + 1), (nels - idx - 1) * elsize);
      }
      return true;
    } else if (cr < 0) {
      lb = idx + 1;
      if (lb > ub) {
        idx = lb;
        break;
      }
    } else {
      ub = idx - 1;
      if (lb > ub) {
        break;
      }
    }
  }
  return false;
}
