#include "iwarrays.h"

#include <string.h>

off_t arrays_sorted_insert(void *els,
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
    memcpy(els, eptr, elsize);
    return idx;
  }
  while (1) {
    int cr;
    idx = (ub + lb) / 2;
    cr = cmp(EL(idx), eptr);
    if (!cr) {
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
  memmove(EL(idx + 1), EL(idx), nels - idx);
  memcpy(EL(idx), eptr, elsize);

#undef EL
  return idx;
}
