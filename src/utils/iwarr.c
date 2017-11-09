#include "iwarr.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "iwlog.h"
#include "iwlog.h"


// Default IWALIST initial size
#ifndef IWALIST_AUNIT
#define IWALIST_AUNIT 64
#endif

off_t iwarr_sorted_insert(void *els,
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

struct IWALIST {
  IWALIST_REC *array; /**< Data array */
  int anum;           /**< Number of allocated elements */
  int start;          /**< First index of used element */
  int size;           /**< Number of live elements  */
};

IWALIST *iwalist_new2(int siz) {
  IWALIST *list = malloc(sizeof(*list));
  if (!list) return 0;
  if (siz < 1) siz = 1;
  list->anum = siz;
  list->array = malloc(sizeof(list->array[0]) * list->anum);
  if (!list->array) {
    free(list);
    return 0;
  }
  list->start = 0;
  list->size = 0;
  return list;
}

IWALIST *iwalist_new(void) {
  return iwalist_new2(IWALIST_AUNIT);
}

void iwalist_destroy(IWALIST *list) {
  if (!list) return;
  IWALIST_REC *array = list->array;
  for (int i = list->start, e = list->start + list->size; i < e; ++i) {
    free(array[i].ptr);
  }
  free(list->array);
  free(list);
}

void iwalist_clear(IWALIST *list) {
  assert(list);
  IWALIST_REC *array = list->array;
  for (int i = list->start, e = list->start + list->size; i < e; ++i) {
    free(array[i].ptr);
  }
  list->start = 0;
  list->size = 0;
}

int iwalist_size(IWALIST *list) {
  assert(list);
  return list->size;
}

const void *iwalist_get(IWALIST *list, int idx, int *sp) {
  assert(list && sp);
  if (idx < 0 || idx >= list->size) {
    *sp = 0;
    return 0;
  }
  *sp = list->array[idx + list->start].size;
  return list->array[idx + list->start].ptr;
}

const char *iwalist_get2(IWALIST *list, int idx) {
  assert(list);
  if (idx < 0 || idx >= list->size) {
    return 0;
  }
  return list->array[idx + list->start].ptr;
}

iwrc iwalist_insert(IWALIST *list, int idx, const void *ptr, int size) {
  assert(list && ptr);
  if (idx < 0 || idx > list->size || size < 0) {
    return IW_ERROR_OUT_OF_BOUNDS;
  }
  idx += list->start;
  if (list->start + list->size >= list->anum) {
    list->anum += list->size + 1;
    void *nptr = realloc(list->array, sizeof(list->array[0]) * list->anum);
    if (!nptr) {
      return IW_ERROR_ERRNO;
    }
    list->array = nptr;
  }
  memmove(list->array + idx + 1,
          list->array + idx,
          sizeof(list->array[0]) * (list->start + list->size - idx));
  list->array[idx].ptr =  malloc(size + 1);
  if (!list->array[idx].ptr) {
    return IW_ERROR_ERRNO;
  }
  memcpy(list->array[idx].ptr, ptr, size);
  list->array[idx].ptr[size] = '\0';
  list->array[idx].size = size;
  list->size++;
  return IW_OK;
}

iwrc iwalist_insert2(IWALIST *list, int idx, const char *str) {
  return iwalist_insert(list, idx, str, strlen(str));
}

iwrc iwalist_set(IWALIST *list, int idx, const void *ptr, int size) {
  assert(list && ptr);
  if (idx < 0 || idx > list->size) {
    return IW_ERROR_OUT_OF_BOUNDS;
  }
  idx += list->start;
  if (size > list->array[idx].size) {
    void *nptr = realloc(list->array[idx].ptr, size + 1);
    if (!nptr) {
      return IW_ERROR_ERRNO;
    }
    list->array[idx].ptr = nptr;
  }
  memcpy(list->array[idx].ptr, ptr, size);
  list->array[idx].size = size;
  list->array[idx].ptr[size] = '\0';
  return IW_OK;
}

iwrc iwalist_set2(IWALIST *list, int idx, const char *str) {
  return iwalist_set(list, idx, str, strlen(str));
}

iwrc iwalist_push(IWALIST *list, const void *ptr, int size) {
  assert(list && ptr);
  if (size < 0) {
    return IW_ERROR_OUT_OF_BOUNDS;
  }
  void *nptr;
  int idx = list->start + list->size;
  if (idx >= list->anum) {
    list->anum += list->size + 1;
    nptr = realloc(list->array, sizeof(list->array[0]) * list->anum);
    if (!nptr) {
      return IW_ERROR_ERRNO;
    }
    list->array = nptr;
  }
  IWALIST_REC *array = list->array;
  nptr = malloc(size + 1);
  if (!nptr) {
    return IW_ERROR_ERRNO;
  }
  array[idx].ptr = nptr;
  mempcpy(array[idx].ptr, ptr, size);
  array[idx].ptr[size] = '\0';
  array[idx].size = size;
  list->size++;
  return IW_OK;
}

iwrc iwalist_push2(IWALIST *list, const char *str) {
  return iwalist_push(list, str, strlen(str));
}

iwrc iwalist_push_allocated(IWALIST *list, void *ptr, int size) {
  assert(list && ptr);
  if (size < 0) {
    return IW_ERROR_OUT_OF_BOUNDS;
  }
  void *nptr;
  int idx = list->start + list->size;
  if (idx >= list->anum) {
    list->anum += list->size + 1;
    nptr = realloc(list->array, sizeof(list->array[0]) * list->anum);
    if (!nptr) {
      return IW_ERROR_ERRNO;
    }
    list->array = nptr;
  }
  IWALIST_REC *array = list->array;
  nptr = realloc(ptr, size + 1);
  if (!nptr) {
    return IW_ERROR_ERRNO;
  }
  array[idx].ptr = nptr;
  array[idx].ptr[size] = '\0';
  array[idx].size = size;
  list->size++;
  return IW_OK;
}

iwrc iwalist_unshift(IWALIST *list, const void *ptr, int size) {
  assert(list && ptr);
  if (size < 0) {
    return IW_ERROR_OUT_OF_BOUNDS;
  }
  void *nptr;
  if (list->start < 1) {
    if (list->start + list->size >= list->anum) {
      list->anum += list->size + 1;
      nptr = realloc(list->array, sizeof(list->array[0]) * list->anum);
      if (!nptr) {
        return IW_ERROR_ERRNO;
      }
      list->array = nptr;
    }
    list->start = list->anum - list->size;
    memmove(list->array + list->start, list->array, list->size * sizeof(list->array[0]));
  }
  int idx = list->start - 1;
  nptr = malloc(size + 1);
  if (!nptr) {
    return IW_ERROR_ERRNO;
  }
  list->array[idx].ptr = nptr;
  list->array[idx].ptr[size] = '\0';
  list->array[idx].size = size;
  list->start--;
  list->size++;
  return IW_OK;
}

iwrc iwalist_unshift2(IWALIST *list, const char *str) {
  return iwalist_unshift(list, str, strlen(str));
}

void *iwalist_pop(IWALIST *list, int *sp) {
  assert(list && sp);
  if (list->anum < 1) return 0;
  int idx = list->start + list->size - 1;
  list->size--;
  *sp = list->array[idx].size;
  return list->array[idx].ptr;
}

char *iwalist_pop2(IWALIST *list) {
  int sz;
  return iwalist_pop(list, &sz);
}

void *iwalist_shift(IWALIST *list, int *sp) {
  assert(list && sp);
  if (list->size < 1) return 0;
  int idx = list->start;
  list->start++;
  list->size--;
  *sp = list->array[idx].size;
  void *rv = list->array[idx].ptr;
  if ((list->start & 0xff) == 0 && list->start > (list->size >> 1)) { // trim list from bottom
    memmove(list->array, list->array + list->start, list->size * sizeof(list->array[0]));
    list->start = 0;
  }
  return rv;
}

char *iwalist_shift2(IWALIST *list) {
  int sz;
  return iwalist_shift(list, &sz);
}

void *iwalist_remove(IWALIST *list, int idx, int *sp) {
  assert(list && sp);
  if (idx >= list->size || idx < 0) {
    return 0;
  }
  idx += list->start;
  void *rv = list->array[idx].ptr;
  *sp = list->array[idx].size;
  list->size--;
  memmove(list->array + idx, list->array + idx + 1,
          sizeof(list->array[0]) * (list->start + list->size - idx));
  return rv;
}

char *iwalist_remove2(IWALIST *list, int idx) {
  int sp;
  return iwalist_remove(list, idx, &sp);
}

static int _iwalist_cmp(const void *a, const void *b, void *opaque) {
  assert(a && b);
  unsigned char *ao = (unsigned char *)((IWALIST_REC *) a)->ptr;
  unsigned char *bo = (unsigned char *)((IWALIST_REC *) b)->ptr;
  int size = (((IWALIST_REC *) a)->size < ((IWALIST_REC *) b)->size) ?
             ((IWALIST_REC *) a)->size : ((IWALIST_REC *) b)->size;
  for (int i = 0; i < size; i++) {
    if (ao[i] > bo[i]) return 1;
    if (ao[i] < bo[i]) return -1;
  }
  return ((IWALIST_REC *) a)->size - ((IWALIST_REC *) b)->size;
}

static int _iwalist_cmp2(const void *a, const void *b) {
  return _iwalist_cmp(a, b, 0);
}

void iwalist_sort(IWALIST *list) {
  qsort_r(list->array + list->start, list->size, sizeof(list->array[0]), _iwalist_cmp, 0);
}

void iwalist_sort2(IWALIST *list,
                   int (*cmp)(const IWALIST_REC *, const IWALIST_REC *, void *opaque),
                   void *opaque) {
  qsort_r(list->array + list->start, list->size, sizeof(list->array[0]),
          (int (*)(const void *, const void *, void *))cmp, 0);
}

int iwalist_search(const IWALIST *list, const void *ptr, int size) {
  for (int i = list->start,
       end = list->start + list->size; i < end; i++) {
    if (list->array[i].size == size && !memcmp(list->array[i].ptr, ptr, size))
      return i - list->start;
  }
  return -1;
}

int iwalist_binary_search(const IWALIST *list, const void *ptr, int size) {
  assert(list);
  if (!ptr || size < 0)  {
    return -1;
  }
  IWALIST_REC key;
  key.ptr = (char *) ptr;
  key.size = size;
  IWALIST_REC *res = bsearch(&key, list->array + list->start,
                             list->size, sizeof(list->array[0]), _iwalist_cmp2);
  return res ? (res - list->array - list->start) : -1;
}

///////////////////////////////////////////////////////////////////////////
//                      Array list to store pointers                     //
///////////////////////////////////////////////////////////////////////////

struct IWPTRLIST {
  void **array; /**< Data array */
  int anum;     /**< Number of allocated elements */
  int start;    /**< First index of used element */
  int size;     /**< Number of live elements  */
};

IWPTRLIST *iwptrlist_new2(int siz) {
  IWPTRLIST *list = malloc(sizeof(*list));
  if (!list) return 0;
  if (siz < 1) siz = 1;
  list->anum = siz;
  list->array = malloc(sizeof(list->array[0]) * list->anum);
  if (!list->array) {
    free(list);
    return 0;
  }
  list->start = 0;
  list->size = 0;
  return list;
}

IWPTRLIST *iwptrlist_new(void) {
  return iwptrlist_new2(IWALIST_AUNIT);
}

void iwptrlist_destroy(IWPTRLIST *list) {
  if (!list) return;
  free(list->array);
  free(list);
}

void iwptrlist_clear(IWPTRLIST *list) {
  assert(list);
  list->size = 0;
  list->start = 0;
}

int iwptrlist_size(IWPTRLIST *list) {
  assert(list);
  return list->size;
}

void *iwptrlist_get(IWPTRLIST *list, int idx) {
  assert(list);
  if (idx < 0 || idx >= list->size) return 0;
  return list->array[list->start + idx];
}

iwrc iwptrlist_insert(IWPTRLIST *list, int idx, void *ptr) {
  assert(list && ptr);
  if (idx < 0 || idx > list->size) {
    return IW_ERROR_OUT_OF_BOUNDS;
  }
  idx += list->start;
  if (list->start + list->size >= list->anum) {
    list->anum += list->size + 1;
    void *nptr = realloc(list->array, sizeof(list->array[0]) * list->anum);
    if (!nptr) {
      return IW_ERROR_ERRNO;
    }
    list->array = nptr;
  }
  memmove(list->array + idx + 1,
          list->array + idx,
          sizeof(list->array[0]) * (list->start + list->size - idx));
  list->array[idx] = ptr;
  list->size++;
  return IW_OK;
}

iwrc iwptrlist_set(IWPTRLIST *list, int idx, void *ptr) {
  assert(list);
  if (idx < 0 || idx > list->size) {
    return IW_ERROR_OUT_OF_BOUNDS;
  }
  idx += list->start;
  list->array[idx] = ptr;
  return IW_OK;
}

iwrc iwptrlist_push(IWPTRLIST *list, void *ptr) {
  assert(list);
  void *nptr;
  int idx = list->start + list->size;
  if (idx >= list->anum) {
    list->anum += list->size + 1;
    nptr = realloc(list->array, sizeof(list->array[0]) * list->anum);
    if (!nptr) {
      return IW_ERROR_ERRNO;
    }
    list->array = nptr;
  }
  list->array[idx] = ptr;
  list->size++;
  return IW_OK;
}

iwrc iwptrlist_unshift(IWPTRLIST *list, void *ptr) {
  assert(list);
  void *nptr;
  if (list->start < 1) {
    if (list->start + list->size >= list->anum) {
      list->anum += list->size + 1;
      nptr = realloc(list->array, sizeof(list->array[0]) * list->anum);
      if (!nptr) {
        return IW_ERROR_ERRNO;
      }
      list->array = nptr;
    }
    list->start = list->anum - list->size;
    memmove(list->array + list->start, list->array, list->size * sizeof(list->array[0]));
  }
  list->start--;
  list->array[list->start] = ptr;
  list->size++;
  return IW_OK;
}

void *iwptrlist_pop(IWPTRLIST *list) {
  assert(list);
  if (list->anum < 1) return 0;
  int idx = list->start + list->size - 1;
  list->size--;
  return list->array[idx];
}

void *iwptrlist_shift(IWPTRLIST *list) {
  assert(list);
  if (list->size < 1) return 0;
  int idx = list->start;
  list->start++;
  list->size--;
  void *rv = list->array[idx];
  if ((list->start & 0xff) == 0 && list->start > (list->size >> 1)) { // trim list from bottom
    memmove(list->array, list->array + list->start, list->size * sizeof(list->array[0]));
    list->start = 0;
  }
  return rv;
}

void *iwptrlist_remove(IWPTRLIST *list, int idx) {
  assert(list);
  if (idx >= list->size || idx < 0) {
    return 0;
  }
  idx += list->start;
  void *rv = list->array[idx];
  list->size--;
  memmove(list->array + idx, list->array + idx + 1,
          sizeof(list->array[0]) * (list->start + list->size - idx));
  return rv;
}
