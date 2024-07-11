#include "iwarr.h"

#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include "iwlog.h"
#include "sort_r.h"

off_t iwarr_sorted_insert(
  void* restrict els,
  size_t nels,
  size_t elsize,
  void* restrict eptr,
  int (*cmp)(const void*, const void*),
  bool skipeq
  ) {
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
  return idx;
#undef EL
}

off_t iwarr_sorted_remove(
  void* restrict els,
  size_t nels,
  size_t elsize,
  void* restrict eptr,
  int (*cmp)(const void*, const void*)
  ) {
#define EL(idx_) (elsptr + (idx_) * elsize)

  off_t idx = 0,
        lb = 0,
        ub = nels - 1;
  char *elsptr = els;
  if (nels == 0) {
    return -1;
  }
  while (1) {
    int cr;
    idx = (ub + lb) / 2;
    cr = cmp(EL(idx), eptr);
    if (!cr) {
      if (idx < nels - 1) {
        memmove(EL(idx), EL(idx + 1), (nels - idx - 1) * elsize);
      }
      return idx;
    } else if (cr < 0) {
      lb = idx + 1;
      if (lb > ub) {
        break;
      }
    } else {
      ub = idx - 1;
      if (lb > ub) {
        break;
      }
    }
  }
  return -1;
#undef EL
}

off_t iwarr_sorted_find(
  void* restrict els,
  size_t nels,
  size_t elsize,
  void* restrict eptr,
  int (*cmp)(const void*, const void*)
  ) {
#define EL(idx_) (elsptr + (idx_) * elsize)

  off_t idx = 0,
        lb = 0,
        ub = nels - 1;
  char *elsptr = els;
  if (nels == 0) {
    return -1;
  }
  while (1) {
    int cr;
    idx = (ub + lb) / 2;
    cr = cmp(EL(idx), eptr);
    if (!cr) {
      return idx;
    } else if (cr < 0) {
      lb = idx + 1;
      if (lb > ub) {
        break;
      }
    } else {
      ub = idx - 1;
      if (lb > ub) {
        break;
      }
    }
  }
  return -1;
#undef EL
}

off_t iwarr_sorted_find2(
  void* restrict els,
  size_t nels,
  size_t elsize,
  void* restrict eptr,
  void *op,
  bool *found,
  int (*cmp)(const void*, const void*, void *cr)
  ) {
#define EL(idx_) (elsptr + (idx_) * elsize)

  off_t idx = 0,
        lb = 0,
        ub = nels - 1;
  char *elsptr = els;
  if (nels == 0) {
    return 0;
  }
  while (1) {
    idx = (ub + lb) / 2;
    int cr = cmp(EL(idx), eptr, op);
    if (!cr) {
      *found = true;
      return idx;
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
  *found = false;
  return idx;
#undef EL
}

///////////////////////////////////////////////////////////////////////////
//                     Fixed sized item list                             //
///////////////////////////////////////////////////////////////////////////

#define IWULIST_ALLOC_UNIT 32

iwrc iwulist_init(IWULIST *list, size_t initial_length, size_t unit_size) {
  list->usize = unit_size;
  list->num = 0;
  list->start = 0;
  if (!initial_length) {
    initial_length = IWULIST_ALLOC_UNIT;
  }
  list->anum = initial_length;
  list->array = malloc(unit_size * initial_length);
  if (!list->array) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  return 0;
}

IWULIST* iwulist_create(size_t initial_length, size_t unit_size) {
  IWULIST *list = malloc(sizeof(*list));
  if (!list) {
    return 0;
  }
  if (iwulist_init(list, initial_length, unit_size)) {
    free(list);
    return 0;
  }
  return list;
}

iwrc iwulist_clear(IWULIST *list) {
  if (list) {
    free(list->array);
    return iwulist_init(list, IWULIST_ALLOC_UNIT, list->usize);
  }
  return 0;
}

void iwulist_reset(IWULIST *list) {
  if (list) {
    list->start = 0;
    list->num = 0;
  }
}

void iwulist_destroy_keep(IWULIST *list) {
  if (list) {
    free(list->array);
    memset(list, 0, sizeof(*list));
  }
}

void iwulist_destroy(IWULIST **listp) {
  if (listp) {
    if (*listp) {
      iwulist_destroy_keep(*listp);
      free(*listp);
    }
    *listp = 0;
  }
}

size_t iwulist_length(const IWULIST *list) {
  return list->num;
}

IWULIST* iwulist_clone(const IWULIST *list) {
  if (!list->num) {
    return iwulist_create(list->anum, list->usize);
  }
  IWULIST *nlist = malloc(sizeof(*nlist));
  if (!nlist) {
    return 0;
  }
  size_t anum = list->num > IWULIST_ALLOC_UNIT ? list->num : IWULIST_ALLOC_UNIT;
  nlist->array = malloc(anum * list->usize);
  if (!nlist->array) {
    free(nlist);
    return 0;
  }
  memcpy(nlist->array, list->array + list->start, list->num * list->usize);
  nlist->usize = list->usize;
  nlist->num = list->num;
  nlist->anum = anum;
  nlist->start = 0;
  return nlist;
}

iwrc iwulist_copy(const struct iwulist *list, struct iwulist *tgt) {
  for (int i = 0, l = iwulist_length(list); i < l; ++i) {
    void *p = iwulist_get(list, i);
    iwrc rc = iwulist_push(tgt, p);
    if (rc) {
      return rc;
    }
  }
  return 0;
}

void* iwulist_at(const IWULIST *list, size_t index, iwrc *orc) {
  *orc = 0;
  if (index >= list->num) {
    *orc = IW_ERROR_OUT_OF_BOUNDS;
    return 0;
  }
  index += list->start;
  return list->array + index * list->usize;
}

void* iwulist_at2(const IWULIST *list, size_t index) {
  if (index >= list->num) {
    return 0;
  }
  index += list->start;
  return list->array + index * list->usize;
}

void* iwulist_get(const IWULIST *list, size_t index) {
  if (index >= list->num) {
    return 0;
  }
  index += list->start;
  return list->array + index * list->usize;
}

iwrc iwulist_push(IWULIST *list, const void *data) {
  size_t index = list->start + list->num;
  if (index >= list->anum) {
    size_t anum = list->anum + list->num + 1;
    void *nptr = realloc(list->array, anum * list->usize);
    if (!nptr) {
      return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
    list->anum = anum;
    list->array = nptr;
  }
  memcpy(list->array + index * list->usize, data, list->usize);
  ++list->num;
  return 0;
}

iwrc iwulist_pop(IWULIST *list) {
  if (!list->num) {
    return IW_ERROR_OUT_OF_BOUNDS;
  }
  size_t num = list->num - 1;
  if ((list->anum > IWULIST_ALLOC_UNIT) && (list->anum >= num * 2)) {
    if (list->start) {
      memmove(list->array, list->array + list->start * list->usize, num * list->usize);
      list->start = 0;
    }
    size_t anum = num > IWULIST_ALLOC_UNIT ? num : IWULIST_ALLOC_UNIT;
    void *nptr = realloc(list->array, anum * list->usize);
    if (!nptr) {
      return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
    list->anum = anum;
    list->array = nptr;
  }
  list->num = num;
  return 0;
}

iwrc iwulist_shift(IWULIST *list) {
  if (!list->num) {
    return IW_ERROR_OUT_OF_BOUNDS;
  }
  size_t num = list->num - 1;
  size_t start = list->start + 1;
  if ((list->anum > IWULIST_ALLOC_UNIT) && (list->anum >= num * 2)) {
    if (start) {
      memmove(list->array, list->array + start * list->usize, num * list->usize);
      start = 0;
    }
    size_t anum = num > IWULIST_ALLOC_UNIT ? num : IWULIST_ALLOC_UNIT;
    void *nptr = realloc(list->array, anum * list->usize);
    if (!nptr) {
      return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
    list->anum = anum;
    list->array = nptr;
  }
  list->start = start;
  list->num = num;
  return 0;
}

iwrc iwulist_insert(IWULIST *list, size_t index, const void *data) {
  if (index > list->num) {
    return IW_ERROR_OUT_OF_BOUNDS;
  }
  index += list->start;
  if (list->start + list->num >= list->anum) {
    size_t anum = list->anum + list->num + 1;
    void *nptr = realloc(list->array, anum * list->usize);
    if (!nptr) {
      return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
    list->anum = anum;
    list->array = nptr;
  }
  memmove(list->array + (index + 1) * list->usize,
          list->array + index * list->usize,
          (list->start + list->num - index) * list->usize);
  memcpy(list->array + index * list->usize, data, list->usize);
  ++list->num;
  return 0;
}

iwrc iwulist_set(IWULIST *list, size_t index, const void *data) {
  if (index >= list->num) {
    return IW_ERROR_OUT_OF_BOUNDS;
  }
  index += list->start;
  memcpy(list->array + index * list->usize, data, list->usize);
  return 0;
}

iwrc iwulist_remove(IWULIST *list, size_t index) {
  if (index >= list->num) {
    return IW_ERROR_OUT_OF_BOUNDS;
  }
  index += list->start;
  --list->num;
  memmove(list->array + index * list->usize, list->array + (index + 1) * list->usize,
          (list->start + list->num - index) * list->usize);
  if ((list->anum > IWULIST_ALLOC_UNIT) && (list->anum >= list->num * 2)) {
    if (list->start) {
      memmove(list->array, list->array + list->start * list->usize, list->num * list->usize);
      list->start = 0;
    }
    size_t anum = list->num > IWULIST_ALLOC_UNIT ? list->num : IWULIST_ALLOC_UNIT;
    void *nptr = realloc(list->array, anum * list->usize);
    if (!nptr) {
      return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
    list->anum = anum;
    list->array = nptr;
  }
  return 0;
}

bool iwulist_remove_first_by(IWULIST *list, void *data_ptr) {
  for (size_t i = list->start; i < list->start + list->num; ++i) {
    void *ptr = list->array + i * list->usize;
    if (memcmp(data_ptr, ptr, list->usize) == 0) {
      return iwulist_remove(list, i - list->start) == 0;
    }
  }
  return false;
}

ssize_t iwulist_find_first(const IWULIST *list, void *data_ptr) {
  for (size_t i = list->start; i < list->start + list->num; ++i) {
    void *ptr = list->array + i * list->usize;
    if (memcmp(data_ptr, ptr, list->usize) == 0) {
      return i - list->start;
    }
  }
  return -1;
}

iwrc iwulist_unshift(IWULIST *list, const void *data) {
  if (!list->start) {
    if (list->num >= list->anum) {
      size_t anum = list->anum + list->num + 1;
      void *nptr = realloc(list->array, anum * list->usize);
      if (!nptr) {
        return iwrc_set_errno(IW_ERROR_ALLOC, errno);
      }
      list->anum = anum;
      list->array = nptr;
    }
    list->start = list->anum - list->num;
    memmove(list->array + list->start * list->usize, list->array, list->num * list->usize);
  }
  memcpy(list->array + (list->start - 1) * list->usize, data, list->usize);
  --list->start;
  ++list->num;
  return 0;
}

void iwulist_sort(IWULIST *list, int (*compar)(const void*, const void*, void*), void *op) {
  sort_r(list->array + list->start * list->usize, list->num, list->usize, compar, op);
}

void* iwulist_array(struct iwulist *list) {
  return list->array + list->start * list->usize;
}

///////////////////////////////////////////////////////////////////////////
//                      Array list implementation                        //
///////////////////////////////////////////////////////////////////////////

iwrc iwlist_init(IWLIST *list, size_t anum) {
  if (!anum) {
    anum = 32;
  }
  list->anum = anum;
  list->array = malloc(sizeof(list->array[0]) * anum);
  if (!list->array) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  list->start = 0;
  list->num = 0;
  return 0;
}

IWLIST* iwlist_create(size_t anum) {
  IWLIST *list = malloc(sizeof(*list));
  if (!list) {
    return 0;
  }
  if (iwlist_init(list, anum)) {
    free(list);
    return 0;
  }
  return list;
}

void iwlist_destroy_keep(IWLIST *list) {
  if (list) {
    IWLISTITEM *array = list->array;
    if (array) {
      size_t end = list->start + list->num;
      for (size_t i = list->start; i < end; ++i) {
        free(array[i].val);
      }
      free(array);
    }
    list->array = 0;
    list->anum = 0;
    list->num = 0;
    list->start = 0;
  }
}

void iwlist_destroy(IWLIST **listp) {
  if (listp) {
    if (*listp) {
      iwlist_destroy_keep(*listp);
      free(*listp);
    }
    *listp = 0;
  }
}

size_t iwlist_length(const IWLIST *list) {
  return list->num;
}

IWLIST* iwlist_clone(const IWLIST *list) {
  size_t num = list->num;
  if (!num) {
    return iwlist_create(0);
  }
  IWLIST *nlist = malloc(sizeof(*nlist));
  if (!nlist) {
    return 0;
  }
  const IWLISTITEM *array = list->array + list->start;
  IWLISTITEM *narray = malloc(sizeof(*narray) * num);
  if (!narray) {
    free(nlist);
    return 0;
  }
  for (size_t i = 0; i < num; ++i) {
    size_t size = array[i].size + 1;
    narray[i].val = malloc(size);
    if (!narray[i].val) {
      free(narray);
      free(nlist);
      return 0;
    }
    memcpy(narray[i].val, array[i].val, size + 1);
  }
  nlist->anum = num;
  nlist->array = narray;
  nlist->start = 0;
  nlist->num = num;
  return nlist;
}

void* iwlist_at(const IWLIST *list, size_t index, size_t *osize, iwrc *orc) {
  *orc = 0;
  if (index >= list->num) {
    *orc = IW_ERROR_OUT_OF_BOUNDS;
    return 0;
  }
  index += list->start;
  if (osize) {
    *osize = list->array[index].size;
  }
  return list->array[index].val;
}

void* iwlist_at2(const IWLIST *list, size_t index, size_t *osize) {
  if (index >= list->num) {
    return 0;
  }
  index += list->start;
  if (osize) {
    *osize = list->array[index].size;
  }
  return list->array[index].val;
}

void* iwlist_get(const IWLIST *list, size_t index, size_t *osize) {
  if (index >= list->num) {
    return 0;
  }
  index += list->start;
  if (osize) {
    *osize = list->array[index].size;
  }
  return list->array[index].val;
}

iwrc iwlist_push(IWLIST *list, const void *data, size_t data_size) {
  size_t index = list->start + list->num;
  if (index >= list->anum) {
    size_t anum = list->anum + list->num + 1;
    void *nptr = realloc(list->array, anum * sizeof(list->array[0]));
    if (!nptr) {
      return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
    list->anum = anum;
    list->array = nptr;
  }
  IWLISTITEM *array = list->array;
  array[index].val = malloc(data_size + 1);
  if (!array[index].val) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  memcpy(array[index].val, data, data_size);
  array[index].val[data_size] = '\0';
  array[index].size = data_size;
  list->num++;
  return 0;
}

void* iwlist_pop(IWLIST *list, size_t *osize, iwrc *orc) {
  *orc = 0;
  if (!list->num) {
    *orc = IW_ERROR_OUT_OF_BOUNDS;
    return 0;
  }
  size_t index = list->start + list->num - 1;
  --list->num;
  if (osize) {
    *osize = list->array[index].size;
  }
  return list->array[index].val;
}

iwrc iwlist_unshift(IWLIST *list, const void *data, size_t data_size) {
  if (!list->start) {
    if (list->num >= list->anum) {
      size_t anum = list->anum + list->num + 1;
      void *nptr = realloc(list->array, anum * sizeof(list->array[0]));
      if (!nptr) {
        return iwrc_set_errno(IW_ERROR_ALLOC, errno);
      }
      list->anum = anum;
      list->array = nptr;
    }
    list->start = list->anum - list->num;
    memmove(list->array + list->start, list->array, list->anum * sizeof(list->array[0]));
  }
  size_t index = list->start - 1;
  list->array[index].val = malloc(data_size + 1);
  memcpy(list->array[index].val, data, data_size);
  list->array[index].val[data_size] = '\0';
  list->array[index].size = data_size;
  --list->start;
  ++list->num;
  return 0;
}

void* iwlist_shift(IWLIST *list, size_t *osize, iwrc *orc) {
  *orc = 0;
  if (!list->num) {
    *orc = IW_ERROR_OUT_OF_BOUNDS;
    return 0;
  }
  size_t index = list->start;
  ++list->start;
  --list->num;
  *osize = list->array[index].size;
  void *rv = list->array[index].val;
  if (!(list->start & 0xff) && (list->start > list->num / 2)) {
    memmove(list->array, list->array + list->start, list->num * sizeof(list->array[0]));
    list->start = 0;
  }
  return rv;
}

iwrc iwlist_insert(IWLIST *list, size_t index, const void *data, size_t data_size) {
  if (index > list->num) {
    return IW_ERROR_OUT_OF_BOUNDS;
  }
  index += list->start;
  if (list->start + list->num >= list->anum) {
    size_t anum = list->anum + list->num + 1;
    void *nptr = realloc(list->array, anum * sizeof(list->array[0]));
    if (!nptr) {
      return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
    list->anum = anum;
    list->array = nptr;
  }
  memmove(list->array + index + 1, list->array + index,
          sizeof(list->array[0]) * (list->start + list->num - index));
  list->array[index].val = malloc(data_size + 1);
  memcpy(list->array[index].val, data, data_size);
  list->array[index].val[data_size] = '\0';
  list->array[index].size = data_size;
  list->num++;
  return 0;
}

iwrc iwlist_set(IWLIST *list, size_t index, const void *data, size_t data_size) {
  if (index >= list->num) {
    return IW_ERROR_OUT_OF_BOUNDS;
  }
  index += list->start;
  if (data_size > list->array[index].size) {
    void *nptr = realloc(list->array[index].val, data_size + 1);
    if (!nptr) {
      return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
    list->array[index].val = nptr;
  }
  memcpy(list->array[index].val, data, data_size);
  list->array[index].size = data_size;
  list->array[index].val[data_size] = '\0';
  return 0;
}

void* iwlist_remove(IWLIST *list, size_t index, size_t *osize, iwrc *orc) {
  *orc = 0;
  if (index >= list->num) {
    *orc = IW_ERROR_OUT_OF_BOUNDS;
    return 0;
  }
  index += list->start;
  void *rv = list->array[index].val;
  *osize = list->array[index].size;
  --list->num;
  memmove(list->array + index, list->array + index + 1,
          sizeof(list->array[0]) * (list->start + list->num - index));
  return rv;
}

void iwlist_sort(IWLIST *list, int (*compar)(const IWLISTITEM*, const IWLISTITEM*, void*), void *op) {
  sort_r(list->array + list->start, list->num, sizeof(list->array[0]),
         (int (*)(const void*, const void*, void*)) compar, op);
}
