#pragma once
#ifndef IWARRAYS_H
#define IWARRAYS_H

#include "basedefs.h"
IW_EXTERN_C_START

#include <stdio.h>

/**
 * @brief Insert new element into sorted array.
 *
 * @a els must point to an allocated memory with size at least `nels + 1`.
 * Upon insert number of array elements will be shifted to the right (`memmove`).
 *
 * @param els Array pointer.
 * @param nels Number of alive array elements.
 * @param elsize Size of every array element.
 * @param eptr Pointer to the new element to be inserted.
 * @param cmp Elements comparison function
 * @return Index of inserted element
 */
off_t iwarr_sorted_insert(void *els,
                          size_t nels,
                          size_t elsize,
                          void *eptr,
                          int (*cmp)(const void *, const void *));

//------------------------ Data array list

struct IWALIST;
typedef struct IWALIST IWALIST;

typedef struct {
  char  *ptr;
  int   size;
} IWALIST_REC;

IW_EXPORT IWALIST *iwalist_new(void);

IW_EXPORT IWALIST *iwalist_new2(int siz);

IW_EXPORT void iwalist_destroy(IWALIST *list);

IW_EXPORT void iwalist_clear(IWALIST *list);

IW_EXPORT int iwalist_size(IWALIST *list);

IW_EXPORT const void *iwalist_get(IWALIST *list, int idx, int *sp);

IW_EXPORT const char *iwalist_get2(IWALIST *list, int idx);

IW_EXPORT iwrc iwalist_insert(IWALIST *list, int idx, const void *ptr, int size);

IW_EXPORT iwrc iwalist_insert2(IWALIST *list, int idx, const char *str);

IW_EXPORT iwrc iwalist_set(IWALIST *list, int idx, const void *ptr, int size);

IW_EXPORT iwrc iwalist_set2(IWALIST *list, int idx, const char *str);

IW_EXPORT iwrc iwalist_push(IWALIST *list, const void *ptr, int size);

IW_EXPORT iwrc iwalist_push2(IWALIST *list, const char *str);

IW_EXPORT iwrc iwalist_push_allocated(IWALIST *list, void *ptr, int size);

IW_EXPORT iwrc iwalist_unshift(IWALIST *list, const void *ptr, int size);

IW_EXPORT iwrc iwalist_unshift2(IWALIST *list, const char *str);

IW_EXPORT void *iwalist_pop(IWALIST *list, int *sp);

IW_EXPORT char *iwalist_pop2(IWALIST *list);

IW_EXPORT void *iwalist_shift(IWALIST *list, int *sp);

IW_EXPORT char *iwalist_shift2(IWALIST *list);

IW_EXPORT void *iwalist_remove(IWALIST *list, int idx, int *sp);

IW_EXPORT char *iwalist_remove2(IWALIST *list, int idx);

IW_EXPORT void iwalist_sort(IWALIST *list);

IW_EXPORT void iwalist_sort2(IWALIST *list,
                             int (*cmp)(const IWALIST_REC *, const IWALIST_REC *, void *opaque),
                             void *opaque);
IW_EXPORT int iwalist_search(const IWALIST *list, const void *ptr, int size);

IW_EXPORT int iwalist_binary_search(const IWALIST *list, const void *ptr, int size);

//------------------------ Pointers array list

struct IWPTRLIST;
typedef struct IWPTRLIST IWPTRLIST;

IW_EXPORT IWPTRLIST *iwptrlist_new(void);

IW_EXPORT IWPTRLIST *iwptrlist_new2(int siz);

IW_EXPORT void iwptrlist_destroy(IWPTRLIST *list);

IW_EXPORT void iwptrlist_clear(IWPTRLIST *list);

IW_EXPORT int iwptrlist_size(IWPTRLIST *list);

IW_EXPORT void *iwptrlist_get(IWPTRLIST *list, int idx);

IW_EXPORT iwrc iwptrlist_insert(IWPTRLIST *list, int idx, void *ptr);

IW_EXPORT iwrc iwptrlist_set(IWPTRLIST *list, int idx, void *ptr);

IW_EXPORT iwrc iwptrlist_push(IWPTRLIST *list, void *ptr);

IW_EXPORT iwrc iwptrlist_unshift(IWPTRLIST *list, void *ptr);

IW_EXPORT void *iwptrlist_pop(IWPTRLIST *list);

IW_EXPORT void *iwptrlist_shift(IWPTRLIST *list);

IW_EXPORT void *iwptrlist_remove(IWPTRLIST *list, int idx);


IW_EXTERN_C_END
#endif
