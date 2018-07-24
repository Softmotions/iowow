#pragma once
#ifndef IWARRAYS_H
#define IWARRAYS_H

#include "basedefs.h"
IW_EXTERN_C_START

#include <stdio.h>
#include <stdbool.h>

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
 * @param skipeq If true and `eptr` is found in array it will not be inserted and method will return -1
 * @return Index of inserted element
 */
off_t iwarr_sorted_insert(void *restrict els,
                          size_t nels,
                          size_t elsize,
                          void *restrict eptr,
                          int (*cmp)(const void *, const void *),
                          bool skipeq);

/**
 * @brief Remove element from a sorteed array.
 * Return true if element is found and removed.
 *
 * @param els Array pointer.
 * @param nels Number of array elements.
 * @param elsize Size of every array element.
 * @param eptr Pointer to the element should to be removed.
 * @param cmp Elements comparison function
 * @return Index of removed element or -1
 */
off_t iwarr_sorted_remove(void *restrict els,
                          size_t nels,
                          size_t elsize,
                          void *restrict eptr,
                          int (*cmp)(const void *, const void *));


off_t iwarr_sorted_find(void *restrict els,
                        size_t nels,
                        size_t elsize,
                        void *restrict eptr,
                        int (*cmp)(const void *, const void *));


off_t iwarr_sorted_find2(void *restrict els,
                         size_t nels,
                         size_t elsize,
                         void *restrict eptr,
                         void *op,
                         bool *found,
                         iwrc(*cmp)(const void *, const void *, void *, int *res));



IW_EXTERN_C_END
#endif
