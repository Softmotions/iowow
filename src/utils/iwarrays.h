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
off_t arrays_sorted_insert(void *els,
                           size_t nels,
                           size_t elsize,
                           void *eptr,
                           int (*cmp)(const void *, const void *));


IW_EXTERN_C_END
#endif
