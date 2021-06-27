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
IW_EXPORT off_t iwarr_sorted_insert(
  void* restrict els,
  size_t nels,
  size_t elsize,
  void* restrict eptr,
  int (*cmp)(const void*, const void*),
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
IW_EXPORT off_t iwarr_sorted_remove(
  void* restrict els,
  size_t nels,
  size_t elsize,
  void* restrict eptr,
  int (*cmp)(const void*, const void*));


IW_EXPORT off_t iwarr_sorted_find(
  void* restrict els,
  size_t nels,
  size_t elsize,
  void* restrict eptr,
  int (*cmp)(const void*, const void*));


IW_EXPORT off_t iwarr_sorted_find2(
  void* restrict els,
  size_t nels,
  size_t elsize,
  void* restrict eptr,
  void *op,
  bool *found,
  iwrc (*cmp)(const void*, const void*, void*, int *res));

///////////////////////////////////////////////////////////////////////////
//                     Fixed sized item list                             //
///////////////////////////////////////////////////////////////////////////

typedef struct {
  char  *array;   /**< Continuous units array */
  size_t usize;   /**< Unit size */
  size_t num;     /**< Number of elements in units array */
  size_t anum;    /**< Actual number of allocated units */
  size_t start;   /**< Offset of units data */
} IWULIST;

/**
 * @brief Initialize units list.
 *
 * @param list Allocated list structure
 * @param initial_length Number of preallocated units
 * @param unit_size      Unit size
 */
IW_EXPORT iwrc iwulist_init(IWULIST *list, size_t initial_length, size_t unit_size);

/**
 * @brief Create new units list.
 *
 * @param initial_length Number of preallocated units
 * @param unit_size      Unit size
 * @return Zero if memory allocation failed `errno` will be set respectively
 */
IW_EXPORT IW_ALLOC IWULIST* iwulist_create(size_t initial_length, size_t unit_size);

/**
 * @brief Cleanup units list.
 *
 * @param list Unit list
 */
IW_EXPORT iwrc iwulist_clear(IWULIST *list);

/**
 * @brief Destroys and deallocates a given unit list.
 *
 */
IW_EXPORT void iwulist_destroy(IWULIST **listp);

/**
 * @brief Destroys internal unit list buffers,
 *        but keep and doesn't free `list` pointer.
 *
 * @see iwulist_destroy()
 */
IW_EXPORT void iwulist_destroy_keep(IWULIST *list);

/**
 * @brief Get number of stored elements.
 */
IW_EXPORT size_t iwulist_length(IWULIST *list);

/**
 * @brief Clones a given list.
 */
IW_EXPORT IW_ALLOC IWULIST* iwulist_clone(IWULIST *list);

/**
 * @brief Gets pinter to element at given `index`
 *
 * @param index Index of element
 * @param [out] orc Set to `IW_ERROR_OUT_OF_BOUNDS` if index is invalid
 */
IW_EXPORT void* iwulist_at(IWULIST *list, size_t index, iwrc *orc);

IW_EXPORT void* iwulist_at2(IWULIST *list, size_t index);

/**
 * @brief Inserts new element at given index.
 *
 * @param index Index of element
 * @param data Pointer to unit data to copy
 */
IW_EXPORT iwrc iwulist_insert(IWULIST *list, size_t index, const void *data);

/**
 * @brief Overwrite element at given index with new data.
 *
 * @param index Index of element
 * @param data Pointer to unit data to copy
 */
IW_EXPORT iwrc iwulist_set(IWULIST *list, size_t index, const void *data);

/**
 * @brief Removes element at specified index.
 *
 * @param index Index of element
 * @param orc Output error code
 */
IW_EXPORT iwrc iwulist_remove(IWULIST *list, size_t index);

/**
 * @brief Adds new element to end of list.
 *
 * @param data Pointer to unit data to copy
 */
IW_EXPORT iwrc iwulist_push(IWULIST *list, const void *data);

/**
 * @brief Removes element from end of list.
 */
IW_EXPORT iwrc iwulist_pop(IWULIST *list);

/**
 * @brief Adds element to front of list.
 */
IW_EXPORT iwrc iwulist_unshift(IWULIST *list, const void *data);

/**
 * @brief Removes element from front of list.
 *
 * @param orc Output error code
 */
IW_EXPORT iwrc iwulist_shift(IWULIST *list);

/**
 * @brief Sorts list using given `compar` function.
 *
 * @param list IWULIST
 * @param compar Elements comparator accepts user data as last argument
 * @param op User data
 */
IW_EXPORT void iwulist_sort(IWULIST *list, int (*compar)(const void*, const void*, void*), void *op);

///////////////////////////////////////////////////////////////////////////
//                    Array list implementation                          //
///////////////////////////////////////////////////////////////////////////

typedef struct {
  char  *val;
  size_t size;
} IWLISTITEM;

typedef struct {
  IWLISTITEM *array;
  size_t      anum;  /**< Number of elements allocated */
  size_t      start; /**< Index of first element */
  size_t      num;   /**< Actual number of elements */
} IWLIST;

/**
 * @brief Initialize allocated empty list object.
 *
 * @param list Allocated list structure
 * @param anum Number of elements to allocate or zero to use defaults
 * @return IW_EXPORT iwlist_init
 */
IW_EXPORT iwrc iwlist_init(IWLIST *list, size_t anum);

/**
 * @brief Constructs new list instance and preallocate `anum` elements.
 *
 * @param anum Number of elements to allocate or zero to use defaults
 * @return Zero if allocation failed, `errno` will be set.
 */
IW_EXPORT IW_ALLOC IWLIST* iwlist_create(size_t anum);

/**
 * @brief Destroys a given list object.
 */
IW_EXPORT void iwlist_destroy(IWLIST **listp);

/**
 * @brief Destroys internal list buffers,
 *        but keep and doesn't free `list` pointer.
 * @see iwilist_destroy()
 */
IW_EXPORT void iwlist_destroy_keep(IWLIST *list);

/**
 * @brief Returns number of elements stored in list.
 */
IW_EXPORT size_t iwlist_length(IWLIST *list);

/**
 * @brief Clone a given list.
 * @return Zero if allocation failed, `errno` will be set.
 */
IW_EXPORT IW_ALLOC IWLIST* iwlist_clone(IWLIST *list);

/**
 * @brief Get element at specified index.
 *
 * @param index Element index
 * @param [out] osize Optional size of returned element data in bytes
 * @param [out] orc Set to `IW_ERROR_OUT_OF_BOUNDS` if index is invalid
 * @return Elements data buffer
 */
IW_EXPORT void* iwlist_at(IWLIST *list, size_t index, size_t *osize, iwrc *orc);

/**
 * @brief Get element at specified index.
 * @param index Element index
 * @param [out] osize Optional size of returned element data in bytes
 * @return Elements data buffer or zero if element is not found
 */
IW_EXPORT void* iwlist_at2(IWLIST *list, size_t index, size_t *osize);

/**
 * @brief Add element to end of list.
 */
IW_EXPORT iwrc iwlist_push(IWLIST *list, const void *data, size_t data_size);

/**
 * @brief Removes last element from list.
 *
 * @param [out] osize Optional size of removed element
 * @param [out] orc Set to `IW_ERROR_OUT_OF_BOUNDS` if list is empty
 * @return IW_EXPORT* iwlist_pop
 */
IW_EXPORT void* iwlist_pop(IWLIST *list, size_t *osize, iwrc *orc);

/**
 * @brief Add element to start of list
 */
IW_EXPORT iwrc iwlist_unshift(IWLIST *list, const void *data, size_t data_size);

/**
 * @brief Removes element at start of list.

 * @param osize Optional size of removed element
 * @param orc Set to `IW_ERROR_OUT_OF_BOUNDS` if list is empty
 * @return IW_EXPORT* iwlist_shift
 */
IW_EXPORT void* iwlist_shift(IWLIST *list, size_t *osize, iwrc *orc);

/**
 * @brief Inserts element at given position.
 */
IW_EXPORT iwrc iwlist_insert(IWLIST *list, size_t index, const void *data, size_t data_size);

/**
 * @brief Set/overwrite element at given position.
 */
IW_EXPORT iwrc iwlist_set(IWLIST *list, size_t index, const void *data, size_t data_size);

/**
 * @brief Remove element at given index.
 *
 * @param osize Optional size of removed element
 */
IW_EXPORT void* iwlist_remove(IWLIST *list, size_t index, size_t *osize, iwrc *orc);

/**
 * @brief Sorts list using given `compar` function.
 *
 * @param list IWLIST
 * @param compar Elements comparator accepts user data as last argument
 * @param op User data
 */
IW_EXPORT void iwlist_sort(IWLIST *list, int (*compar)(const IWLISTITEM*, const IWLISTITEM*, void*), void *op);

IW_EXTERN_C_END
#endif
