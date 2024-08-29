#pragma once
#ifndef IWARRAYS_H
#define IWARRAYS_H

#include "basedefs.h"
#include <stdbool.h>

IW_EXTERN_C_START

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
  void *els,
  size_t nels,
  size_t elsize,
  void *eptr,
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
  void* els,
  size_t nels,
  size_t elsize,
  void* eptr,
  int (*cmp)(const void*, const void*));


IW_EXPORT off_t iwarr_sorted_find(
  void* els,
  size_t nels,
  size_t elsize,
  void* eptr,
  int (*cmp)(const void*, const void*));


IW_EXPORT off_t iwarr_sorted_find2(
  void* els,
  size_t nels,
  size_t elsize,
  void* eptr,
  void *op,
  bool *found,
  int (*cmp)(const void*, const void*, void*));

///////////////////////////////////////////////////////////////////////////
//                     Fixed sized item list                             //
///////////////////////////////////////////////////////////////////////////

struct iwulist;
typedef struct iwulist IWULIST;

struct iwulist {
  char  *array;   /**< Continuous units array */
  size_t usize;   /**< Unit size */
  size_t num;     /**< Number of elements in units array */
  size_t anum;    /**< Actual number of allocated units */
  size_t start;   /**< Offset of units data */
};

/**
 * @brief Initialize units list.
 *
 * @param list Allocated list structure
 * @param initial_length Number of preallocated units
 * @param unit_size      Unit size
 */
IW_EXPORT iwrc iwulist_init(struct iwulist *list, size_t initial_length, size_t unit_size);

/**
 * @brief Create new units list.
 *
 * @param initial_length Number of preallocated units
 * @param unit_size      Unit size
 * @return Zero if memory allocation failed `errno` will be set respectively
 */
IW_EXPORT IW_ALLOC struct iwulist* iwulist_create(size_t initial_length, size_t unit_size);

/**
 * @brief Cleanup units list.
 *
 * @param list Unit list
 */
IW_EXPORT iwrc iwulist_clear(struct iwulist *list);

/**
 * @brief Resets number of elements to zero.
 * Underlying list array is not destroyed.
 */
IW_EXPORT void iwulist_reset(struct iwulist *list);

/**
 * @brief Destroys and deallocates a given unit list.
 *
 */
IW_EXPORT void iwulist_destroy(struct iwulist **listp);

/**
 * @brief Destroys internal unit list buffers,
 *        but keep and doesn't free `list` pointer.
 *
 * @see iwulist_destroy()
 */
IW_EXPORT void iwulist_destroy_keep(struct iwulist *list);

/**
 * @brief Get number of stored elements.
 */
IW_EXPORT size_t iwulist_length(const struct iwulist *list);

/**
 * @brief Clones a given list.
 */
IW_EXPORT IW_ALLOC struct iwulist* iwulist_clone(const struct iwulist *list);

/**
 * @brief Copies all element of `list` into `tgt` list
 */
IW_EXPORT iwrc iwulist_copy(const struct iwulist *list, struct iwulist *tgt);

/**
 * @brief Gets pinter to element at given `index`
 *
 * @param index Index of element
 * @param [out] orc Set to `IW_ERROR_OUT_OF_BOUNDS` if index is invalid
 */
IW_EXPORT void* iwulist_at(const struct iwulist *list, size_t index, iwrc *orc);

IW_EXPORT void* iwulist_at2(const struct iwulist *list, size_t index);

/**
 * Alias for iwulist_at2()
 */
IW_EXPORT void* iwulist_get(const struct iwulist *list, size_t index);

/**
 * @brief Inserts new element at given index.
 *
 * @param index Index of element
 * @param data Pointer to unit data to copy
 */
IW_EXPORT iwrc iwulist_insert(struct iwulist *list, size_t index, const void *data);

/**
 * @brief Overwrite element at given index with new data.
 *
 * @param index Index of element
 * @param data Pointer to unit data to copy
 */
IW_EXPORT iwrc iwulist_set(struct iwulist *list, size_t index, const void *data);

/**
 * @brief Removes element at specified index.
 *
 * @param index Index of element
 * @param orc Output error code
 */
IW_EXPORT iwrc iwulist_remove(struct iwulist *list, size_t index);

/**
 * @brief Removes first element matches the given `data_ptr` content.
 * @note `data_ptr` buffer must at least of list unit size.
 *
 * @param data_ptr Pointer to data buffer list items will be matched against.
 * @return True if matched element was found.
 */
IW_EXPORT bool iwulist_remove_first_by(struct iwulist *list, void *data_ptr);

/**
 * @brief Finds first element matched the given `data_ptr` content.
 * @note `data_ptr` buffer must at least of list unit size.
 *
 * @param data_ptr Pointer to data buffer list items will be matched against.
 * @return Index of first matched element or `-1` if item not found.
 */
IW_EXPORT ssize_t iwulist_find_first(const struct iwulist *list, void *data_ptr);

/**
 * @brief Adds new element to end of list.
 *
 * @param data Pointer to unit data to copy
 */
IW_EXPORT iwrc iwulist_push(struct iwulist *list, const void *data);

/**
 * @brief Removes element from end of list.
 */
IW_EXPORT iwrc iwulist_pop(struct iwulist *list);

/**
 * @brief Adds element to front of list.
 */
IW_EXPORT iwrc iwulist_unshift(struct iwulist *list, const void *data);

/**
 * @brief Removes element from front of list.
 *
 * @param orc Output error code
 */
IW_EXPORT iwrc iwulist_shift(struct iwulist *list);

/**
 * @brief Sorts list using given `compar` function.
 *
 * @param list struct iwulist
 * @param compar Elements comparator accepts user data as last argument
 * @param op User data
 */
IW_EXPORT void iwulist_sort(struct iwulist *list, int (*compar)(const void*, const void*, void*), void *op);


IW_EXPORT void* iwulist_array(struct iwulist *list);

///////////////////////////////////////////////////////////////////////////
//                    Array list implementation                          //
///////////////////////////////////////////////////////////////////////////

struct iwlistitem;
struct iwlist;
typedef struct iwlistitem IWLISTITEM;
typedef struct iwlist IWLIST;

struct iwlistitem {
  char  *val;
  size_t size;
};

struct iwlist {
  struct iwlistitem *array;
  size_t anum;       /**< Number of elements allocated */
  size_t start;      /**< Index of first element */
  size_t num;        /**< Actual number of elements */
};

/**
 * @brief Initialize allocated empty list object.
 *
 * @param list Allocated list structure
 * @param anum Number of elements to allocate or zero to use defaults
 * @return IW_EXPORT iwlist_init
 */
IW_EXPORT iwrc iwlist_init(struct iwlist *list, size_t anum);

/**
 * @brief Constructs new list instance and preallocate `anum` elements.
 *
 * @param anum Number of elements to allocate or zero to use defaults
 * @return Zero if allocation failed, `errno` will be set.
 */
IW_EXPORT IW_ALLOC struct iwlist* iwlist_create(size_t anum);

/**
 * @brief Destroys a given list object.
 */
IW_EXPORT void iwlist_destroy(struct iwlist **listp);

/**
 * @brief Destroys internal list buffers,
 *        but keep and doesn't free `list` pointer.
 * @see iwilist_destroy()
 */
IW_EXPORT void iwlist_destroy_keep(struct iwlist *list);

/**
 * @brief Returns number of elements stored in list.
 */
IW_EXPORT size_t iwlist_length(const struct iwlist *list);

/**
 * @brief Clone a given list.
 * @return Zero if allocation failed, `errno` will be set.
 */
IW_EXPORT IW_ALLOC struct iwlist* iwlist_clone(const struct iwlist *list);

/**
 * @brief Get element at specified index.
 *
 * @param index Element index
 * @param [out] osize Optional size of returned element data in bytes
 * @param [out] orc Set to `IW_ERROR_OUT_OF_BOUNDS` if index is invalid
 * @return Elements data buffer
 */
IW_EXPORT void* iwlist_at(const struct iwlist *list, size_t index, size_t *osize, iwrc *orc);

/**
 * @brief Get element at specified index.
 * @param index Element index
 * @param [out] osize Optional size of returned element data in bytes
 * @return Elements data buffer or zero if element is not found
 */
IW_EXPORT void* iwlist_at2(const struct iwlist *list, size_t index, size_t *osize);

/**
 * Alias of iwlist_at2()
 */
IW_EXPORT void* iwlist_get(const struct iwlist *list, size_t index, size_t *osize);

/**
 * @brief Add element to end of list.
 */
IW_EXPORT iwrc iwlist_push(struct iwlist *list, const void *data, size_t data_size);

/**
 * @brief Removes last element from list.
 *
 * @param [out] osize Optional size of removed element
 * @param [out] orc Set to `IW_ERROR_OUT_OF_BOUNDS` if list is empty
 * @return IW_EXPORT* iwlist_pop
 */
IW_EXPORT void* iwlist_pop(struct iwlist *list, size_t *osize, iwrc *orc);

/**
 * @brief Add element to start of list
 */
IW_EXPORT iwrc iwlist_unshift(struct iwlist *list, const void *data, size_t data_size);

/**
 * @brief Removes element at start of list.

 * @param osize Optional size of removed element
 * @param orc Set to `IW_ERROR_OUT_OF_BOUNDS` if list is empty
 * @return IW_EXPORT* iwlist_shift
 */
IW_EXPORT void* iwlist_shift(struct iwlist *list, size_t *osize, iwrc *orc);

/**
 * @brief Inserts element at given position.
 */
IW_EXPORT iwrc iwlist_insert(struct iwlist *list, size_t index, const void *data, size_t data_size);

/**
 * @brief Set/overwrite element at given position.
 */
IW_EXPORT iwrc iwlist_set(struct iwlist *list, size_t index, const void *data, size_t data_size);

/**
 * @brief Remove element at given index.
 *
 * @param osize Optional size of removed element
 */
IW_EXPORT void* iwlist_remove(struct iwlist *list, size_t index, size_t *osize, iwrc *orc);

/**
 * @brief Sorts list using given `compar` function.
 *
 * @param list struct iwlist
 * @param compar Elements comparator accepts user data as last argument
 * @param op User data
 */
IW_EXPORT void iwlist_sort(struct iwlist *list, int (*compar)(const IWLISTITEM*, const IWLISTITEM*, void*), void *op);

IW_EXTERN_C_END
#endif
