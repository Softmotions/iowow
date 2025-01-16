#pragma once
#ifndef IWPOOL_H
#define IWPOOL_H

/**************************************************************************************************
 * Memory pool implementation.
 *
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2024 Softmotions Ltd <info@softmotions.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *************************************************************************************************/

#include "basedefs.h"
#include <stdarg.h>

IW_EXTERN_C_START;

#ifndef IWPOOL_POOL_SIZ
#define IWPOOL_POOL_SIZ (8UL * 1024)
#endif

struct iwpool;
typedef struct iwpool IWPOOL;

/**
 * @brief Creates a memory pool and preallocate initial buffer of size `siz` bytes.
 * In the case if `siz` is zero then size of initial memory buffer will be `IWPOOL_POOL_SIZ` bytes.
 *
 * @param siz Initial memory buffer size. Can be zero.
 * @return Pointer to the new pool or `zero` if allocation is failed.
 */
IW_EXPORT WUR struct iwpool* iwpool_create(size_t siz);

/**
 * @brief Create empty pool with no preallocated buffer.
 * @return Pointer to the new pool or `zero` if allocation is failed.
 */
IW_EXPORT WUR struct iwpool* iwpool_create_empty(void);

/**
 * @brief Creates a memory pool within a given parent and preallocate initial buffer of `siz` bytes.
 * In the case if `siz` is zero then size of initial memory buffer will be `IWPOOL_POOL_SIZ` bytes.
 * If parent pool is destroyed this memory pool will be destroyed as well. It also allowed to
 * destroy memory pool by `iwpool_destroy()`
 */
IW_EXPORT WUR struct iwpool* iwpool_create_attach(struct iwpool *parent, size_t siz);

/**
 * @brief Create empty pool within a given parent and no preallocated buffer.
 * If parent pool is destroyed this memory pool will be destroyed as well. It also allowed to
 * destroy memory pool by `iwpool_destroy()`
 * @return Pointer to the new pool or `zero` if allocation is failed.
 */
IW_EXPORT WUR struct iwpool* iwpool_create_empty_attach(struct iwpool *parent);

/**
 * @brief Allocates buffer of specified size.
 *
 * @param siz  Size of buffer.
 * @param pool Pointer to memory pool.
 * @return Pointer to buffer or `zero` if allocation is failed.
 */
IW_EXPORT void* iwpool_alloc(size_t siz, struct iwpool *pool);

/**
 * @brief Allocates zero initialized memory buffer
 *        and initializes allocated buffer with zeroes.
 *
 * @param siz Size of buffer.
 * @param pool Pointer to memory pool.
 * @return Pointer to buffer or `zero` if allocation is failed.
 */
IW_EXPORT void* iwpool_calloc(size_t siz, struct iwpool *pool);

/**
 * @brief Copy a given `str` of size `len` into memory pool.
 *
 * @param pool Pointer to memory pool.
 * @param str Pointer to buffer to copy.
 * @param len Size of buffer in bytes.
 * @param rcp Pointer to status code holder.
 * @return Pointer to copied buffer or `zero` if operation failed.
 */
IW_EXPORT char* iwpool_strndup(struct iwpool *pool, const char *str, size_t len, iwrc *rcp);

/**
 * @brief Copy a given zero terminated char buffer into memory pool.
 *
 * @param pool Pointer to memory pool.
 * @param str Zero terminated char buffer.
 * @param rcp Pointer to status code holder.
 * @return Pointer to copied buffer or `zero` if operation failed.
 */
IW_EXPORT char* iwpool_strdup(struct iwpool *pool, const char *str, iwrc *rcp);

IW_EXPORT char* iwpool_strdup2(struct iwpool *pool, const char *str);

IW_EXPORT char* iwpool_strndup2(struct iwpool *pool, const char *str, size_t len);

/**
 * @brief Do `fprintf` into string allocated in this memory pool.
 *
 * @param pool Pointer to memory pool.
 * @param format `fprintf` format specification.
 * @param ...
 * @return Pointer to resulted string of `zero` if operation is failed.
 */
IW_EXPORT char* iwpool_printf(struct iwpool *pool, const char *format, ...) __attribute__((format(__printf__, 2, 3)));

IW_EXPORT char* iwpool_printf_va(struct iwpool *pool, const char *format, va_list va);

IW_EXPORT const char** iwpool_split_string(
  struct iwpool *pool, const char *haystack,
  const char *split_chars, bool ignore_whitespace);

IW_EXPORT const char** iwpool_printf_split(
  struct iwpool *pool,
  const char *split_chars, bool ignore_whitespace,
  const char *format, ...) __attribute__((format(__printf__, 4, 5)));

IW_EXPORT const char** iwpool_copy_cstring_array(const char** v, struct iwpool *pool);

/**
 * Increments an internal reference count.
 * References are decremented by `iwpool_destroy()`.
 *
 * @return Actual number of references.
 */
IW_EXPORT int iwpool_ref(struct iwpool *pool);

/**
 * @brief Destroys a given memory pool and frees its resources.
 *
 * @param pool
 * @return IW_EXPORT
 */
IW_EXPORT bool iwpool_destroy(struct iwpool *pool);

/**
 * @brief Dispose function for `struct iwpool` stored as user data.
 *
 * @param pool Memory pool to be destroyed.
 */
IW_EXPORT void iwpool_free_fn(void *pool);

/**
 * @brief Sets arbitrary user data associated with this pool.
 *        User data will be freed on pool destroy or new user data set.
 *
 * @param pool Pointer to memory pool.
 * @param data User data. Can be zero.
 * @param free_fn User data dispose function. Can be zero.
 */
IW_EXPORT void iwpool_user_data_set(struct iwpool *pool, void *data, void (*free_fn)(void*));

/**
 * @brief Returns pointer to user data associated with this pool. Or zero.
 */
IW_EXPORT void* iwpool_user_data_get(struct iwpool *pool);

/**
 * @brief Reset user data free function for current user data stored in pool.
 *
 * @param pool Pointer to memory pool.
 * @return Pointer to current user data stored or zero,
 */
IW_EXPORT void* iwpool_user_data_detach(struct iwpool *pool);

/**
 * @brief Returns number of bytes allocated for this memory pool.
 *
 * @param pool Pointer to memory pool.
 */
IW_EXPORT size_t iwpool_allocated_size(struct iwpool *pool);

/**
 * @brief Returns number of bytes actually used for allocated buffers.
 *
 * @param pool Pointer to mmemory pool.
 */
IW_EXPORT size_t iwpool_used_size(struct iwpool *pool);

IW_EXTERN_C_END;
#endif
