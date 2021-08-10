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
 * Copyright (c) 2012-2021 Softmotions Ltd <info@softmotions.com>
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
IW_EXTERN_C_START

#ifndef IWPOOL_POOL_SIZ
#define IWPOOL_POOL_SIZ (8 * 1024)
#endif

struct _IWPOOL;
typedef struct _IWPOOL IWPOOL;

/**
 * @brief Creates memory pool and preallocate initial buffer of size `siz` bytes.
 * In the case if `siz` is zero then size of initial memory buffer will be `IWPOOL_POOL_SIZ` bytes.
 *
 * @param siz Initial memory buffer size. Can be zero.
 * @return Pointer to the new pool or `zero` if allocation is failed.
 */
IW_EXPORT IW_ALLOC IWPOOL* iwpool_create(size_t siz);

/**
 * @brief Create empty pool with no preallocated buffer.
 * @return Pointer to the new pool or `zero` if allocation is failed.
 */
IW_EXPORT IW_ALLOC IWPOOL* iwpool_create_empty(void);

/**
 * @brief Allocates buffer of specified size.
 *
 * @param siz  Size of buffer.
 * @param pool Pointer to memory pool.
 * @return Pointer to buffer or `zero` if allocation is failed.
 */
IW_EXPORT void* iwpool_alloc(size_t siz, IWPOOL *pool);

/**
 * @brief Allocates zero initialized memory buffer
 *        and initializes allocated buffer with zeroes.
 *
 * @param siz Size of buffer.
 * @param pool Pointer to memory pool.
 * @return Pointer to buffer or `zero` if allocation is failed.
 */
IW_EXPORT void* iwpool_calloc(size_t siz, IWPOOL *pool);

/**
 * @brief Copy a given `str` of size `len` into memory pool.
 *
 * @param pool Pointer to memory pool.
 * @param str Pointer to buffer to copy.
 * @param len Size of buffer in bytes.
 * @param rcp Pointer to status code holder.
 * @return Pointer to copied buffer or `zero` if operation failed.
 */
IW_EXPORT char* iwpool_strndup(IWPOOL *pool, const char *str, size_t len, iwrc *rcp);

/**
 * @brief Copy a given zero terminated char buffer into memory pool.
 *
 * @param pool Pointer to memory pool.
 * @param str Zero terminated char buffer.
 * @param rcp Pointer to status code holder.
 * @return Pointer to copied buffer or `zero` if operation failed.
 */
IW_EXPORT char* iwpool_strdup(IWPOOL *pool, const char *str, iwrc *rcp);

IW_EXPORT char* iwpool_strdup2(IWPOOL *pool, const char *str);

IW_EXPORT char* iwpool_strndup2(IWPOOL *pool, const char *str, size_t len);

/**
 * @brief Do `fprintf` into string allocated in this memory pool.
 *
 * @param pool Pointer to memory pool.
 * @param format `fprintf` format specification.
 * @param ...
 * @return Pointer to resulted string of `zero` if operation is failed.
 */
IW_EXPORT char* iwpool_printf(IWPOOL *pool, const char *format, ...);

IW_EXPORT char** iwpool_split_string(
  IWPOOL *pool, const char *haystack,
  const char *split_chars, bool ignore_whitespace);

IW_EXPORT char** iwpool_printf_split(
  IWPOOL *pool,
  const char *split_chars, bool ignore_whitespace,
  const char *format, ...);

/**
 * @brief Destroys a given memory pool and frees its resources.
 *
 * @param pool
 * @return IW_EXPORT
 */
IW_EXPORT void iwpool_destroy(IWPOOL *pool);

/**
 * @brief Dispose function for `IWPOOL` stored as user data.
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
IW_EXPORT void iwpool_user_data_set(IWPOOL *pool, void *data, void (*free_fn) (void*));

/**
 * @brief Returns pointer to user data associated with this pool. Or zero.
 */
IW_EXPORT void* iwpool_user_data_get(IWPOOL *pool);

/**
 * @brief Reset user data free function for current user data stored in pool.
 *
 * @param pool Pointer to memory pool.
 * @return Pointer to current user data stored or zero,
 */
IW_EXPORT void* iwpool_user_data_detach(IWPOOL *pool);

/**
 * @brief Returns number of bytes allocated for this memory pool.
 *
 * @param pool Pointer to memory pool.
 */
IW_EXPORT size_t iwpool_allocated_size(IWPOOL *pool);

/**
 * @brief Returns number of bytes actually used for allocated buffers.
 *
 * @param pool Pointer to mmemory pool.
 */
IW_EXPORT size_t iwpool_used_size(IWPOOL *pool);

IW_EXTERN_C_END
#endif
