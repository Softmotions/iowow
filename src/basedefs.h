#ifndef BASEDEFS_H
#define BASEDEFS_H

/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2017 Softmotions Ltd <info@softmotions.com>
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

/**
 * @file
 * @brief Very basic definitions.
 * @author Anton Adamansky (adamansky@softmotions.com)
 */

#ifdef __cplusplus
#define IW_EXTERN_C_START extern "C" {
#define IW_EXTERN_C_END }
#else
#define IW_EXTERN_C_START
#define IW_EXTERN_C_END
#endif

#if (defined(_WIN32) || defined(_WIN64))
#if (defined(IW_NODLL) || defined(IW_STATIC))
#define IW_EXPORT
#else
#ifdef IW_API_EXPORTS
#define IW_EXPORT __declspec(dllexport)
#else
#define IW_EXPORT __declspec(dllimport)
#endif
#endif
#else
#if __GNUC__ >= 4
#define IW_EXPORT __attribute__((visibility("default")))
#else
#define IW_EXPORT
#endif
#endif

#if defined(__GNUC__) || defined(__clang__)
#define IW_INLINE static __inline__
#else
#define IW_INLINE static inline
#endif

#if __GNUC__ >= 4
#define WUR __attribute__((__warn_unused_result__))
#else
#define WUR`
#endif

#define IW_ARR_STATIC static
#define IW_ARR_CONST const

#ifdef _WIN32
#include <windows.h>
#define INVALIDHANDLE(_HNDL) \
  (((_HNDL) == INVALID_HANDLE_VALUE) || (_HNDL) == NULL)
#else
typedef int HANDLE;
#define INVALID_HANDLE_VALUE (-1)
#define INVALIDHANDLE(_HNDL) ((_HNDL) < 0 || (_HNDL) == UINT16_MAX)
#endif

#define IW_ERROR_START 70000

#include <stdint.h>

/**
 * @brief The operation result status code.
 *
 * Zero status code `0` indicates <em>operation success</em>
 *
 * Status code can embed an `errno` code as operation result.
 * In this case `uint32_t iwrc_strip_errno(iwrc *rc)` used
 * to fetch embedded errno.
 *
 * @see iwlog.h
 */
typedef uint64_t iwrc;

/**
 * @brief A rational number.
 */
typedef struct IW_RNUM {
  int32_t n;  /**< Numerator */
  int32_t dn; /**< Denometator */
} IW_RNUM;

#endif
