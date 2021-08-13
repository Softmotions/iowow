#ifndef BASEDEFS_H
#define BASEDEFS_H

/**************************************************************************************************
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

/**
 * @file
 * @brief Very basic definitions.
 * @author Anton Adamansky (adamansky@softmotions.com)
 */

#ifdef __cplusplus
#define IW_EXTERN_C_START extern "C" {
#define IW_EXTERN_C_END   }
#else
#define IW_EXTERN_C_START
#define IW_EXTERN_C_END
#endif

#define IW_XSTR(s) IW_STR(s)
#define IW_STR(s)  #s

#define IW_MAX(X__, Y__) ({ __typeof__(X__) x = (X__);  __typeof__(Y__) y = (Y__); x < y ? y : x; })
#define IW_MIN(X__, Y__) ({ __typeof__(X__) x = (X__);  __typeof__(Y__) y = (Y__); x < y ? x : y; })


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

#if defined(__GNUC__)
#define IW_INLINE static inline __attribute__((always_inline))
#else
#define IW_INLINE static inline
#endif

#define IW_SOFT_INLINE static inline

#if __GNUC__ >= 4
#define WUR      __attribute__((__warn_unused_result__))
#define IW_ALLOC __attribute__((malloc)) __attribute__((warn_unused_result))
#else
#define WUR
#define IW_ALLOC
#endif

#define IW_ARR_STATIC static
#define IW_ARR_CONST  const

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

#ifdef _WIN32
#define IW_PATH_CHR '\\'
#define IW_PATH_STR "\\"
#define IW_LINE_SEP "\r\n"
#else
#define IW_PATH_CHR '/'
#define IW_PATH_STR "/"
#define IW_LINE_SEP "\n"
#endif

#define ZGO(label__, val__)           \
  ({ __typeof__(val__) v__ = (val__); \
     if (!v__) goto label__;           \
     v__; })

#define ZRET(ret__, val__)            \
  ({ __typeof__(val__) v__ = (val__); \
     if (!v__) return ret__;           \
     v__; })

#ifdef __GNUC__
#define RCGO(rc__, label__) if (__builtin_expect((!!(rc__)), 0)) goto label__
#else
#define RCGO(rc__, label__) if (rc__) goto label__
#endif

#define RCIF(res__, rc__, rcv__, label__)   \
  if (res__) {                              \
    rc__ = (rcv__);                         \
    goto label__;                           \
  }

#define RCHECK(rc__, label__, expr__) \
  rc__ = expr__;                       \
  RCGO(rc__, label__)

#define RCC(rc__, label__, expr__) RCHECK(rc__, label__, expr__)

#ifndef RCGA
#define RCGA(v__, label__)                        \
  if (!(v__)) {                                   \
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);  \
    goto label__;                                 \
  }
#endif

#ifndef RCA
#define RCA(v__, label__) RCGA(v__, label__)
#endif

#ifndef RCB
#define RCB(label__, v__) RCGA(v__, label__)
#endif

#ifndef RCN
#define RCN(label__, v__)                       \
  if ((v__) < 0) {                                \
    rc = iwrc_set_errno(IW_ERROR_ERRNO, errno);   \
    goto label__;                                 \
  }
#endif

#ifndef RCT
#define RCT(label__, val__)                                         \
  ({ __typeof__(val__) v__ = (val__);                               \
     if (v__) {                                                     \
       rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, v__);          \
       goto label__;                                                \
     }                                                              \
   })
#endif

#ifdef __GNUC__
#define RCRET(rc__) if (__builtin_expect((!!(rc__)), 0)) return (rc__)
#else
#define RCRET(rc__) if (rc__) return (rc__)
#endif

#define RCR(expr__) \
  ({ iwrc rc__ = (expr__); RCRET(rc__); 0; })

#ifdef __GNUC__
#define RCBREAK(rc__) if (__builtin_expect((!!(rc__)), 0)) break
#else
#define RCBREAK(rc__) if (rc__) break
#endif

#ifdef __GNUC__
#define RCONT(rc__) if (__builtin_expect((!!(rc__)), 0)) continue
#else
#define RCONT(rc__) if (rc__) continue
#endif

#ifndef MIN
#define MIN(a_, b_) ((a_) < (b_) ? (a_) : (b_))
#endif

#ifndef MAX
#define MAX(a_, b_) ((a_) > (b_) ? (a_) : (b_))
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

#ifdef _WIN32
typedef _locale_t locale_t;
#endif

#if defined(__GNUC__) || defined(__clang__)
#define IW_DEPRECATED __attribute__((deprecated))
#elif defined(_MSC_VER)
#define IW_DEPRECATED __declspec(deprecated)
#else
#define IW_DEPRECATED
#endif

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
