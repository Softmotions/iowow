#ifndef BASEDEFS_H
#define BASEDEFS_H

/**************************************************************************************************
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

#define IW_MAX(x__, y__) ({ __typeof__(x__) x = (x__);  __typeof__(y__) y = (y__); x < y ? y : x; })
#define IW_MIN(x__, y__) ({ __typeof__(x__) x = (x__);  __typeof__(y__) y = (y__); x < y ? x : y; })
#define IW_LLEN(l__)     (sizeof(l__) - 1)

/* Is given c-ptr is not empty */
#define IW_NES(s__) ((s__) && *(s__) != '\0')

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
#define WUR      __attribute__((warn_unused_result))
#define IW_ALLOC __attribute__((malloc)) __attribute__((warn_unused_result))
#define IW_NORET __attribute__((noreturn))
#else
#define WUR
#define IW_ALLOC
#define IW_NORET
#endif

#define IW_CONSTRUCTOR __attribute__((constructor))
#define IW_DESTRUCTOR  __attribute__((destructor))

#define IW_CLEANUP(func__) __attribute__(cleanup(func__))

#define IW_CLEANUP_FUNC(type__, func__)                \
        static inline void func__ ## _cc(type__ * p) { \
          if (*p) {                                    \
            *p = func__(*p);                           \
          }                                            \
        }

#define IW_CLEANUP_DESTROY_FUNC(type__, func__)        \
        static inline void func__ ## _cc(type__ * p) { \
          if (*p) {                                    \
            func__(*p);                                \
          }                                            \
        }


#define IW_SENTINEL __attribute__((sentinel))

#define IW_ARR_STATIC static
#define IW_ARR_CONST  const

#ifdef _WIN32
#include <windows.h>
#define INVALIDHANDLE(h__) \
        (((h__) == INVALID_HANDLE_VALUE) || (h__) == NULL)
#else
typedef int HANDLE;
#define INVALID_HANDLE_VALUE (-1)
#define INVALIDHANDLE(h__) ((h__) < 0 || (h__) == UINT16_MAX)
#endif

#define IW_ERROR_START 70000

#define IWNUMBUF_SIZE 32

#ifdef _WIN32
#define IW_PATH_CHR '\\'
#define IW_PATH_STR "\\"
#define IW_LINE_SEP "\r\n"
#else
#define IW_PATH_CHR '/'
#define IW_PATH_STR "/"
#define IW_LINE_SEP "\n"
#endif

#define ZGO(label__, val__)                 \
        ({ __typeof__(val__) v__ = (val__); \
           if (!v__) goto label__;          \
           v__; })

#define ZRET(ret__, val__)                  \
        ({ __typeof__(val__) v__ = (val__); \
           if (!v__) return ret__;          \
           v__; })

#ifdef __GNUC__
#define RCGO(rc__, label__) if (__builtin_expect((!!(rc__)), 0)) goto label__
#else
#define RCGO(rc__, label__) if (rc__) goto label__
#endif

#define RCIF(res__, rc__, rcv__, label__) \
        if (res__) {                      \
          rc__ = (rcv__);                 \
          goto label__;                   \
        }

#define RCHECK(rc__, label__, expr__) \
        rc__ = expr__;                \
        RCGO(rc__, label__)

#define RCC(rc__, label__, expr__) RCHECK(rc__, label__, expr__)

#ifndef RCGA
#define RCGA(v__, label__)                            \
        if (!(v__)) {                                 \
          rc = iwrc_set_errno(IW_ERROR_ALLOC, errno); \
          goto label__;                               \
        }
#endif

#ifndef RCA
#define RCA(v__, label__) RCGA(v__, label__)
#endif

#ifndef RCB
#define RCB(label__, v__) RCGA(v__, label__)
#endif

#ifndef RCRA
#define RCRA(v__) \
        if (!v__) return iwrc_set_errno(IW_ERROR_ALLOC, errno);
#endif

#ifndef RCN
#define RCN(label__, v__)                             \
        if ((v__) < 0) {                              \
          rc = iwrc_set_errno(IW_ERROR_ERRNO, errno); \
          goto label__;                               \
        }
#endif

#ifndef RCT
#define RCT(label__, val__)                                      \
        ({ __typeof__(val__) v__ = (val__);                      \
           if (v__) {                                            \
             rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, v__); \
             goto label__;                                       \
           }                                                     \
         })
#endif

#ifndef RCTM
#define RCTM(label__, mtx__)                                     \
        ({ int v__ = pthread_mutex_lock(mtx__);                  \
           if (v__ == EOWNERDEAD) {                              \
             pthread_mutex_consistent(mtx__);                    \
           } else if (v__) {                                     \
             rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, v__); \
             goto label__;                                       \
           }                                                     \
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

/* Align x_ with v_. v_ must be simple power for 2 value. */
#define IW_ROUNDUP(x_, v_) (((x_) + (v_) - 1) & ~((v_) - 1))

/* Round down align x_ with v_. v_ must be simple power for 2 value. */
#define IW_ROUNDOWN(x_, v_) ((x_) - ((x_) & ((v_) - 1)))

#ifdef __GNUC__
#define IW_LIKELY(x_)   __builtin_expect(!!(x_), 1)
#define IW_UNLIKELY(x_) __builtin_expect(!!(x_), 0)
#else
#define IW_LIKELY(x_)
#define IW_UNLIKELY(x_)
#endif

#if defined(NDEBUG)
#define IW_DODEBUG(IW_expr_)
#else
#define IW_DODEBUG(IW_expr_) \
        { IW_expr_; }
#endif

#if __GNUC__ >= 5
#define IW_SWAB16(num_) __builtin_bswap16(num_)
#else
#define IW_SWAB16(num_) \
        ((((num_) & 0x00ffU) << 8) | (((num_) & 0xff00U) >> 8))
#endif

#if __GNUC__ >= 4
#define IW_SWAB32(num_) __builtin_bswap32(num_)
#else
#define IW_SWAB32(num_)                                                   \
        ((((num_) & 0x000000ffUL) << 24) | (((num_) & 0x0000ff00UL) << 8) \
         | (((num_) & 0x00ff0000UL) >> 8) | (((num_) & 0xff000000UL) >> 24))
#endif

#if __GNUC__ >= 4
#define IW_SWAB64(num_) __builtin_bswap64(num_)
#else
#define IW_SWAB64(num_)                             \
        ((((num_) & 0x00000000000000ffULL) << 56)   \
         | (((num_) & 0x000000000000ff00ULL) << 40) \
         | (((num_) & 0x0000000000ff0000ULL) << 24) \
         | (((num_) & 0x00000000ff000000ULL) << 8)  \
         | (((num_) & 0x000000ff00000000ULL) >> 8)  \
         | (((num_) & 0x0000ff0000000000ULL) >> 24) \
         | (((num_) & 0x00ff000000000000ULL) >> 40) \
         | (((num_) & 0xff00000000000000ULL) >> 56))
#endif

#if defined(IW_BIGENDIAN) || defined(IW_NET_BIGENDIAN)
#define IW_HTOIS(num_)  IW_SWAB16(num_)
#define IW_HTOIL(num_)  IW_SWAB32(num_)
#define IW_HTOILL(num_) IW_SWAB64(num_)
#define IW_ITOHS(num_)  IW_SWAB16(num_)
#define IW_ITOHL(num_)  IW_SWAB32(num_)
#define IW_ITOHLL(num_) IW_SWAB64(num_)
#else
#define IW_HTOIS(num_)  (num_)
#define IW_HTOIL(num_)  (num_)
#define IW_HTOILL(num_) (num_)
#define IW_ITOHS(num_)  (num_)
#define IW_ITOHL(num_)  (num_)
#define IW_ITOHLL(num_) (num_)
#endif

#define IW_WRITEBV(ptr_, v_, m_)                            \
        static_assert(sizeof(v_) == 1, "Mismatch v_ size"); \
        (v_) = (m_);                                        \
        memcpy(ptr_, &(v_), 1);                             \
        (ptr_) += 1

#define IW_WRITESV(ptr_, v_, m_)                            \
        static_assert(sizeof(v_) == 2, "Mismatch v_ size"); \
        (v_) = (m_);                                        \
        (v_) = IW_HTOIS(v_);                                \
        memcpy(ptr_, &(v_), 2);                             \
        (ptr_) += 2

#define IW_WRITELV(ptr_, v_, m_)                            \
        static_assert(sizeof(v_) == 4, "Mismatch v_ size"); \
        (v_) = (m_);                                        \
        (v_) = IW_HTOIL(v_);                                \
        memcpy(ptr_, &(v_), 4);                             \
        (ptr_) += 4

#define IW_WRITELLV(ptr_, v_, m_)                           \
        static_assert(sizeof(v_) == 8, "Mismatch v_ size"); \
        (v_) = (m_);                                        \
        (v_) = IW_HTOILL(v_);                               \
        memcpy((ptr_), &(v_), 8);                           \
        (ptr_) += 8

#define IW_READBV(ptr_, t_, m_)                             \
        static_assert(sizeof(t_) == 1, "Mismatch t_ size"); \
        (t_) = 0;                                           \
        memcpy(&(t_), ptr_, 1);                             \
        (m_) = (t_);                                        \
        (ptr_) += 1

#define IW_READSV(ptr_, t_, m_)                             \
        static_assert(sizeof(t_) == 2, "Mismatch t_ size"); \
        (t_) = 0;                                           \
        memcpy(&(t_), ptr_, 2);                             \
        (m_) = IW_ITOHS(t_);                                \
        (ptr_) += 2

#define IW_READLV(ptr_, t_, m_)                             \
        static_assert(sizeof(t_) == 4, "Mismatch t_ size"); \
        (t_) = 0;                                           \
        memcpy(&(t_), ptr_, 4);                             \
        (m_) = IW_ITOHL(t_);                                \
        (ptr_) += 4

#define IW_READLLV(ptr_, t_, m_)                            \
        static_assert(sizeof(t_) == 8, "Mismatch t_ size"); \
        (t_) = 0;                                           \
        memcpy(&(t_), ptr_, 8);                             \
        (m_) = IW_ITOHLL(t_);                               \
        (ptr_) += 8

#ifndef SIZE_T_MAX
#define SIZE_T_MAX ((size_t) -1)
#endif

#ifndef OFF_T_MIN
#define OFF_T_MIN ((off_t) (((uint64_t) 1) << (8 * sizeof(off_t) - 1)))
#endif
#ifndef OFF_T_MAX
#define OFF_T_MAX ((off_t) ~(((uint64_t) 1) << (8 * sizeof(off_t) - 1)))
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include <errno.h>

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
