#pragma once
#ifndef IWUTILS_H
#define IWUTILS_H

/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2026 Softmotions Ltd <info@softmotions.com>
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
 * @author Anton Adamansky (adamansky@softmotions.com)
 */

#include "basedefs.h"
#include "iwxstr.h"
#include <math.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

IW_EXTERN_C_START;

#define IW_RANGES_OVERLAP(IW_s1_, IW_e1_, IW_s2_, IW_e2_) \
        (  ((IW_e1_) > (IW_s2_) && (IW_e1_) <= (IW_e2_))  \
        || ((IW_s1_) >= (IW_s2_) && (IW_s1_) < (IW_e2_))  \
        || ((IW_s1_) <= (IW_s2_) && (IW_e1_) >= (IW_e2_)))

///////////////////////////////////////////////////////////////////////////
//                    Variable length number encoding                    //
///////////////////////////////////////////////////////////////////////////

IW_INLINE int iw_setvnumbuf32(void *buf, uint32_t n) {
  uint8_t *p = (uint8_t*) buf;
  if (IW_LIKELY(n < 0x80U)) {
    p[0] = (uint8_t) n;
    return 1;
  }
  p[0] = (uint8_t) ~((uint8_t) (n & 0x7fU));
  if (n < 0x4000U) {
    p[1] = (uint8_t) ((n >> 7) & 0x7fU);
    return 2;
  }
  p[1] = (uint8_t) ~((uint8_t) ((n >> 7) & 0x7fU));
  if (n < 0x200000U) {
    p[2] = (uint8_t) ((n >> 14) & 0x7fU);
    return 3;
  }
  p[2] = (uint8_t) ~((uint8_t) ((n >> 14) & 0x7fU));
  if (n < 0x10000000U) {
    p[3] = (uint8_t) ((n >> 21) & 0x7fU);
    return 4;
  }
  p[3] = (uint8_t) ~((uint8_t) ((n >> 21) & 0x7fU));
  p[4] = (uint8_t) ((n >> 28) & 0x0fU);
  return 5;
}

IW_INLINE int iw_setvnumbuf64(void *buf, uint64_t n) {
  uint8_t *p = (uint8_t*) buf;
  if (IW_LIKELY(n < UINT64_C(0x80))) {
    p[0] = (uint8_t) n;
    return 1;
  }
  p[0] = (uint8_t) ~((uint8_t) (n & UINT64_C(0x7f)));
  if (n < UINT64_C(0x4000)) {
    p[1] = (uint8_t) ((n >> 7) & UINT64_C(0x7f));
    return 2;
  }
  p[1] = (uint8_t) ~((uint8_t) ((n >> 7) & UINT64_C(0x7f)));
  if (n < UINT64_C(0x200000)) {
    p[2] = (uint8_t) ((n >> 14) & UINT64_C(0x7f));
    return 3;
  }
  p[2] = (uint8_t) ~((uint8_t) ((n >> 14) & UINT64_C(0x7f)));
  if (n < UINT64_C(0x10000000)) {
    p[3] = (uint8_t) ((n >> 21) & UINT64_C(0x7f));
    return 4;
  }
  p[3] = (uint8_t) ~((uint8_t) ((n >> 21) & UINT64_C(0x7f)));
  if (n < UINT64_C(0x800000000)) {
    p[4] = (uint8_t) ((n >> 28) & UINT64_C(0x7f));
    return 5;
  }
  p[4] = (uint8_t) ~((uint8_t) ((n >> 28) & UINT64_C(0x7f)));
  if (n < UINT64_C(0x40000000000)) {
    p[5] = (uint8_t) ((n >> 35) & UINT64_C(0x7f));
    return 6;
  }
  p[5] = (uint8_t) ~((uint8_t) ((n >> 35) & UINT64_C(0x7f)));
  if (n < UINT64_C(0x2000000000000)) {
    p[6] = (uint8_t) ((n >> 42) & UINT64_C(0x7f));
    return 7;
  }
  p[6] = (uint8_t) ~((uint8_t) ((n >> 42) & UINT64_C(0x7f)));
  if (n < UINT64_C(0x100000000000000)) {
    p[7] = (uint8_t) ((n >> 49) & UINT64_C(0x7f));
    return 8;
  }
  p[7] = (uint8_t) ~((uint8_t) ((n >> 49) & UINT64_C(0x7f)));
  if (n < (UINT64_C(1) << 63)) {
    p[8] = (uint8_t) ((n >> 56) & UINT64_C(0x7f));
    return 9;
  }
  p[8] = (uint8_t) ~((uint8_t) ((n >> 56) & UINT64_C(0x7f)));
  p[9] = (uint8_t) ((n >> 63) & UINT64_C(0x01));
  return 10;
}

IW_INLINE uint32_t iw_readvnumbuf32(const void *buf, int *step) {
  const uint8_t *p = (const uint8_t*) buf;
  uint8_t b = p[0];
  if (IW_LIKELY(b < 0x80U)) {
    if (step) {
      *step = 1;
    }
    return b;
  }
  uint32_t n = ((uint32_t) ~b) & 0x7fU;
  b = p[1];
  if (b < 0x80U) {
    if (step) {
      *step = 2;
    }
    return n | ((uint32_t) b << 7);
  }
  n |= (((uint32_t) ~b) & 0x7fU) << 7;
  b = p[2];
  if (b < 0x80U) {
    if (step) {
      *step = 3;
    }
    return n | ((uint32_t) b << 14);
  }
  n |= (((uint32_t) ~b) & 0x7fU) << 14;
  b = p[3];
  if (b < 0x80U) {
    if (step) {
      *step = 4;
    }
    return n | ((uint32_t) b << 21);
  }
  n |= (((uint32_t) ~b) & 0x7fU) << 21;
  b = p[4];
  if (step) {
    *step = 5;
  }
  return n | ((uint32_t) b << 28);
}

IW_INLINE uint64_t iw_readvnumbuf64(const void *buf, int *step) {
  const uint8_t *p = (const uint8_t*) buf;
  uint8_t b = p[0];
  if (IW_LIKELY(b < 0x80U)) {
    if (step) {
      *step = 1;
    }
    return b;
  }
  uint64_t n = ((uint64_t) ~b) & UINT64_C(0x7f);
  b = p[1];
  if (b < 0x80U) {
    if (step) {
      *step = 2;
    }
    return n | ((uint64_t) b << 7);
  }
  n |= (((uint64_t) ~b) & UINT64_C(0x7f)) << 7;
  b = p[2];
  if (b < 0x80U) {
    if (step) {
      *step = 3;
    }
    return n | ((uint64_t) b << 14);
  }
  n |= (((uint64_t) ~b) & UINT64_C(0x7f)) << 14;
  b = p[3];
  if (b < 0x80U) {
    if (step) {
      *step = 4;
    }
    return n | ((uint64_t) b << 21);
  }
  n |= (((uint64_t) ~b) & UINT64_C(0x7f)) << 21;
  b = p[4];
  if (b < 0x80U) {
    if (step) {
      *step = 5;
    }
    return n | ((uint64_t) b << 28);
  }
  n |= (((uint64_t) ~b) & UINT64_C(0x7f)) << 28;
  b = p[5];
  if (b < 0x80U) {
    if (step) {
      *step = 6;
    }
    return n | ((uint64_t) b << 35);
  }
  n |= (((uint64_t) ~b) & UINT64_C(0x7f)) << 35;
  b = p[6];
  if (b < 0x80U) {
    if (step) {
      *step = 7;
    }
    return n | ((uint64_t) b << 42);
  }
  n |= (((uint64_t) ~b) & UINT64_C(0x7f)) << 42;
  b = p[7];
  if (b < 0x80U) {
    if (step) {
      *step = 8;
    }
    return n | ((uint64_t) b << 49);
  }
  n |= (((uint64_t) ~b) & UINT64_C(0x7f)) << 49;
  b = p[8];
  if (b < 0x80U) {
    if (step) {
      *step = 9;
    }
    return n | ((uint64_t) b << 56);
  }
  n |= (((uint64_t) ~b) & UINT64_C(0x7f)) << 56;
  b = p[9];
  if (step) {
    *step = 10;
  }
  return n | ((uint64_t) b << 63);
}

#define IW_READVNUMBUF(buf_, num_, step_)                \
        do {                                             \
          int _iw_step_;                                 \
          (num_) = iw_readvnumbuf32((buf_), &_iw_step_); \
          (step_) = _iw_step_;                           \
        } while (0)

#define IW_READVNUMBUF64(buf_, num_, step_)              \
        do {                                             \
          int _iw_step_;                                 \
          (num_) = iw_readvnumbuf64((buf_), &_iw_step_); \
          (step_) = _iw_step_;                           \
        } while (0)

#define IW_READVNUMBUF64_2(buf_, num_)          \
        do {                                    \
          (num_) = iw_readvnumbuf64((buf_), 0); \
        } while (0)

#define IW_SETVNUMBUF(len_, buf_, num_)                        \
        do {                                                   \
          (len_) = iw_setvnumbuf32((buf_), (uint32_t) (num_)); \
        } while (0)

#define IW_SETVNUMBUF64(len_, buf_, num_)                      \
        do {                                                   \
          (len_) = iw_setvnumbuf64((buf_), (uint64_t) (num_)); \
        } while (0)


#define IW_VNUMBUFSZ 10

#define IW_VNUMSIZE32(num_)         \
        ((num_) < 0x80ULL ? 1       \
         : (num_) < 0x4000ULL ? 2   \
         : (num_) < 0x200000ULL ? 3 \
         : (num_) < 0x10000000ULL ? 4 : 5)

/* Size of variable number in bytes */
#ifdef IW_32
#define IW_VNUMSIZE IW_VNUMSIZE32
#else
#define IW_VNUMSIZE(num_)                    \
        ((num_) < 0x80ULL ? 1                \
         : (num_) < 0x4000ULL ? 2            \
         : (num_) < 0x200000ULL ? 3          \
         : (num_) < 0x10000000ULL ? 4        \
         : (num_) < 0x800000000ULL ? 5       \
         : (num_) < 0x40000000000ULL ? 6     \
         : (num_) < 0x2000000000000ULL ? 7   \
         : (num_) < 0x100000000000000ULL ? 8 \
         : (num_) < 0x8000000000000000ULL ? 9 : 10)
#endif

/* Lexicographic comparison of values */
#define IW_CMP(rv_, vp1_, vp1sz_, vp2_, vp2sz_)                                          \
        do {                                                                             \
          (rv_) = 0;                                                                     \
          int min_ = (vp1sz_) < (vp2sz_) ? (vp1sz_) : (vp2sz_);                          \
          for (int i = 0; i < min_; i++) {                                               \
            (rv_) = (int) (((const uint8_t*) (vp1_))[i] - ((const uint8_t*) (vp2_))[i]); \
            if (rv_) {                                                                   \
              break;                                                                     \
            }                                                                            \
          }                                                                              \
          if ((rv_) == 0)(rv_) = (vp1sz_) - (vp2sz_);                                    \
        } while (0)


/* Lexicographic comparison common prefix of values */
#define IW_CMP2(rv_, vp1_, vp1sz_, vp2_, vp2sz_)                                         \
        do {                                                                             \
          (rv_) = 0;                                                                     \
          int min_ = (vp1sz_) < (vp2sz_) ? (vp1sz_) : (vp2sz_);                          \
          for (int i = 0; i < min_; i++) {                                               \
            (rv_) = (int) (((const uint8_t*) (vp1_))[i] - ((const uint8_t*) (vp2_))[i]); \
            if (rv_) {                                                                   \
              break;                                                                     \
            }                                                                            \
          }                                                                              \
        } while (0)

IW_EXPORT iwrc iwu_init(void);

/**
 * @brief Set seed to random generator
 */
IW_EXPORT void iwu_rand_seed(uint32_t seed);

/**
 * @brief Generate random in [0, 0xffffffff]
 */
IW_EXPORT uint32_t iwu_rand_u32(void);

/**
 * @brief Create normal distributed random number.
 * @param avg Distribution pivot
 * @param sd Avg square deviation
 */
IW_EXPORT double_t iwu_rand_dnorm(double_t avg, double_t sd);

/**
 * @brief Create uniform distributed integer random number in: `[0, range)`
 */
IW_EXPORT uint32_t iwu_rand_range(uint32_t range);

/**
 * @brief Create normal distributed integer random number.
 */
IW_EXPORT uint32_t iwu_rand_inorm(int range);

IW_EXPORT int iwlog2_32(uint32_t val);

IW_EXPORT int iwlog2_64(uint64_t val);

IW_EXPORT uint32_t iwu_crc32(const uint8_t *buf, int len, uint32_t init);

/**
 * @brief Replaces a char @a sch with @a rch in a null terminated @a data char buffer.
 */
IW_EXPORT char* iwu_replace_char(char *data, char sch, char rch);

/**
 * @brief Returns `\0` terminated string as replacement
 * of given `key`.
 */
typedef const char* (*iwu_replace_mapper)(const char *key, void *op);

/**
 * @brief Replaces all occurriences of `keys`
 * in `data` using `mapper` function.
 *
 * @param [out] result Resulting xstr buffer.
 * @param data   Data to search
 * @param datalen Length of data buffer
 * @param keys   Array of keys to search
 * @param keysz  Number of elements in keys array.
 *               Negative for NULL terminated arrays.
 * @param mapper Replacement mapper
 * @param mapper_op Replacement mapper opaque data
 */
IW_EXPORT iwrc iwu_replace(
  IWXSTR           **result,
  const char        *data,
  int                datalen,
  const char        *keys[],
  int                keysz,
  iwu_replace_mapper mapper,
  void              *mapper_op);

IW_EXPORT int iwu_cmp_files(FILE *f1, FILE *f2, bool verbose);

IW_EXPORT char* iwu_file_read_as_buf(const char *path);

IW_EXPORT char* iwu_file_read_as_buf_len(const char *path, size_t *out_len);

/**
 * Read file to memory allocated buffer.
 * @param path File path
 * @param len_max Maxim number of bytes to read. If -1 then no limit set.
 * @param [out] Number of of bytes read actually.
 * @returns Zero(\0) terminated file data buffer. Or NULL in the case of error.
 */
IW_EXPORT char* iwu_file_read_as_buf_max(const char *path, ssize_t len_max, size_t *out_len);

/**
 * @brief Create X31 hash value.
 */
static inline uint32_t iwu_x31_u32_hash(const char *s) {
  uint32_t h = (uint32_t) *s;
  if (h) {
    for (++s; *s; ++s) {
      h = (h << 5) - h + (uint32_t) *s;
    }
  }
  return h;
}

static inline size_t iwu_strnlen(const char *s, size_t maxlen) {
  size_t i;
  for (i = 0; i < maxlen && s[i]; ++i) ;
  return i;
}

static inline char* iwu_strncpy(char *dst, const char *src, size_t dst_sz) {
  if (dst_sz > 1) {
    size_t len = iwu_strnlen(src, dst_sz - 1);
    memcpy(dst, src, len);
    dst[len] = '\0';
  } else if (dst_sz) {
    dst[0] = '\0';
  }
  return dst;
}

static inline char* iwu_strnncpy(char *dst, const char *src, size_t src_len, size_t dst_sz) {
  if (dst_sz > 1 && src_len) {
    size_t len = MIN(src_len, dst_sz - 1);
    memcpy(dst, src, len);
    dst[len] = '\0';
  } else if (dst_sz) {
    dst[0] = '\0';
  }
  return dst;
}

IW_EXTERN_C_END;

#endif
