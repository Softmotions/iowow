#pragma once
#ifndef IWUTILS_H
#define IWUTILS_H

/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2022 Softmotions Ltd <info@softmotions.com>
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

IW_EXTERN_C_START

#define IW_RANGES_OVERLAP(IW_s1_, IW_e1_, IW_s2_, IW_e2_) \
  (  ((IW_e1_) > (IW_s2_) && (IW_e1_) <= (IW_e2_))          \
  || ((IW_s1_) >= (IW_s2_) && (IW_s1_) < (IW_e2_))          \
  || ((IW_s1_) <= (IW_s2_) && (IW_e1_) >= (IW_e2_)))

///////////////////////////////////////////////////////////////////////////
//                    Variable length number encoding                    //
///////////////////////////////////////////////////////////////////////////

/* set a buffer for a variable length 32 bit number */
#define IW_SETVNUMBUF(len_, buf_, num_) \
  do { \
    int32_t _num_ = (num_); \
    if (_num_ == 0) { \
      ((signed char*) (buf_))[0] = 0; \
      (len_) = 1; \
    } else { \
      (len_) = 0; \
      while (_num_ > 0) { \
        int _rem_ = _num_ & 0x7f; \
        _num_ >>= 7; \
        if (_num_ > 0) { \
          ((signed char*) (buf_))[(len_)] = ~(_rem_); \
        } else { \
          ((signed char*) (buf_))[(len_)] = _rem_; \
        } \
        (len_)++; \
      } \
    } \
  } while (0)

/* set a buffer for a variable length 64 number */
#define IW_SETVNUMBUF64(len_, buf_, num_) \
  do { \
    int64_t _num_ = (num_); \
    if (_num_ == 0) { \
      ((signed char*) (buf_))[0] = 0; \
      (len_) = 1; \
    } else { \
      (len_) = 0; \
      while (_num_ > 0) { \
        int _rem_ = _num_ & 0x7f; \
        _num_ >>= 7; \
        if (_num_ > 0) { \
          ((signed char*) (buf_))[(len_)] = ~(_rem_); \
        } else { \
          ((signed char*) (buf_))[(len_)] = _rem_; \
        } \
        (len_)++; \
      } \
    } \
  } while (0)


/* read a 32 bit variable length buffer */
#define IW_READVNUMBUF(buf_, num_, step_) \
  do { \
    (num_) = 0; \
    int32_t _base_ = 1; \
    int _i_ = 0; \
    while (1) { \
      if (((const signed char*) (buf_))[_i_] >= 0) { \
        (num_) += _base_ * ((const signed char*) (buf_))[_i_]; \
        break; \
      } \
      (num_) += _base_ * ~(((const signed char*) (buf_))[_i_]); \
      _base_ <<= 7; \
      _i_++; \
    } \
    (step_) = _i_ + 1; \
  } while (0)

/* read a 64 bit variable length buffer */
#define IW_READVNUMBUF64(buf_, num_, step_) \
  do { \
    (num_) = 0; \
    int64_t _base_ = 1; \
    int _i_ = 0; \
    while (1) { \
      if (((const signed char*) (buf_))[_i_] >= 0) { \
        (num_) += _base_ * ((const signed char*) (buf_))[_i_]; \
        break; \
      } \
      (num_) += _base_ * ~(((const signed char*) (buf_))[_i_]); \
      _base_ <<= 7; \
      _i_++; \
    } \
    (step_) = _i_ + 1; \
  } while (0)


/* read a 64 bit variable length buffer */
#define IW_READVNUMBUF64_2(buf_, num_) \
  do { \
    (num_) = 0; \
    int64_t _base_ = 1; \
    int _i_ = 0; \
    while (1) { \
      if (((const signed char*) (buf_))[_i_] >= 0) { \
        (num_) += _base_ * ((const signed char*) (buf_))[_i_]; \
        break; \
      } \
      (num_) += _base_ * ~(((const signed char*) (buf_))[_i_]); \
      _base_ <<= 7; \
      _i_++; \
    } \
  } while (0)


#define IW_VNUMBUFSZ 10

#define IW_VNUMSIZE32(num_) \
  ((num_) < 0x80ULL ? 1   \
   : (num_) < 0x4000ULL ? 2   \
   : (num_) < 0x200000ULL ? 3   \
   : (num_) < 0x10000000ULL ? 4 : 5)

/* Size of variable number in bytes */
#ifdef IW_32
#define IW_VNUMSIZE IW_VNUMSIZE32
#else
#define IW_VNUMSIZE(num_) \
  ((num_) < 0x80ULL ? 1   \
   : (num_) < 0x4000ULL ? 2   \
   : (num_) < 0x200000ULL ? 3   \
   : (num_) < 0x10000000ULL ? 4   \
   : (num_) < 0x800000000ULL ? 5   \
   : (num_) < 0x40000000000ULL ? 6   \
   : (num_) < 0x2000000000000ULL ? 7   \
   : (num_) < 0x100000000000000ULL ? 8   \
   : (num_) < 0x8000000000000000ULL ? 9 : 10)
#endif

/* Lexicographic comparison of values */
#define IW_CMP(rv_, vp1_, vp1sz_, vp2_, vp2sz_) \
  do { \
    (rv_) = 0; \
    int min_ = (vp1sz_) < (vp2sz_) ? (vp1sz_) : (vp2sz_); \
    for (int i = 0; i < min_; i++) { \
      (rv_) = (int) (((const uint8_t*) (vp1_))[i] - ((const uint8_t*) (vp2_))[i]); \
      if (rv_) { \
        break; \
      } \
    } \
    if ((rv_) == 0) (rv_) = (vp1sz_) - (vp2sz_); \
  } while (0)


/* Lexicographic comparison common prefix of values */
#define IW_CMP2(rv_, vp1_, vp1sz_, vp2_, vp2sz_) \
  do { \
    (rv_) = 0; \
    int min_ = (vp1sz_) < (vp2sz_) ? (vp1sz_) : (vp2sz_); \
    for (int i = 0; i < min_; i++) { \
      (rv_) = (int) (((const uint8_t*) (vp1_))[i] - ((const uint8_t*) (vp2_))[i]); \
      if (rv_) { \
        break; \
      } \
    } \
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
 * @brief Create X31 hash value.
 */
IW_EXPORT uint32_t iwu_x31_u32_hash(const char *data);

IW_EXTERN_C_END

#endif
