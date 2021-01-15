#ifndef IWBITS_H
#define IWBITS_H

//
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


/** @file
 *  @brief Various bit manipulation utility methods.
 */

#include "basedefs.h"
#include <stdint.h>

IW_EXTERN_C_START

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wlong-long"
#endif

/**
 * @brief Find the first set bit number. Undefined if @a x is zero.
 */
IW_INLINE uint8_t iwbits_find_first_sbit64(uint64_t x) {
  //return __builtin_ffsll(x) - 1;
  uint8_t ret = 0;
  if ((x & 0xffffffffU) == 0) {
    ret += 32;
    x >>= 32;
  }
  if ((x & 0xffffU) == 0) {
    ret += 16;
    x >>= 16;
  }
  if ((x & 0xffU) == 0) {
    ret += 8;
    x >>= 8;
  }
  if ((x & 0xfU) == 0) {
    ret += 4;
    x >>= 4;
  }
  if ((x & 0x3U) == 0) {
    ret += 2;
    x >>= 2;
  }
  if ((x & 0x1U) == 0) {
    ret += 1;
  }
  return ret;
}

/**
 * @brief Find the last set bit number. Undefined if @a x is zero.
 */
IW_INLINE uint8_t iwbits_find_last_sbit64(uint64_t x) {
  //return 63 - __builtin_clzll(x);
  uint8_t num = 63;
  if ((x & 0xffffffff00000000ULL) == 0) {
    num -= 32;
    x <<= 32;
  }
  if ((x & 0xffff000000000000ULL) == 0) {
    num -= 16;
    x <<= 16;
  }
  if ((x & 0xff00000000000000ULL) == 0) {
    num -= 8;
    x <<= 8;
  }
  if ((x & 0xf000000000000000ULL) == 0) {
    num -= 4;
    x <<= 4;
  }
  if ((x & 0xc000000000000000ULL) == 0) {
    num -= 2;
    x <<= 2;
  }
  if ((x & 0x8000000000000000ULL) == 0) {
    num -= 1;
  }
  return num;
}

/**
 * @brief Reverese bits in a given @a x
 * Thanks to: http://www.hackersdelight.org/hdcodetxt/reverse.c.txt
 */
IW_INLINE uint64_t iwbits_reverse_64(uint64_t x) {
  uint64_t t;
  x = (x << 32) | (x >> 32);              /* Swap register halves. */
  x = (x & 0x0001ffff0001ffffLL) << 15    /* Rotate left */
      | (x & 0xfffe0000fffe0000LL) >> 17; /* 15. */
  t = (x ^ (x >> 10)) & 0x003f801f003f801fLL;
  x = (t | (t << 10)) ^ x;
  t = (x ^ (x >> 4)) & 0x0e0384210e038421LL;
  x = (t | (t << 4)) ^ x;
  t = (x ^ (x >> 2)) & 0x2248884222488842LL;
  x = (t | (t << 2)) ^ x;
  return x;
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

IW_EXTERN_C_END
#endif
