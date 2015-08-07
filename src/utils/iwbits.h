#ifndef IWBITS_H
#define IWBITS_H
/**************************************************************************************************
 *  IOWOW library
 *  Copyright (C) 2012-2015 Softmotions Ltd <info@softmotions.com>
 *
 *  This file is part of IOWOW.
 *  IOWOW is free software; you can redistribute it and/or modify it under the terms of
 *  the GNU Lesser General Public License as published by the Free Software Foundation; either
 *  version 2.1 of the License or any later version. IOWOW is distributed in the hope
 *  that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 *  License for more details.
 *  You should have received a copy of the GNU Lesser General Public License along with IOWOW;
 *  if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 *  Boston, MA 02111-1307 USA.
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
IW_INLINE int iwbits_find_first_sbit64(uint64_t x) {
    int ret = 0;
    if ((x & 0xffffffff) == 0) {
        ret += 32;
        x >>= 32;
    }
    if ((x & 0xffff) == 0) {
        ret += 16;
        x >>= 16;
    }
    if ((x & 0xff) == 0) {
        ret += 8;
        x >>= 8;
    }
    if ((x & 0xf) == 0) {
        ret += 4;
        x >>= 4;
    }
    if ((x & 0x3) == 0) {
        ret += 2;
        x >>= 2;
    }
    if ((x & 0x1) == 0) {
        ret += 1;
    }
    return ret;
}

/**
 * @brief Find the last set bit number. Undefined if @a x is zero.
 */
IW_INLINE int iwbits_find_last_sbit64(uint64_t x) {
    int num = 63;
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
    x = (x << 32) | (x >> 32);   /* Swap register halves. */
    x = (x & 0x0001ffff0001ffffLL) << 15 | /* Rotate left */
        (x & 0xfffe0000fffe0000LL) >> 17;  /* 15. */
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
