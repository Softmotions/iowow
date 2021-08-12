#pragma once
#ifndef IWCONV_H
#define IWCONV_H

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

#include "basedefs.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

IW_EXTERN_C_START

#define IWFTOA_BUFSIZE 32

IW_EXPORT int64_t iwatoi(const char *str);

IW_EXPORT long double iwatof(const char *str);

IW_EXPORT int iwitoa(int64_t v, char *buf, int max);

/**
 * Convert a given floating point number to string.
 * @note Exponent notation can be used during conversion
 */
IW_EXPORT char* iwftoa(long double v, char buf[static IWFTOA_BUFSIZE]);

/**
 * Compare real(float) numbers encoded as decimal point string value.
 * @note Exponential notation not supported.
 */
IW_EXPORT int iwafcmp(const char *aptr, int asiz, const char *bptr, int bsiz);

IW_EXPORT size_t iwhex2bin(const char *hex, int hexlen, char *out, int max);

IW_EXPORT char* iwbin2hex(
  char* const                hex,
  const size_t               hex_maxlen,
  const unsigned char* const bin,
  const size_t               bin_len);

IW_EXTERN_C_END

#endif
