#pragma once
#ifndef IWCONV_H
#define IWCONV_H

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

#include "basedefs.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

IW_EXTERN_C_START;

/**
 * @brief Converts the leading decimal number of `str` to `int64_t`.
 *
 * Leading whitespace and an optional `+`/`-` sign are accepted, the conversion stops at the first
 * character which is not a digit. The `inf` value is converted to `INT64_MAX`/`INT64_MIN`.
 * Overflow is not detected.
 *
 * @param str String to convert. Not zero.
 */
IW_EXPORT int64_t iwatoi(const char *str);

/**
 * @brief Same as iwatoi() but converts at most `len` bytes of `str`.
 */
IW_EXPORT int64_t iwatoi2(const char *str, size_t len);

/**
 * @brief Converts the leading decimal number of `str` to `long double`.
 *
 * Leading whitespace, an optional sign, a fractional part and an `e`/`E` exponent are accepted.
 * The conversion stops at the first character which does not belong to the number.
 * The `inf` value is converted to `HUGE_VAL`/`-HUGE_VAL`.
 *
 * @param str String to convert. Not zero.
 */
IW_EXPORT long double iwatof(const char *str);

/**
 * @brief Converts `v` to its `\0` terminated decimal representation.
 *
 * @param v   Value to convert.
 * @param buf Output buffer.
 * @param max Size of the `buf` buffer.
 * @return Length of the full decimal representation. If `buf` is too small the result is
 *         truncated to `max - 1` characters (`snprintf()` semantics).
 */
IW_EXPORT int iwitoa(int64_t v, char *buf, int max);

/**
 * Convert a given floating point number to string.
 * @note Exponent notation can be used during conversion
 */
IW_EXPORT char* iwftoa(long double v, char buf[IWNUMBUF_SIZE]);

/**
 * Compare real(float) numbers encoded as decimal point string value.
 * @note Exponential notation not supported.
 */
IW_EXPORT int iwafcmp(const char *aptr, int asiz, const char *bptr, int bsiz);

/**
 * @brief Decodes the hexadecimal string `hex` into the `out` buffer.
 *
 * An odd number of the hexadecimal characters is allowed, the missing leading `0` is added.
 *
 * @param hex    Hexadecimal string to decode.
 * @param hexlen Number of the characters in `hex`.
 * @param out    Output buffer.
 * @param max    Size of the `out` buffer. The decoding stops when the buffer is full.
 * @return Number of the decoded bytes.
 */
IW_EXPORT size_t iwhex2bin(const char *hex, int hexlen, char *out, int max);

/**
 * @brief Encodes the `bin` buffer as a lowercase hexadecimal `\0` terminated string.
 *
 * @param hex        Output buffer.
 * @param hex_maxlen Size of the `hex` buffer, it must be greater than `2 * bin_len`.
 * @param bin        Binary data to encode.
 * @param bin_len    Number of the bytes in `bin`.
 * @return The `hex` buffer, or zero if the output buffer is not big enough.
 */
IW_EXPORT char* iwbin2hex(
  char* const                hex,
  const size_t               hex_maxlen,
  const unsigned char* const bin,
  const size_t               bin_len);

/**
 * @brief Converts the whole `v` string to `long double`.
 *
 * The conversion is independent of the current `LC_NUMERIC` locale.
 *
 * @param v         String to convert, it must contain a number and nothing else.
 * @param [out] rcp Holder of the `IW_ERROR_INVALID_ARGS` error code if `v` is not a valid number.
 * @return Converted value, or zero on error.
 */
IW_EXPORT long double iw_strtold(const char *v, iwrc *rcp);

/**
 * @brief Converts the whole `v` string to `double`.
 *
 * @see iw_strtold()
 */
IW_EXPORT double iw_strtod(const char *v, iwrc *rcp);

/**
 * @brief Converts a decimal string to `double` independently of the current `LC_NUMERIC` locale.
 *
 * The decimal separator of the parsed value is always `.` and the conversion is correctly rounded.
 * The common decimal numbers (integer mantissa within 53 bits and a decimal exponent within
 * `[-22, 22]`) are parsed by a fast path which is exact by construction, anything else is passed
 * to the `strtod()` running in the C locale.
 *
 * @param str String to parse.
 * @param [out] end Optional holder of the position right after the parsed number.
 */
IW_EXPORT double iw_strtod_c(const char *str, char **end);

/// Backward compatible alias of iw_strtod_c().
#define iwstrtod iw_strtod_c

/**
 * @brief Same as iw_strtod_c() but returns a `long double`.
 *
 * @note There is no fast path for `long double`: the value is always converted by `strtold()`
 *       running in the C locale.
 */
IW_EXPORT long double iw_strtold_c(const char *str, char **end);

/**
 * @brief `snprintf()` which always uses the C numeric locale.
 *
 * Floating point numbers are formatted with `.` as the decimal separator independently of the
 * current `LC_NUMERIC` locale.
 *
 * @return The `snprintf()` result: the number of characters that would be written, or a negative
 *         value on an output error.
 */
IW_EXPORT int iw_snprintf_c(char *buf, size_t size, const char *format, ...)
  __attribute__((format(__printf__, 3, 4)));

/**
 * @brief Converts the whole `v` string to `long int`.
 *
 * @param v         String to convert, it must contain a number and nothing else.
 * @param base      Numeric base, `0` means auto detection.
 * @param [out] rcp Holder of the `IW_ERROR_INVALID_ARGS` error code if `v` is not a valid number.
 * @return Converted value, or zero on error.
 */
IW_EXPORT long int iw_strtol(const char *v, int base, iwrc *rcp);

/// Same as iw_strtol() but returns a `long long`.
IW_EXPORT long long iw_strtoll(const char *v, int base, iwrc *rcp);

/// Same as iw_strtol() but returns an `unsigned long int`.
IW_EXPORT unsigned long int iw_strtoul(const char *v, int base, iwrc *rcp);

/// Same as iw_strtol() but returns an `unsigned long long`.
IW_EXPORT unsigned long long iw_strtoull(const char *v, int base, iwrc *rcp);

/// Perform a percent decoding-in place.
IW_EXPORT iwrc iw_decode_percent_inplace(char *buf, size_t len, size_t *out_len);

IW_EXTERN_C_END;

#endif
