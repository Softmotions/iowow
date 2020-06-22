#pragma once
#ifndef IWSHA2_H
#define IWSHA2_H

/**************************************************************************************************
 * SHA-256 hash generator.
 * Based on https://github.com/amosnier/sha-2
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.

 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org>
 *
 *************************************************************************************************/

#include "basedefs.h"
#include <stddef.h>

IW_EXTERN_C_START

/**
 * @brief  Computes sha256 sum for given `input` data of `len` bytes.
 *
 * Limitations:
 * - Since input is a pointer in RAM, the data to hash should be in RAM, which could be a problem
 *   for large data sizes.
 * - SHA algorithms theoretically operate on bit strings. However, this implementation has no support
 *   for bit string lengths that are not multiples of eight, and it really operates on arrays of bytes.
 *   In particular, the len parameter is a number of bytes.
 *
 * @param hash Hash sum placeholder
 * @param input
 * @param len
 */
IW_EXPORT void iwsha256(const void *input, size_t len, uint8_t hash_out[32]);

IW_EXPORT void iwsha256str(const void *input, size_t len, char str_out[65]);

IW_EXPORT void iwhash2str(uint8_t hash[32], char str_out[65]);

IW_EXTERN_C_END
#endif
