#pragma once
#ifndef IWPOOL_H
#define IWPOOL_H

/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2020 Softmotions Ltd <info@softmotions.com>
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
#include <stddef.h>
#include <stdbool.h>
IW_EXTERN_C_START

#ifndef IWPOOL_POOL_SIZ
#define IWPOOL_POOL_SIZ   (8 * 1024)
#endif

struct _IWPOOL;
typedef struct _IWPOOL IWPOOL;

IW_EXPORT IWPOOL *iwpool_create(size_t siz);

IW_EXPORT void *iwpool_alloc(size_t siz, IWPOOL *pool);

IW_EXPORT void *iwpool_calloc(size_t siz, IWPOOL *pool);

IW_EXPORT char *iwpool_strndup(IWPOOL *pool, const char *str, size_t len, iwrc *rcp);

IW_EXPORT char *iwpool_strdup(IWPOOL *pool, const char *str, iwrc *rcp);

IW_EXPORT char *iwpool_printf(IWPOOL *pool, const char *format, ...);

IW_EXPORT char **iwpool_split_string(IWPOOL *pool, const char *haystack,
                                     const char *split_chars, bool ignore_whitespace);

IW_EXPORT void iwpool_destroy(IWPOOL *pool);

IW_EXPORT size_t iwpool_allocated_size(IWPOOL *pool);

IW_EXTERN_C_END
#endif
