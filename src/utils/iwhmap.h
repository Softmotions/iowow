#pragma once
#ifndef IWHMAP_H
#define IWHMAP_H

/**************************************************************************************************
 * Hashmap implementation.
 *
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
IW_EXTERN_C_START

struct _IWHMAP;
typedef struct _IWHMAP IWHMAP;

typedef struct {
  IWHMAP     *hm;
  const void *key;
  const void *val;
  uint32_t    bucket;
  int32_t     entry;
} IWHMAP_ITER;

/**
 * @brief Key/Value free callback which uses standard `free()` deallocation.
 *
 * @param key Pointer to key or zero.
 * @param val Pointer to value of zero.
 */
IW_EXPORT void iwhmap_kv_free(void *key, void *val);

IW_EXPORT IWHMAP *iwhmap_create(
  int (*cmp_fn)(const void*, const void*),
  uint32_t (*hash_key_fn)(const void*),
  void (*kv_free_fn)(void*, void*));

IW_EXPORT IWHMAP *iwhmap_create_i64(void (*kv_free_fn)(void*, void*));

IW_EXPORT IWHMAP *iwhmap_create_i32(void (*kv_free_fn)(void*, void*));

IW_EXPORT IWHMAP *iwhmap_create_str(void (*kv_free_fn)(void*, void*));

IW_EXPORT iwrc iwhmap_put(IWHMAP *hm, void *key, void *val);

IW_EXPORT void iwhmap_remove(IWHMAP *hm, const void *key);

IW_EXPORT void *iwhmap_get(IWHMAP *hm, const void *key);

IW_EXPORT int iwhmap_count(IWHMAP *hm);

IW_EXPORT void iwhmap_clear(IWHMAP *hm);

IW_EXPORT void iwhmap_iter_init(IWHMAP *hm, IWHMAP_ITER *iter);

IW_EXPORT bool iwhmap_iter_next(IWHMAP_ITER *iter);

IW_EXPORT void iwhmap_destroy(IWHMAP *hm);

IW_EXTERN_C_END
#endif
