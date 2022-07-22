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

IW_EXPORT IWHMAP* iwhmap_create(
  int (*cmp_fn)(const void*, const void*),
  uint32_t (*hash_key_fn)(const void*),
  void (*kv_free_fn)(void*, void*));

IW_EXPORT IWHMAP* iwhmap_create_ptr(void (*kv_free_fn)(void*, void*));

IW_EXPORT IWHMAP* iwhmap_create_u64(void (*kv_free_fn)(void*, void*));

IW_EXPORT IWHMAP* iwhmap_create_u32(void (*kv_free_fn)(void*, void*));

IW_EXPORT IWHMAP* iwhmap_create_str(void (*kv_free_fn)(void*, void*));

IW_EXPORT iwrc iwhmap_put(IWHMAP *hm, void *key, void *val);

IW_EXPORT iwrc iwhmap_put_u32(IWHMAP *hm, uint32_t key, void *val);

IW_EXPORT iwrc iwhmap_put_u64(IWHMAP *hm, uint64_t key, void *val);

IW_EXPORT iwrc iwhmap_rename(IWHMAP *hm, void *key_old, void *key_new);

IW_EXPORT bool iwhmap_remove(IWHMAP *hm, const void *key);

IW_EXPORT bool iwhmap_remove_u64(IWHMAP *hm, uint64_t key);

IW_EXPORT bool iwhmap_remove_u32(IWHMAP *hm, uint32_t key);

IW_EXPORT void* iwhmap_get(IWHMAP *hm, const void *key);

IW_EXPORT void* iwhmap_get_u64(IWHMAP *hm, uint64_t key);

IW_EXPORT void* iwhmap_get_u32(IWHMAP *hm, uint32_t key);

IW_EXPORT uint32_t iwhmap_count(IWHMAP *hm);

IW_EXPORT void iwhmap_clear(IWHMAP *hm);

IW_EXPORT void iwhmap_iter_init(IWHMAP *hm, IWHMAP_ITER *iter);

IW_EXPORT bool iwhmap_iter_next(IWHMAP_ITER *iter);

IW_EXPORT void iwhmap_destroy(IWHMAP *hm);

typedef bool (*iwhmap_lru_eviction_needed)(IWHMAP *hm, void *user_data);

IW_EXPORT bool iwhmap_lru_eviction_max_count(IWHMAP *hm, void *max_count_val);

/// Init LRU eviction mode for given `hm` map.
/// @param ev Returns `true` if needed to evict the next least recently used element.
/// @param ev_user_data Arbitrary user data from `ev` function.
IW_EXPORT void iwhmap_lru_init(IWHMAP *hm, iwhmap_lru_eviction_needed ev, void *ev_user_data);

IW_EXTERN_C_END
#endif
