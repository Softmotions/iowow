#pragma once
#ifndef IWSTREE_H
#define IWSTREE_H

/*
   Copyright (c) 2011, Willem-Hendrik Thiart
   Copyright (c) 2012-2021 Softmotions Ltd <info@softmotions.com>
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
 * The names of its contributors may not be used to endorse or promote
      products derived from this software without specific prior written
      permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED. IN NO EVENT SHALL WILLEM-HENDRIK THIART BE LIABLE FOR ANY
   DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "basedefs.h"
#include <stdbool.h>

IW_EXTERN_C_START

typedef struct {
  void *root;
  int (*cmp)(const void*, const void*);
  void (*kvfree)(void*, void*);
  int count;
} IWSTREE;

typedef struct _IWSTREE_ITER {
  IWSTREE *st;        /**< Owner tree */
  int      spos;      /**< Position of top element stack */
  int      slen;      /**< Max number of elements in stack */
  void   **stack;     /**< Bottom of iterator stack */
} IWSTREE_ITER;

typedef bool (*IWSTREE_VISITOR)(void *key, void *val, void *op, iwrc *rcp);

/**
 * @brief Constructs new splay tree
 *
 * @param cmp Keys compare function. If zero address pointers will be compared.
 * @param kvfree Optional `(key, value)` free function
 * @return IWSTREE* or NULL if memory allocation failed
 */
IW_EXPORT IW_ALLOC IWSTREE *iwstree_create(
  int (*cmp)(const void*, const void*),
  void (*kvfree)(void*, void*)
  );

IW_EXPORT int iwstree_str_cmp(const void *o1, const void *o2);

IW_EXPORT int iwstree_uint64_cmp(const void *o1, const void *o2);

IW_EXPORT int iwstree_int64_cmp(const void *o1, const void *o2);

IW_EXPORT void iwstree_clear(IWSTREE *st);

IW_EXPORT void iwstree_destroy(IWSTREE *st);

IW_EXPORT int iwstree_is_empty(IWSTREE *st);

IW_EXPORT void *iwstree_remove(IWSTREE *st, const void *key);

IW_EXPORT void *iwstree_get(IWSTREE *st, const void *key);

IW_EXPORT int iwstree_count(IWSTREE *st);

IW_EXPORT void *iwstree_peek(IWSTREE *st);

IW_EXPORT iwrc iwstree_put(IWSTREE *st, void *key, void *value);

IW_EXPORT iwrc iwstree_put_overwrite(IWSTREE *st, void *key, void *value);

IW_EXPORT iwrc iwstree_visit(IWSTREE *st, IWSTREE_VISITOR visitor, void *op);

IW_EXPORT iwrc iwstree_iter_init(IWSTREE *st, IWSTREE_ITER *iter);

IW_EXPORT bool iwstree_iter_has_next(IWSTREE_ITER *iter);

IW_EXPORT iwrc iwstree_iter_next(IWSTREE_ITER *iter, void **key, void **val);

IW_EXPORT void iwstree_iter_close(IWSTREE_ITER *iter);

IW_EXTERN_C_END
#endif
