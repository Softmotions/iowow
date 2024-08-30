#pragma once
#ifndef IWRB_H
#define IWRB_H

/**************************************************************************************************
 * Ring buffer.
 *
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2024 Softmotions Ltd <info@softmotions.com>
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

IW_EXTERN_C_START;

struct iwrp;
struct iwrp_iter;
typedef struct iwrp IWRB;
typedef struct iwrp_iter IWRB_ITER;

struct iwrp {
  ssize_t pos;
  size_t  len;
  size_t  usize;
  char   *buf;
};

struct iwrp_iter {
  const IWRB *rb;
  size_t      pos;
  ssize_t     ipos;
};

IW_EXPORT IW_ALLOC struct iwrp* iwrb_create(size_t usize, size_t len);

IW_EXPORT void iwrb_clear(struct iwrp *rb);

IW_EXPORT void iwrb_destroy(struct iwrp **rbp);

IW_EXPORT struct iwrp* iwrb_wrap(void *buf, size_t len, size_t usize);

IW_EXPORT void iwrb_put(struct iwrp *rb, const void *buf);

IW_EXPORT void iwrb_back(struct iwrp *rb);

IW_EXPORT void* iwrb_peek(const struct iwrp *rb);

IW_EXPORT size_t iwrb_num_cached(const struct iwrp *rb);

IW_EXPORT void iwrb_iter_init(const struct iwrp *rb, IWRB_ITER *iter);

IW_EXPORT void* iwrb_iter_prev(IWRB_ITER *iter);

IW_EXTERN_C_END;
#endif
