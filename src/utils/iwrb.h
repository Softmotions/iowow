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

typedef struct {
  ssize_t pos;
  size_t  size;
  size_t  usize;
  char   *buf;
} IWRB;

typedef struct {
  const IWRB *rb;
  size_t      pos;
} IWRB_ITER;

IW_EXPORT IWRB* iwrb_create(size_t unit_size, size_t size);

IW_EXPORT void iwrb_destroy(IWRB *rb);

IW_EXPORT IWRB* iwrb_wrap(void *buf, size_t buf_len, size_t unit_size);

IW_EXPORT void iwrb_put(IWRB *rb, void *buf);

IW_EXPORT void* iwrb_peek(const IWRB *rb);

IW_EXPORT void iwrb_iter_init(const IWRB *rb, IWRB_ITER *iter);

IW_EXPORT void* iwrc_iter_next(IWRB_ITER *iter);

IW_EXTERN_C_END
#endif
