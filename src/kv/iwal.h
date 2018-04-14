#pragma once
#ifndef IWAL_H
#define IWAL_H

/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2018 Softmotions Ltd <info@softmotions.com>
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

/** @file
 *  @brief Write Ahead Logging (WAL) module.
 */
#include "iwkv.h"
#include "iwdlsnr.h"

IW_EXTERN_C_START

typedef struct IWAL_OPTS {
  size_t buffer_sz;
} IWAL_OPTS;

iwrc iwal_create(const IWAL_OPTS *opts, IWDLSNR **olsnr);

void iwal_reset_write_bytes_count(void);

off_t iwal_get_write_bytes_count(void);

iwrc iwal_sync(void);

void iwal_destroy(IWDLSNR *lsnr);

IW_EXTERN_C_END
#endif
