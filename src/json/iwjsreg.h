#pragma once
#ifndef IWJSREG_H
#define IWJSREG_H

/**************************************************************************************************
 * IWOWOW A simple JSON registry stored in single file supporting atomic updates.
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
#include <pthread.h>

IW_EXTERN_C_START

#define IWJSREG_FORMAT_BINARY 0x01U
#define IWJSREG_AUTOSYNC      0x02U
#define IWJSREG_READONLY      0x04U

struct iwjsreg;
struct iwjsreg_spec {
  const char       *path;
  pthread_rwlock_t *rwl; ///< Optional RWL used for locking (Useful for shared-mem interprocess locks)
                         ///  If not set, and internal in-process pthread_rwlock_t will be created.
  unsigned flags;
};

IW_EXPORT iwrc iwjsreg_open(struct iwjsreg_spec *spec, struct iwjsreg **out);

IW_EXPORT iwrc iwjsreg_close(struct iwjsreg**);

IW_EXPORT iwrc iwjsreg_sync(struct iwjsreg*);

IW_EXPORT iwrc iwjsreg_remove(struct iwjsreg*, const char *key);

IW_EXPORT iwrc iwjsreg_set_str(struct iwjsreg*, const char *key, const char *value);

IW_EXPORT iwrc iwjsreg_set_i64(struct iwjsreg*, const char *key, int64_t value);

IW_EXPORT iwrc iwjsreg_inc_i64(struct iwjsreg*, const char *key, int64_t inc, int64_t *out);

IW_EXPORT iwrc iwjsreg_set_bool(struct iwjsreg *reg, const char *key, bool value);

IW_EXPORT iwrc iwjsreg_get_str(struct iwjsreg*, const char *key, char **out);

IW_EXPORT iwrc iwjsreg_get_i64(struct iwjsreg*, const char *key, int64_t *out);

IW_EXPORT iwrc iwjsreg_get_bool(struct iwjsreg*, const char *key, bool *out);

IW_EXTERN_C_END

#endif