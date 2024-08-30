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
#include "iwjson.h"
#include <pthread.h>

IW_EXTERN_C_START;

#define IWJSREG_FORMAT_BINARY 0x01U
#define IWJSREG_AUTOSYNC      0x02U
#define IWJSREG_READONLY      0x04U

struct iwjsreg;
struct iwjsreg_spec {
  const char       *path;
  pthread_rwlock_t *rwl;        ///< Optional RWL provided for locking.
  iwrc     (*wlock_fn)(void*);  ///< Optional exclusive write lock function to set read/write registry lock.
  iwrc     (*rlock_fn)(void*);  ///< Optional shared read lock function to set the lock.
  iwrc     (*unlock_fn)(void*); ///< Optional unlock function releasing the lock
  void    *fn_data;             ///< Arbitrary user data used in wlock_fn,rlock_fn,unlock_fn
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

IW_EXPORT iwrc iwjsreg_copy(struct iwjsreg*, const char *path, struct iwpool *pool, struct jbl_node **out);

IW_EXPORT iwrc iwjsreg_merge(struct iwjsreg*, const char *path, struct jbl_node *json);

IW_EXPORT iwrc iwjsreg_merge_str(struct iwjsreg*, const char *path, const char *value, int len);

IW_EXPORT iwrc iwjsreg_merge_i64(struct iwjsreg *reg, const char *path, int64_t value);

IW_EXPORT iwrc iwjsreg_merge_f64(struct iwjsreg *reg, const char *path, double value);

IW_EXPORT iwrc iwjsreg_merge_bool(struct iwjsreg *reg, const char *path, bool value);

IW_EXPORT iwrc iwjsreg_merge_remove(struct iwjsreg *reg, const char *path);

IW_EXPORT iwrc iwjsreg_replace(struct iwjsreg*, const char *path, struct jbl_node *json);

IW_EXPORT iwrc iwjsreg_at_i64(struct iwjsreg*, const char *path, int64_t *out);

IW_EXPORT iwrc iwjsreg_at_f64(struct iwjsreg*, const char *path, double *out);

IW_EXPORT iwrc iwjsreg_at_bool(struct iwjsreg*, const char *path, bool *out);

IW_EXPORT iwrc iwjsreg_at_str_alloc(struct iwjsreg*, const char *path, char *out);

IW_EXTERN_C_END;

#endif
