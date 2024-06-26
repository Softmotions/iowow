/*
 * Copyright (c) 2015, Aleksey Demakov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once
#ifndef IWTH_H
#define IWTH_H

#include "basedefs.h"
#include <pthread.h>

/**
 * Timed condition wait.
 * NOTE: Condition `cond` must be initialized with CLOCK_MONOTONIC attribute if system supports monotonic clock.
 *
 *   pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
 */
IW_EXPORT iwrc iw_cond_timed_wait_ms(
  pthread_cond_t  *cond,
  pthread_mutex_t *mtx,
  long             timeout_ms,
  bool            *out_is_timeout);

#if defined(__APPLE__) || (defined(__ANDROID_API__) && __ANDROID_API__ < 24)

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(PTHREAD_BARRIER_SERIAL_THREAD)
# define PTHREAD_BARRIER_SERIAL_THREAD (1)
#endif

#if !defined(PTHREAD_PROCESS_PRIVATE)
# define PTHREAD_PROCESS_PRIVATE (42)
#endif
#if !defined(PTHREAD_PROCESS_SHARED)
# define PTHREAD_PROCESS_SHARED (43)
#endif

typedef struct {
  char noop;
} pthread_barrierattr_t;

typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t  cond;
  unsigned int    limit;
  unsigned int    count;
  unsigned int    phase;
} pthread_barrier_t;

IW_EXPORT int pthread_barrierattr_init(pthread_barrierattr_t *attr);
IW_EXPORT int pthread_barrierattr_destroy(pthread_barrierattr_t *attr);

IW_EXPORT int pthread_barrierattr_getpshared(
  const pthread_barrierattr_t* restrict attr,
  int* restrict                         pshared);
IW_EXPORT int pthread_barrierattr_setpshared(
  pthread_barrierattr_t *attr,
  int                    pshared);

IW_EXPORT int pthread_barrier_init(
  pthread_barrier_t* restrict           barrier,
  const pthread_barrierattr_t* restrict attr,
  unsigned int                          count);
IW_EXPORT int pthread_barrier_destroy(pthread_barrier_t *barrier);

IW_EXPORT int pthread_barrier_wait(pthread_barrier_t *barrier);

#ifdef  __cplusplus
}
#endif

#endif /* __APPLE__ */

#endif
