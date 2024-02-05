#pragma once
#ifndef PTHREAD_BARRIER_SHIM
#define PTHREAD_BARRIER_SHIM

#include <pthread.h>

#ifdef __APPLE__

typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t  cond;
  int canary;
  int threshold;
} pthread_barrier_t;

typedef struct {} pthread_barrierattr_t;

int pthread_barrier_init(pthread_barrier_t *barrier, const pthread_barrierattr_t *attr, unsigned count);
int pthread_barrier_destroy(pthread_barrier_t *barrier);
int pthread_barrier_wait(pthread_barrier_t *barrier);

#define PTHREAD_BARRIER_SHIM_IMPL

#endif
#endif
