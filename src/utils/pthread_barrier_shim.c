#include "pthread_barrier_shim.h"

#ifdef PTHREAD_BARRIER_SHIM_IMPL

#include <errno.h>

int pthread_barrier_init(pthread_barrier_t *barrier, const pthread_barrierattr_t *attr, unsigned count) {
  if (count == 0) {
    errno = EINVAL;
    return -1;
  }
  if (attr != NULL) {
    errno = ENOSYS;
    return -1;
  }
  if (pthread_mutex_init(&barrier->mutex, NULL) < 0) {
    return -1;
  }
  if (pthread_cond_init(&barrier->cond, NULL) < 0) {
    pthread_mutex_destroy(&barrier->mutex);
    return -1;
  }
  barrier->threshold = count;
  barrier->canary = 0;
  return 0;
}

int pthread_barrier_destroy(pthread_barrier_t *barrier) {
  barrier->threshold = -1;
  pthread_cond_destroy(&barrier->cond);
  return pthread_mutex_destroy(&barrier->mutex);
}

int pthread_barrier_wait(pthread_barrier_t *barrier) {
  int rc = pthread_mutex_lock(&barrier->mutex);
  if (rc == 0) {
    if (++barrier->canary == barrier->threshold) {
      barrier->canary = 0;
      pthread_cond_broadcast(&barrier->cond);
      rc = -1;
    } else {
      pthread_cond_wait(&barrier->cond, &barrier->mutex);
    }

    pthread_mutex_unlock(&barrier->mutex);
  }
  return rc;
}

#endif
