#include "iwth.h"
#include "iwp.h"
#include "iwlog.h"

#include <errno.h>
#include <time.h>

iwrc iw_cond_timed_wait_ms(pthread_cond_t *cond, pthread_mutex_t *mtx, long timeout_ms, bool *out_is_timeout) {
  iwrc rc;
  int rci;
  struct timespec tp;
  *out_is_timeout = false;

#if defined(IW_HAVE_CLOCK_MONOTONIC) && defined(IW_HAVE_PTHREAD_CONDATTR_SETCLOCK)
  rc = iwp_clock_get_time(CLOCK_MONOTONIC, &tp);
#else
  rc = iwp_clock_get_time(CLOCK_REALTIME, &tp);
#endif
  RCRET(rc);
  tp.tv_sec += timeout_ms / 1000;
  tp.tv_nsec += (timeout_ms % 1000) * 1000000;
  if (tp.tv_nsec >= 1000000000) {
    tp.tv_sec += 1;
    tp.tv_nsec -= 1000000000;
  }
  do {
    rci = pthread_cond_timedwait(cond, mtx, &tp);
  } while (rci == EINTR);
  if (rci) {
    if (rci == ETIMEDOUT) {
      *out_is_timeout = true;
    } else {
      rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
    }
  }

  return rc;
}

#ifdef __APPLE__

#ifndef __unused
#define __unused __attribute__((unused))
#endif

int pthread_barrierattr_init(pthread_barrierattr_t *attr __unused) {
  return 0;
}

int pthread_barrierattr_destroy(pthread_barrierattr_t *attr __unused) {
  return 0;
}

int pthread_barrierattr_getpshared(
  const pthread_barrierattr_t* restrict attr __unused,
  int* restrict                         pshared) {
  *pshared = PTHREAD_PROCESS_PRIVATE;
  return 0;
}

int pthread_barrierattr_setpshared(
  pthread_barrierattr_t *attr __unused,
  int                    pshared) {
  if (pshared != PTHREAD_PROCESS_PRIVATE) {
    errno = EINVAL;
    return -1;
  }
  return 0;
}

int pthread_barrier_init(
  pthread_barrier_t* restrict           barrier,
  const pthread_barrierattr_t* restrict attr __unused,
  unsigned                              count) {
  if (count == 0) {
    errno = EINVAL;
    return -1;
  }

  if (pthread_mutex_init(&barrier->mutex, 0) < 0) {
    return -1;
  }
  if (pthread_cond_init(&barrier->cond, 0) < 0) {
    int errno_save = errno;
    pthread_mutex_destroy(&barrier->mutex);
    errno = errno_save;
    return -1;
  }

  barrier->limit = count;
  barrier->count = 0;
  barrier->phase = 0;

  return 0;
}

int pthread_barrier_destroy(pthread_barrier_t *barrier) {
  pthread_mutex_destroy(&barrier->mutex);
  pthread_cond_destroy(&barrier->cond);
  return 0;
}

int pthread_barrier_wait(pthread_barrier_t *barrier) {
  pthread_mutex_lock(&barrier->mutex);
  barrier->count++;
  if (barrier->count >= barrier->limit) {
    barrier->phase++;
    barrier->count = 0;
    pthread_cond_broadcast(&barrier->cond);
    pthread_mutex_unlock(&barrier->mutex);
    return PTHREAD_BARRIER_SERIAL_THREAD;
  } else {
    unsigned phase = barrier->phase;
    do {
      pthread_cond_wait(&barrier->cond, &barrier->mutex);
    } while (phase == barrier->phase);
    pthread_mutex_unlock(&barrier->mutex);
    return 0;
  }
}

#endif /* __APPLE__ */
