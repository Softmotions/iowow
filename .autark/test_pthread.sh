#!/bin/sh

cat > './test_pthread.c' << 'EOF'
#include <pthread.h>
int main(void) {
  pthread_t t;
  return 0;
}
EOF

cat > './test_pthread_spinlock.c' << 'EOF'
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
int main(void) {
  pthread_spinlock_t lock;
  if (pthread_spin_init(&lock, PTHREAD_PROCESS_PRIVATE) != 0) {
    return 1;
  }
  pthread_spin_destroy(&lock);
  return 0;
}
EOF

# `pthread_condattr_setclock()` is used to express `iw_cond_timed_wait_ms()` deadlines
# in the monotonic clock, so they are not affected by the wall clock changes.
# Compile/link check, as for the spinlock above.
cat > './test_pthread_condattr_clock.c' << 'EOF'
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <time.h>
int main(void) {
  pthread_condattr_t attr;
  if (pthread_condattr_init(&attr) != 0) {
    return 1;
  }
  if (pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) != 0) {
    return 1;
  }
  pthread_condattr_destroy(&attr);
  return 0;
}
EOF

CC=${CC:-cc}

if ${CC} ./test_pthread.c -pthread; then
  PTHREAD_LFLAG=-pthread
  autark set "PTHREAD_LFLAG=$PTHREAD_LFLAG"
elif ${CC} ./test_pthread.c -lpthread; then
  PTHREAD_LFLAG=-lpthread
  autark set "PTHREAD_LFLAG=$PTHREAD_LFLAG"
fi

if [ -n "${PTHREAD_LFLAG}" ]; then
  if ${CC} ./test_pthread_spinlock.c ${PTHREAD_LFLAG}; then
    autark set "PTHREAD_HAS_SPINLOCK=1"
  fi
  if ${CC} ./test_pthread_condattr_clock.c ${PTHREAD_LFLAG}; then
    autark set "IW_HAVE_PTHREAD_CONDATTR_SETCLOCK=1"
  fi
fi

autark env CC