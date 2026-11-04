// Tests of the timed condition wait (`iwth.h`).
//
// `iw_cond_timed_wait_ms()` computes the wait deadline using the same clock the
// condition variable was created with: `CLOCK_MONOTONIC` when the platform supports
// `pthread_condattr_setclock()`, the wall clock otherwise. A mismatch between the two
// clocks makes the deadline effectively infinite (a timed wait which never completes),
// which is checked here by the watchdog thread: it broadcasts the condition variable
// shortly after the expected timeout, so a broken timed wait fails the case instead of
// hanging the test suite.

#include "iowow.h"
#include "iwcfg.h"
#include "iwtests.h"
#include "iwth.h"

#include <stdatomic.h>
#include <pthread.h>
#include <time.h>

static int init_suite(void) {
  return iw_init();
}

/// Initializes the condition variable with the clock used by `iw_cond_timed_wait_ms()`.
static void _cond_init(pthread_cond_t *cond) {
  pthread_condattr_t cattr;
  IW_TEST_ASSERT_EQUAL_FATAL(pthread_condattr_init(&cattr), 0);
#if defined(IW_HAVE_CLOCK_MONOTONIC) && defined(IW_HAVE_PTHREAD_CONDATTR_SETCLOCK)
  IW_TEST_ASSERT_EQUAL_FATAL(pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC), 0);
#endif
  IW_TEST_ASSERT_EQUAL_FATAL(pthread_cond_init(cond, &cattr), 0);
  pthread_condattr_destroy(&cattr);
}

static long _elapsed_ms(const struct timespec *start) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - start->tv_sec) * 1000L + (now.tv_nsec - start->tv_nsec) / 1000000L;
}

struct _watchdog_ctx {
  pthread_cond_t *cond;
  long            delay_ms;
  atomic_bool     done; ///< Set by the waiter when the watchdog is not needed anymore
};

/// Wakes up the condition variable waiters if the timed wait does not complete in time.
static void* _watchdog(void *arg) {
  struct _watchdog_ctx *ctx = arg;
  const struct timespec slice = { .tv_sec = 0, .tv_nsec = 10 * 1000000L };
  for (long waited = 0; waited < ctx->delay_ms; waited += 10) {
    if (atomic_load(&ctx->done)) {
      return 0;
    }
    nanosleep(&slice, 0);
  }
  if (!atomic_load(&ctx->done)) {
    pthread_cond_broadcast(ctx->cond);
  }
  return 0;
}

static void test_iwth_cond_timed_wait_timeout(void) {
  pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
  pthread_cond_t  cond;
  pthread_t       watchdog;
  struct timespec start;
  bool is_timeout = false;

  _cond_init(&cond);

  struct _watchdog_ctx ctx = { .cond = &cond, .delay_ms = 3000 };
  IW_TEST_ASSERT_EQUAL_FATAL(pthread_create(&watchdog, 0, _watchdog, &ctx), 0);

  clock_gettime(CLOCK_MONOTONIC, &start);
  pthread_mutex_lock(&mtx);
  iwrc rc = iw_cond_timed_wait_ms(&cond, &mtx, 100, &is_timeout);
  pthread_mutex_unlock(&mtx);
  long elapsed = _elapsed_ms(&start);
  atomic_store(&ctx.done, true);

  IW_TEST_ASSERT_EQUAL(rc, 0);
  IW_TEST_ASSERT_TRUE(is_timeout);
  // The watchdog wakes up the wait as well, so the elapsed time is bounded.
  IW_TEST_ASSERT_TRUE(elapsed < 1000);

  pthread_join(watchdog, 0);
  pthread_cond_destroy(&cond);
  pthread_mutex_destroy(&mtx);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

static void test_iwth_cond_timed_wait_broadcast(void) {
  pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
  pthread_cond_t  cond;
  pthread_t       watchdog;
  struct timespec start;
  bool is_timeout = true;

  _cond_init(&cond);

  struct _watchdog_ctx ctx = { .cond = &cond, .delay_ms = 100 };
  IW_TEST_ASSERT_EQUAL_FATAL(pthread_create(&watchdog, 0, _watchdog, &ctx), 0);

  clock_gettime(CLOCK_MONOTONIC, &start);
  pthread_mutex_lock(&mtx);
  iwrc rc = iw_cond_timed_wait_ms(&cond, &mtx, 3000, &is_timeout);
  pthread_mutex_unlock(&mtx);
  long elapsed = _elapsed_ms(&start);
  atomic_store(&ctx.done, true);

  IW_TEST_ASSERT_EQUAL(rc, 0);
  IW_TEST_ASSERT_FALSE(is_timeout);
  IW_TEST_ASSERT_TRUE(elapsed < 2000);

  pthread_join(watchdog, 0);
  pthread_cond_destroy(&cond);
  pthread_mutex_destroy(&mtx);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

int main(int argc, char *argv[]) {
  static const struct iw_test_case cases[] = {
    IW_TEST_CASE(test_iwth_cond_timed_wait_timeout),
    IW_TEST_CASE(test_iwth_cond_timed_wait_broadcast),
  };
  return iw_test_run(argc, argv, IW_TEST_SUITE("iwth_test1", cases, init_suite, 0));
}
