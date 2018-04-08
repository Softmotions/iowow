#include "iowow.h"
#include "log/iwlog.h"
#include "utils/iwutils.h"
#include "utils/iwrlock.h"
#include "platform/iwp.h"

#include "iwcfg.h"
#include <pthread.h>
#include <CUnit/Basic.h>

#define LK4THREADS 8
#define LK4RANGESZ 100
#define LK4TITERATIONS 1000

static IWRLOCK *lk;
static unsigned char lk4range[LK4RANGESZ] = {0};


typedef struct {
  int none;
} LK4TASK;


int init_suite(void) {
  iwrc rc = iw_init();
  if (rc) {
    return 1;
  }
  rc = iwrl_new(&lk);
  return rc ? 1 : 0;
}

int clean_suite(void) {
  assert(lk);
  iwrc rc = iwrl_destroy(lk);
  return rc ? 1 : 0;
}

static iwrc lock(IWRLOCK *lk, off_t start, off_t len, iwrl_lockflags lflags, uint64_t bsleepms,
                 uint64_t asleepms, int is_unlock) {
  iwrc rc = 0;
  CU_ASSERT_PTR_NOT_NULL_FATAL(lk);
  if (bsleepms) {
    IWRC(iwp_sleep(bsleepms), rc);
  }
  IWRC(iwrl_lock(lk, start, len, lflags), rc);
  CU_ASSERT_FALSE(rc);
  if (asleepms) {
    IWRC(iwp_sleep(asleepms), rc);
  }
  if (is_unlock) {
    IWRC(iwrl_unlock(lk, start, len), rc);
  }
  CU_ASSERT_FALSE(rc);
  return rc;
}


static iwrc unlock(IWRLOCK *lk, off_t start, off_t len) {
  iwrc rc = 0;
  CU_ASSERT_PTR_NOT_NULL_FATAL(lk);
  IWRC(iwrl_unlock(lk, start, len), rc);
  CU_ASSERT_EQUAL(rc, 0);
  return rc;
}

static int num_lockers(IWRLOCK *lk) {
  int nl;
  iwrc rc = iwrl_num_ranges(lk, &nl);
  CU_ASSERT_FALSE_FATAL(rc);
  return nl;
}


static int num_writers(IWRLOCK *lk) {
  int nl;
  iwrc rc = iwrl_write_ranges(lk, &nl);
  CU_ASSERT_FALSE_FATAL(rc);
  return nl;
}

void test_iwrlock1(void) {
  lock(lk, 10, 100, IWRL_WRITE, 0, 0, 1);
  lock(lk, 0, 100, IWRL_WRITE, 0, 0, 0);
  unlock(lk, 10, 10);
  CU_ASSERT_TRUE(num_lockers(lk));
  lock(lk, 90, 50, IWRL_WRITE, 0, 0, 0);
  CU_ASSERT_TRUE(num_lockers(lk));
  lock(lk, 10, 100, IWRL_READ, 0, 0, 0);
  unlock(lk, 10, 100);
  unlock(lk, 0, 200);
  CU_ASSERT_FALSE(num_lockers(lk));
}

void test_iwrlock2(void) {
  for (int i = 0; i < 10000; ++i) {
    lock(lk, 0, 100, IWRL_WRITE, 0, 0, 1);
  }
  CU_ASSERT_FALSE(num_lockers(lk));
}

void test_iwrlock3(void) {
  lock(lk, 10, 1, IWRL_WRITE, 0, 0, 1);
  lock(lk, 0, 1, IWRL_READ, 0, 0, 0);
  CU_ASSERT_TRUE(num_lockers(lk) == 1);
  lock(lk, 0, 1, IWRL_WRITE, 0, 0, 0);
  unlock(lk, 0, 1);

  lock(lk, 0, 2, IWRL_READ, 0, 0, 0);
  unlock(lk, 0, 1);
  unlock(lk, 1, 1);
  CU_ASSERT_FALSE(num_lockers(lk));
}

static void *lk4th(void *op) {
  LK4TASK *task = op;
  iwrc rc = 0;
  CU_ASSERT_PTR_NOT_NULL_FATAL(task);
  for (int i = 0; i < LK4TITERATIONS; ++i) {
    iwrl_lockflags mode = (iwu_rand_range(3) == 0) ? IWRL_WRITE : IWRL_READ;
    off_t start = iwu_rand_range(LK4RANGESZ - 1);
    off_t len = iwu_rand_range(LK4RANGESZ - start);
    if (!len)
      len = 1;
    rc = lock(lk, start, len, mode, 0, iwu_rand_range(4), 0);
    CU_ASSERT_FALSE_FATAL(rc);
    for (int j = 0; j < len; ++j) {
      if (mode & IWRL_WRITE) {
        if (iwu_rand_range(10) == 1) {
          iwp_sleep(1);
        }
        lk4range[start + j] = 0xff;
      } else {
        CU_ASSERT_EQUAL_FATAL(lk4range[start + j], 0x00);
      }
    }
    if (mode & IWRL_WRITE) {
      iwp_sleep(iwu_rand_range(4));
      for (int j = 0; j < len; ++j) {
        lk4range[start + j] = 0x00;
      }
    }
    IWRC(iwrl_unlock(lk, start, len), rc);
    CU_ASSERT_FALSE_FATAL(rc);
  }
  free(task);
  return 0;
}

void test_iwrlock4(void) {
  pthread_t tlist[LK4THREADS];
  for (int i = 0; i < LK4THREADS; ++i) {
    LK4TASK *task = malloc(sizeof(*task));
    CU_ASSERT_PTR_NOT_NULL_FATAL(task);
    CU_ASSERT_EQUAL_FATAL(pthread_create(&tlist[i], 0, lk4th, task), 0);
  }
  for (int i = 0; i < LK4THREADS; ++i) {
    pthread_join(tlist[i], 0);
  }
}

int main() {
  CU_pSuite pSuite = NULL;

  /* Initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry())
    return CU_get_error();

  /* Add a suite to the registry */
  pSuite = CU_add_suite("iwrlock_test1", init_suite, clean_suite);

  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Add the tests to the suite */
  if ((NULL == CU_add_test(pSuite, "test_iwrlock1", test_iwrlock1)) ||
      (NULL == CU_add_test(pSuite, "test_iwrlock2", test_iwrlock2)) ||
      (NULL == CU_add_test(pSuite, "test_iwrlock3", test_iwrlock3)) ||
      (NULL == CU_add_test(pSuite, "test_iwrlock4", test_iwrlock4))) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Run all tests using the CUnit Basic interface */
  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  int ret = CU_get_error() || CU_get_number_of_failures();
  CU_cleanup_registry();
  return ret;
}
