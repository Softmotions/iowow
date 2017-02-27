// clang-format off
/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2017 Softmotions Ltd <info@softmotions.com>
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
// clang-format on

/** Inspired by http://blitiri.com.ar/p/libfilo/ Alberto Bertogli
 * (albertogli@telpin.com.ar) code */

#include "iwrlock.h"
#include "log/iwlog.h"
#include "iwcfg.h"

#include <pthread.h>
#include <semaphore.h>

/**
 * @brief Single lock range.
 */
typedef struct _IWRL_LOCKER_RANGE {
  off_t start;
  off_t end;
  struct _IWRL_LOCKER_RANGE *next;
  struct _IWRL_LOCKER_RANGE *prev;
  pthread_t owner;
  int flags;
} _IWRL_LOCKER_RANGE;

/**
 * @brief A range waiters for lock.
 */
typedef struct _IWRL_WAITER_RANGE {
  off_t start;
  off_t end;
  struct _IWRL_WAITER_RANGE *next;
  struct _IWRL_WAITER_RANGE *prev;
  pthread_t owner;
  sem_t sem;
  int flags;
} _IWRL_WAITER_RANGE;

/**
 * @brief Range lock.
 */
struct _IWRLOCK {
  struct _IWRL_LOCKER_RANGE *lockers;
  struct _IWRL_WAITER_RANGE *waiters;
  pthread_mutex_t lock;
};

#define _IWRL_IS_RANGES_OVERLAP(IW_s1_, IW_e1_, IW_s2_, IW_e2_)                                              \
  (((IW_e1_) >= (IW_s2_) && (IW_e1_) <= (IW_e2_)) || ((IW_s1_) >= (IW_s2_) && (IW_s1_) <= (IW_e2_)) ||       \
   ((IW_s1_) <= (IW_s2_) && (IW_e1_) >= (IW_e2_)))

#define _IWRL_IS_RANGES_OVERLAP2(IW_l, IW_s, IW_e)                                                           \
  _IWRL_IS_RANGES_OVERLAP((IW_l)->start, (IW_l)->end, (IW_s), (IW_e))

#define _IWRL_IS_OWNER(IW_l_) (pthread_equal((IW_l_)->owner, pthread_self()))

#define _IWRL_IS_OWNER2(IW_l_, IW_o_) (pthread_equal((IW_l_)->owner, IW_o_))

IW_INLINE iwrc _iwrl_lock(IWRLOCK *lk) {
  int err = pthread_mutex_lock(&lk->lock);
  return err ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, err) : 0;
}

IW_INLINE iwrc _iwrl_unlock(IWRLOCK *lk) {
  int err = pthread_mutex_unlock(&lk->lock);
  return err ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, err) : 0;
}

static int _iwrl_is_free(IWRLOCK *lk, off_t start, off_t end) {
  for (_IWRL_LOCKER_RANGE *lr = lk->lockers; lr; lr = lr->next) {
    if (_IWRL_IS_RANGES_OVERLAP2(lr, start, end)) {
      return 0;
    }
  }
  return 1;
}

static int _iwrl_is_canlock(IWRLOCK *lk, off_t start, off_t end, int lflags, pthread_t owner, int *_is_free) {
  int is_free = 1;
  for (_IWRL_LOCKER_RANGE *lr = lk->lockers; lr; lr = lr->next) {
    int overlap = _IWRL_IS_RANGES_OVERLAP2(lr, start, end);
    if (is_free && overlap) {
      is_free = 0;
    }
    if (overlap && ((lflags | lr->flags) & IWRL_WRITE) && !_IWRL_IS_OWNER2(lr, owner)) {
      *_is_free = 0;
      return 0;
    }
  }
  *_is_free = is_free;
  return 1;
}

static iwrc _iwrl_lock_append(IWRLOCK *lk, off_t start, off_t end, int lflags, pthread_t owner) {
  _IWRL_LOCKER_RANGE *lr = malloc(sizeof(*lr));
  if (!lr) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  lr->start = start;
  lr->end = end;
  lr->flags = lflags;
  lr->owner = owner;
  if (!lk->lockers) {
    lr->prev = lr->next = 0;
    lk->lockers = lr;
  } else {
    lr->prev = 0;
    lk->lockers->prev = lr;
    lr->next = lk->lockers;
    lk->lockers = lr;
  }
  return 0;
}

static iwrc _iwrl_exclude_range(IWRLOCK *lk, _IWRL_LOCKER_RANGE *lr, off_t start, off_t end, pthread_t owner,
                                int *remove_lr) {
  assert(_IWRL_IS_OWNER2(lr, owner));
  *remove_lr = 0;
  if (lr->start >= start && lr->end <= end) {
    *remove_lr = 1;
    return 0;
  } else if (lr->start < start && lr->end <= end) {
    lr->end = start - 1;
    return 0;
  } else if (lr->start >= start && lr->end > end) {
    lr->start = end + 1;
    return 0;
  } else if (lr->start < start && lr->end > end) {
    iwrc rc = _iwrl_lock_append(lk, lr->start, start - 1, lr->flags, owner);
    IWRC(_iwrl_lock_append(lk, end + 1, lr->end, lr->flags, owner), rc);
    *remove_lr = 1;
    return rc;
  }
  assert(0);
  return IW_ERROR_OUT_OF_BOUNDS;
}

static iwrc _iwrl_range_lock(IWRLOCK *lk, off_t start, off_t end, int lflags, pthread_t owner) {
  iwrc rc = 0;
  int remove_lr;
  for (_IWRL_LOCKER_RANGE *nr, *lr = lk->lockers; lr; lr = nr) {
    nr = lr->next;
    if (!_IWRL_IS_RANGES_OVERLAP2(lr, start, end) || !_IWRL_IS_OWNER2(lr, owner)) {
      continue;
    }
    rc = _iwrl_exclude_range(lk, lr, start, end, owner, &remove_lr);
    if (remove_lr) {
      if (lk->lockers == lr) {
        lk->lockers = lr->next;
      }
      if (lr->prev) {
        lr->prev->next = lr->next;
      }
      if (lr->next) {
        lr->next->prev = lr->prev;
      }
      free(lr);
    }
    if (rc) {
      break;
    }
  }
  return rc ? rc : _iwrl_lock_append(lk, start, end, lflags, owner);
}

// Assumed:
//  _iwrl_lock is active
static iwrc _iwrl_range_wait(IWRLOCK *lk, off_t start, off_t end, int lflags, pthread_t owner) {
  iwrc rc = 0;
  _IWRL_WAITER_RANGE *wr = malloc(sizeof(*wr));
  if (!wr) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  wr->start = start;
  wr->end = end;
  wr->flags = lflags;
  wr->owner = owner;
  wr->next = wr->prev = 0;
  if (sem_init(&wr->sem, 0, 0)) {
    rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, errno);
    goto finish;
  }
  if (!lk->waiters) {
    wr->next = 0;
    wr->prev = wr;
    lk->waiters = wr;
  } else {
    wr->next = 0;
    wr->prev = lk->waiters->prev;
    lk->waiters->prev->next = wr;
    lk->waiters->prev = wr;
  }
  IWRC(_iwrl_unlock(lk), rc);
  while (sem_wait(&wr->sem)) {
    if (errno != EINTR) {
      IWRC(iwrc_set_errno(IW_ERROR_THREADING_ERRNO, errno), rc);
      break;
    }
  }
  if (sem_destroy(&wr->sem)) {
    IWRC(iwrc_set_errno(IW_ERROR_THREADING_ERRNO, errno), rc);
  }
finish:
  free(wr);
  return rc;
}

// Assumed:
//  _iwrl_lock is active
static iwrc _iwrl_range_nofify(IWRLOCK *lk, off_t start, off_t end) {
  iwrc rc = 0;
  int is_free;
  for (_IWRL_WAITER_RANGE *wr = lk->waiters; wr; wr = wr->next) {
    if (_IWRL_IS_RANGES_OVERLAP2(wr, start, end) &&
        _iwrl_is_canlock(lk, wr->start, wr->end, wr->flags, wr->owner, &is_free)) {
      IWRC(_iwrl_range_lock(lk, wr->start, wr->end, wr->flags, wr->owner), rc);
      if (lk->waiters == wr) {
        if (wr->next) {
          wr->next->prev = lk->waiters->prev;
        }
        lk->waiters = wr->next;
      } else if (lk->waiters->prev == wr) {
        wr->prev->next = 0;
        lk->waiters->prev = wr->prev;
      } else {
        wr->prev->next = wr->next;
        wr->next->prev = wr->prev;
      }
      if (sem_post(&wr->sem)) {
        IWRC(iwrc_set_errno(IW_ERROR_THREADING_ERRNO, errno), rc);
      }
      return rc;
    }
  }
  return 0;
}

///////////////////////////////// Public API

iwrc iwrl_new(IWRLOCK **lk) {
  assert(lk);
  *lk = 0;
  iwrc rc = 0;
  int err;
  pthread_mutexattr_t attr;
  IWRLOCK *l = calloc(1, sizeof(*l));
  if (!l) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  pthread_mutexattr_init(&attr);
  err = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL);
  if (err) {
    rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, err);
    goto finish;
  }
  pthread_mutex_init(&(l->lock), &attr);
  pthread_mutexattr_destroy(&attr);
finish:
  if (rc) {
    free(l);
  } else {
    *lk = l;
  }
  return rc;
}

iwrc iwrl_destroy(IWRLOCK *lk) {
  assert(lk);
  iwrc rc = 0;
  IWRC(_iwrl_lock(lk), rc);
  for (_IWRL_LOCKER_RANGE *nr, *lr = lk->lockers; lr; lr = nr) {
    nr = lr->next;
    free(lr);
  }
  for (_IWRL_WAITER_RANGE *nw, *wr = lk->waiters; wr; wr = nw) {
    nw = wr->next;
    free(wr);
  }
  IWRC(_iwrl_unlock(lk), rc);
  pthread_mutex_destroy(&lk->lock);
  free(lk);
  return rc;
}

iwrc iwrl_lock(IWRLOCK *lk, off_t start, off_t len, iwrl_lockflags lflags) {
  assert(lk);
  iwrc rc = 0;
  off_t end = start + len - 1;
  pthread_t owner = pthread_self();
  int is_free;
  if (start < 0 || len <= 0) {
    return IW_ERROR_OUT_OF_BOUNDS;
  }
  rc = _iwrl_lock(lk);
  if (rc) {
    return rc;
  }
  if (!lk->lockers) {
    IWRC(_iwrl_lock_append(lk, start, end, lflags, owner), rc);
    IWRC(_iwrl_unlock(lk), rc);
  } else if (_iwrl_is_canlock(lk, start, end, lflags, owner, &is_free)) {
    if (is_free) {
      IWRC(_iwrl_lock_append(lk, start, end, lflags, owner), rc);
    } else {
      IWRC(_iwrl_range_lock(lk, start, end, lflags, owner), rc);
    }
    IWRC(_iwrl_unlock(lk), rc);
  } else {
    // wait, _iwrl_lock will be unlocked in _iwrl_range_wait
    IWRC(_iwrl_range_wait(lk, start, end, lflags, owner), rc);
  }
  return rc;
}

iwrc iwrl_trylock(IWRLOCK *lk, off_t start, off_t len, iwrl_lockflags lflags) {
  assert(lk);
  iwrc rc = 0;
  off_t end = start + len - 1;
  pthread_t owner = pthread_self();
  int is_free;
  if (start < 0 || len <= 0) {
    return IW_ERROR_OUT_OF_BOUNDS;
  }
  rc = _iwrl_lock(lk);
  if (rc) {
    return rc;
  }
  if (!lk->lockers) {
    IWRC(_iwrl_lock_append(lk, start, end, lflags, owner), rc);
  } else if (_iwrl_is_canlock(lk, start, end, lflags, owner, &is_free)) {
    if (is_free) {
      IWRC(_iwrl_lock_append(lk, start, end, lflags, owner), rc);
    } else {
      IWRC(_iwrl_range_lock(lk, start, end, lflags, owner), rc);
    }
  } else {
    rc = IW_ERROR_FALSE;
  }
  IWRC(_iwrl_unlock(lk), rc);
  return rc;
}

iwrc iwrl_unlock(IWRLOCK *lk, off_t start, off_t len) {
  assert(lk);
  iwrc rc = 0;
  off_t end = start + len - 1;
  pthread_t owner = pthread_self();
  int remove_lr;
  if (start < 0 || len <= 0) {
    return IW_ERROR_OUT_OF_BOUNDS;
  }
  rc = _iwrl_lock(lk);
  if (rc) {
    return rc;
  }
  for (_IWRL_LOCKER_RANGE *next, *lr = lk->lockers; lr; lr = next) {
    next = lr->next;
    if (!_IWRL_IS_OWNER2(lr, owner) || !_IWRL_IS_RANGES_OVERLAP2(lr, start, end)) {
      continue;
    }
    rc = _iwrl_exclude_range(lk, lr, start, end, owner, &remove_lr);
    if (remove_lr) {
      if (lk->lockers == lr) {
        lk->lockers = lr->next;
      }
      if (lr->prev) {
        lr->prev->next = lr->next;
      }
      if (lr->next) {
        lr->next->prev = lr->prev;
      }
      free(lr);
    }
    if (rc) {
      break;
    }
  }
  IWRC(_iwrl_range_nofify(lk, start, end), rc);
  IWRC(_iwrl_unlock(lk), rc);
  return rc;
}

iwrc iwrl_num_ranges(IWRLOCK *lk, int *ret) {
  assert(lk);
  int cnt = 0;
  iwrc rc = _iwrl_lock(lk);
  if (rc) {
    *ret = 0;
    return rc;
  }
  for (_IWRL_LOCKER_RANGE *lr = lk->lockers; lr; lr = lr->next) {
    ++cnt;
  }
  *ret = cnt;
  return _iwrl_unlock(lk);
}

iwrc iwrl_write_ranges(IWRLOCK *lk, int *ret) {
  assert(lk);
  int cnt = 0;
  iwrc rc = _iwrl_lock(lk);
  if (rc) {
    *ret = 0;
    return rc;
  }
  for (_IWRL_LOCKER_RANGE *lr = lk->lockers; lr; lr = lr->next) {
    if (lr->flags & IWRL_WRITE) {
      ++cnt;
    }
  }
  *ret = cnt;
  return _iwrl_unlock(lk);
}
