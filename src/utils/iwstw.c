#include "iwstw.h"
#include "iwth.h"
#include "iwlog.h"
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

struct _TASK {
  iwstw_task_f fn;
  void *arg;
  struct _TASK *next;
};

struct _IWSTW {
  struct _TASK     *head;
  struct _TASK     *tail;
  pthread_mutex_t   mtx;
  pthread_barrier_t brr;
  pthread_cond_t    cond;
  pthread_t thr;
  int       cnt;
  int       queue_limit;
  volatile bool shutdown;
};

void *worker_fn(void *op) {
  struct _IWSTW *stw = op;
  assert(stw);
  pthread_barrier_wait(&stw->brr);

  while (true) {
    void *arg;
    iwstw_task_f fn = 0;

    pthread_mutex_lock(&stw->mtx);
    if (stw->head) {
      struct _TASK *h = stw->head;
      fn = h->fn;
      arg = h->arg;
      stw->head = h->next;
      if (stw->tail == h) {
        stw->tail = stw->head;
      }
      --stw->cnt;
      free(h);
    }
    pthread_mutex_unlock(&stw->mtx);

    if (fn) {
      fn(arg);
    }

    pthread_mutex_lock(&stw->mtx);
    if (stw->head) {
      pthread_mutex_unlock(&stw->mtx);
      continue;
    } else if (stw->shutdown) {
      pthread_mutex_unlock(&stw->mtx);
      break;
    }
    pthread_cond_wait(&stw->cond, &stw->mtx);
    pthread_mutex_unlock(&stw->mtx);
  }
  return 0;
}

void iwstw_shutdown(IWSTW *stwp, bool wait_for_all) {
  if (!stwp || !*stwp) {
    return;
  }
  IWSTW stw = *stwp;
  pthread_mutex_lock(&stw->mtx);
  if (stw->shutdown) {
    pthread_mutex_unlock(&stw->mtx);
    return;
  }
  if (!wait_for_all) {
    struct _TASK *t = stw->head;
    while (t) {
      struct _TASK *o = t;
      t = t->next;
      free(o);
    }
    stw->head = 0;
    stw->tail = 0;
    stw->cnt = 0;
  }
  stw->shutdown = true;
  pthread_cond_broadcast(&stw->cond);
  pthread_mutex_unlock(&stw->mtx);
  int rci = pthread_join(stw->thr, 0);
  if (rci) {
    iwrc rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
    iwlog_ecode_error3(rc);
  }
  pthread_barrier_destroy(&stw->brr);
  pthread_cond_destroy(&stw->cond);
  pthread_mutex_destroy(&stw->mtx);
  free(stw);
  *stwp = 0;
}

int iwstr_queue_size(IWSTW stw) {
  int res = 0;
  pthread_mutex_lock(&stw->mtx);
  res = stw->cnt;
  pthread_mutex_unlock(&stw->mtx);
  return res;
}

iwrc iwstw_schedule(IWSTW stw, iwstw_task_f fn, void *arg) {
  if (!stw || !fn) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  struct _TASK *task = malloc(sizeof(*task));
  RCA(task, finish);
  *task = (struct _TASK) {
    .fn = fn,
    .arg = arg
  };
  int rci = pthread_mutex_lock(&stw->mtx);
  if (rci) {
    rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, errno);
    goto finish;
  }
  if (stw->shutdown) {
    rc = IW_ERROR_INVALID_STATE;
    pthread_mutex_unlock(&stw->mtx);
    goto finish;
  }
  if (stw->queue_limit && (stw->cnt + 1 > stw->queue_limit)) {
    rc = IW_ERROR_OVERFLOW;
    pthread_mutex_unlock(&stw->mtx);
    goto finish;
  }
  if (stw->tail) {
    stw->tail->next = task;
    stw->tail = task;
  } else {
    stw->head = task;
    stw->tail = task;
  }
  ++stw->cnt;
  pthread_cond_broadcast(&stw->cond);
  pthread_mutex_unlock(&stw->mtx);

finish:
  if (rc) {
    free(task);
  }
  return rc; // NOLINT (clang-analyzer-unix.Malloc)
}

iwrc iwstw_start(int queue_limit, IWSTW *stwp_out) {
  struct _IWSTW *stw = malloc(sizeof(*stw));
  if (!stw) {
    *stwp_out = 0;
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  int rci;
  iwrc rc = 0;
  *stw = (struct _IWSTW) {
    .queue_limit = queue_limit,
    .mtx = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER
  };
  rci = pthread_barrier_init(&stw->brr, 0, 2);
  if (rci) {
    rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, errno);
    goto finish;
  }
  rci = pthread_create(&stw->thr, 0, worker_fn, stw);
  if (rci) {
    rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, errno);
    pthread_barrier_destroy(&stw->brr);
    goto finish;
  }
  pthread_barrier_wait(&stw->brr);

finish:
  if (rc) {
    *stwp_out = 0;
    free(stw);
  } else {
    *stwp_out = stw;
  }
  return 0;
}
