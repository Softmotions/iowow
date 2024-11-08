#include "iwstw.h"
#include "iwlog.h"
#include "iwp.h"

#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <pthread.h>

struct _task {
  iwstw_task_f fn;
  void *arg;
  struct _task *next;
};

struct iwstw {
  struct _task *head;
  struct _task *tail;
  char *thread_name;
  iwstw_on_task_discard_f on_task_discard;
  pthread_mutex_t mtx;
  pthread_cond_t  cond;
  pthread_cond_t  cond_queue;
  pthread_t       thr;
  int  cnt;
  int  queue_limit;
  bool queue_blocking;
  bool queue_blocked;
  volatile bool shutdown;
};

static void* _worker_fn(void *op) {
  struct iwstw *stw = op;
  assert(stw);

  if (stw->thread_name) {
    iwp_set_current_thread_name(stw->thread_name);
  }

  while (true) {
    void *arg;
    iwstw_task_f fn = 0;

    pthread_mutex_lock(&stw->mtx);
    if (stw->head) {
      struct _task *h = stw->head;
      fn = h->fn;
      arg = h->arg;
      stw->head = h->next;
      if (stw->head == 0) {
        stw->tail = 0;
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
      if (stw->queue_blocked && stw->cnt < stw->queue_limit) {
        stw->queue_blocked = false;
        pthread_cond_broadcast(&stw->cond_queue);
      }
      pthread_mutex_unlock(&stw->mtx);
      continue;
    } else if (stw->shutdown) {
      pthread_mutex_unlock(&stw->mtx);
      break;
    } else if (stw->queue_blocked && stw->cnt < stw->queue_limit) {
      stw->queue_blocked = false;
      pthread_cond_broadcast(&stw->cond_queue);
    }
    pthread_cond_wait(&stw->cond, &stw->mtx);
    pthread_mutex_unlock(&stw->mtx);
  }
  return 0;
}

iwrc iwstw_shutdown(struct iwstw * *stwp, bool wait_for_all) {
  if (!stwp || !*stwp) {
    return 0;
  }
  struct iwstw *stw = *stwp;
  pthread_mutex_lock(&stw->mtx);
  if (stw->shutdown) {
    pthread_mutex_unlock(&stw->mtx);
    return 0;
  }
  pthread_t st = pthread_self();
  if (stw->thr == pthread_self()) {
    iwlog_error("iwstw | Thread iwstw_shutdown() from self thread: %lu", (unsigned long) st);
    return IW_ERROR_ASSERTION;
  }
  if (!wait_for_all) {
    struct _task *t = stw->head;
    while (t) {
      struct _task *o = t;
      t = t->next;
      if (stw->on_task_discard) {
        stw->on_task_discard(t->fn, t->arg);
      }
      free(o);
    }
    stw->head = 0;
    stw->tail = 0;
    stw->cnt = 0;
  }
  stw->shutdown = true;
  pthread_cond_broadcast(&stw->cond);
  if (stw->queue_blocking) {
    pthread_cond_broadcast(&stw->cond_queue);
  }
  pthread_mutex_unlock(&stw->mtx);
  pthread_join(stw->thr, 0);
  pthread_cond_destroy(&stw->cond);
  pthread_mutex_destroy(&stw->mtx);

  free(stw->thread_name);
  free(stw);
  *stwp = 0;
  return 0;
}

int iwstw_queue_size(struct iwstw *stw) {
  int res = 0;
  pthread_mutex_lock(&stw->mtx);
  res = stw->cnt;
  pthread_mutex_unlock(&stw->mtx);
  return res;
}

iwrc iwstw_schedule(struct iwstw *stw, iwstw_task_f fn, void *arg) {
  if (!stw || !fn) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  struct _task *task = malloc(sizeof(*task));
  RCA(task, finish);
  *task = (struct _task) {
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

  while (stw->queue_limit && (stw->cnt + 1 > stw->queue_limit)) {
    if (stw->queue_blocking) {
      if (stw->shutdown) {
        rc = IW_ERROR_INVALID_STATE;
        pthread_mutex_unlock(&stw->mtx);
        goto finish;
      }
      stw->queue_blocked = true;
      pthread_cond_wait(&stw->cond_queue, &stw->mtx);
    } else {
      rc = IW_ERROR_OVERFLOW;
      pthread_mutex_unlock(&stw->mtx);
      goto finish;
    }
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

iwrc iwstw_schedule_only(struct iwstw *stw, iwstw_task_f fn, void *arg) {
  if (!stw || !fn) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  struct _task *task = malloc(sizeof(*task));
  RCA(task, finish);
  *task = (struct _task) {
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

  struct _task *t = stw->head;
  while (t) {
    struct _task *o = t;
    t = t->next;
    if (stw->on_task_discard) {
      stw->on_task_discard(t->fn, t->arg);
    }
    free(o);
  }

  stw->head = task;
  stw->tail = task;
  stw->cnt = 1;

  pthread_cond_broadcast(&stw->cond);
  pthread_mutex_unlock(&stw->mtx);

finish:
  if (rc) {
    free(task);
  }
  return rc; // NOLINT (clang-analyzer-unix.Malloc)
}

iwrc iwstw_schedule_empty_only(struct iwstw *stw, iwstw_task_f fn, void *arg, bool *out_scheduled) {
  if (!stw || !fn || !out_scheduled) {
    return IW_ERROR_INVALID_ARGS;
  }
  *out_scheduled = false;
  iwrc rc = 0;
  struct _task *task = malloc(sizeof(*task));
  RCA(task, finish);
  *task = (struct _task) {
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
  if (stw->head) {
    pthread_mutex_unlock(&stw->mtx);
    free(task);
    goto finish;
  }
  *out_scheduled = true;
  stw->head = task;
  stw->tail = task;
  ++stw->cnt;
  pthread_cond_broadcast(&stw->cond);
  pthread_mutex_unlock(&stw->mtx);

finish:
  if (rc) {
    free(task);
  }
  return rc; // NOLINT (clang-analyzer-unix.Malloc)
}

void iwstw_set_on_task_discard(struct iwstw *stw, iwstw_on_task_discard_f on_task_discard) {
  stw->on_task_discard = on_task_discard;
}

iwrc iwstw_start(const char *thread_name, int queue_limit, bool queue_blocking, struct iwstw **out_stw) {
  if (queue_limit < 0 || !out_stw) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (thread_name && strlen(thread_name) > 15) {
    return IW_ERROR_INVALID_ARGS;
  }
  struct iwstw *stw = malloc(sizeof(*stw));
  if (!stw) {
    *out_stw = 0;
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  int rci;
  iwrc rc = 0;
  *stw = (struct iwstw) {
    .queue_limit = queue_limit,
    .mtx = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER,
    .cond_queue = PTHREAD_COND_INITIALIZER,
    .queue_blocking = queue_blocking
  };
  if (thread_name) {
    stw->thread_name = strdup(thread_name);
  }

  rci = pthread_create(&stw->thr, 0, _worker_fn, stw);
  if (rci) {
    rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, errno);
    goto finish;
  }

finish:
  if (rc) {
    *out_stw = 0;
    free(stw->thread_name);
    free(stw);
  } else {
    *out_stw = stw;
  }
  return 0;
}
