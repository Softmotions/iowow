#include "iwtp.h"
#include "iwth.h"
#include "iwlog.h"

#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <string.h>

struct _TASK {
  iwtp_task_f fn;
  void       *arg;
  struct _TASK *next;
};

struct _IWTP {
  struct _TASK   *head;
  struct _TASK   *tail;
  pthread_mutex_t mtx;
  pthread_cond_t  cond;
  pthread_t      *threads;
  int num_threads;
  int queue_limit;
  int cnt;
  volatile bool shutdown;
};

iwrc iwtp_schedule(IWTP tp, iwtp_task_f fn, void *arg) {
  if (!tp || !fn) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  struct _TASK *task = malloc(sizeof(*task));
  RCA(task, finish);

  *task = (struct _TASK) {
    .fn = fn,
    .arg = arg
  };

  int rci = pthread_mutex_lock(&tp->mtx);
  if (rci) {
    rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, errno);
    goto finish;
  }
  if (tp->shutdown) {
    rc = IW_ERROR_INVALID_STATE;
    pthread_mutex_unlock(&tp->mtx);
    goto finish;
  }
  if (tp->queue_limit && (tp->cnt + 1 > tp->queue_limit)) {
    rc = IW_ERROR_OVERFLOW;
    pthread_mutex_unlock(&tp->mtx);
    goto finish;
  }
  if (tp->tail) {
    tp->tail->next = task;
    tp->tail = task;
  } else {
    tp->head = task;
    tp->tail = task;
  }
  ++tp->cnt;
  pthread_cond_signal(&tp->cond);
  pthread_mutex_unlock(&tp->mtx);

finish:
  if (rc) {
    free(task);
  }
  return rc;
}

static void *_worker_fn(void *op) {
  struct _IWTP *tp = op;
  assert(tp);

  while (true) {
    void *arg;
    iwtp_task_f fn = 0;

    pthread_mutex_lock(&tp->mtx);
    if (tp->head) {
      struct _TASK *h = tp->head;
      fn = h->fn;
      arg = h->arg;
      tp->head = h->next;
      if (tp->tail == h) {
        tp->tail = tp->head;
      }
      --tp->cnt;
      free(h);
    }
    pthread_mutex_unlock(&tp->mtx);

    if (fn) {
      fn(arg);
    }

    pthread_mutex_lock(&tp->mtx);
    if (tp->head) {
      pthread_mutex_unlock(&tp->mtx);
      continue;
    } else if (tp->shutdown) {
      pthread_mutex_unlock(&tp->mtx);
      break;
    }
    pthread_cond_wait(&tp->cond, &tp->mtx);
    if (tp->shutdown) {
      pthread_mutex_unlock(&tp->mtx);
      break;
    }
    pthread_mutex_unlock(&tp->mtx);
  }
  return 0;
}

iwrc iwtp_create(int num_threads, int queue_limit, IWTP *out_tp) {
  if (num_threads < 1 || num_threads > 1023 || queue_limit < 0 || !out_tp) {
    return IW_ERROR_INVALID_ARGS;
  }
  struct _IWTP *tp = malloc(sizeof(*tp) + sizeof(pthread_t) * num_threads);
  if (!tp) {
    *out_tp = 0;
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  *tp = (struct _IWTP) {
    .num_threads = num_threads,
    .queue_limit = queue_limit,
    .mtx = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER
  };
  tp->threads = (void*) ((char*) tp + sizeof(*tp));
  memset(tp->threads, 0, sizeof(pthread_t) * num_threads);
  while (num_threads--) {
    pthread_create(&tp->threads[num_threads], 0, _worker_fn, tp);
  }
  *out_tp = tp;
  return 0;
}

void iwtp_shutdown(IWTP *tpp, bool wait_for_all) {
  if (!tpp || !*tpp) {
    return;
  }
  IWTP tp = *tpp;
  pthread_mutex_lock(&tp->mtx);
  if (tp->shutdown) {
    pthread_mutex_unlock(&tp->mtx);
    return;
  }
  if (!wait_for_all) {
    struct _TASK *t = tp->head;
    while (t) {
      struct _TASK *o = t;
      t = t->next;
      free(o);
    }
    tp->head = 0;
    tp->tail = 0;
    tp->cnt = 0;
  }
  tp->shutdown = true;
  pthread_cond_broadcast(&tp->cond);
  pthread_mutex_unlock(&tp->mtx);

  for (int i = 0; i < tp->num_threads; ++i) {
    if (tp->threads[i]) {
      pthread_join(tp->threads[i], 0);
    }
  }
  pthread_cond_destroy(&tp->cond);
  pthread_mutex_destroy(&tp->mtx);
  free(tp);
  *tpp = 0;
}

int iwtp_queue_size(IWTP tp) {
  int res = 0;
  pthread_mutex_lock(&tp->mtx);
  res = tp->cnt;
  pthread_mutex_unlock(&tp->mtx);
  return res;
}
