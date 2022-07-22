#include "iwtp.h"
#include "iwth.h"
#include "iwp.h"
#include "iwlog.h"

#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <string.h>

struct task {
  iwtp_task_f fn;
  void       *arg;
  struct task *next;
};

struct iwtp {
  struct task    *head;
  struct task    *tail;
  pthread_mutex_t mtx;
  pthread_cond_t  cond;
  pthread_t      *threads;
  char *thread_name_prefix;
  int   num_threads;
  int   queue_limit;
  int   cnt;
  volatile bool shutdown;
};

iwrc iwtp_schedule(IWTP tp, iwtp_task_f fn, void *arg) {
  if (!tp || !fn) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (tp->shutdown) {
    return IW_ERROR_INVALID_STATE;
  }

  iwrc rc = 0;
  struct task *task = malloc(sizeof(*task));
  RCA(task, finish);

  *task = (struct task) {
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

static void* _worker_fn(void *op) {
  struct iwtp *tp = op;
  assert(tp);

  if (tp->thread_name_prefix) {
    pthread_t st = pthread_self();
    for (int i = 0; i < tp->num_threads; ++i) {
      if (tp->threads[i] == st) {
        char nbuf[strlen(tp->thread_name_prefix) + 16];
        snprintf(nbuf, sizeof(nbuf), "%s%d", tp->thread_name_prefix, i);
        iwp_set_current_thread_name(nbuf);
        break;
      }
    }
  }

  while (true) {
    void *arg;
    iwtp_task_f fn = 0;

    pthread_mutex_lock(&tp->mtx);
    if (tp->head) {
      struct task *h = tp->head;
      fn = h->fn;
      arg = h->arg;
      tp->head = h->next;
      if (tp->head == 0) {
        tp->tail = 0;
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
    pthread_mutex_unlock(&tp->mtx);
  }
  return 0;
}

iwrc iwtp_start(const char *thread_name_prefix, int num_threads, int queue_limit, IWTP *out_tp) {
  if (num_threads < 1 || num_threads > 1023 || queue_limit < 0 || !out_tp) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (thread_name_prefix && strlen(thread_name_prefix) > 15) {
    return IW_ERROR_INVALID_ARGS;
  }

  struct iwtp *tp = malloc(sizeof(*tp) + sizeof(pthread_t) * num_threads);
  if (!tp) {
    *out_tp = 0;
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  *tp = (struct iwtp) {
    .num_threads = num_threads,
    .queue_limit = queue_limit,
    .mtx = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER
  };
  if (thread_name_prefix) {
    tp->thread_name_prefix = strdup(thread_name_prefix);
  }
  tp->threads = (void*) ((char*) tp + sizeof(*tp));
  memset(tp->threads, 0, sizeof(pthread_t) * num_threads);
  while (num_threads--) {
    pthread_create(&tp->threads[num_threads], 0, _worker_fn, tp);
  }
  *out_tp = tp;
  return 0;
}

iwrc iwtp_shutdown(IWTP *tpp, bool wait_for_all) {
  if (!tpp || !*tpp) {
    return 0;
  }
  IWTP tp = *tpp;
  if (!__sync_bool_compare_and_swap(&tp->shutdown, 0, 1)) {
    return 0;
  }

  pthread_mutex_lock(&tp->mtx);
  pthread_t st = pthread_self();
  for (int i = 0; i < tp->num_threads; ++i) {
    if (tp->threads[i] == st) {
      pthread_mutex_unlock(&tp->mtx);
      iwlog_error("iwtp | Thread iwtp_shutdown() from one of pool thread: %lu", (unsigned long) st);
      return IW_ERROR_ASSERTION;
    }
  }
  if (!wait_for_all) {
    struct task *t = tp->head;
    while (t) {
      struct task *o = t;
      t = t->next;
      free(o);
    }
    tp->head = 0;
    tp->tail = 0;
    tp->cnt = 0;
  }
  pthread_cond_broadcast(&tp->cond);
  pthread_mutex_unlock(&tp->mtx);

  for (int i = 0; i < tp->num_threads; ++i) {
    if (tp->threads[i]) {
      pthread_join(tp->threads[i], 0);
    }
  }

  pthread_cond_destroy(&tp->cond);
  pthread_mutex_destroy(&tp->mtx);
  free(tp->thread_name_prefix);
  free(tp);
  *tpp = 0;
  return 0;
}

int iwtp_queue_size(IWTP tp) {
  int res = 0;
  pthread_mutex_lock(&tp->mtx);
  res = tp->cnt;
  pthread_mutex_unlock(&tp->mtx);
  return res;
}
