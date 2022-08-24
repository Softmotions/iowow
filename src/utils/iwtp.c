#include "iwtp.h"
#include "iwth.h"
#include "iwp.h"
#include "iwlog.h"
#include "iwarr.h"

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
  IWULIST threads;

  char *thread_name_prefix;
  int   num_threads;
  int   num_threads_busy;
  int   overflow_threads_factor;
  int   queue_limit;
  int   queue_size;

  bool warn_on_overflow_thread_spawn;
  volatile bool shutdown;
};

static void* _worker_fn(void *op);

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

  pthread_mutex_lock(&tp->mtx);
  if (tp->shutdown) {
    rc = IW_ERROR_INVALID_STATE;
    pthread_mutex_unlock(&tp->mtx);
    goto finish;
  }

  if (tp->queue_limit && (tp->queue_size + 1 > tp->queue_limit)) {
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
  ++tp->queue_size;

  if (  tp->num_threads_busy >= tp->num_threads
     && iwulist_length(&tp->threads) < tp->num_threads * (1 + tp->overflow_threads_factor)) {
    pthread_t th;
    pthread_create(&th, 0, _worker_fn, tp);
  }

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

  pthread_t st = pthread_self();

  pthread_mutex_lock(&tp->mtx);
  size_t idx = iwulist_length(&tp->threads);
  if (iwulist_push(&tp->threads, &st)) {
    pthread_mutex_unlock(&tp->mtx);
    return 0;
  }
  if (tp->thread_name_prefix) {
    char nbuf[64];
    if (idx >= tp->num_threads) {
      snprintf(nbuf, sizeof(nbuf), "%s%zd+", tp->thread_name_prefix, idx);
    } else {
      snprintf(nbuf, sizeof(nbuf), "%s%zd", tp->thread_name_prefix, idx);
    }
    iwp_set_current_thread_name(nbuf);
  }
  pthread_mutex_unlock(&tp->mtx);

  if (tp->warn_on_overflow_thread_spawn && idx >= tp->num_threads) {
    iwlog_warn("iwtp | Overflow thread spawned: %s%zd+",
               tp->thread_name_prefix ? tp->thread_name_prefix : "", idx);
  }

  while (true) {
    void *arg;
    iwtp_task_f fn = 0;

    pthread_mutex_lock(&tp->mtx);
    ++tp->num_threads_busy;
    if (tp->head) {
      struct task *h = tp->head;
      fn = h->fn;
      arg = h->arg;
      tp->head = h->next;
      if (tp->head == 0) {
        tp->tail = 0;
      }
      --tp->queue_size;
      free(h);
    }
    pthread_mutex_unlock(&tp->mtx);

    if (fn) {
      fn(arg);
    }

    pthread_mutex_lock(&tp->mtx);
    --tp->num_threads_busy;
    if (tp->head) {
      pthread_mutex_unlock(&tp->mtx);
      continue;
    } else if (tp->shutdown) {
      pthread_mutex_unlock(&tp->mtx);
      break;
    }
    if (idx < tp->num_threads) {
      pthread_cond_wait(&tp->cond, &tp->mtx);
    } else { // Overflow thread will be terminated immediately.
      iwulist_remove_first_by(&tp->threads, &st);
      pthread_mutex_unlock(&tp->mtx);
      break;
    }
    pthread_mutex_unlock(&tp->mtx);
  }
  return 0;
}

iwrc iwtp_start_spec(const struct iwtp_spec *spec, IWTP *out_tp) {
  iwrc rc = 0;
  if (!spec || spec->num_threads < 1 || spec->num_threads > 1023 || spec->queue_limit < 0 || !out_tp) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (spec->thread_name_prefix && strlen(spec->thread_name_prefix) > 15) {
    return IW_ERROR_INVALID_ARGS;
  }

  struct iwtp *tp = malloc(sizeof(*tp) + sizeof(pthread_t) * spec->num_threads);
  if (!tp) {
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    goto finish;
  }

  *tp = (struct iwtp) {
    .warn_on_overflow_thread_spawn = spec->warn_on_overflow_thread_spawn,
    .overflow_threads_factor = spec->overflow_threads_factor,
    .num_threads = spec->num_threads,
    .queue_limit = spec->queue_limit,
    .mtx = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER
  };

  if (spec->thread_name_prefix) {
    tp->thread_name_prefix = strdup(spec->thread_name_prefix);
  }

  iwulist_init(&tp->threads, spec->num_threads, sizeof(pthread_t));
  for (size_t i = 0; i < spec->num_threads; ++i) {
    pthread_t th;
    int rci = pthread_create(&th, 0, _worker_fn, tp);
    if (rci) {
      rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
      iwlog_ecode_error3(rc);
      iwtp_shutdown(&tp, false);
      goto finish;
    }
  }

finish:
  if (!rc) {
    *out_tp = tp;
  } else {
    *out_tp = 0;
  }
  return rc;
}

iwrc iwtp_start(const char *thread_name_prefix, int num_threads, int queue_limit, IWTP *out_tp) {
  return iwtp_start_spec(&(struct iwtp_spec) {
    .thread_name_prefix = thread_name_prefix,
    .num_threads = num_threads,
    .queue_limit = queue_limit
  }, out_tp);
}

iwrc iwtp_shutdown(IWTP *tpp, bool wait_for_all) {
  if (!tpp || !*tpp) {
    return 0;
  }
  IWTP tp = *tpp;
  if (!__sync_bool_compare_and_swap(&tp->shutdown, 0, 1)) {
    return 0;
  }
  IWULIST *joinlist = 0;

  pthread_mutex_lock(&tp->mtx);
  pthread_t st = pthread_self();
  if (iwulist_find_first(&tp->threads, &st) != -1) {
    pthread_mutex_unlock(&tp->mtx);
    iwlog_error("iwtp | Thread iwtp_shutdown() from one of pool thread: %lu", (unsigned long) st);
    return IW_ERROR_ASSERTION;
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
    tp->queue_size = 0;
  }
  joinlist = iwulist_clone(&tp->threads);
  pthread_cond_broadcast(&tp->cond);
  pthread_mutex_unlock(&tp->mtx);

  for (size_t i = 0, l = iwulist_length(joinlist); i < l; ++i) {
    pthread_t jt = *(pthread_t*) iwulist_at2(joinlist, i);
    pthread_join(jt, 0);
  }

  pthread_cond_destroy(&tp->cond);
  pthread_mutex_destroy(&tp->mtx);
  iwulist_destroy_keep(&tp->threads);
  iwulist_destroy(&joinlist);
  free(tp->thread_name_prefix);
  free(tp);
  *tpp = 0;
  return 0;
}

int iwtp_queue_size(IWTP tp) {
  int res = 0;
  pthread_mutex_lock(&tp->mtx);
  res = tp->queue_size;
  pthread_mutex_unlock(&tp->mtx);
  return res;
}
