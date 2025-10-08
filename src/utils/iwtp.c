#include "iwtp.h"
#include "iwp.h"
#include "iwlog.h"
#include "iwarr.h"
#include "iwp.h"

#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <pthread.h>

struct _task {
  iwtp_task_f fn;
  void       *arg;
  struct _task *next;
};

struct iwtp {
  struct _task   *head;
  struct _task   *tail;

  pthread_mutex_t mtx;
  pthread_cond_t  cond;
  struct iwulist  threads;

  char *thread_name_prefix;
  void (*thread_initializer)(pthread_t);

  int   num_threads;
  int   num_threads_busy;
  int   overflow_threads_factor;
  int   queue_limit;
  int   queue_size;

  bool warn_on_overflow_thread_spawn;
  bool shutdown;
};

static void* _worker_fn(void *op);

iwrc iwtp_schedule(struct iwtp *tp, iwtp_task_f fn, void *arg) {
  if (!tp || !fn) {
    return IW_ERROR_INVALID_ARGS;
  }

  iwrc rc = 0;
  struct _task *task = malloc(sizeof(*task));
  RCA(task, finish);

  *task = (struct _task) {
    .fn = fn,
    .arg = arg
  };

  pthread_mutex_lock(&tp->mtx);
  if (tp->queue_limit && (tp->queue_size + 1 > tp->queue_limit)) {
    rc = IW_ERROR_OVERFLOW;
    pthread_mutex_unlock(&tp->mtx);
    iwlog_error("iwtp | Reached  thread pool queue size limit: %d", tp->queue_limit);
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

  if (  tp->queue_size > 1
     && tp->num_threads_busy >= tp->num_threads
     && iwulist_length(&tp->threads) < ((size_t) tp->num_threads * (1 + tp->overflow_threads_factor))) {
    pthread_t th;
    int rci = pthread_create(&th, 0, _worker_fn, tp);
    if (rci) {
      iwlog_ecode_error2(iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci), "iwtp | Failed to create overflow thread");
    }
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
  int idx = iwulist_find_first(&tp->threads, &st);
  int num_threads = tp->num_threads;
  pthread_mutex_unlock(&tp->mtx);

  if (idx == -1) { // should never be happen
    return 0;
  }

  if (tp->thread_name_prefix) {
    char nbuf[64];
    snprintf(nbuf, sizeof(nbuf), "%s%d", tp->thread_name_prefix, idx);
    iwp_set_current_thread_name(nbuf);
  }

  if (tp->thread_initializer) {
    tp->thread_initializer(st);
  }

  if (idx >= num_threads && tp->warn_on_overflow_thread_spawn) {
    iwlog_warn("iwtp | Overflow thread spawned: %s%d+",
               tp->thread_name_prefix ? tp->thread_name_prefix : "", idx);
  }

  while (true) {
    void *arg;
    iwtp_task_f fn = 0;

    pthread_mutex_lock(&tp->mtx);
    ++tp->num_threads_busy;
    if (tp->head) {
      struct _task *h = tp->head;
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

    if (idx >= tp->num_threads) {
      // Overflow thread will be terminated immediately.
      if (!tp->shutdown) {
        iwulist_remove_first_by(&tp->threads, &st);
        pthread_detach(st);
      }
      pthread_mutex_unlock(&tp->mtx);
      break;
    }

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

iwrc iwtp_start_by_spec(const struct iwtp_spec *spec, struct iwtp **out_tp) {
  iwrc rc = 0;
  if (!spec || !out_tp) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (spec->thread_name_prefix && strlen(spec->thread_name_prefix) > 15) {
    return IW_ERROR_INVALID_ARGS;
  }

  int num_threads = spec->num_threads;
  if (num_threads < 1) {
    num_threads = iwp_num_cpu_cores();
  } else if (num_threads > 1023) {
    num_threads = 1024;
  }

  int queue_limit = spec->queue_limit;
  if (queue_limit < 1) {
    queue_limit = 0;
  }

  int overflow_threads_factor = spec->overflow_threads_factor;
  if (overflow_threads_factor > 2) {
    overflow_threads_factor = 2;
  }

  struct iwtp *tp = malloc(sizeof(*tp));
  if (!tp) {
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    goto finish;
  }

  *tp = (struct iwtp) {
    .warn_on_overflow_thread_spawn = spec->warn_on_overflow_thread_spawn,
    .overflow_threads_factor = overflow_threads_factor,
    .thread_initializer = spec->thread_initializer,
    .num_threads = num_threads,
    .queue_limit = queue_limit,
    .mtx = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER
  };

  if (spec->thread_name_prefix) {
    tp->thread_name_prefix = strdup(spec->thread_name_prefix);
  }

  RCC(rc, finish, iwulist_init(&tp->threads, num_threads, sizeof(pthread_t)));

  for (size_t i = 0; i < num_threads; ++i) {
    pthread_t th;
    pthread_mutex_lock(&tp->mtx);
    int rci = pthread_create(&th, 0, _worker_fn, tp);
    if (rci) {
      pthread_mutex_unlock(&tp->mtx);
      rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
      iwlog_ecode_error3(rc);
      goto finish;
    } else {
      iwulist_push(&tp->threads, &th);
    }
    pthread_mutex_unlock(&tp->mtx);
  }

finish:
  if (IW_UNLIKELY(rc)) {
    *out_tp = 0;
    iwtp_shutdown(&tp, false);
  } else {
    *out_tp = tp;
  }
  return rc;
}

iwrc iwtp_start(const char *thread_name_prefix, int num_threads, int queue_limit, struct iwtp **out_tp) {
  return iwtp_start_by_spec(&(struct iwtp_spec) {
    .thread_name_prefix = thread_name_prefix,
    .num_threads = num_threads,
    .queue_limit = queue_limit
  }, out_tp);
}

iwrc iwtp_shutdown(struct iwtp **tpp, bool wait_for_all) {
  if (!tpp || !*tpp) {
    return 0;
  }
  struct iwtp *tp = *tpp;
  struct iwulist *joinlist = 0;

  pthread_mutex_lock(&tp->mtx);
  pthread_t st = pthread_self();
  if (iwulist_find_first(&tp->threads, &st) != -1) {
    pthread_mutex_unlock(&tp->mtx);
    iwlog_error("iwtp | Calling iwtp_shutdown() from one of managed thread: %lu", (unsigned long) st);
    return IW_ERROR_ASSERTION;
  }

  if (tp->shutdown) {
    pthread_mutex_unlock(&tp->mtx);
    return 0;
  }

  *tpp = 0;
  tp->shutdown = true;

  if (!wait_for_all) {
    struct _task *t = tp->head;
    while (t) {
      struct _task *o = t;
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
    pthread_t t = *(pthread_t*) iwulist_at2(joinlist, i);
    pthread_join(t, 0);
  }

  pthread_cond_destroy(&tp->cond);
  pthread_mutex_destroy(&tp->mtx);
  iwulist_destroy_keep(&tp->threads);
  iwulist_destroy(&joinlist);
  free(tp->thread_name_prefix);
  free(tp);
  return 0;
}

int iwtp_queue_size(struct iwtp *tp) {
  int res = 0;
  pthread_mutex_lock(&tp->mtx);
  res = tp->queue_size;
  pthread_mutex_unlock(&tp->mtx);
  return res;
}

int iwtp_threads_busy_num(struct iwtp *tp) {
  int res = 0;
  pthread_mutex_lock(&tp->mtx);
  res = tp->num_threads_busy;
  pthread_mutex_unlock(&tp->mtx);
  return res;
}
