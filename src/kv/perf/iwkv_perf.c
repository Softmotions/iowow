/*
 * iwkv_perf.c
 *
 * iwkv performance benchmark tool.
 *
 * NOTE: iwkv performance tests are DeepSeek AI generated code.
 *
 * Workloads:
 *   crud        create -> read -> update -> delete passes over the dataset
 *   read-mostly loaded dataset followed by a mixed read/update pass
 *   scan        loaded dataset followed by a full cursor range scan
 *
 * Dimensions:
 *   concurrency  `single` (one thread) and `multi` (N threads, default 8)
 *   durability   WAL disabled (`wal-off`), WAL enabled (`wal-on`) and
 *                WAL enabled with per-operation fsync (`wal-sync`)
 *   dataset      ~100K x 32B, ~100K x 240B, ~100K x 1016B and ~1M x 32B
 *                (key+value sizes)
 *
 * The tool results are reported with the following methodology:
 *   - the first iteration of every combination is discarded as a warm-up,
 *     the remaining `--repeats` iterations are aggregated;
 *   - phase throughput is reported as the median across measured iterations
 *     together with the min/max spread;
 *   - per-operation latencies are collected into a log2 histogram and
 *     reported as mean/p50/p90/p99/p99.9/max (closed-loop measurement);
 *   - multi-threaded phases start from a `pthread_barrier` so that thread
 *     startup is not accounted for by the measured window;
 *   - the resulting database and WAL file sizes are reported.
 *
 * Build time defaults are provided by the `IWKV_PERF_*` Autark options and can
 * be overridden at runtime with command line flags or the environment
 * variables of the same names (IWKV_PERF_NUM_THREADS, IWKV_PERF_REPEATS,
 * IWKV_PERF_DATASET_SMALL_NUM, IWKV_PERF_DATASET_LARGE_NUM).
 *
 * The tool is built and executed only when the `IWKV_RUN_PERF` build option
 * is set. See `src/kv/Autark` and `src/kv/perf/Autark`.
 */

#include "iwkv.h"
#include "iwlog.h"
#include "iwp.h"

#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if !defined(_WIN32)
#include <sys/utsname.h>
#endif

#define PERF_STR_(x) #x
#define PERF_STR(x)  PERF_STR_(x)

#ifndef IWKV_PERF_GIT_REV
#define IWKV_PERF_GIT_REV unknown
#endif
#ifndef __VERSION__
#define __VERSION__ "unknown"
#endif

/* Build time defaults, see the `IWKV_PERF_*` Autark options. */
#ifndef IWKV_PERF_NUM_THREADS
#define IWKV_PERF_NUM_THREADS 8
#endif
#ifndef IWKV_PERF_REPEATS
#define IWKV_PERF_REPEATS 3
#endif
#ifndef IWKV_PERF_DATASET_SMALL_NUM
#define IWKV_PERF_DATASET_SMALL_NUM 100000
#endif
#ifndef IWKV_PERF_DATASET_LARGE_NUM
#define IWKV_PERF_DATASET_LARGE_NUM 1000000
#endif
#ifndef IWKV_PERF_READ_PCT
#define IWKV_PERF_READ_PCT 95
#endif

/** Total number of mixed operations per record in the `read-mostly` workload. */
#define PERF_READ_MOSTLY_OPS_MULT 4
/** Number of phase result slots. */
#define PERF_PHASE_MAX 4
/** Number of stored iterations per combination. */
#define PERF_MAX_REPEATS 10
/** Default Zipfian exponent (YCSB default). */
#define PERF_ZIPF_THETA 0.99
/** Small key buffer used for lookups of missing records. */
#define PERF_MISS_KEY_MAX 64

#define PERF_BIT(x) (1u << (unsigned) (x))

enum perf_workload {
  PERF_WORKLOAD_CRUD = 0,
  PERF_WORKLOAD_READ_MOSTLY,
  PERF_WORKLOAD_SCAN,
  _PERF_WORKLOAD_NUM,
};

enum perf_durability {
  PERF_DURABILITY_WAL_OFF = 0,
  PERF_DURABILITY_WAL_ON,
  PERF_DURABILITY_WAL_SYNC,
  _PERF_DURABILITY_NUM,
};

enum perf_key_dist {
  PERF_KD_UNIFORM = 0,
  PERF_KD_ZIPFIAN,
  _PERF_KD_NUM,
};

enum perf_keyspace {
  PERF_KS_SHARED = 0,
  PERF_KS_PARTITIONED,
  _PERF_KS_NUM,
};

enum perf_read_mode {
  PERF_RM_ALLOC = 0,
  PERF_RM_COPY,
  _PERF_RM_NUM,
};

enum perf_format {
  PERF_FMT_TEXT = 0,
  PERF_FMT_JSON,
  PERF_FMT_CSV,
  _PERF_FMT_NUM,
};

enum perf_verify {
  PERF_VERIFY_OFF = 0,
  PERF_VERIFY_SAMPLE,
  PERF_VERIFY_FULL,
  _PERF_VERIFY_NUM,
};

static const char *perf_workload_names[_PERF_WORKLOAD_NUM] = { "crud", "read-mostly", "scan" };
static const char *perf_durability_names[_PERF_DURABILITY_NUM] = { "wal-off", "wal-on", "wal-sync" };
static const char *perf_key_dist_names[_PERF_KD_NUM] = { "uniform", "zipfian" };
static const char *perf_keyspace_names[_PERF_KS_NUM] = { "shared", "partitioned" };
static const char *perf_read_mode_names[_PERF_RM_NUM] = { "alloc", "copy" };
static const char *perf_verify_names[_PERF_VERIFY_NUM] = { "off", "sample", "full" };
static const char *perf_phase_names[_PERF_WORKLOAD_NUM][PERF_PHASE_MAX] = {
  { "create", "read", "update", "delete" },
  { "load", "mixed", 0, 0 },
  { "load", "scan", 0, 0 },
};

/* ---------------------------------------------------------------- config */

typedef struct perf_config {
  unsigned wl_mask;
  unsigned ds_mask;
  unsigned conc_mask;      /* bit 0 - single, bit 1 - multi */
  unsigned dur_mask;
  int      threads;
  int      repeats;          /* Total iterations, the first one is a warm-up */
  int      read_pct;
  int      miss_pct;         /* Percentage of read operations targeted at missing keys */
  int      key_dist;
  int      keyspace;
  int      read_mode;
  int      format;
  int      latency;
  int      verify;
  int      verify_every;
  uint64_t small_n;
  uint64_t large_n;
  const char *output;
} perf_config;

static perf_config g_cfg = {
  .wl_mask = PERF_BIT(PERF_WORKLOAD_CRUD) | PERF_BIT(PERF_WORKLOAD_READ_MOSTLY),
  .ds_mask = 0xfu,
  .conc_mask = 0x3u,
  .dur_mask = PERF_BIT(PERF_DURABILITY_WAL_OFF) | PERF_BIT(PERF_DURABILITY_WAL_ON),
  .threads = IWKV_PERF_NUM_THREADS,
  .repeats = IWKV_PERF_REPEATS,
  .read_pct = IWKV_PERF_READ_PCT,
  .miss_pct = 0,
  .key_dist = PERF_KD_UNIFORM,
  .keyspace = PERF_KS_SHARED,
  .read_mode = PERF_RM_ALLOC,
  .format = PERF_FMT_TEXT,
  .latency = 1,
  .verify = PERF_VERIFY_SAMPLE,
  .verify_every = 64,
  .small_n = IWKV_PERF_DATASET_SMALL_NUM,
  .large_n = IWKV_PERF_DATASET_LARGE_NUM,
  .output = 0,
};

/* -------------------------------------------------------------- datasets */

typedef struct perf_dataset {
  const char *name;
  uint64_t    nrecs;
  size_t      ksz;
  size_t      vsz;
  bool large;      /* Uses the large record count */
  bool zipf_ready;
  struct perf_zipf *zipf; /* Filled lazily when key_dist is zipfian */
} perf_dataset;

typedef struct perf_zipf {
  uint64_t n;
  double   theta;
  double   zeta_n;
  double   zeta_2;
  double   alpha;
  double   eta;
} perf_zipf;

static perf_dataset perf_datasets[] = {
  { "small32", 0, 16, 16, false, false, 0 },
  { "small240", 0, 16, 224, false, false, 0 },
  { "small1016", 0, 16, 1000, false, false, 0 },
  { "large32", 0, 16, 16, true, false, 0 },
};
#define PERF_DS_NUM (sizeof(perf_datasets) / sizeof(perf_datasets[0]))

/* ------------------------------------------------------------ histogram */

#define PERF_HIST_BUCKETS 64

typedef struct perf_hist {
  uint64_t b[PERF_HIST_BUCKETS];
  uint64_t count;
  uint64_t sum;
  uint64_t max;
} perf_hist;

static void perf_hist_record(perf_hist *h, uint64_t ns) {
  unsigned idx;
  if (ns <= 1) {
    idx = (unsigned) ns;
  } else {
    idx = 64u - (unsigned) __builtin_clzll(ns);
  }
  if (idx >= PERF_HIST_BUCKETS) {
    idx = PERF_HIST_BUCKETS - 1;
  }
  ++h->b[idx];
  ++h->count;
  h->sum += ns;
  if (ns > h->max) {
    h->max = ns;
  }
}

static void perf_hist_merge(perf_hist *dst, const perf_hist *src) {
  for (unsigned i = 0; i < PERF_HIST_BUCKETS; ++i) {
    dst->b[i] += src->b[i];
  }
  dst->count += src->count;
  dst->sum += src->sum;
  if (src->max > dst->max) {
    dst->max = src->max;
  }
}

static uint64_t perf_hist_percentile(const perf_hist *h, double p) {
  if (!h->count) {
    return 0;
  }
  uint64_t target = (uint64_t) ((double) h->count * p / 100.0);
  if (target >= h->count) {
    target = h->count - 1;
  }
  uint64_t acc = 0;
  for (unsigned i = 0; i < PERF_HIST_BUCKETS; ++i) {
    acc += h->b[i];
    if (acc > target) {
      return i == 0 ? 1 : ((uint64_t) 1 << i);
    }
  }
  return h->max;
}

/* ------------------------------------------------------------ structures */

typedef struct perf_ctx {
  IWDB db;
  const perf_dataset *ds;
  uint64_t nrecs;
  size_t   ksz;
  size_t   vsz;
  const uint8_t *keys;
  const uint8_t *val_tmpl;
  int  nthreads;
  bool concurrent;
  bool sync;        /* IWKV_SYNC op flag */
  int  read_mode;
  int  key_dist;
  int  keyspace;
  bool latency;     /* Latency collection allowed */
  bool record_lat;  /* Latency collection enabled for current phase */
  int  verify;
  int  verify_every;
  int  read_pct;
  int  miss_pct;
  bool scan_desc;   /* Engine iterates keys in descending order */
  perf_zipf *zipf;
  pthread_barrier_t *bar;
} perf_ctx;

struct perf_task;

typedef void (*perf_worker_fn)(struct perf_task *t);

typedef struct perf_task {
  perf_ctx      *ctx;
  perf_worker_fn fn;
  int       tid;
  uint64_t  kstart, kcnt;        /* Key range */
  uint64_t  ostart, ocnt;        /* Operation range */
  uint64_t  reads, writes, misses, scanned;
  perf_hist lat;
  uint8_t  *val_ins;
  uint8_t  *val_upd;
  uint8_t  *read_buf;
  uint8_t   miss_key[PERF_MISS_KEY_MAX];
  uint64_t  rng;
  uint64_t  verify_ctr;
  pthread_t thr;
} perf_task;

typedef struct perf_phase {
  double   secs;
  uint64_t reads, writes, misses, scanned;
} perf_phase;

typedef struct perf_iter {
  perf_phase ph[PERF_PHASE_MAX];
  int      nph;
  double   metric_secs;
  uint64_t metric_ops;
  uint64_t db_peak_size;   /* Peak main db file size while the db was open */
  uint64_t db_final_size;  /* Final (checkpointed and trimmed) main db file size */
  uint64_t wal_peak_size;  /* Peak WAL file size while the db was open */
  uint64_t wal_final_size; /* Final WAL file size after close */
} perf_iter;

typedef struct perf_result {
  perf_dataset      *ds;
  enum perf_workload wl;
  enum perf_durability dur;
  bool      concurrent;
  int       nthreads;
  int       nmeasured;
  perf_iter iters[PERF_MAX_REPEATS];
  perf_hist lat;
  double    thr_med, thr_min, thr_max;
} perf_result;

/* -------------------------------------------------------------- helpers */

static void perf_die(const char *what, iwrc rc) {
  if (rc) {
    fprintf(stderr, "\niwkv_perf: %s failed, rc=%d\n", what, (int) rc);
    iwlog_ecode_error3(rc);
  } else {
    fprintf(stderr, "\niwkv_perf: %s failed\n", what);
  }
  fflush(stdout);
  fflush(stderr);
  _exit(1);
}

static inline uint64_t perf_now_ns(void) {
  struct timespec ts;
  iwrc rc = iwp_clock_get_time(CLOCK_MONOTONIC, &ts);
  if (rc) {
    perf_die("iwp_clock_get_time", rc);
  }
  return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

static uint64_t perf_env_u64(const char *name, uint64_t def) {
  const char *s = getenv(name);
  if (s && *s) {
    char *e = 0;
    unsigned long long v = strtoull(s, &e, 0);
    if (e && e != s && !*e) {
      return (uint64_t) v;
    }
  }
  return def;
}

static uint64_t perf_rand_next(uint64_t *s) {
  uint64_t x = *s;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  *s = x;
  return x;
}

static uint64_t perf_hash64(uint64_t x) {
  x ^= x >> 30;
  x *= 0xBF58476D1CE4E5B9ULL;
  x ^= x >> 27;
  x *= 0x94D049BB133111EBULL;
  x ^= x >> 31;
  return x;
}

static void perf_key_init(uint8_t *k, uint64_t idx, size_t ksz) {
  uint64_t x = idx ^ 0x9E3779B97F4A7C15ULL;
  size_t off = 0;
  while (off < ksz) {
    uint64_t m = x;
    m ^= m >> 30;
    m *= 0xBF58476D1CE4E5B9ULL;
    m ^= m >> 27;
    m *= 0x94D049BB133111EBULL;
    m ^= m >> 31;
    for (int b = 0; b < 8 && off < ksz; ++b, ++off) {
      k[off] = (uint8_t) (m >> (8 * b));
    }
    ++x;
  }
}

/* Ordered key used by the scan workload: big-endian index forms a monotonic
   sequence so that a key range maps onto a contiguous sorted range. */
static void perf_key_init_ordered(uint8_t *k, uint64_t idx, size_t ksz) {
  for (int b = 0; b < 8 && (size_t) b < ksz; ++b) {
    k[b] = (uint8_t) (idx >> (56 - 8 * b));
  }
  for (size_t i = 8; i < ksz; ++i) {
    k[i] = (uint8_t) (31 * i + 7);
  }
}

static uint64_t perf_ordered_key_idx(const uint8_t *k) {
  uint64_t v = 0;
  for (int b = 0; b < 8; ++b) {
    v = (v << 8) | k[b];
  }
  return v;
}

static void perf_val_template(uint8_t *v, size_t vsz) {
  uint64_t x = 0x9E3779B97F4A7C15ULL;
  for (size_t i = 0; i < vsz; ++i) {
    x = x * 6364136223846793005ULL + 1442695040888963407ULL;
    v[i] = (uint8_t) (x >> 56);
  }
}

/* Values are self describing: <8 byte index><1 byte generation><filler>. */
static void perf_val_set(uint8_t *v, uint64_t idx, uint8_t gen) {
  memcpy(v, &idx, sizeof(idx));
  v[8] = gen;
}

static bool perf_val_match(const void *data, size_t size, uint64_t idx) {
  if (size < 9) {
    return true;
  }
  const uint8_t *p = data;
  uint64_t got;
  memcpy(&got, p, sizeof(got));
  return got == idx && p[8] <= 1;
}

static void perf_task_verify(perf_task *t, const void *data, size_t size, uint64_t idx) {
  int v = t->ctx->verify;
  if (v == PERF_VERIFY_OFF) {
    return;
  }
  if (v == PERF_VERIFY_SAMPLE) {
    if ((t->verify_ctr++ & (uint64_t) (t->ctx->verify_every - 1)) != 0) {
      return;
    }
  }
  if (!perf_val_match(data, size, idx)) {
    perf_die("value verification", 0);
  }
}

static void perf_fmt_size(uint64_t bytes, char *buf, size_t bufsz) {
  static const char *units[] = { "B", "KB", "MB", "GB", "TB" };
  double v = (double) bytes;
  int u = 0;
  while (v >= 1024.0 && u < 4) {
    v /= 1024.0;
    ++u;
  }
  snprintf(buf, bufsz, "%.2f %s", v, units[u]);
}

/* Formats a record count in a compact human readable form, e.g. 100K or 1M. */
static void perf_fmt_count(uint64_t n, char *buf, size_t bufsz) {
  static const struct {
    uint64_t    div;
    const char *suffix;
  } units[] = {
    { 1000000000000ULL, "T" },
    { 1000000000ULL, "G" },
    { 1000000ULL, "M" },
    { 1000ULL, "K" },
  };
  for (size_t i = 0; i < sizeof(units) / sizeof(units[0]); ++i) {
    if (n >= units[i].div) {
      double v = (double) n / (double) units[i].div;
      if (v == (double) (uint64_t) v) {
        snprintf(buf, bufsz, "%" PRIu64 "%s", (uint64_t) v, units[i].suffix);
      } else {
        snprintf(buf, bufsz, "%.1f%s", v, units[i].suffix);
      }
      return;
    }
  }
  snprintf(buf, bufsz, "%" PRIu64, n);
}

static void perf_fmt_ns(uint64_t ns, char *buf, size_t bufsz) {
  if (ns < 1000) {
    snprintf(buf, bufsz, "%" PRIu64 " ns", ns);
  } else if (ns < 1000000) {
    snprintf(buf, bufsz, "%.2f us", (double) ns / 1e3);
  } else if (ns < 1000000000ULL) {
    snprintf(buf, bufsz, "%.2f ms", (double) ns / 1e6);
  } else {
    snprintf(buf, bufsz, "%.2f s", (double) ns / 1e9);
  }
}

static uint64_t perf_file_size(const char *path) {
  IWP_FILE_STAT st;
  memset(&st, 0, sizeof(st));
  iwrc rc = iwp_fstat(path, &st);
  return rc ? 0 : st.size;
}

/* Tracks the peak file size. Both the main db file (trimmed on close) and the
   WAL (checkpointed and truncated on close) must be sampled while the database
   is still open, otherwise the reported size is the empty post-close state. */
static void perf_track_peak(const char *path, uint64_t *peak) {
  uint64_t sz = perf_file_size(path);
  if (sz > *peak) {
    *peak = sz;
  }
}

static void perf_sample_sizes(const char *dbpath, const char *walpath, perf_iter *it) {
  perf_track_peak(dbpath, &it->db_peak_size);
  perf_track_peak(walpath, &it->wal_peak_size);
}

/* ---------------------------------------------------------------- zipf */

static double perf_zipf_zeta(uint64_t n, double theta) {
  double sum = 0.0;
  for (uint64_t i = 1; i <= n; ++i) {
    sum += pow(1.0 / (double) i, theta);
  }
  return sum;
}

static void perf_zipf_init(perf_zipf *z, uint64_t n, double theta) {
  z->n = n;
  z->theta = theta;
  z->zeta_2 = perf_zipf_zeta(2, theta);
  z->zeta_n = perf_zipf_zeta(n, theta);
  z->alpha = 1.0 / (1.0 - theta);
  z->eta = (1.0 - pow(2.0 / (double) n, 1.0 - theta)) / (1.0 - z->zeta_2 / z->zeta_n);
}

static uint64_t perf_zipf_next(perf_zipf *z, uint64_t *rng) {
  double u = (double) (perf_rand_next(rng) >> 11) * (1.0 / 9007199254740992.0);
  double uz = u * z->zeta_n;
  if (uz < 1.0) {
    return 0;
  }
  if (uz < 1.0 + pow(0.5, z->theta)) {
    return 1;
  }
  uint64_t ret = (uint64_t) ((double) z->n * pow(z->eta * u - z->eta + 1.0, z->alpha));
  return ret < z->n ? ret : z->n - 1;
}

static uint64_t perf_pick_idx(perf_task *t, perf_ctx *ctx) {
  if (ctx->keyspace == PERF_KS_SHARED) {
    if (ctx->key_dist == PERF_KD_ZIPFIAN && ctx->zipf && ctx->zipf->n) {
      return perf_hash64(perf_zipf_next(ctx->zipf, &t->rng)) % ctx->nrecs;
    }
    return perf_rand_next(&t->rng) % ctx->nrecs;
  }
  if (!t->kcnt) {
    return t->kstart;
  }
  return t->kstart + (perf_rand_next(&t->rng) % t->kcnt);
}

/* --------------------------------------------------------------- workers */

static void perf_insert(perf_task *t) {
  perf_ctx *ctx = t->ctx;
  iwkv_opflags oflags = ctx->sync ? IWKV_SYNC : 0;
  IWKV_val key = { 0 };
  IWKV_val val = { 0 };
  key.size = ctx->ksz;
  val.size = ctx->vsz;
  val.data = t->val_ins;
  for (uint64_t i = 0; i < t->kcnt; ++i) {
    uint64_t idx = t->kstart + i;
    key.data = (void*) (ctx->keys + (size_t) idx * ctx->ksz);
    if (ctx->vsz >= 9) {
      perf_val_set(t->val_ins, idx, 0);
    }
    uint64_t t0 = 0;
    if (ctx->record_lat) {
      t0 = perf_now_ns();
    }
    iwrc rc = iwkv_put(ctx->db, &key, &val, oflags);
    if (ctx->record_lat) {
      perf_hist_record(&t->lat, perf_now_ns() - t0);
    }
    if (rc) {
      perf_die("iwkv_put", rc);
    }
    ++t->writes;
  }
}

static void perf_update(perf_task *t) {
  perf_ctx *ctx = t->ctx;
  iwkv_opflags oflags = ctx->sync ? IWKV_SYNC : 0;
  IWKV_val key = { 0 };
  IWKV_val val = { 0 };
  key.size = ctx->ksz;
  val.size = ctx->vsz;
  val.data = t->val_upd;
  for (uint64_t i = 0; i < t->kcnt; ++i) {
    uint64_t idx = t->kstart + i;
    key.data = (void*) (ctx->keys + (size_t) idx * ctx->ksz);
    if (ctx->vsz >= 9) {
      perf_val_set(t->val_upd, idx, 1);
    }
    uint64_t t0 = 0;
    if (ctx->record_lat) {
      t0 = perf_now_ns();
    }
    iwrc rc = iwkv_put(ctx->db, &key, &val, oflags);
    if (ctx->record_lat) {
      perf_hist_record(&t->lat, perf_now_ns() - t0);
    }
    if (rc) {
      perf_die("iwkv_put", rc);
    }
    ++t->writes;
  }
}

static void perf_delete(perf_task *t) {
  perf_ctx *ctx = t->ctx;
  iwkv_opflags oflags = ctx->sync ? IWKV_SYNC : 0;
  IWKV_val key = { 0 };
  key.size = ctx->ksz;
  for (uint64_t i = 0; i < t->kcnt; ++i) {
    key.data = (void*) (ctx->keys + (size_t) (t->kstart + i) * ctx->ksz);
    uint64_t t0 = 0;
    if (ctx->record_lat) {
      t0 = perf_now_ns();
    }
    iwrc rc = iwkv_del(ctx->db, &key, oflags);
    if (ctx->record_lat) {
      perf_hist_record(&t->lat, perf_now_ns() - t0);
    }
    if (rc) {
      perf_die("iwkv_del", rc);
    }
    ++t->writes;
  }
}

static void perf_read(perf_task *t) {
  perf_ctx *ctx = t->ctx;
  IWKV_val key = { 0 };
  key.size = ctx->ksz;
  for (uint64_t i = 0; i < t->kcnt; ++i) {
    uint64_t idx = t->kstart + i;
    key.data = (void*) (ctx->keys + (size_t) idx * ctx->ksz);
    if (ctx->read_mode == PERF_RM_COPY) {
      size_t vsz = 0;
      uint64_t t0 = 0;
      if (ctx->record_lat) {
        t0 = perf_now_ns();
      }
      iwrc rc = iwkv_get_copy(ctx->db, &key, t->read_buf, ctx->vsz, &vsz);
      if (ctx->record_lat) {
        perf_hist_record(&t->lat, perf_now_ns() - t0);
      }
      if (rc) {
        perf_die("iwkv_get_copy", rc);
      }
      perf_task_verify(t, t->read_buf, vsz, idx);
    } else {
      IWKV_val val = { 0 };
      uint64_t t0 = 0;
      if (ctx->record_lat) {
        t0 = perf_now_ns();
      }
      iwrc rc = iwkv_get(ctx->db, &key, &val);
      if (ctx->record_lat) {
        perf_hist_record(&t->lat, perf_now_ns() - t0);
      }
      if (rc) {
        perf_die("iwkv_get", rc);
      }
      perf_task_verify(t, val.data, val.size, idx);
      iwkv_val_dispose(&val);
    }
    ++t->reads;
  }
}

static void perf_mixed(perf_task *t) {
  perf_ctx *ctx = t->ctx;
  iwkv_opflags oflags = ctx->sync ? IWKV_SYNC : 0;
  IWKV_val key = { 0 };
  key.size = ctx->ksz;
  for (uint64_t i = 0; i < t->ocnt; ++i) {
    bool is_write = (ctx->read_pct < 100) && ((t->ostart + i) % 100) >= (uint64_t) ctx->read_pct;
    if (is_write) {
      uint64_t idx = perf_pick_idx(t, ctx);
      key.data = (void*) (ctx->keys + (size_t) idx * ctx->ksz);
      if (ctx->vsz >= 9) {
        perf_val_set(t->val_upd, idx, 1);
      }
      IWKV_val val = { 0 };
      val.size = ctx->vsz;
      val.data = t->val_upd;
      uint64_t t0 = 0;
      if (ctx->record_lat) {
        t0 = perf_now_ns();
      }
      iwrc rc = iwkv_put(ctx->db, &key, &val, oflags);
      if (ctx->record_lat) {
        perf_hist_record(&t->lat, perf_now_ns() - t0);
      }
      if (rc) {
        perf_die("iwkv_put", rc);
      }
      ++t->writes;
      continue;
    }
    bool is_miss = ctx->miss_pct > 0 && (perf_rand_next(&t->rng) % 100) < (uint64_t) ctx->miss_pct;
    uint64_t idx = 0;
    if (is_miss) {
      idx = ctx->nrecs + (perf_rand_next(&t->rng) % ctx->nrecs);
      perf_key_init(t->miss_key, idx, ctx->ksz);
      key.data = t->miss_key;
    } else {
      idx = perf_pick_idx(t, ctx);
      key.data = (void*) (ctx->keys + (size_t) idx * ctx->ksz);
    }
    if (ctx->read_mode == PERF_RM_COPY) {
      size_t vsz = 0;
      uint64_t t0 = 0;
      if (ctx->record_lat) {
        t0 = perf_now_ns();
      }
      iwrc rc = iwkv_get_copy(ctx->db, &key, t->read_buf, ctx->vsz, &vsz);
      if (ctx->record_lat) {
        perf_hist_record(&t->lat, perf_now_ns() - t0);
      }
      if (is_miss) {
        if (rc != IWKV_ERROR_NOTFOUND) {
          perf_die("expected NOTFOUND", rc);
        }
        ++t->misses;
      } else {
        if (rc) {
          perf_die("iwkv_get_copy", rc);
        }
        perf_task_verify(t, t->read_buf, vsz, idx);
        ++t->reads;
      }
    } else {
      IWKV_val val = { 0 };
      uint64_t t0 = 0;
      if (ctx->record_lat) {
        t0 = perf_now_ns();
      }
      iwrc rc = iwkv_get(ctx->db, &key, &val);
      if (ctx->record_lat) {
        perf_hist_record(&t->lat, perf_now_ns() - t0);
      }
      if (is_miss) {
        if (rc != IWKV_ERROR_NOTFOUND) {
          perf_die("expected NOTFOUND", rc);
        }
        ++t->misses;
      } else {
        if (rc) {
          perf_die("iwkv_get", rc);
        }
        perf_task_verify(t, val.data, val.size, idx);
        ++t->reads;
      }
      iwkv_val_dispose(&val);
    }
  }
}

static void perf_scan(perf_task *t) {
  perf_ctx *ctx = t->ctx;
  IWKV_cursor cur = 0;
  IWKV_val first = { 0 };
  uint64_t first_idx = ctx->scan_desc ? (ctx->nrecs - 1 - t->kstart) : t->kstart;
  first.size = ctx->ksz;
  /* The scan workload uses ordered keys, so index order matches sorted key
     order. When the engine iterates in descending key order the first record
     of the ordinal window [kstart, kstart + kcnt) carries the largest index. */
  first.data = (void*) (ctx->keys + (size_t) first_idx * ctx->ksz);
  iwrc rc = iwkv_cursor_open(ctx->db, &cur, IWKV_CURSOR_BEFORE_FIRST, 0);
  if (rc) {
    perf_die("iwkv_cursor_open", rc);
  }
  rc = iwkv_cursor_to_key(cur, IWKV_CURSOR_GE, &first);
  if (rc && t->kcnt) {
    perf_die("iwkv_cursor_to_key", rc);
  }
  for (uint64_t i = 0; i < t->kcnt; ++i) {
    IWKV_val val = { 0 };
    uint64_t t0 = 0;
    if (ctx->record_lat) {
      t0 = perf_now_ns();
    }
    rc = iwkv_cursor_get(cur, 0, &val);
    if (ctx->record_lat) {
      perf_hist_record(&t->lat, perf_now_ns() - t0);
    }
    if (rc) {
      perf_die("iwkv_cursor_get", rc);
    }
    if (  ctx->verify == PERF_VERIFY_FULL
       || (ctx->verify == PERF_VERIFY_SAMPLE && ((t->verify_ctr++ & (uint64_t) (ctx->verify_every - 1)) == 0))) {
      /* The scanned key is not tracked here, verify the value is well formed. */
      if (val.size < 9 || ((const uint8_t*) val.data)[8] > 1) {
        perf_die("scan value verification", 0);
      }
    }
    iwkv_val_dispose(&val);
    ++t->scanned;
    if (i + 1 < t->kcnt) {
      rc = iwkv_cursor_to(cur, IWKV_CURSOR_NEXT);
      if (rc) {
        perf_die("iwkv_cursor_to", rc);
      }
    }
  }
  rc = iwkv_cursor_close(&cur);
  if (rc) {
    perf_die("iwkv_cursor_close", rc);
  }
}

/* Probes the engine iteration direction using the first two ordered keys. */
static bool perf_scan_descending(perf_ctx *ctx) {
  IWKV_cursor cur = 0;
  uint64_t i0 = 0, i1 = 0;
  bool have1 = false;
  if (iwkv_cursor_open(ctx->db, &cur, IWKV_CURSOR_BEFORE_FIRST, 0)) {
    return true;
  }
  for (int n = 0; n < 2; ++n) {
    if (iwkv_cursor_to(cur, IWKV_CURSOR_NEXT)) {
      break;
    }
    IWKV_val k = { 0 };
    if (iwkv_cursor_key(cur, &k)) {
      break;
    }
    uint64_t idx = perf_ordered_key_idx(k.data);
    iwkv_val_dispose(&k);
    if (n == 0) {
      i0 = idx;
    } else {
      i1 = idx;
      have1 = true;
    }
  }
  iwkv_cursor_close(&cur);
  return have1 ? (i1 < i0) : true;
}

/* ---------------------------------------------------------- phase runner */

static void* perf_thread_entry(void *arg) {
  perf_task *t = arg;
  if (t->ctx->bar) {
    pthread_barrier_wait(t->ctx->bar);
  }
  t->fn(t);
  return 0;
}

static uint64_t perf_phase_ops(const perf_phase *ph) {
  return ph->reads + ph->writes + ph->misses + ph->scanned;
}

static void perf_run_phase(
  perf_ctx      *ctx,
  perf_worker_fn fn,
  uint64_t       key_units,
  uint64_t       op_units,
  perf_hist     *collect,
  perf_phase    *out) {
  memset(out, 0, sizeof(*out));
  int nt = ctx->concurrent ? ctx->nthreads : 1;
  if (nt < 1) {
    nt = 1;
  }
  perf_task *tasks = calloc((size_t) nt, sizeof(*tasks));
  if (!tasks) {
    perf_die("calloc", 0);
  }
  for (int i = 0; i < nt; ++i) {
    perf_task *t = &tasks[i];
    t->ctx = ctx;
    t->fn = fn;
    t->tid = i;
    t->kstart = (key_units * (uint64_t) i) / (uint64_t) nt;
    t->kcnt = (key_units * (uint64_t) (i + 1)) / (uint64_t) nt - t->kstart;
    t->ostart = (op_units * (uint64_t) i) / (uint64_t) nt;
    t->ocnt = (op_units * (uint64_t) (i + 1)) / (uint64_t) nt - t->ostart;
    t->rng = 0x243F6A8885A308D3ULL ^ ((uint64_t) (i + 1) * 0x9E3779B97F4A7C15ULL);
    if (!t->rng) {
      t->rng = 1;
    }
    t->val_ins = malloc(ctx->vsz);
    t->val_upd = malloc(ctx->vsz);
    t->read_buf = malloc(ctx->vsz);
    if (!t->val_ins || !t->val_upd || !t->read_buf) {
      perf_die("malloc", 0);
    }
    if (ctx->vsz >= 9) {
      memcpy(t->val_ins, ctx->val_tmpl, ctx->vsz);
      memcpy(t->val_upd, ctx->val_tmpl, ctx->vsz);
    }
  }
  ctx->record_lat = collect != 0 && ctx->latency;
  uint64_t t0 = 0;
  uint64_t t1 = 0;
  if (nt == 1) {
    t0 = perf_now_ns();
    fn(&tasks[0]);
    t1 = perf_now_ns();
  } else {
    pthread_barrier_t bar;
    int rci = pthread_barrier_init(&bar, 0, (unsigned) nt + 1);
    if (rci) {
      fprintf(stderr, "\niwkv_perf: pthread_barrier_init failed: %d\n", rci);
      _exit(1);
    }
    ctx->bar = &bar;
    for (int i = 0; i < nt; ++i) {
      rci = pthread_create(&tasks[i].thr, 0, perf_thread_entry, &tasks[i]);
      if (rci) {
        fprintf(stderr, "\niwkv_perf: pthread_create failed: %d\n", rci);
        _exit(1);
      }
    }
    pthread_barrier_wait(&bar);
    t0 = perf_now_ns();
    for (int i = 0; i < nt; ++i) {
      pthread_join(tasks[i].thr, 0);
    }
    t1 = perf_now_ns();
    pthread_barrier_destroy(&bar);
    ctx->bar = 0;
  }
  ctx->record_lat = false;
  for (int i = 0; i < nt; ++i) {
    perf_task *t = &tasks[i];
    out->reads += t->reads;
    out->writes += t->writes;
    out->misses += t->misses;
    out->scanned += t->scanned;
    if (collect) {
      perf_hist_merge(collect, &t->lat);
    }
    free(t->val_ins);
    free(t->val_upd);
    free(t->read_buf);
  }
  out->secs = (double) (t1 - t0) / 1e9;
  free(tasks);
}

/* ---------------------------------------------------------- combination */

static void perf_run_iteration(
  enum perf_workload   wl,
  bool                 concurrent,
  enum perf_durability dur,
  perf_dataset        *ds,
  const uint8_t       *keys,
  const uint8_t       *val_tmpl,
  perf_iter           *it,
  perf_hist           *metric_lat) {
  memset(it, 0, sizeof(*it));
  char path[PATH_MAX];
  char walpath[PATH_MAX];
  snprintf(path, sizeof(path), "iwkv_perf_%s_%s_%s_%s.db",
           perf_workload_names[wl], concurrent ? "mt" : "st",
           perf_durability_names[dur], ds->name);
  snprintf(walpath, sizeof(walpath), "%s-wal", path);
  unlink(path);
  unlink(walpath);

  IWKV_OPTS opts = {
    .path = path,
    .oflags = IWKV_TRUNC,
    .wal = {
      .enabled = (dur != PERF_DURABILITY_WAL_OFF)
    }
  };
  IWKV iwkv = 0;
  iwrc rc = iwkv_open(&opts, &iwkv);
  if (rc) {
    perf_die("iwkv_open", rc);
  }
  IWDB db = 0;
  rc = iwkv_db(iwkv, 1, 0, &db);
  if (rc) {
    perf_die("iwkv_db", rc);
  }

  perf_ctx ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.db = db;
  ctx.ds = ds;
  ctx.nrecs = ds->nrecs;
  ctx.ksz = ds->ksz;
  ctx.vsz = ds->vsz;
  ctx.keys = keys;
  ctx.val_tmpl = val_tmpl;
  ctx.nthreads = concurrent ? g_cfg.threads : 1;
  ctx.concurrent = concurrent;
  ctx.sync = (dur == PERF_DURABILITY_WAL_SYNC);
  ctx.read_mode = g_cfg.read_mode;
  ctx.key_dist = g_cfg.key_dist;
  ctx.keyspace = g_cfg.keyspace;
  ctx.latency = g_cfg.latency != 0;
  ctx.verify = g_cfg.verify;
  ctx.verify_every = g_cfg.verify_every;
  ctx.read_pct = g_cfg.read_pct;
  ctx.miss_pct = g_cfg.miss_pct;
  ctx.zipf = (g_cfg.key_dist == PERF_KD_ZIPFIAN) ? ds->zipf : 0;
  ctx.scan_desc = true;

  perf_worker_fn read_fn = perf_read;

  switch (wl) {
    case PERF_WORKLOAD_CRUD:
      perf_run_phase(&ctx, perf_insert, ds->nrecs, ds->nrecs, metric_lat, &it->ph[0]);
      perf_sample_sizes(path, walpath, it);
      perf_run_phase(&ctx, read_fn, ds->nrecs, ds->nrecs, metric_lat, &it->ph[1]);
      perf_run_phase(&ctx, perf_update, ds->nrecs, ds->nrecs, metric_lat, &it->ph[2]);
      perf_sample_sizes(path, walpath, it);
      perf_run_phase(&ctx, perf_delete, ds->nrecs, ds->nrecs, metric_lat, &it->ph[3]);
      it->nph = 4;
      break;
    case PERF_WORKLOAD_READ_MOSTLY: {
      perf_run_phase(&ctx, perf_insert, ds->nrecs, ds->nrecs, 0, &it->ph[0]);
      perf_sample_sizes(path, walpath, it);
      uint64_t mixed = ds->nrecs * PERF_READ_MOSTLY_OPS_MULT;
      perf_run_phase(&ctx, perf_mixed, ds->nrecs, mixed, metric_lat, &it->ph[1]);
      it->nph = 2;
      break;
    }
    case PERF_WORKLOAD_SCAN:
      perf_run_phase(&ctx, perf_insert, ds->nrecs, ds->nrecs, 0, &it->ph[0]);
      perf_sample_sizes(path, walpath, it);
      ctx.scan_desc = perf_scan_descending(&ctx);
      perf_run_phase(&ctx, perf_scan, ds->nrecs, ds->nrecs, metric_lat, &it->ph[1]);
      it->nph = 2;
      break;
    default:
      perf_die("unknown workload", 0);
  }

  /* The metric covers all phases except the read-mostly/scan load phase. */
  int first_metric = (wl == PERF_WORKLOAD_CRUD) ? 0 : 1;
  for (int i = first_metric; i < it->nph; ++i) {
    it->metric_secs += it->ph[i].secs;
    it->metric_ops += perf_phase_ops(&it->ph[i]);
  }

  /* Flush buffered WAL data so the peak size reflects all writes. The
     close-time checkpoint would otherwise truncate the WAL to zero. */
  if (dur != PERF_DURABILITY_WAL_OFF) {
    rc = iwkv_sync(iwkv, IWFS_SYNCDEFAULT);
    if (rc) {
      perf_die("iwkv_sync", rc);
    }
    perf_sample_sizes(path, walpath, it);
  }

  rc = iwkv_close(&iwkv);
  if (rc) {
    perf_die("iwkv_close", rc);
  }
  it->db_final_size = perf_file_size(path);
  it->wal_final_size = perf_file_size(walpath);
  unlink(path);
  unlink(walpath);
}

static int perf_cmp_double(const void *a, const void *b) {
  double x = *(const double*) a;
  double y = *(const double*) b;
  return (x > y) - (x < y);
}

static void perf_run_combination(
  enum perf_workload   wl,
  bool                 concurrent,
  enum perf_durability dur,
  perf_dataset        *ds,
  perf_result         *res) {
  memset(res, 0, sizeof(*res));
  res->ds = ds;
  res->wl = wl;
  res->dur = dur;
  res->concurrent = concurrent;
  res->nthreads = concurrent ? g_cfg.threads : 1;

  size_t keysz = (size_t) ds->nrecs * ds->ksz;
  uint8_t *keys = malloc(keysz);
  uint8_t *val_tmpl = malloc(ds->vsz);
  if (!keys || !val_tmpl) {
    perf_die("malloc", 0);
  }
  for (uint64_t i = 0; i < ds->nrecs; ++i) {
    if (wl == PERF_WORKLOAD_SCAN) {
      perf_key_init_ordered(keys + (size_t) i * ds->ksz, i, ds->ksz);
    } else {
      perf_key_init(keys + (size_t) i * ds->ksz, i, ds->ksz);
    }
  }
  perf_val_template(val_tmpl, ds->vsz);

  int total = g_cfg.repeats;
  if (total < 1) {
    total = 1;
  }
  if (total > PERF_MAX_REPEATS) {
    total = PERF_MAX_REPEATS;
  }
  int nmeasured = 0;
  double thr[PERF_MAX_REPEATS];
  for (int it = 0; it < total; ++it) {
    perf_hist iter_lat;
    memset(&iter_lat, 0, sizeof(iter_lat));
    perf_iter result;
    perf_run_iteration(wl, concurrent, dur, ds, keys, val_tmpl, &result, &iter_lat);
    if (it == 0 && total > 1) {
      continue; /* Warm-up iteration */
    }
    res->iters[nmeasured] = result;
    if (result.metric_secs > 0) {
      thr[nmeasured] = (double) result.metric_ops / result.metric_secs;
    } else {
      thr[nmeasured] = 0;
    }
    perf_hist_merge(&res->lat, &iter_lat);
    ++nmeasured;
  }
  res->nmeasured = nmeasured;
  if (nmeasured > 0) {
    double sorted[PERF_MAX_REPEATS];
    memcpy(sorted, thr, (size_t) nmeasured * sizeof(double));
    qsort(sorted, (size_t) nmeasured, sizeof(double), perf_cmp_double);
    res->thr_min = sorted[0];
    res->thr_max = sorted[nmeasured - 1];
    res->thr_med = nmeasured & 1
                   ? sorted[nmeasured / 2]
                   : (sorted[nmeasured / 2 - 1] + sorted[nmeasured / 2]) / 2.0;
  }
  free(keys);
  free(val_tmpl);
}

/* ------------------------------------------------------------ provenance */

static const char* perf_cpu_model(void) {
#if defined(__linux__)
  static char buf[256];
  static bool loaded = false;
  if (!loaded) {
    loaded = true;
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f) {
      char line[512];
      while (fgets(line, sizeof(line), f)) {
        if (!strncmp(line, "model name", 10)) {
          char *c = strchr(line, ':');
          if (c) {
            ++c;
            while (*c == ' ') {
              ++c;
            }
            size_t n = strcspn(c, "\r\n");
            if (n >= sizeof(buf)) {
              n = sizeof(buf) - 1;
            }
            memcpy(buf, c, n);
            buf[n] = 0;
          }
          break;
        }
      }
      fclose(f);
    }
    if (!buf[0]) {
      snprintf(buf, sizeof(buf), "unknown");
    }
  }
  return buf;
#else
  return "unknown";
#endif
}

static const char* perf_os_string(void) {
#if defined(_WIN32)
  return "windows";
#else
  static char buf[256];
  static bool loaded = false;
  if (!loaded) {
    loaded = true;
    struct utsname u;
    if (uname(&u) == 0) {
      snprintf(buf, sizeof(buf), "%s %s", u.sysname, u.release);
    } else {
      snprintf(buf, sizeof(buf), "unknown");
    }
  }
  return buf;
#endif
}

static long perf_cores(void) {
  long n = sysconf(_SC_NPROCESSORS_ONLN);
  return n > 0 ? n : 0;
}

static long perf_page_size(void) {
  long n = sysconf(_SC_PAGESIZE);
  return n > 0 ? n : 0;
}

/* ------------------------------------------------------------- reporting */

static void perf_json_str(FILE *f, const char *s) {
  fputc('"', f);
  for ( ; s && *s; ++s) {
    unsigned char c = (unsigned char) *s;
    switch (c) {
      case '"':
        fputs("\\\"", f);
        break;
      case '\\':
        fputs("\\\\", f);
        break;
      case '\n':
        fputs("\\n", f);
        break;
      case '\r':
        fputs("\\r", f);
        break;
      case '\t':
        fputs("\\t", f);
        break;
      default:
        if (c < 0x20) {
          fprintf(f, "\\u%04x", c);
        } else {
          fputc(c, f);
        }
    }
  }
  fputc('"', f);
}

static int perf_median_iter(const perf_result *r);

static void perf_print_text(FILE *f, const perf_result *r) {
  char recbuf[32];
  char keybuf[24];
  char valbuf[24];
  char thrbuf[24];
  char cntbuf[24];
  char dbbuf[32];
  char dbfbuf[32];
  char walbuf[32];
  char walfbuf[32];
  char dbpair[48];
  char walpair[48];
  const perf_iter *mi = &r->iters[perf_median_iter(r)];
  perf_fmt_count(r->ds->nrecs, cntbuf, sizeof(cntbuf));
  snprintf(recbuf, sizeof(recbuf), "records=%s", cntbuf);
  snprintf(keybuf, sizeof(keybuf), "key=%zuB", r->ds->ksz);
  snprintf(valbuf, sizeof(valbuf), "val=%zuB", r->ds->vsz);
  snprintf(thrbuf, sizeof(thrbuf), "threads=%d", r->nthreads);
  perf_fmt_size(mi->db_peak_size, dbbuf, sizeof(dbbuf));
  perf_fmt_size(mi->db_final_size, dbfbuf, sizeof(dbfbuf));
  perf_fmt_size(mi->wal_peak_size, walbuf, sizeof(walbuf));
  perf_fmt_size(mi->wal_final_size, walfbuf, sizeof(walfbuf));
  snprintf(dbpair, sizeof(dbpair), "%s/%s", dbbuf, dbfbuf);
  snprintf(walpair, sizeof(walpair), "%s/%s", walbuf, walfbuf);
  fprintf(f, "\n[%-11s | %-6s | %-8s | %-9s] %-16s %-9s %-10s %-11s measured=%d\n",
          perf_workload_names[r->wl], r->concurrent ? "multi" : "single",
          perf_durability_names[r->dur], r->ds->name,
          recbuf, keybuf, valbuf, thrbuf, r->nmeasured);
  fprintf(f, "    throughput: median %.0f ops/s (min %.0f, max %.0f)\n",
          r->thr_med, r->thr_min, r->thr_max);
  for (int i = 0; i < mi->nph; ++i) {
    const perf_phase *ph = &mi->ph[i];
    double rate = ph->secs > 0 ? (double) perf_phase_ops(ph) / ph->secs : 0.0;
    fprintf(f, "    %-7s %8.3f s %12.0f ops/s\n", perf_phase_names[r->wl][i], ph->secs, rate);
  }
  if (r->lat.count) {
    char mean[32], p50[32], p90[32], p99[32], p999[32], mx[32];
    perf_fmt_ns(r->lat.sum / r->lat.count, mean, sizeof(mean));
    perf_fmt_ns(perf_hist_percentile(&r->lat, 50.0), p50, sizeof(p50));
    perf_fmt_ns(perf_hist_percentile(&r->lat, 90.0), p90, sizeof(p90));
    perf_fmt_ns(perf_hist_percentile(&r->lat, 99.0), p99, sizeof(p99));
    perf_fmt_ns(perf_hist_percentile(&r->lat, 99.9), p999, sizeof(p999));
    perf_fmt_ns(r->lat.max, mx, sizeof(mx));
    fprintf(f, "    latency: mean %s  p50 %s  p90 %s  p99 %s  p99.9 %s  max %s\n",
            mean, p50, p90, p99, p999, mx);
  }
  fprintf(f, "    db: %-21swal: %s\n", dbpair, walpair);
}

static int perf_median_iter(const perf_result *r) {
  int midx = 0;
  double best = 1e300;
  for (int i = 0; i < r->nmeasured; ++i) {
    double t = r->iters[i].metric_secs > 0
               ? (double) r->iters[i].metric_ops / r->iters[i].metric_secs : 0.0;
    double d = fabs(t - r->thr_med);
    if (d < best) {
      best = d;
      midx = i;
    }
  }
  return midx;
}

static void perf_print_summary(FILE *f, const perf_result *results, size_t num) {
  fprintf(f, "\n\n=== Summary (median measured throughput) ===\n");
  fprintf(f, "%-12s %-6s %-9s %-9s %12s %10s %14s %14s %12s\n",
          "workload", "conc", "durability", "dataset", "ops", "secs", "median ops/s", "max ops/s", "db peak");
  for (size_t i = 0; i < num; ++i) {
    const perf_result *r = &results[i];
    const perf_iter *mi = &r->iters[perf_median_iter(r)];
    char dbbuf[32];
    perf_fmt_size(mi->db_peak_size, dbbuf, sizeof(dbbuf));
    fprintf(f, "%-12s %-6s %-9s %-9s %12" PRIu64 " %10.3f %14.0f %14.0f %12s\n",
            perf_workload_names[r->wl], r->concurrent ? "multi" : "single",
            perf_durability_names[r->dur], r->ds->name,
            mi->metric_ops, mi->metric_secs, r->thr_med, r->thr_max, dbbuf);
  }
}

static void perf_print_json(FILE *f, const perf_result *results, size_t num) {
  fprintf(f, "{\n");
  fprintf(f, "  \"tool\": \"iwkv_perf\",\n");
  fprintf(f, "  \"provenance\": {\n");
  fprintf(f, "    \"git_rev\": ");
  perf_json_str(f, PERF_STR(IWKV_PERF_GIT_REV));
  fprintf(f, ",\n    \"compiler\": ");
  perf_json_str(f, __VERSION__);
  fprintf(f, ",\n    \"os\": ");
  perf_json_str(f, perf_os_string());
  fprintf(f, ",\n    \"cpu\": ");
  perf_json_str(f, perf_cpu_model());
  fprintf(f, ",\n    \"cores\": %ld,\n    \"page_size\": %ld\n  },\n", perf_cores(), perf_page_size());
  fprintf(f, "  \"config\": {\n");
  fprintf(f, "    \"threads\": %d, \"repeats\": %d, \"read_pct\": %d, \"miss_pct\": %d,\n",
          g_cfg.threads, g_cfg.repeats, g_cfg.read_pct, g_cfg.miss_pct);
  fprintf(f, "    \"key_dist\": ");
  perf_json_str(f, perf_key_dist_names[g_cfg.key_dist]);
  fprintf(f, ", \"keyspace\": ");
  perf_json_str(f, perf_keyspace_names[g_cfg.keyspace]);
  fprintf(f, ", \"read_mode\": ");
  perf_json_str(f, perf_read_mode_names[g_cfg.read_mode]);
  fprintf(f, ", \"verify\": ");
  perf_json_str(f, perf_verify_names[g_cfg.verify]);
  fprintf(f, ",\n    \"datasets\": [");
  for (size_t i = 0; i < PERF_DS_NUM; ++i) {
    fprintf(f, "%s{\"name\": ", i ? ", " : "");
    perf_json_str(f, perf_datasets[i].name);
    fprintf(f, ", \"records\": %" PRIu64 ", \"key_size\": %zu, \"value_size\": %zu}",
            perf_datasets[i].nrecs, perf_datasets[i].ksz, perf_datasets[i].vsz);
  }
  fprintf(f, "]\n  },\n");
  fprintf(f, "  \"results\": [\n");
  for (size_t i = 0; i < num; ++i) {
    const perf_result *r = &results[i];
    fprintf(f, "    {\n      \"workload\": ");
    perf_json_str(f, perf_workload_names[r->wl]);
    fprintf(f, ", \"concurrency\": ");
    perf_json_str(f, r->concurrent ? "multi" : "single");
    fprintf(f, ", \"durability\": ");
    perf_json_str(f, perf_durability_names[r->dur]);
    fprintf(f, ", \"dataset\": ");
    perf_json_str(f, r->ds->name);
    fprintf(f,
            ",\n      \"records\": %" PRIu64
            ", \"key_size\": %zu, \"value_size\": %zu, \"threads\": %d, \"iterations\": %d,\n",
            r->ds->nrecs,
            r->ds->ksz,
            r->ds->vsz,
            r->nthreads,
            r->nmeasured);
    fprintf(f, "      \"throughput_median\": %.0f, \"throughput_min\": %.0f, \"throughput_max\": %.0f,\n",
            r->thr_med, r->thr_min, r->thr_max);
    fprintf(f, "      \"latency_ns\": {\"mean\": %" PRIu64 ", \"p50\": %" PRIu64 ", \"p90\": %" PRIu64
            ", \"p99\": %" PRIu64 ", \"p999\": %" PRIu64 ", \"max\": %" PRIu64 "},\n",
            r->lat.count ? r->lat.sum / r->lat.count : 0,
            perf_hist_percentile(&r->lat, 50.0), perf_hist_percentile(&r->lat, 90.0),
            perf_hist_percentile(&r->lat, 99.0), perf_hist_percentile(&r->lat, 99.9), r->lat.max);
    const perf_iter *mi = &r->iters[perf_median_iter(r)];
    fprintf(f, "      \"phases\": [");
    for (int j = 0; j < mi->nph; ++j) {
      const perf_phase *ph = &mi->ph[j];
      fprintf(f, "%s{\"name\": ", j ? ", " : "");
      perf_json_str(f, perf_phase_names[r->wl][j]);
      fprintf(f, ", \"secs\": %.6f, \"ops\": %" PRIu64 "}", ph->secs, perf_phase_ops(ph));
    }
    fprintf(f, "],\n");
    fprintf(f,
            "      \"db_peak_size\": %" PRIu64 ", \"db_final_size\": %" PRIu64 ", \"wal_peak_size\": %" PRIu64
            ", \"wal_final_size\": %" PRIu64 "\n    }%s\n",
            mi->db_peak_size,
            mi->db_final_size,
            mi->wal_peak_size,
            mi->wal_final_size,
            (i + 1 < num) ? "," : "");
  }
  fprintf(f, "  ]\n}\n");
}

static void perf_print_csv(FILE *f, const perf_result *results, size_t num) {
  fprintf(f,
          "workload,concurrency,durability,dataset,records,key_size,value_size,threads,iterations,"
          "median_ops_s,min_ops_s,max_ops_s,lat_mean_ns,lat_p50_ns,lat_p99_ns,db_peak_bytes,db_final_bytes,"
          "wal_peak_bytes,wal_final_bytes\n");
  for (size_t i = 0; i < num; ++i) {
    const perf_result *r = &results[i];
    const perf_iter *mi = &r->iters[perf_median_iter(r)];
    fprintf(f,
            "%s,%s,%s,%s,%" PRIu64 ",%zu,%zu,%d,%d,%.0f,%.0f,%.0f,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%"
            PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
            perf_workload_names[r->wl],
            r->concurrent ? "multi" : "single",
            perf_durability_names[r->dur],
            r->ds->name,
            r->ds->nrecs,
            r->ds->ksz,
            r->ds->vsz,
            r->nthreads,
            r->nmeasured,
            r->thr_med,
            r->thr_min,
            r->thr_max,
            r->lat.count ? r->lat.sum / r->lat.count : 0,
            perf_hist_percentile(&r->lat, 50.0),
            perf_hist_percentile(&r->lat, 99.0),
            mi->db_peak_size,
            mi->db_final_size,
            mi->wal_peak_size,
            mi->wal_final_size);
  }
}

/* ------------------------------------------------------------------ CLI */

static void perf_usage(FILE *f) {
  fprintf(f,
          "Usage: iwkv_perf [options]\n"
          "\n"
          "Selection:\n"
          "  --workload=LIST   crud,read-mostly,scan           (default: crud,read-mostly)\n"
          "  --dataset=LIST    small32,small240,small1016,large32 (default: all)\n"
          "  --conc=LIST       single,multi                    (default: both)\n"
          "  --wal=LIST        off,on,sync                     (default: off,on)\n"
          "\n"
          "Tuning:\n"
          "  --threads=N       Threads for the multi mode        (default: %d)\n"
          "  --repeats=N       Total iterations, first is warm-up (default: %d)\n"
          "  --read-pct=N      Read percentage in read-mostly    (default: %d)\n"
          "  --miss-pct=N      Missing-key read percentage       (default: 0)\n"
          "  --key-dist=MODE   uniform,zipfian                   (default: uniform)\n"
          "  --keyspace=MODE   shared,partitioned                (default: shared)\n"
          "  --read-mode=MODE  alloc,copy                        (default: alloc)\n"
          "  --latency=on|off  Collect per-operation latency     (default: on)\n"
          "  --verify=MODE     off,sample,full                   (default: sample)\n"
          "  --verify-every=N  Sampling interval for verify=sample (default: 64)\n"
          "  --small=N         Records in the small datasets\n"
          "  --large=N         Records in the large dataset\n"
          "  --quick           Tiny datasets and a single iteration\n"
          "\n"
          "Output:\n"
          "  --format=FMT      text,json,csv                     (default: text)\n"
          "  --output=FILE     Write the report into FILE\n"
          "  --list            List the available options and exit\n"
          "  -h, --help        Show this help\n",
          IWKV_PERF_NUM_THREADS, IWKV_PERF_REPEATS, IWKV_PERF_READ_PCT);
}

typedef struct perf_nameval {
  const char *name;
  unsigned    bit;
} perf_nameval;

static bool perf_opt(const char *arg, const char *name, const char **val) {
  size_t n = strlen(name);
  if (!strncmp(arg, name, n) && arg[n] == '=') {
    *val = arg + n + 1;
    return true;
  }
  return false;
}

static const char* perf_next_token(const char **p, char *buf, size_t bufsz) {
  const char *s = *p;
  if (!s || !*s) {
    return 0;
  }
  const char *e = strchr(s, ',');
  size_t n = e ? (size_t) (e - s) : strlen(s);
  if (n >= bufsz) {
    n = bufsz - 1;
  }
  memcpy(buf, s, n);
  buf[n] = 0;
  *p = e ? e + 1 : s + strlen(s);
  return buf;
}

static bool perf_parse_mask(const char *v, const perf_nameval *map, unsigned *out) {
  char buf[64];
  const char *p = v;
  unsigned m = 0;
  while (perf_next_token(&p, buf, sizeof(buf))) {
    if (!buf[0]) {
      continue;
    }
    int found = -1;
    for (int i = 0; map[i].name; ++i) {
      if (!strcmp(map[i].name, buf)) {
        found = i;
        break;
      }
    }
    if (found < 0) {
      fprintf(stderr, "iwkv_perf: unknown value '%s'\n", buf);
      return false;
    }
    m |= map[found].bit;
  }
  if (!m) {
    return false;
  }
  *out = m;
  return true;
}

static bool perf_parse_int(const char *v, int lo, int hi, int *out) {
  char *e = 0;
  long n = strtol(v, &e, 10);
  if (!e || e == v || *e || n < lo || n > hi) {
    return false;
  }
  *out = (int) n;
  return true;
}

static bool perf_parse_u64(const char *v, uint64_t lo, uint64_t hi, uint64_t *out) {
  char *e = 0;
  unsigned long long n = strtoull(v, &e, 10);
  if (!e || e == v || *e || n < lo || n > hi) {
    return false;
  }
  *out = (uint64_t) n;
  return true;
}

static int perf_name_index(const char *v, const char* const *names, int num) {
  for (int i = 0; i < num; ++i) {
    if (!strcmp(v, names[i])) {
      return i;
    }
  }
  return -1;
}

static bool perf_parse_args(int argc, char **argv) {
  static const perf_nameval wlmap[] = {
    { "crud", PERF_BIT(PERF_WORKLOAD_CRUD) },
    { "read-mostly", PERF_BIT(PERF_WORKLOAD_READ_MOSTLY) },
    { "scan", PERF_BIT(PERF_WORKLOAD_SCAN) },
    { 0, 0 }
  };
  static const perf_nameval dsmap[] = {
    { "small32", PERF_BIT(0) },
    { "small240", PERF_BIT(1) },
    { "small1016", PERF_BIT(2) },
    { "large32", PERF_BIT(3) },
    { 0, 0 }
  };
  static const perf_nameval concmap[] = {
    { "single", PERF_BIT(0) },
    { "multi", PERF_BIT(1) },
    { 0, 0 }
  };
  static const perf_nameval durmap[] = {
    { "off", PERF_BIT(PERF_DURABILITY_WAL_OFF) },
    { "on", PERF_BIT(PERF_DURABILITY_WAL_ON) },
    { "sync", PERF_BIT(PERF_DURABILITY_WAL_SYNC) },
    { 0, 0 }
  };

  for (int i = 1; i < argc; ++i) {
    const char *a = argv[i];
    const char *v = 0;
    if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
      perf_usage(stdout);
      exit(0);
    } else if (!strcmp(a, "--list")) {
      printf("workloads: %s, %s, %s\n", perf_workload_names[0], perf_workload_names[1], perf_workload_names[2]);
      printf("datasets:  ");
      for (size_t i = 0; i < PERF_DS_NUM; ++i) {
        char nbuf[24];
        uint64_t n = perf_datasets[i].large ? g_cfg.large_n : g_cfg.small_n;
        perf_fmt_count(n, nbuf, sizeof(nbuf));
        printf("%s%s (%s records)", i ? ", " : "", perf_datasets[i].name, nbuf);
      }
      printf("\n");
      printf("conc:      single, multi\n");
      printf("wal:       off, on, sync\n");
      printf("key-dist:  uniform, zipfian\n");
      printf("keyspace:  shared, partitioned\n");
      printf("read-mode: alloc, copy\n");
      printf("verify:    off, sample, full\n");
      printf("format:    text, json, csv\n");
      exit(0);
    } else if (!strcmp(a, "--quick")) {
      g_cfg.small_n = 5000;
      g_cfg.large_n = 20000;
      g_cfg.repeats = 1;
    } else if (!strcmp(a, "--latency=off")) {
      g_cfg.latency = 0;
    } else if (!strcmp(a, "--latency=on")) {
      g_cfg.latency = 1;
    } else if (perf_opt(a, "--workload", &v)) {
      if (!perf_parse_mask(v, wlmap, &g_cfg.wl_mask)) {
        return false;
      }
    } else if (perf_opt(a, "--dataset", &v)) {
      if (!perf_parse_mask(v, dsmap, &g_cfg.ds_mask)) {
        return false;
      }
    } else if (perf_opt(a, "--conc", &v)) {
      if (!perf_parse_mask(v, concmap, &g_cfg.conc_mask)) {
        return false;
      }
    } else if (perf_opt(a, "--wal", &v)) {
      if (!perf_parse_mask(v, durmap, &g_cfg.dur_mask)) {
        return false;
      }
    } else if (perf_opt(a, "--threads", &v)) {
      if (!perf_parse_int(v, 1, 4096, &g_cfg.threads)) {
        return false;
      }
    } else if (perf_opt(a, "--repeats", &v)) {
      if (!perf_parse_int(v, 1, PERF_MAX_REPEATS, &g_cfg.repeats)) {
        return false;
      }
    } else if (perf_opt(a, "--read-pct", &v)) {
      if (!perf_parse_int(v, 0, 100, &g_cfg.read_pct)) {
        return false;
      }
    } else if (perf_opt(a, "--miss-pct", &v)) {
      if (!perf_parse_int(v, 0, 100, &g_cfg.miss_pct)) {
        return false;
      }
    } else if (perf_opt(a, "--verify-every", &v)) {
      if (!perf_parse_int(v, 1, 1 << 20, &g_cfg.verify_every)) {
        return false;
      }
    } else if (perf_opt(a, "--small", &v)) {
      if (!perf_parse_u64(v, 1, 100000000ULL, &g_cfg.small_n)) {
        return false;
      }
    } else if (perf_opt(a, "--large", &v)) {
      if (!perf_parse_u64(v, 1, 100000000ULL, &g_cfg.large_n)) {
        return false;
      }
    } else if (perf_opt(a, "--key-dist", &v)) {
      int idx = perf_name_index(v, perf_key_dist_names, _PERF_KD_NUM);
      if (idx < 0) {
        return false;
      }
      g_cfg.key_dist = idx;
    } else if (perf_opt(a, "--keyspace", &v)) {
      int idx = perf_name_index(v, perf_keyspace_names, _PERF_KS_NUM);
      if (idx < 0) {
        return false;
      }
      g_cfg.keyspace = idx;
    } else if (perf_opt(a, "--read-mode", &v)) {
      int idx = perf_name_index(v, perf_read_mode_names, _PERF_RM_NUM);
      if (idx < 0) {
        return false;
      }
      g_cfg.read_mode = idx;
    } else if (perf_opt(a, "--verify", &v)) {
      int idx = perf_name_index(v, perf_verify_names, _PERF_VERIFY_NUM);
      if (idx < 0) {
        return false;
      }
      g_cfg.verify = idx;
    } else if (perf_opt(a, "--format", &v)) {
      if (!strcmp(v, "text")) {
        g_cfg.format = PERF_FMT_TEXT;
      } else if (!strcmp(v, "json")) {
        g_cfg.format = PERF_FMT_JSON;
      } else if (!strcmp(v, "csv")) {
        g_cfg.format = PERF_FMT_CSV;
      } else {
        return false;
      }
    } else if (perf_opt(a, "--output", &v)) {
      g_cfg.output = v;
    } else {
      fprintf(stderr, "iwkv_perf: unknown option '%s'\n", a);
      return false;
    }
  }
  /* verify_every must be a power of two for the sampling mask */
  {
    int n = 1;
    while (n < g_cfg.verify_every) {
      n <<= 1;
    }
    g_cfg.verify_every = n;
  }
  return true;
}

/* ----------------------------------------------------------------- main */

static void perf_dataset_sizes(void) {
  for (size_t i = 0; i < PERF_DS_NUM; ++i) {
    perf_datasets[i].nrecs = perf_datasets[i].large ? g_cfg.large_n : g_cfg.small_n;
  }
}

static void perf_zipf_prepare(void) {
  if (g_cfg.key_dist != PERF_KD_ZIPFIAN) {
    return;
  }
  for (size_t i = 0; i < PERF_DS_NUM; ++i) {
    perf_dataset *ds = &perf_datasets[i];
    if (!ds->zipf_ready) {
      ds->zipf = malloc(sizeof(perf_zipf));
      if (!ds->zipf) {
        perf_die("malloc", 0);
      }
      perf_zipf_init(ds->zipf, ds->nrecs, PERF_ZIPF_THETA);
      ds->zipf_ready = true;
    }
  }
}

static unsigned perf_popcount(unsigned m) {
  unsigned n = 0;
  while (m) {
    n += m & 1u;
    m >>= 1;
  }
  return n;
}

int main(int argc, char **argv) {
  g_cfg.threads = (int) perf_env_u64("IWKV_PERF_NUM_THREADS", (uint64_t) IWKV_PERF_NUM_THREADS);
  g_cfg.repeats = (int) perf_env_u64("IWKV_PERF_REPEATS", (uint64_t) IWKV_PERF_REPEATS);
  g_cfg.read_pct = (int) perf_env_u64("IWKV_PERF_READ_PCT", (uint64_t) IWKV_PERF_READ_PCT);
  g_cfg.small_n = perf_env_u64("IWKV_PERF_DATASET_SMALL_NUM", (uint64_t) IWKV_PERF_DATASET_SMALL_NUM);
  g_cfg.large_n = perf_env_u64("IWKV_PERF_DATASET_LARGE_NUM", (uint64_t) IWKV_PERF_DATASET_LARGE_NUM);
  if (g_cfg.threads < 1) {
    g_cfg.threads = 1;
  }
  if (g_cfg.repeats < 1) {
    g_cfg.repeats = 1;
  }
  if (!perf_parse_args(argc, argv)) {
    perf_usage(stderr);
    return 2;
  }
  perf_dataset_sizes();
  perf_zipf_prepare();

  FILE *out = stdout;
  if (g_cfg.output) {
    out = fopen(g_cfg.output, "w");
    if (!out) {
      fprintf(stderr, "iwkv_perf: cannot open '%s'\n", g_cfg.output);
      return 2;
    }
  }

  if (g_cfg.format == PERF_FMT_TEXT) {
    fprintf(out, "IOWOW iwkv performance benchmark\n");
    fprintf(out, "  git rev: %s\n", PERF_STR(IWKV_PERF_GIT_REV));
    fprintf(out, "  compiler: %s\n", __VERSION__);
    fprintf(out, "  os: %s\n", perf_os_string());
    fprintf(out, "  cpu: %s\n", perf_cpu_model());
    fprintf(out, "  logical cores: %ld\n", perf_cores());
    fprintf(out, "  concurrent mode threads: %d\n", g_cfg.threads);
    fprintf(out, "  iterations per combination: %d (first is a warm-up)\n", g_cfg.repeats);
    fprintf(out, "  key distribution: %s, keyspace: %s, read mode: %s\n",
            perf_key_dist_names[g_cfg.key_dist], perf_keyspace_names[g_cfg.keyspace],
            perf_read_mode_names[g_cfg.read_mode]);
    fprintf(out, "  read-mostly mix: %d%% reads, %d%% missing keys\n", g_cfg.read_pct, g_cfg.miss_pct);
    fprintf(out, "  latencies: %s, verify: %s\n", g_cfg.latency ? "on" : "off", perf_verify_names[g_cfg.verify]);
    fprintf(out, "  datasets:\n");
    for (size_t i = 0; i < PERF_DS_NUM; ++i) {
      char nbuf[24];
      perf_fmt_count(perf_datasets[i].nrecs, nbuf, sizeof(nbuf));
      fprintf(out, "    %-9s %8s records, key=%zuB val=%zuB (~%zuB/record)\n",
              perf_datasets[i].name, nbuf, perf_datasets[i].ksz,
              perf_datasets[i].vsz, perf_datasets[i].ksz + perf_datasets[i].vsz);
    }
    fflush(out);
  }

  iwrc rc = iwkv_init();
  if (rc) {
    perf_die("iwkv_init", rc);
  }

  unsigned ncombos = perf_popcount(g_cfg.wl_mask) * perf_popcount(g_cfg.conc_mask)
                     * perf_popcount(g_cfg.dur_mask) * (unsigned) PERF_DS_NUM;
  perf_result *results = calloc(ncombos ? ncombos : 1, sizeof(*results));
  if (!results) {
    perf_die("calloc", 0);
  }

  unsigned n = 0;
  for (int wl = 0; wl < _PERF_WORKLOAD_NUM; ++wl) {
    if (!(g_cfg.wl_mask & PERF_BIT(wl))) {
      continue;
    }
    for (int ci = 0; ci < 2; ++ci) {
      if (!(g_cfg.conc_mask & PERF_BIT(ci))) {
        continue;
      }
      for (int dur = 0; dur < _PERF_DURABILITY_NUM; ++dur) {
        if (!(g_cfg.dur_mask & PERF_BIT(dur))) {
          continue;
        }
        for (size_t ds = 0; ds < PERF_DS_NUM; ++ds) {
          if (!(g_cfg.ds_mask & (1u << ds))) {
            continue;
          }
          if (g_cfg.format != PERF_FMT_TEXT) {
            fprintf(stderr, "iwkv_perf: %-11s | %-6s | %-8s | %-9s\n", perf_workload_names[wl],
                    ci ? "multi" : "single", perf_durability_names[dur], perf_datasets[ds].name);
          }
          perf_run_combination((enum perf_workload) wl, ci != 0, (enum perf_durability) dur,
                               &perf_datasets[ds], &results[n]);
          if (g_cfg.format == PERF_FMT_TEXT) {
            perf_print_text(out, &results[n]);
            fflush(out);
          }
          ++n;
        }
      }
    }
  }

  if (g_cfg.format == PERF_FMT_JSON) {
    perf_print_json(out, results, n);
  } else if (g_cfg.format == PERF_FMT_CSV) {
    perf_print_csv(out, results, n);
  } else {
    perf_print_summary(out, results, n);
  }
  if (out != stdout) {
    fclose(out);
  }
  free(results);
  return 0;
}
