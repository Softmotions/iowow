/*
 * iwkv_test12.c - Basic randomized (differential) fuzz tests for iwkv.
 *
 * Overview:
 *  - `fuzz_run()` drives a pseudo-random sequence of operations against a
 *    single iwkv database while maintaining a reference model in memory.
 *    Supported modes: WAL disabled (`sync`), WAL enabled (`wal`) and WAL
 *    enabled with periodic simulated crashes (`wal-crash`).
 *    In the crash mode the database is closed without running the final WAL
 *    checkpoint and the state recovered from the WAL on the next open is
 *    verified against the last durable snapshot.
 *  - `iwkv_test12_4()` performs a byte-level fuzz of the database and WAL
 *    files: random corruptions and truncations must never crash or hang the
 *    engine. Each attempt runs in a forked child with a timeout so a fault
 *    is contained and reported instead of taking down the suite. It is
 *    opt-in: set IWKV_FUZZ_ROUNDS to a non-zero value to enable it.
 *
 * Environment overrides:
 *   IWKV_FUZZ_SEED   - RNG seed (decimal or 0x-prefixed), default 0x12f00d
 *   IWKV_FUZZ_ITERS  - number of operations per operation-fuzz mode
 *   IWKV_FUZZ_ROUNDS - number of file corruption rounds (0 disables)
 *   IWKV_FUZZ_NOFORK - run corruption attempts in-process (for debugging)
 *
 * The `IWKV_FUZZ_ITERS`/`IWKV_FUZZ_ROUNDS` defaults can also be baked in at
 * build time via the Autark options of the same name. The Autark option
 * `IWKV_RUN_FUZZ` enables the corruption fuzzer with a non-zero default.
 */

#include "iwkv.h"
#include "iwutils.h"
#include "iwtests.h"
#include "iwkv_internal.h"

#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define FUZZ_NKEYS  256
#define FUZZ_KEYPFX 4
#define FUZZ_KEYMAX 16
#define FUZZ_MAXVAL 12000

#define FUZZ_MODE_SYNC      0
#define FUZZ_MODE_WAL       1
#define FUZZ_MODE_WAL_CRASH 2

#define FUZZ_DEFAULT_SEED 0x12f00d
// Defaults may be provided by the `IWKV_FUZZ_ITERS`/`IWKV_FUZZ_ROUNDS` Autark
// build options (or the environment at build time). The byte-corruption
// fuzzer is opt-in: `IWKV_RUN_FUZZ` enables it with a non-zero round count.
#ifdef IWKV_FUZZ_DEFAULT_ITERS
#define FUZZ_DEFAULT_ITERS IWKV_FUZZ_DEFAULT_ITERS
#else
#define FUZZ_DEFAULT_ITERS 2000
#endif
#ifdef IWKV_FUZZ_DEFAULT_ROUNDS
#define FUZZ_DEFAULT_ROUNDS IWKV_FUZZ_DEFAULT_ROUNDS
#else
#define FUZZ_DEFAULT_ROUNDS 0
#endif
#define FUZZ_CORRUPT_TIMEOUT_MS 5000

enum {
  FUZZ_CORRUPT_OK = 0,
  FUZZ_CORRUPT_CRASH,
  FUZZ_CORRUPT_HANG,
  FUZZ_CORRUPT_FORKERR,
};

typedef struct fuzz_rec {
  bool     present;
  size_t   size;
  uint8_t *data;
} fuzz_rec;

static uint8_t fuzz_key[FUZZ_NKEYS][FUZZ_KEYMAX];
static size_t fuzz_klen[FUZZ_NKEYS];
static struct fuzz_rec fuzz_live[FUZZ_NKEYS];
static struct fuzz_rec fuzz_durable[FUZZ_NKEYS];
static uint8_t fuzz_val[FUZZ_MAXVAL];

int init_suite(void) {
  return iwkv_init();
}

static uint32_t fuzz_env_u32(const char *name, uint32_t def) {
  const char *s = getenv(name);
  if (s && *s) {
    return (uint32_t) strtoul(s, 0, 0);
  }
  return def;
}

//--------------------------  Reference model

static void fuzz_rec_free(struct fuzz_rec *r) {
  free(r->data);
  r->data = 0;
  r->size = 0;
  r->present = false;
}

static void fuzz_model_clear(struct fuzz_rec *m) {
  for (int i = 0; i < FUZZ_NKEYS; ++i) {
    fuzz_rec_free(&m[i]);
  }
}

static void fuzz_rec_set(struct fuzz_rec *r, const uint8_t *data, size_t size) {
  free(r->data);
  r->data = 0;
  r->size = size;
  r->present = true;
  if (size) {
    r->data = malloc(size);
    IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(r->data);
    memcpy(r->data, data, size);
  }
}

static void fuzz_model_copy(struct fuzz_rec *dst, const struct fuzz_rec *src) {
  for (int i = 0; i < FUZZ_NKEYS; ++i) {
    fuzz_rec_free(&dst[i]);
    if (src[i].present) {
      fuzz_rec_set(&dst[i], src[i].data, src[i].size);
    }
  }
}

//--------------------------  Keys and values

// Keys are unique by construction: 4 random prefix bytes, 2 bytes derived
// from the key index and an optional random suffix. Different indexes always
// differ in the two index bytes.
static void fuzz_keys_generate(void) {
  for (int i = 0; i < FUZZ_NKEYS; ++i) {
    uint8_t *k = fuzz_key[i];
    for (int j = 0; j < FUZZ_KEYPFX; ++j) {
      k[j] = (uint8_t) iwu_rand_u32();
    }
    k[FUZZ_KEYPFX] = (uint8_t) (i & 0xff);
    k[FUZZ_KEYPFX + 1] = (uint8_t) ((i >> 8) & 0xff);
    size_t suffix = iwu_rand_range(FUZZ_KEYMAX - FUZZ_KEYPFX - 2 + 1);
    for (size_t j = 0; j < suffix; ++j) {
      k[FUZZ_KEYPFX + 2 + j] = (uint8_t) iwu_rand_u32();
    }
    fuzz_klen[i] = FUZZ_KEYPFX + 2 + suffix;
  }
}

// Mix of tiny, medium and large values so that both in-place updates and
// kvblk relocation/splitting paths are exercised.
static size_t fuzz_rand_val_size(void) {
  uint32_t r = iwu_rand_range(100);
  if (r < 5) {
    return 0;
  }
  if (r < 15) {
    return 1 + iwu_rand_range(8192);
  }
  if (r < 30) {
    return 1 + iwu_rand_range(32);
  }
  return 1 + iwu_rand_range(512);
}

static void fuzz_rand_fill(size_t sz) {
  for (size_t j = 0; j < sz; ++j) {
    fuzz_val[j] = (uint8_t) iwu_rand_u32();
  }
}

//--------------------------  Database operations

static iwrc fuzz_db_put(struct iwdb *db, int i, const uint8_t *v, size_t vsz, iwkv_opflags of) {
  struct iwkv_val key = { .data = fuzz_key[i], .size = fuzz_klen[i] };
  struct iwkv_val val = { .data = (void*) v, .size = vsz };
  return iwkv_put(db, &key, &val, of);
}

static iwrc fuzz_db_del(struct iwdb *db, int i, iwkv_opflags of) {
  struct iwkv_val key = { .data = fuzz_key[i], .size = fuzz_klen[i] };
  return iwkv_del(db, &key, of);
}

static iwrc fuzz_db_get(struct iwdb *db, int i, struct iwkv_val *val) {
  struct iwkv_val key = { .data = fuzz_key[i], .size = fuzz_klen[i] };
  return iwkv_get(db, &key, val);
}

//--------------------------  Verification

static void fuzz_verify_key(struct iwdb *db, int i, const struct fuzz_rec *m) {
  struct iwkv_val val = { 0 };
  iwrc rc = fuzz_db_get(db, i, &val);
  if (m[i].present) {
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
    IW_TEST_ASSERT_EQUAL_FATAL(val.size, m[i].size);
    if (m[i].size) {
      IW_TEST_ASSERT_EQUAL_FATAL(memcmp(val.data, m[i].data, m[i].size), 0);
    }
    iwkv_val_dispose(&val);
  } else {
    IW_TEST_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_NOTFOUND);
  }
}

static void fuzz_verify_all(struct iwdb *db, const struct fuzz_rec *m) {
  for (int i = 0; i < FUZZ_NKEYS; ++i) {
    fuzz_verify_key(db, i, m);
  }
}

// iwkv iterates records in descending key order, so this comparator returns
// the reverse of the (memcmp, then shorter-first) engine key order.
static int fuzz_key_cmp(const void *a, const void *b) {
  int ia = *(const int*) a;
  int ib = *(const int*) b;
  size_t la = fuzz_klen[ia], lb = fuzz_klen[ib];
  size_t lm = la < lb ? la : lb;
  int r = memcmp(fuzz_key[ia], fuzz_key[ib], lm);
  if (r) {
    return -r;
  }
  return (la < lb) ? 1 : (la > lb) ? -1 : 0;
}

// Walk the whole database with a cursor and check that it yields exactly the
// present records in the engine key order.
static void fuzz_verify_cursor(struct iwdb *db, const struct fuzz_rec *m) {
  int order[FUZZ_NKEYS];
  int n = 0;
  for (int i = 0; i < FUZZ_NKEYS; ++i) {
    if (m[i].present) {
      order[n++] = i;
    }
  }
  qsort(order, n, sizeof(int), fuzz_key_cmp);

  struct iwkv_cursor *cur = 0;
  iwrc rc = iwkv_cursor_open(db, &cur, IWKV_CURSOR_BEFORE_FIRST, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  for (int j = 0; j < n; ++j) {
    int i = order[j];
    rc = iwkv_cursor_to(cur, IWKV_CURSOR_NEXT);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
    struct iwkv_val k = { 0 }, v = { 0 };
    rc = iwkv_cursor_get(cur, &k, &v);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
    IW_TEST_ASSERT_EQUAL_FATAL(k.size, fuzz_klen[i]);
    IW_TEST_ASSERT_EQUAL(memcmp(k.data, fuzz_key[i], fuzz_klen[i]), 0);
    IW_TEST_ASSERT_EQUAL_FATAL(v.size, m[i].size);
    if (m[i].size) {
      IW_TEST_ASSERT_EQUAL(memcmp(v.data, m[i].data, m[i].size), 0);
    }
    iwkv_kv_dispose(&k, &v);
  }

  rc = iwkv_cursor_to(cur, IWKV_CURSOR_NEXT);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_NOTFOUND);
  rc = iwkv_cursor_close(&cur);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

//--------------------------  Open / reopen helpers

static void fuzz_opts_init(struct iwkv_opts *opts, const char *path, int mode) {
  memset(opts, 0, sizeof(*opts));
  opts->path = path;
  opts->oflags = IWKV_TRUNC;
  if (mode == FUZZ_MODE_WAL_CRASH) {
    opts->oflags |= IWKV_NO_TRIM_ON_CLOSE;
  }
  if (mode != FUZZ_MODE_SYNC) {
    opts->wal.enabled = true;
    opts->wal.wal_buffer_sz = (size_t) 64 * 1024;
    opts->wal.checkpoint_buffer_sz = (size_t) 8 * 1024 * 1024;
    opts->wal.no_crc = (mode != FUZZ_MODE_WAL);
    if (mode == FUZZ_MODE_WAL_CRASH) {
      // Only explicit `iwkv_sync()` creates durable savepoints, so a
      // simulated crash always rolls back to the last synced state.
      opts->wal.savepoint_timeout_sec = UINT32_MAX;
      opts->wal.checkpoint_timeout_sec = UINT32_MAX;
    } else {
      opts->wal.savepoint_timeout_sec = 1;
      opts->wal.checkpoint_timeout_sec = 2;
    }
  }
}

static void fuzz_open(struct iwkv_opts *opts, struct iwkv **kvp, struct iwdb **dbp) {
  iwrc rc = iwkv_open(opts, kvp);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(*kvp, 1, 0, dbp);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

static void fuzz_close(struct iwkv **kvp, bool crash) {
  if (crash) {
    iwkvd_trigger_xor(IWKVD_WAL_NO_CHECKPOINT_ON_CLOSE);
    iwrc rc = iwkv_close(kvp);
    iwkvd_trigger_xor(IWKVD_WAL_NO_CHECKPOINT_ON_CLOSE);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  } else {
    iwrc rc = iwkv_close(kvp);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  }
}

//--------------------------  Operation fuzz driver

static void fuzz_cursor_mutate(struct iwdb *db) {
  int i = (int) iwu_rand_range(FUZZ_NKEYS);
  if (!fuzz_live[i].present) {
    return;
  }
  struct iwkv_val key = { .data = fuzz_key[i], .size = fuzz_klen[i] };
  struct iwkv_cursor *cur = 0;
  iwrc rc = iwkv_cursor_open(db, &cur, IWKV_CURSOR_EQ, &key);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  if (iwu_rand_range(100) < 60) {
    size_t vsz = fuzz_rand_val_size();
    fuzz_rand_fill(vsz);
    struct iwkv_val val = { .data = fuzz_val, .size = vsz };
    rc = iwkv_cursor_set(cur, &val, 0);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
    fuzz_rec_set(&fuzz_live[i], fuzz_val, vsz);
  } else {
    rc = iwkv_cursor_del(cur, 0);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
    fuzz_rec_free(&fuzz_live[i]);
  }
  rc = iwkv_cursor_close(&cur);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

static void fuzz_run(const char *path, int mode, uint32_t seed, uint32_t iters) {
  char walpath[512];
  snprintf(walpath, sizeof(walpath), "%s-wal", path);
  unlink(path);
  unlink(walpath);

  bool crash = (mode == FUZZ_MODE_WAL_CRASH);
  bool wal = (mode != FUZZ_MODE_SYNC);

  iwu_rand_seed(seed);
  fuzz_keys_generate();
  fuzz_model_clear(fuzz_live);
  fuzz_model_clear(fuzz_durable);

  struct iwkv_opts opts;
  fuzz_opts_init(&opts, path, mode);

  struct iwkv *kv = 0;
  struct iwdb *db = 0;
  fuzz_open(&opts, &kv, &db);

  for (uint32_t it = 0; it < iters; ++it) {
    uint32_t op = iwu_rand_range(100);
    iwrc rc;

    if (op < 55) { // put
      int i = (int) iwu_rand_range(FUZZ_NKEYS);
      size_t vsz = fuzz_rand_val_size();
      fuzz_rand_fill(vsz);
      bool noovr = (iwu_rand_range(100) < 10);
      iwkv_opflags of = noovr ? IWKV_NO_OVERWRITE : 0;
      if (!wal && (iwu_rand_range(100) < 10)) {
        of |= IWKV_SYNC;
      }
      rc = fuzz_db_put(db, i, fuzz_val, vsz, of);
      if (noovr && fuzz_live[i].present) {
        IW_TEST_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_KEY_EXISTS);
      } else {
        IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
        fuzz_rec_set(&fuzz_live[i], fuzz_val, vsz);
      }
    } else if (op < 75) { // del
      int i = (int) iwu_rand_range(FUZZ_NKEYS);
      iwkv_opflags of = (!wal && (iwu_rand_range(100) < 10)) ? IWKV_SYNC : 0;
      rc = fuzz_db_del(db, i, of);
      if (fuzz_live[i].present) {
        IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
        fuzz_rec_free(&fuzz_live[i]);
      } else {
        IW_TEST_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_NOTFOUND);
      }
    } else if (op < 90) { // get
      int i = (int) iwu_rand_range(FUZZ_NKEYS);
      fuzz_verify_key(db, i, fuzz_live);
    } else if (op < 95) { // sync
      rc = iwkv_sync(kv, 0);
      IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
      fuzz_model_copy(fuzz_durable, fuzz_live);
    } else if (op < 98) { // cursor mutation
      fuzz_cursor_mutate(db);
    } else { // clean reopen
      fuzz_close(&kv, false);
      opts.oflags &= ~IWKV_TRUNC;
      fuzz_open(&opts, &kv, &db);
      fuzz_verify_all(db, fuzz_live);
      fuzz_verify_cursor(db, fuzz_live);
      fuzz_model_copy(fuzz_durable, fuzz_live);
    }

    if (crash && ((it % 97) == 0)) {
      rc = iwkv_sync(kv, 0);
      IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
      fuzz_model_copy(fuzz_durable, fuzz_live);

      fuzz_close(&kv, true);
      opts.oflags &= ~IWKV_TRUNC;
      fuzz_open(&opts, &kv, &db);

      // Unsynced changes are lost, the recovered state must match the last
      // durable snapshot exactly.
      fuzz_verify_all(db, fuzz_durable);
      fuzz_verify_cursor(db, fuzz_durable);
      fuzz_model_copy(fuzz_live, fuzz_durable);
    }

    if ((it % 251) == 0) {
      fuzz_verify_all(db, fuzz_live);
      fuzz_verify_cursor(db, fuzz_live);
    }
  }

  fuzz_verify_all(db, fuzz_live);
  fuzz_verify_cursor(db, fuzz_live);
  fuzz_close(&kv, false);

  fuzz_model_clear(fuzz_live);
  fuzz_model_clear(fuzz_durable);
}

//--------------------------  File corruption fuzz

static uint8_t* fuzz_file_read(const char *path, size_t *sz) {
  *sz = 0;
  FILE *f = fopen(path, "rb");
  if (!f) {
    return 0;
  }
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return 0;
  }
  long l = ftell(f);
  if ((l < 0) || (fseek(f, 0, SEEK_SET) != 0)) {
    fclose(f);
    return 0;
  }
  uint8_t *b = malloc((size_t) l + 1);
  if (!b) {
    fclose(f);
    return 0;
  }
  size_t r = fread(b, 1, (size_t) l, f);
  fclose(f);
  *sz = r;
  return b;
}

static int fuzz_file_write(const char *path, const uint8_t *buf, size_t sz) {
  FILE *f = fopen(path, "wb");
  if (!f) {
    return -1;
  }
  size_t w = sz ? fwrite(buf, 1, sz, f) : 0;
  fclose(f);
  return (w == sz) ? 0 : -1;
}

static void fuzz_corrupt(void *buf, size_t sz) {
  if (!sz) {
    return;
  }
  uint32_t nmut = 1 + iwu_rand_range(8);
  for (uint32_t m = 0; m < nmut; ++m) {
    size_t off;
    if ((iwu_rand_range(100) < 70) && (sz > 512)) {
      off = iwu_rand_range(512); // bias to headers
    } else {
      off = iwu_rand_range((uint32_t) sz);
    }
    ((uint8_t*) buf)[off] ^= (uint8_t) (1 + iwu_rand_range(0xff));
  }
}

typedef void (*fuzz_probe_fn)(const char *path);

// Child side of a corruption fuzzing attempt: the engine must either report
// an error or recover to a state it can traverse; it must never crash.
static void fuzz_corrupt_open_verify(const char *path) {
  struct iwkv_opts opts;
  memset(&opts, 0, sizeof(opts));
  opts.path = path;
  opts.wal.enabled = true;
  opts.wal.wal_buffer_sz = (size_t) (64 * 1024);
  opts.wal.checkpoint_buffer_sz = 1ULL << 40;
  opts.wal.savepoint_timeout_sec = UINT32_MAX;
  opts.wal.checkpoint_timeout_sec = UINT32_MAX;

  struct iwkv *kv = 0;
  iwrc rc = iwkv_open(&opts, &kv);
  if (!rc) {
    struct iwdb *db = 0;
    rc = iwkv_db(kv, 1, 0, &db);
    if (!rc && db) {
      struct iwkv_cursor *cur = 0;
      rc = iwkv_cursor_open(db, &cur, IWKV_CURSOR_BEFORE_FIRST, 0);
      if (!rc) {
        uint32_t guard = 0;
        while ((iwkv_cursor_to(cur, IWKV_CURSOR_NEXT) == 0) && (guard++ < (1U << 20))) {
          struct iwkv_val k = { 0 }, v = { 0 };
          if (iwkv_cursor_get(cur, &k, &v)) {
            break;
          }
          iwkv_kv_dispose(&k, &v);
        }
        iwkv_cursor_close(&cur);
      }
    }
    iwkv_close(&kv);
  }
}

// Write-path variant of `fuzz_corrupt_open_verify()`. Error paths of the
// write code (`_lx_addkv()`, `_sblk_addkv()`) hold an exfile mmap read lock;
// failing to release it leaks the lock and deadlocks `iwkv_close()` when it
// takes the write lock for the tail trim.
static void fuzz_corrupt_open_put_verify(const char *path) {
  struct iwkv_opts opts;
  memset(&opts, 0, sizeof(opts));
  opts.path = path;
  opts.wal.enabled = true;
  opts.wal.wal_buffer_sz = (size_t) (64 * 1024);
  opts.wal.checkpoint_buffer_sz = 1ULL << 40;
  opts.wal.savepoint_timeout_sec = UINT32_MAX;
  opts.wal.checkpoint_timeout_sec = UINT32_MAX;

  struct iwkv *kv = 0;
  iwrc rc = iwkv_open(&opts, &kv);
  if (!rc) {
    struct iwdb *db = 0;
    rc = iwkv_db(kv, 1, 0, &db);
    if (!rc && db) {
      char kbuf[32];
      uint8_t vbuf[64];
      for (int i = 0; i < 128; ++i) {
        memset(vbuf, i, sizeof(vbuf));
        snprintf(kbuf, sizeof(kbuf), "n%05d", i);
        struct iwkv_val key = { .data = kbuf, .size = strlen(kbuf) };
        struct iwkv_val val = { .data = vbuf, .size = sizeof(vbuf) };
        iwkv_put(db, &key, &val, 0);
        snprintf(kbuf, sizeof(kbuf), "%05d", i);
        key.data = kbuf;
        key.size = strlen(kbuf);
        iwkv_del(db, &key, 0);
      }
    }
    iwkv_close(&kv); // deadlocks if a read lock leaked
  }
}

static int fuzz_wait_timeout(pid_t pid, uint32_t timeout_ms, int *status) {
  uint32_t waited = 0;
  for ( ; ; ) {
    pid_t r = waitpid(pid, status, WNOHANG);
    if (r == pid) {
      return 0;
    }
    if (r < 0) {
      return -1;
    }
    if (waited >= timeout_ms) {
      kill(pid, SIGKILL);
      waitpid(pid, status, 0);
      return 1;
    }
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
    nanosleep(&ts, 0);
    ++waited;
  }
}

// Run a single corrupted image through the engine in an isolated child so a
// crash or a hang cannot take down the whole test suite.
static int fuzz_corrupt_attempt(
  fuzz_probe_fn probe, const char *path, uint8_t *db, size_t dbsz,
  uint8_t *wal, size_t walsz) {
  char walpath[512];
  snprintf(walpath, sizeof(walpath), "%s-wal", path);

  uint8_t *wdb = malloc(dbsz ? dbsz : 1);
  uint8_t *wwal = malloc(walsz ? walsz : 1);
  if (!wdb || !wwal) {
    free(wdb);
    free(wwal);
    return FUZZ_CORRUPT_FORKERR;
  }
  if (dbsz) {
    memcpy(wdb, db, dbsz);
  }
  if (walsz) {
    memcpy(wwal, wal, walsz);
  }

  fuzz_corrupt(wdb, dbsz);
  fuzz_corrupt(wwal, walsz);

  size_t wdbsz = dbsz;
  size_t wwalsz = walsz;
  // Occasionally truncate to simulate a torn write.
  if (dbsz && (iwu_rand_range(100) < 15)) {
    wdbsz = iwu_rand_range((uint32_t) dbsz);
  }
  if (walsz && (iwu_rand_range(100) < 25)) {
    wwalsz = iwu_rand_range((uint32_t) walsz);
  }

  int res = FUZZ_CORRUPT_OK;
  if (fuzz_file_write(path, wdb, wdbsz) || fuzz_file_write(walpath, wwal, wwalsz)) {
    res = FUZZ_CORRUPT_FORKERR;
  }
  free(wdb);
  free(wwal);
  if (res) {
    return res;
  }

  // IWKV_FUZZ_NOFORK=1 runs the attempt in-process; useful to debug a single
  // round under a debugger or sanitizer.
  if (fuzz_env_u32("IWKV_FUZZ_NOFORK", 0)) {
    probe(path);
    return FUZZ_CORRUPT_OK;
  }

  pid_t pid = fork();
  if (pid == 0) {
    probe(path);
    _exit(0);
  }
  if (pid < 0) {
    return FUZZ_CORRUPT_FORKERR;
  }
  int status = 0;
  int w = fuzz_wait_timeout(pid, FUZZ_CORRUPT_TIMEOUT_MS, &status);
  if (w == 1) {
    return FUZZ_CORRUPT_HANG;
  }
  if (w < 0) {
    return FUZZ_CORRUPT_FORKERR;
  }
  if (WIFSIGNALED(status)) {
    return FUZZ_CORRUPT_CRASH;
  }
  if (WIFEXITED(status) && (WEXITSTATUS(status) == 0)) {
    return FUZZ_CORRUPT_OK;
  }
  return FUZZ_CORRUPT_CRASH;
}

static void fuzz_corrupt_build(const char *path, const char *srcpath, bool keep_wal) {
  char srcwal[512];
  char walpath[512];
  snprintf(srcwal, sizeof(srcwal), "%s-wal", srcpath);
  snprintf(walpath, sizeof(walpath), "%s-wal", path);
  unlink(srcpath);
  unlink(srcwal);

  struct iwkv_opts opts;
  memset(&opts, 0, sizeof(opts));
  opts.path = srcpath;
  opts.oflags = IWKV_TRUNC | IWKV_NO_TRIM_ON_CLOSE;
  opts.wal.enabled = true;
  opts.wal.wal_buffer_sz = (size_t) 64 * 1024;
  opts.wal.checkpoint_buffer_sz = 1ULL << 20;
  opts.wal.savepoint_timeout_sec = UINT32_MAX;
  opts.wal.checkpoint_timeout_sec = UINT32_MAX;

  struct iwkv *kv = 0;
  struct iwdb *db = 0;
  fuzz_open(&opts, &kv, &db);

  uint8_t vbuf[4096];
  char kbuf[32];
  for (int i = 0; i < 128; ++i) {
    size_t vsz = 1 + (size_t) ((i * 37) % 2000);
    for (size_t j = 0; j < vsz; ++j) {
      vbuf[j] = (uint8_t) (i + j);
    }
    snprintf(kbuf, sizeof(kbuf), "%05d", i);
    struct iwkv_val key = { .data = kbuf, .size = strlen(kbuf) };
    struct iwkv_val val = { .data = vbuf, .size = vsz };
    iwrc rc = iwkv_put(db, &key, &val, 0);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  }
  iwrc rc = iwkv_sync(kv, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  fuzz_close(&kv, keep_wal);

  unlink(path);
  unlink(walpath);
  // Copy the base image to the working path.
  size_t dbsz, walsz;
  uint8_t *dbbuf = fuzz_file_read(srcpath, &dbsz);
  uint8_t *walbuf = fuzz_file_read(srcwal, &walsz);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(dbbuf);
  IW_TEST_ASSERT_EQUAL_FATAL(fuzz_file_write(path, dbbuf, dbsz), 0);
  if (walbuf) {
    IW_TEST_ASSERT_EQUAL_FATAL(fuzz_file_write(walpath, walbuf, walsz), 0);
  }
  free(dbbuf);
  free(walbuf);
  unlink(srcpath);
  unlink(srcwal);
}

static void fuzz_corrupt_run(
  fuzz_probe_fn probe, const char *srcpath, uint32_t seed, uint32_t env_seed,
  uint32_t rounds, bool keep_wal) {
  char walpath[512];
  const char *path = "iwkv_test12_corrupt.db";
  snprintf(walpath, sizeof(walpath), "%s-wal", srcpath);

  fuzz_corrupt_build(path, srcpath, keep_wal);

  size_t dbsz = 0, walsz = 0;
  uint8_t *dbbuf = fuzz_file_read(path, &dbsz);
  uint8_t *walbuf = fuzz_file_read(walpath, &walsz);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(dbbuf);

  uint32_t ncrash = 0, nhang = 0, nerr = 0;
  for (uint32_t r = 0; r < rounds; ++r) {
    // Reseed per round so a finding is reproducible by rerunning with the
    // same IWKV_FUZZ_SEED and IWKV_FUZZ_ROUNDS=r+1.
    iwu_rand_seed(seed + r * 2654435761u);
    int res = fuzz_corrupt_attempt(probe, path, dbbuf, dbsz, walbuf, walsz);
    if (res != FUZZ_CORRUPT_OK) {
      const char *kind = (res == FUZZ_CORRUPT_CRASH) ? "crash"
                         : (res == FUZZ_CORRUPT_HANG) ? "hang" : "setup-error";
      fprintf(stderr,
              "\n[iwkv_test12] corruption %s round=%u keep_wal=%d "
              "(repro: IWKV_FUZZ_SEED=%u IWKV_FUZZ_ROUNDS=%u)\n",
              kind, r, (int) keep_wal, env_seed, r + 1);
      if (res == FUZZ_CORRUPT_CRASH) {
        ++ncrash;
      } else if (res == FUZZ_CORRUPT_HANG) {
        ++nhang;
      } else {
        ++nerr;
      }
    }
    // Restore the pristine image for the next round.
    IW_TEST_ASSERT_EQUAL_FATAL(fuzz_file_write(path, dbbuf, dbsz), 0);
    if (walbuf) {
      IW_TEST_ASSERT_EQUAL_FATAL(fuzz_file_write(walpath, walbuf, walsz), 0);
    }
  }
  fprintf(stderr, "[iwkv_test12] corruption fuzz keep_wal=%d rounds=%u crashes=%u hangs=%u errors=%u\n",
          (int) keep_wal, rounds, ncrash, nhang, nerr);
  if (ncrash || nhang) {
    IW_TEST_FAIL("corruption fuzzing detected engine crashes/hangs");
  }

  free(dbbuf);
  free(walbuf);
  unlink(path);
  unlink(walpath);
}

//--------------------------  Test cases

static void iwkv_test12_1_sync(void) {
  uint32_t seed = fuzz_env_u32("IWKV_FUZZ_SEED", FUZZ_DEFAULT_SEED);
  uint32_t iters = fuzz_env_u32("IWKV_FUZZ_ITERS", FUZZ_DEFAULT_ITERS);
  fprintf(stderr, "\niwkv_test12_1_sync seed=%u iters=%u\n", seed, iters);
  fuzz_run("iwkv_test12_sync.db", FUZZ_MODE_SYNC, seed, iters);
}

static void iwkv_test12_2_wal(void) {
  uint32_t seed = fuzz_env_u32("IWKV_FUZZ_SEED", FUZZ_DEFAULT_SEED) + 1;
  uint32_t iters = fuzz_env_u32("IWKV_FUZZ_ITERS", FUZZ_DEFAULT_ITERS);
  fprintf(stderr, "\niwkv_test12_2_wal seed=%u iters=%u\n", seed, iters);
  fuzz_run("iwkv_test12_wal.db", FUZZ_MODE_WAL, seed, iters);
}

static void iwkv_test12_3_wal_crash(void) {
  uint32_t seed = fuzz_env_u32("IWKV_FUZZ_SEED", FUZZ_DEFAULT_SEED) + 2;
  uint32_t iters = fuzz_env_u32("IWKV_FUZZ_ITERS", FUZZ_DEFAULT_ITERS);
  fprintf(stderr, "\niwkv_test12_3_wal_crash seed=%u iters=%u\n", seed, iters);
  fuzz_run("iwkv_test12_wal_crash.db", FUZZ_MODE_WAL_CRASH, seed, iters);
}

static void iwkv_test12_4_file_fuzz(void) {
  uint32_t base = fuzz_env_u32("IWKV_FUZZ_SEED", FUZZ_DEFAULT_SEED);
  uint32_t rounds = fuzz_env_u32("IWKV_FUZZ_ROUNDS", FUZZ_DEFAULT_ROUNDS);
  if (rounds == 0) {
    IW_TEST_SKIP("set IWKV_FUZZ_ROUNDS to enable the fuzzer");
  }
  fprintf(stderr, "\niwkv_test12_4_file_fuzz seed=%u rounds=%u\n", base, rounds);
  // WAL contains uncheckpointed records: corrupt both files.
  fuzz_corrupt_run(fuzz_corrupt_open_verify, "iwkv_test12_corrupt_src.db", base, base, rounds, true);
  // WAL was applied on close: corrupt the main database file only.
  fuzz_corrupt_run(fuzz_corrupt_open_verify, "iwkv_test12_corrupt_src2.db",
                   base ^ 0x9e3779b9u, base, rounds, false);
}

// A malformed first-database address in the file header must be rejected
// instead of being dereferenced out of the mapped region.
static void iwkv_test12_5_malformed_dbaddr(void) {
  const char *path = "iwkv_test12_badaddr.db";
  const char *walpath = "iwkv_test12_badaddr.db-wal";
  unlink(path);
  unlink(walpath);

  struct iwkv_opts opts = { .path = path, .oflags = IWKV_TRUNC };
  struct iwkv *kv = 0;
  struct iwdb *db = 0;
  iwrc rc = iwkv_open(&opts, &kv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(kv, 1, 0, &db);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_close(&kv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  // Database header layout: [magic:u4][first_db_addr:u8][fmt_version:u4]
  // and it is stored after the FSM control header.
  FILE *f = fopen(path, "r+b");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(f);
  uint64_t badaddr = 0x0000002000000000ULL;
  IW_TEST_ASSERT_EQUAL_FATAL(fseek(f, IWFSM_CUSTOM_HDR_DATA_OFFSET + 4, SEEK_SET), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(fwrite(&badaddr, 1, sizeof(badaddr), f), sizeof(badaddr));
  fclose(f);

  opts.oflags &= ~IWKV_TRUNC;
  rc = iwkv_open(&opts, &kv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_CORRUPTED);

  unlink(path);
  unlink(walpath);
}

// A failure of `iwfs_fsmfile_open()` happens after the WAL object has already
// been created. The cleanup must not leave `iwkv->dlsnr` pointing at the freed
// WAL or `iwkv_close()`/`iwal_shutdown()` will use it after free.
static void iwkv_test12_6_malformed_fsm_hdr(void) {
  const char *path = "iwkv_test12_badfsm.db";
  const char *walpath = "iwkv_test12_badfsm.db-wal";
  unlink(path);
  unlink(walpath);

  struct iwkv_opts opts = {
    .path = path,
    .oflags = IWKV_TRUNC,
    .wal = { .enabled = true }
  };
  struct iwkv *kv = 0;
  struct iwdb *db = 0;
  iwrc rc = iwkv_open(&opts, &kv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(kv, 1, 0, &db);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_close(&kv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  // The FSM control header starts with [magic:u4][block pow:u1]. An invalid
  // block pow makes the open fail right after `iwal_create()`.
  FILE *f = fopen(path, "r+b");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(f);
  uint8_t badpow = 166;
  IW_TEST_ASSERT_EQUAL_FATAL(fseek(f, 4, SEEK_SET), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(fwrite(&badpow, 1, 1, f), 1);
  fclose(f);

  opts.oflags &= ~IWKV_TRUNC;
  rc = iwkv_open(&opts, &kv);
  IW_TEST_ASSERT_NOT_EQUAL_FATAL(rc, 0);

  unlink(path);
  unlink(walpath);
}

/// Returns true when the 256-byte slot at `p` looks like a persistent V2 SBLK
/// that references a KVBLK. Used to corrupt only plausible skip-list blocks.
static bool fuzz_is_sblk_slot(const uint8_t *p) {
  const uint8_t flags = p[SOFF_FLAGS_U1];
  const uint8_t lvl = p[SOFF_LVL_U1];
  const uint8_t pnum = p[SOFF_PNUM_U1];
  const uint8_t bpos = p[SOFF_BPOS_U1_V2];
  uint32_t kvblkn;
  memcpy(&kvblkn, p + SOFF_KBLK_U4, sizeof(kvblkn));
  kvblkn = IW_ITOHL(kvblkn);
  return !(flags & ~SBLK_PERSISTENT_FLAGS)
         && (lvl < SLEVELS)
         && (pnum <= KVBLK_IDXNUM)
         && (bpos >= 1) && (bpos <= SBLK_PAGE_SBLK_NUM_V2)
         && (kvblkn != 0);
}

/// Walks every record of the database with a cursor, disposing the keys and
/// values. Errors are ignored; the point is to reach every SBLK so corrupted
/// blocks are dereferenced (or rejected) rather than silently skipped.
static void fuzz_walk_db(struct iwdb *db) {
  struct iwkv_cursor *cur = 0;
  iwrc rc = iwkv_cursor_open(db, &cur, IWKV_CURSOR_BEFORE_FIRST, 0);
  if (rc) {
    return;
  }
  uint32_t guard = 0;
  while (  (iwkv_cursor_to(cur, IWKV_CURSOR_NEXT) == 0)
        && (guard++ < (1U << 20))) {
    struct iwkv_val k = { 0 }, v = { 0 };
    if (iwkv_cursor_get(cur, &k, &v)) {
      break;
    }
    iwkv_kv_dispose(&k, &v);
  }
  iwkv_cursor_close(&cur);
}

// A non-database SBLK must always reference a KVBLK. A corrupted block with a
// zero `kblk` used to leave `sblk->kvblk == NULL`, which
// `iwkv_cursor_copy_key()` then dereferenced in `_kvblk_key_peek()` (SIGSEGV).
static void iwkv_test12_7_sblk_kvblk_corruption(void) {
  const char *path = "iwkv_test12_sblk.db";
  const char *walpath = "iwkv_test12_sblk.db-wal";
  unlink(path);
  unlink(walpath);

  struct iwkv_opts opts = { .path = path, .oflags = IWKV_TRUNC };
  struct iwkv *kv = 0;
  struct iwdb *db = 0;
  iwrc rc = iwkv_open(&opts, &kv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(kv, 1, 0, &db);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  for (int i = 0; i < 128; ++i) {
    char kbuf[16];
    uint8_t vbuf[48];
    int n = snprintf(kbuf, sizeof(kbuf), "k%05d", i);
    memset(vbuf, i, sizeof(vbuf));
    struct iwkv_val key = { .data = kbuf, .size = (size_t) n };
    struct iwkv_val val = { .data = vbuf, .size = sizeof(vbuf) };
    rc = iwkv_put(db, &key, &val, 0);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  }
  rc = iwkv_close(&kv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  size_t dbsz = 0;
  uint8_t *dbbuf = fuzz_file_read(path, &dbsz);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(dbbuf);
  IW_TEST_ASSERT_TRUE_FATAL(dbsz > SBLK_SZ);

  opts.oflags &= ~IWKV_TRUNC;
  uint32_t hits = 0;
  for (size_t base = 0; base + SBLK_SZ <= dbsz; base += SBLK_SZ) {
    if (!fuzz_is_sblk_slot(dbbuf + base)) {
      continue;
    }
    ++hits;
    uint8_t *mut = malloc(dbsz);
    IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(mut);
    memcpy(mut, dbbuf, dbsz);
    memset(mut + base + SOFF_KBLK_U4, 0, 4);
    IW_TEST_ASSERT_EQUAL_FATAL(fuzz_file_write(path, mut, dbsz), 0);
    free(mut);

    kv = 0;
    rc = iwkv_open(&opts, &kv);
    if (!rc) {
      db = 0;
      rc = iwkv_db(kv, 1, 0, &db);
      if (!rc) {
        fuzz_walk_db(db);
      }
      iwkv_close(&kv);
    }
    IW_TEST_ASSERT_EQUAL_FATAL(fuzz_file_write(path, dbbuf, dbsz), 0);
  }
  fprintf(stderr, "\n[iwkv_test12] SBLK kvblk sweep: %u slot(s), no crash\n", hits);
  IW_TEST_ASSERT_TRUE_FATAL(hits > 0);
  free(dbbuf);
  unlink(path);
  unlink(walpath);
}

// Corrupting the FSM block-size exponent makes `_fsm_trim_tail_lw()` pick a
// free block at/beyond the bitmap offset. It used to hit `assert(0)` and then
// deallocate the wrong (bitmap-overlapping) block. The FSM code must reject
// the inconsistent state instead.
static void iwkv_test12_8_fsm_trim_corruption(void) {
  const char *path = "iwkv_test12_fsmtrim.db";
  const char *walpath = "iwkv_test12_fsmtrim.db-wal";
  unlink(path);
  unlink(walpath);

  struct iwkv_opts opts = { .path = path, .oflags = IWKV_TRUNC };
  struct iwkv *kv = 0;
  struct iwdb *db = 0;
  iwrc rc = iwkv_open(&opts, &kv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(kv, 1, 0, &db);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  for (int i = 0; i < 64; ++i) {
    char kbuf[16];
    uint8_t vbuf[32];
    int n = snprintf(kbuf, sizeof(kbuf), "k%05d", i);
    memset(vbuf, i, sizeof(vbuf));
    struct iwkv_val key = { .data = kbuf, .size = (size_t) n };
    struct iwkv_val val = { .data = vbuf, .size = sizeof(vbuf) };
    rc = iwkv_put(db, &key, &val, 0);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  }
  rc = iwkv_close(&kv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  size_t dbsz = 0;
  uint8_t *dbbuf = fuzz_file_read(path, &dbsz);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(dbbuf);
  IW_TEST_ASSERT_TRUE_FATAL(dbsz > 5);

  opts.oflags &= ~IWKV_TRUNC;
  for (uint8_t pow = 0; pow <= 6; ++pow) {
    uint8_t *mut = malloc(dbsz);
    IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(mut);
    memcpy(mut, dbbuf, dbsz);
    mut[4] = pow; // FSM control header: [magic:u4][bpow:u1]
    IW_TEST_ASSERT_EQUAL_FATAL(fuzz_file_write(path, mut, dbsz), 0);
    free(mut);

    kv = 0;
    rc = iwkv_open(&opts, &kv);
    if (!rc) {
      // The close path runs `_fsm_trim_tail_lw()`. Any error is acceptable,
      // a crash is not.
      iwkv_close(&kv);
    }
    IW_TEST_ASSERT_EQUAL_FATAL(fuzz_file_write(path, dbbuf, dbsz), 0);
  }
  fprintf(stderr, "\n[iwkv_test12] FSM block pow trim sweep: no crash\n");
  free(dbbuf);
  unlink(path);
  unlink(walpath);
}

// A corrupted database chain where `next_db_blk` points back to an already
// loaded database must be rejected instead of looping forever in
// `_db_load_chain()`.
static void iwkv_test12_9_db_chain_cycle(void) {
  const char *path = "iwkv_test12_dbcycle.db";
  const char *walpath = "iwkv_test12_dbcycle.db-wal";
  unlink(path);
  unlink(walpath);

  struct iwkv_opts opts = { .path = path, .oflags = IWKV_TRUNC };
  struct iwkv *kv = 0;
  struct iwdb *db = 0;
  iwrc rc = iwkv_open(&opts, &kv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(kv, 1, 0, &db);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  uint8_t vbuf[16] = { 0 };
  struct iwkv_val key = { .data = "k", .size = 1 };
  struct iwkv_val val = { .data = vbuf, .size = sizeof(vbuf) };
  rc = iwkv_put(db, &key, &val, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_close(&kv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  // Read the first database address from the iwkv file header
  // [magic:u4][first_db_addr:u8].
  uint64_t dbaddr = 0;
  FILE *f = fopen(path, "r+b");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(f);
  IW_TEST_ASSERT_EQUAL_FATAL(fseek(f, IWFSM_CUSTOM_HDR_DATA_OFFSET + 4, SEEK_SET), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(fread(&dbaddr, 1, sizeof(dbaddr), f), sizeof(dbaddr));
  dbaddr = IW_ITOHLL(dbaddr);
  IW_TEST_ASSERT_TRUE_FATAL(dbaddr > 0);

  // Point the database `next_db_blk` to itself.
  uint32_t selfblk = IW_HTOIL((uint32_t) ADDR2BLK(dbaddr));
  IW_TEST_ASSERT_EQUAL_FATAL(fseek(f, (long) dbaddr + DOFF_NEXTDB_U4, SEEK_SET), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(fwrite(&selfblk, 1, sizeof(selfblk), f), sizeof(selfblk));
  fclose(f);

  opts.oflags &= ~IWKV_TRUNC;
  rc = iwkv_open(&opts, &kv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_CORRUPTED);

  unlink(path);
  unlink(walpath);
}

// Writes into a corrupted database must release the exfile mmap read lock on
// every error path. A leaked read lock deadlocks `iwkv_close()` (the tail trim
// takes the write lock). This complements the read-only corruption fuzzer.
static void iwkv_test12_10_corrupt_put_fuzz(void) {
  uint32_t base = fuzz_env_u32("IWKV_FUZZ_SEED", FUZZ_DEFAULT_SEED);
  uint32_t rounds = fuzz_env_u32("IWKV_FUZZ_ROUNDS", FUZZ_DEFAULT_ROUNDS);
  if (rounds == 0) {
    IW_TEST_SKIP("set IWKV_FUZZ_ROUNDS to enable the fuzzer");
  }
  fprintf(stderr, "\niwkv_test12_10_corrupt_put_fuzz seed=%u rounds=%u\n", base, rounds);
  fuzz_corrupt_run(fuzz_corrupt_open_put_verify, "iwkv_test12_corrupt_puts.db",
                   base, base, rounds, true);
  fuzz_corrupt_run(fuzz_corrupt_open_put_verify, "iwkv_test12_corrupt_puts2.db",
                   base ^ 0x85ebca6bu, base, rounds, false);
}

// Creating a database requires draining all active workers (open cursors).
// Doing that from a thread that holds a cursor must fail fast instead of
// deadlocking on itself. This is reachable from corrupted metadata that
// references a database which does not exist.
static void iwkv_test12_11_exclusive_lock_with_cursor(void) {
  const char *path = "iwkv_test12_nw.db";
  const char *walpath = "iwkv_test12_nw.db-wal";
  unlink(path);
  unlink(walpath);

  struct iwkv_opts opts = { .path = path, .oflags = IWKV_TRUNC };
  struct iwkv *kv = 0;
  struct iwdb *db = 0;
  iwrc rc = iwkv_open(&opts, &kv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(kv, 1, 0, &db);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  struct iwkv_val key = { .data = "k", .size = 1 };
  struct iwkv_val val = { .data = "v", .size = 1 };
  rc = iwkv_put(db, &key, &val, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  struct iwkv_cursor *cur = 0;
  rc = iwkv_cursor_open(db, &cur, IWKV_CURSOR_BEFORE_FIRST, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  struct iwdb *db2 = 0;
  rc = iwkv_db(kv, 2, 0, &db2);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, IW_ERROR_INVALID_STATE);
  IW_TEST_ASSERT_PTR_NULL_FATAL(db2);

  rc = iwkv_cursor_close(&cur);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  // Once the cursor is closed the database can be created normally.
  rc = iwkv_db(kv, 2, 0, &db2);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_close(&kv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  unlink(path);
  unlink(walpath);
}

//---------------------------- WAL file format / recovery fuzz

// Runs a probe over the current image in an isolated child so that a crash or
// a hang is contained and reported.
static int fuzz_probe_fork(fuzz_probe_fn probe, const char *path) {
  if (fuzz_env_u32("IWKV_FUZZ_NOFORK", 0)) {
    probe(path);
    return FUZZ_CORRUPT_OK;
  }
  pid_t pid = fork();
  if (pid == 0) {
    probe(path);
    _exit(0);
  }
  if (pid < 0) {
    return FUZZ_CORRUPT_FORKERR;
  }
  int status = 0;
  int w = fuzz_wait_timeout(pid, FUZZ_CORRUPT_TIMEOUT_MS, &status);
  if (w == 1) {
    return FUZZ_CORRUPT_HANG;
  }
  if (w < 0) {
    return FUZZ_CORRUPT_FORKERR;
  }
  if (WIFSIGNALED(status)) {
    return FUZZ_CORRUPT_CRASH;
  }
  if (WIFEXITED(status) && (WEXITSTATUS(status) == 0)) {
    return FUZZ_CORRUPT_OK;
  }
  return FUZZ_CORRUPT_CRASH;
}

static const char* fuzz_corrupt_kind(int res) {
  return (res == FUZZ_CORRUPT_CRASH) ? "crash"
         : (res == FUZZ_CORRUPT_HANG) ? "hang" : "setup-error";
}

static void fuzz_walpath(char *out, size_t outsz, const char *dbpath) {
  snprintf(out, outsz, "%s-wal", dbpath);
}

#pragma pack(push, 1)
struct fuzz_walhdr {
  uint32_t magic;
  uint32_t flags;
};
struct fuzz_wbsep {
  uint8_t  id;
  uint8_t  pad[3];
  uint32_t crc;
  uint32_t len;
};
struct fuzz_wbset {
  uint8_t  id;
  uint8_t  pad[3];
  uint32_t val;
  int64_t  off;
  int64_t  len;
};
struct fuzz_wbcopy {
  uint8_t id;
  uint8_t pad[3];
  int64_t off;
  int64_t len;
  int64_t noff;
};
struct fuzz_wbwrite {
  uint8_t  id;
  uint8_t  pad[3];
  uint32_t crc;
  uint32_t len;
  int64_t  off;
};
struct fuzz_wbresize {
  uint8_t id;
  uint8_t pad[3];
  int64_t osize;
  int64_t nsize;
};
struct fuzz_wbsavepoint {
  uint8_t  id;
  uint8_t  pad[3];
  uint64_t ts;
};
struct fuzz_wbreset {
  uint8_t id;
  uint8_t pad[3];
};
struct fuzz_wbpatch {
  uint8_t  id;
  uint8_t  pad[3];
  uint32_t crc;
  uint32_t len;
  int64_t  off;
};
#pragma pack(pop)

enum {
  FUZZ_WOP_SET = 1,
  FUZZ_WOP_COPY,
  FUZZ_WOP_WRITE,
  FUZZ_WOP_RESIZE,
  FUZZ_WOP_SAVEPOINT,
  FUZZ_WOP_RESET,
  FUZZ_WOP_PATCH,
  FUZZ_WOP_SEP = 127,
};

#define FUZZ_WAL_MAGIC 0x4c415749U

struct fuzz_buf {
  uint8_t *p;
  size_t   len;
  size_t   cap;
  bool     oom;
};

static void fuzz_buf_reserve(struct fuzz_buf *b, size_t extra) {
  if (b->oom || (b->len + extra <= b->cap)) {
    return;
  }
  size_t ncap = b->cap ? b->cap : 256;
  while (ncap < b->len + extra) {
    ncap *= 2;
  }
  uint8_t *np = realloc(b->p, ncap);
  if (!np) {
    b->oom = true;
    return;
  }
  b->p = np;
  b->cap = ncap;
}

static void fuzz_buf_append(struct fuzz_buf *b, const void *data, size_t sz) {
  fuzz_buf_reserve(b, sz);
  if (b->oom) {
    return;
  }
  memcpy(b->p + b->len, data, sz);
  b->len += sz;
}

static void fuzz_buf_append_sep(struct fuzz_buf *b, uint32_t crc, uint32_t len) {
  struct fuzz_wbsep sep = { .id = FUZZ_WOP_SEP, .crc = crc, .len = len };
  fuzz_buf_append(b, &sep, sizeof(sep));
}

/// Builds a WAL image in the pre-rework iwkv layout (no magic header, only the
/// record types that existed then). When `with_header` is true a current-format
/// header with `flags` is prepended so the record parser is reached while the
/// records themselves keep the legacy layout.
static uint8_t* fuzz_build_legacy_wal(size_t *outlen, bool with_header, uint32_t hdrflags) {
  struct fuzz_buf b = { 0 };
  *outlen = 0;
  if (with_header) {
    struct fuzz_walhdr hdr = { .magic = FUZZ_WAL_MAGIC, .flags = hdrflags };
    fuzz_buf_append(&b, &hdr, sizeof(hdr));
  }

  struct fuzz_wbsavepoint sp = { .id = FUZZ_WOP_SAVEPOINT, .ts = 1 };
  struct fuzz_wbset set = { .id = FUZZ_WOP_SET, .val = 0, .off = 0, .len = 1 };
  uint8_t payload[32];
  memset(payload, 0x5a, sizeof(payload));
  struct fuzz_wbwrite wr = {
    .id = FUZZ_WOP_WRITE,
    .crc = 0,
    .len = sizeof(payload),
    .off = 0
  };
  size_t seg1_len = sizeof(sp) + sizeof(set) + sizeof(wr) + sizeof(payload);
  fuzz_buf_append_sep(&b, 0, (uint32_t) seg1_len);
  fuzz_buf_append(&b, &sp, sizeof(sp));
  fuzz_buf_append(&b, &set, sizeof(set));
  fuzz_buf_append(&b, &wr, sizeof(wr));
  fuzz_buf_append(&b, payload, sizeof(payload));

  struct fuzz_wbcopy cp = { .id = FUZZ_WOP_COPY, .off = 0, .len = 1, .noff = 1 };
  struct fuzz_wbresize rs = { .id = FUZZ_WOP_RESIZE, .osize = 4096, .nsize = 4096 };
  struct fuzz_wbreset rst = { .id = FUZZ_WOP_RESET };
  size_t seg2_len = sizeof(cp) + sizeof(rs) + sizeof(rst);
  fuzz_buf_append_sep(&b, 0, (uint32_t) seg2_len);
  fuzz_buf_append(&b, &cp, sizeof(cp));
  fuzz_buf_append(&b, &rs, sizeof(rs));
  fuzz_buf_append(&b, &rst, sizeof(rst));

  if (b.oom) {
    free(b.p);
    return 0;
  }
  *outlen = b.len;
  return b.p;
}

/// Generates a syntactically shaped but semantically hostile WAL image: a valid
/// magic header (usually) followed by a first `WBSEP` and a sequence of records
/// with extreme/random offsets, lengths and optionally truncated payloads.
static uint8_t* fuzz_build_malformed_wal(size_t *outlen, uint32_t seed) {
  struct fuzz_buf b = { 0 };
  *outlen = 0;
  iwu_rand_seed(seed);

  if (iwu_rand_range(100) < 85) {
    struct fuzz_walhdr hdr = {
      .magic = FUZZ_WAL_MAGIC,
      .flags = (iwu_rand_range(100) < 50) ? 1U : 0U
    };
    fuzz_buf_append(&b, &hdr, sizeof(hdr));
  }
  fuzz_buf_append_sep(&b, iwu_rand_u32(), iwu_rand_range(4096));

  uint32_t nops = 1 + iwu_rand_range(24);
  for (uint32_t i = 0; i < nops && !b.oom; ++i) {
    switch (iwu_rand_range(8)) {
      case 0: {
        struct fuzz_wbset r = {
          .id = FUZZ_WOP_SET, .val = iwu_rand_u32(),
          .off = (int64_t) iwu_rand_u32(), .len = (int64_t) iwu_rand_u32()
        };
        fuzz_buf_append(&b, &r, sizeof(r));
        break;
      }
      case 1: {
        struct fuzz_wbcopy r = {
          .id = FUZZ_WOP_COPY, .off = (int64_t) iwu_rand_u32(),
          .len = (int64_t) iwu_rand_u32(), .noff = (int64_t) iwu_rand_u32()
        };
        fuzz_buf_append(&b, &r, sizeof(r));
        break;
      }
      case 2: {
        uint32_t len = iwu_rand_range(512);
        struct fuzz_wbwrite r = {
          .id = FUZZ_WOP_WRITE, .crc = iwu_rand_u32(),
          .len = len, .off = (int64_t) iwu_rand_u32()
        };
        fuzz_buf_append(&b, &r, sizeof(r));
        uint32_t wr = (iwu_rand_range(100) < 25) ? iwu_rand_range(len + 1) : len;
        for (uint32_t j = 0; j < wr && !b.oom; ++j) {
          uint8_t v = (uint8_t) iwu_rand_u32();
          fuzz_buf_append(&b, &v, 1);
        }
        break;
      }
      case 3: {
        struct fuzz_wbresize r = {
          .id = FUZZ_WOP_RESIZE, .osize = (int64_t) iwu_rand_u32(),
          .nsize = (int64_t) iwu_rand_u32()
        };
        fuzz_buf_append(&b, &r, sizeof(r));
        break;
      }
      case 4: {
        struct fuzz_wbsavepoint r = { .id = FUZZ_WOP_SAVEPOINT, .ts = iwu_rand_u32() };
        fuzz_buf_append(&b, &r, sizeof(r));
        break;
      }
      case 5: {
        struct fuzz_wbreset r = { .id = FUZZ_WOP_RESET };
        fuzz_buf_append(&b, &r, sizeof(r));
        break;
      }
      case 6: {
        uint32_t len = iwu_rand_range(256);
        struct fuzz_wbpatch r = {
          .id = FUZZ_WOP_PATCH, .crc = iwu_rand_u32(),
          .len = len, .off = (int64_t) iwu_rand_u32()
        };
        fuzz_buf_append(&b, &r, sizeof(r));
        uint32_t wr = (iwu_rand_range(100) < 25) ? iwu_rand_range(len + 1) : len;
        for (uint32_t j = 0; j < wr && !b.oom; ++j) {
          uint8_t v = (uint8_t) iwu_rand_u32();
          fuzz_buf_append(&b, &v, 1);
        }
        break;
      }
      default: {
        fuzz_buf_append_sep(&b, iwu_rand_u32(), iwu_rand_u32());
        break;
      }
    }
  }
  if (b.oom) {
    free(b.p);
    return 0;
  }
  *outlen = b.len;
  return b.p;
}

// Legacy (pre-rework) WAL images: no magic header, no `WOP_PATCH` records and
// standard CRC-32. The current engine must reject or recover from them without
// crashing.
static void iwkv_test12_12_legacy_wal_format(void) {
  const char *path = "iwkv_test12_legacy.db";
  char walpath[512];
  fuzz_walpath(walpath, sizeof(walpath), path);
  fuzz_corrupt_build(path, "iwkv_test12_legacy_src.db", false);

  size_t dbsz = 0;
  uint8_t *dbbuf = fuzz_file_read(path, &dbsz);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(dbbuf);

  static const struct {
    const char *name;
    bool        header;
    uint32_t    flags;
  } cases[] = {
    { "legacy-no-header", false, 0 },
    { "header+legacy-records", true, 0 },
    { "header-crc+legacy-records", true, 1 },
  };
  uint32_t nfail = 0;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    size_t len = 0;
    uint8_t *img = fuzz_build_legacy_wal(&len, cases[i].header, cases[i].flags);
    IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(img);
    IW_TEST_ASSERT_EQUAL_FATAL(fuzz_file_write(path, dbbuf, dbsz), 0);
    IW_TEST_ASSERT_EQUAL_FATAL(fuzz_file_write(walpath, img, len), 0);
    free(img);
    int res = fuzz_probe_fork(fuzz_corrupt_open_verify, path);
    if (res != FUZZ_CORRUPT_OK) {
      fprintf(stderr, "\n[iwkv_test12] legacy WAL '%s' -> %s\n", cases[i].name, fuzz_corrupt_kind(res));
      ++nfail;
    }
    unlink(walpath);
  }
  free(dbbuf);
  if (nfail) {
    IW_TEST_FAIL("legacy WAL images made the engine crash/hang");
  }
  unlink(path);
  unlink(walpath);
}

// Malformed current-format WAL records with extreme offsets/lengths.
static void iwkv_test12_13_malformed_wal_fuzz(void) {
  uint32_t base = fuzz_env_u32("IWKV_FUZZ_SEED", FUZZ_DEFAULT_SEED);
  uint32_t rounds = fuzz_env_u32("IWKV_FUZZ_ROUNDS", FUZZ_DEFAULT_ROUNDS);
  if (rounds == 0) {
    IW_TEST_SKIP("set IWKV_FUZZ_ROUNDS to enable the fuzzer");
  }
  const char *path = "iwkv_test12_malformed.db";
  char walpath[512];
  fuzz_walpath(walpath, sizeof(walpath), path);
  fuzz_corrupt_build(path, "iwkv_test12_malformed_src.db", false);

  size_t dbsz = 0;
  uint8_t *dbbuf = fuzz_file_read(path, &dbsz);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(dbbuf);

  uint32_t ncrash = 0, nhang = 0, nerr = 0;
  for (uint32_t r = 0; r < rounds; ++r) {
    size_t len = 0;
    uint8_t *img = fuzz_build_malformed_wal(&len, base + r * 2654435761u);
    if (!img || !len) {
      free(img);
      continue;
    }
    IW_TEST_ASSERT_EQUAL_FATAL(fuzz_file_write(path, dbbuf, dbsz), 0);
    if (fuzz_file_write(walpath, img, len)) {
      free(img);
      ++nerr;
      continue;
    }
    free(img);
    int res = fuzz_probe_fork(fuzz_corrupt_open_verify, path);
    if (res != FUZZ_CORRUPT_OK) {
      fprintf(stderr,
              "\n[iwkv_test12] malformed WAL %s round=%u (repro: IWKV_FUZZ_SEED=%u IWKV_FUZZ_ROUNDS=%u)\n",
              fuzz_corrupt_kind(res), r, base, r + 1);
      if (res == FUZZ_CORRUPT_CRASH) {
        ++ncrash;
      } else if (res == FUZZ_CORRUPT_HANG) {
        ++nhang;
      } else {
        ++nerr;
      }
    }
    if (ncrash || nhang) {
      break;
    }
    unlink(walpath);
  }
  fprintf(stderr, "[iwkv_test12] malformed WAL fuzz rounds=%u crashes=%u hangs=%u errors=%u\n",
          rounds, ncrash, nhang, nerr);
  free(dbbuf);
  if (ncrash || nhang) {
    IW_TEST_FAIL("malformed WAL fuzzing detected engine crashes/hangs");
  }
  unlink(path);
  unlink(walpath);
}

// Truncation of a real WAL (with uncheckpointed records) at many lengths.
static void iwkv_test12_14_wal_truncation(void) {
  uint32_t max_rounds = fuzz_env_u32("IWKV_FUZZ_ROUNDS", FUZZ_DEFAULT_ROUNDS);
  if (max_rounds == 0) {
    IW_TEST_SKIP("set IWKV_FUZZ_ROUNDS to enable the fuzzer");
  }
  const char *path = "iwkv_test12_waltrunc.db";
  char walpath[512];
  fuzz_walpath(walpath, sizeof(walpath), path);
  fuzz_corrupt_build(path, "iwkv_test12_waltrunc_src.db", true);

  size_t dbsz = 0, walsz = 0;
  uint8_t *dbbuf = fuzz_file_read(path, &dbsz);
  uint8_t *walbuf = fuzz_file_read(walpath, &walsz);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(dbbuf);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(walbuf);
  IW_TEST_ASSERT_TRUE_FATAL(walsz > 0);

  uint32_t n = (walsz < max_rounds) ? (uint32_t) walsz : max_rounds;
  uint32_t ncrash = 0, nhang = 0;
  for (uint32_t i = 0; i < n; ++i) {
    size_t cut = (walsz <= max_rounds) ? i : (size_t) ((uint64_t) i * walsz / n);
    if (  fuzz_file_write(path, dbbuf, dbsz)
       || fuzz_file_write(walpath, walbuf, cut)) {
      continue;
    }
    int res = fuzz_probe_fork(fuzz_corrupt_open_verify, path);
    if (res != FUZZ_CORRUPT_OK) {
      fprintf(stderr, "\n[iwkv_test12] WAL truncation %s cut=%zu/%zu\n",
              fuzz_corrupt_kind(res), cut, walsz);
      if (res == FUZZ_CORRUPT_CRASH) {
        ++ncrash;
      } else if (res == FUZZ_CORRUPT_HANG) {
        ++nhang;
      }
    }
    if (ncrash || nhang) {
      break;
    }
  }
  fprintf(stderr, "[iwkv_test12] WAL truncation cuts=%u crashes=%u hangs=%u\n", n, ncrash, nhang);
  free(dbbuf);
  free(walbuf);
  if (ncrash || nhang) {
    IW_TEST_FAIL("WAL truncation fuzzing detected engine crashes/hangs");
  }
  unlink(path);
  unlink(walpath);
}

static const struct iw_test_case cases[] = {
  IW_TEST_CASE(iwkv_test12_1_sync),
  IW_TEST_CASE(iwkv_test12_2_wal),
  IW_TEST_CASE(iwkv_test12_3_wal_crash),
  IW_TEST_CASE(iwkv_test12_4_file_fuzz),
  IW_TEST_CASE(iwkv_test12_5_malformed_dbaddr),
  IW_TEST_CASE(iwkv_test12_6_malformed_fsm_hdr),
  IW_TEST_CASE(iwkv_test12_7_sblk_kvblk_corruption),
  IW_TEST_CASE(iwkv_test12_8_fsm_trim_corruption),
  IW_TEST_CASE(iwkv_test12_9_db_chain_cycle),
  IW_TEST_CASE(iwkv_test12_10_corrupt_put_fuzz),
  IW_TEST_CASE(iwkv_test12_11_exclusive_lock_with_cursor),
  IW_TEST_CASE(iwkv_test12_12_legacy_wal_format),
  IW_TEST_CASE(iwkv_test12_13_malformed_wal_fuzz),
  IW_TEST_CASE(iwkv_test12_14_wal_truncation),
};

int main(int argc, char *argv[]) {
  return iw_test_run(argc, argv, IW_TEST_SUITE("iwkv_test12", cases, init_suite, 0));
}

