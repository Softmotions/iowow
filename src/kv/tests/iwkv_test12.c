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
#include "iwkv_tests.h"
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
static fuzz_rec fuzz_live[FUZZ_NKEYS];
static fuzz_rec fuzz_durable[FUZZ_NKEYS];
static uint8_t fuzz_val[FUZZ_MAXVAL];

int init_suite(void) {
  return iwkv_init();
}

int clean_suite(void) {
  return 0;
}

static uint32_t fuzz_env_u32(const char *name, uint32_t def) {
  const char *s = getenv(name);
  if (s && *s) {
    return (uint32_t) strtoul(s, 0, 0);
  }
  return def;
}

//--------------------------  Reference model

static void fuzz_rec_free(fuzz_rec *r) {
  free(r->data);
  r->data = 0;
  r->size = 0;
  r->present = false;
}

static void fuzz_model_clear(fuzz_rec *m) {
  for (int i = 0; i < FUZZ_NKEYS; ++i) {
    fuzz_rec_free(&m[i]);
  }
}

static void fuzz_rec_set(fuzz_rec *r, const uint8_t *data, size_t size) {
  free(r->data);
  r->data = 0;
  r->size = size;
  r->present = true;
  if (size) {
    r->data = malloc(size);
    CU_ASSERT_PTR_NOT_NULL_FATAL(r->data);
    memcpy(r->data, data, size);
  }
}

static void fuzz_model_copy(fuzz_rec *dst, const fuzz_rec *src) {
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

static iwrc fuzz_db_put(IWDB db, int i, const uint8_t *v, size_t vsz, iwkv_opflags of) {
  IWKV_val key = { .data = fuzz_key[i], .size = fuzz_klen[i] };
  IWKV_val val = { .data = (void*) v, .size = vsz };
  return iwkv_put(db, &key, &val, of);
}

static iwrc fuzz_db_del(IWDB db, int i, iwkv_opflags of) {
  IWKV_val key = { .data = fuzz_key[i], .size = fuzz_klen[i] };
  return iwkv_del(db, &key, of);
}

static iwrc fuzz_db_get(IWDB db, int i, IWKV_val *val) {
  IWKV_val key = { .data = fuzz_key[i], .size = fuzz_klen[i] };
  return iwkv_get(db, &key, val);
}

//--------------------------  Verification

static void fuzz_verify_key(IWDB db, int i, const fuzz_rec *m) {
  IWKV_val val = { 0 };
  iwrc rc = fuzz_db_get(db, i, &val);
  if (m[i].present) {
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_EQUAL_FATAL(val.size, m[i].size);
    if (m[i].size) {
      CU_ASSERT_EQUAL_FATAL(memcmp(val.data, m[i].data, m[i].size), 0);
    }
    iwkv_val_dispose(&val);
  } else {
    CU_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_NOTFOUND);
  }
}

static void fuzz_verify_all(IWDB db, const fuzz_rec *m) {
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
static void fuzz_verify_cursor(IWDB db, const fuzz_rec *m) {
  int order[FUZZ_NKEYS];
  int n = 0;
  for (int i = 0; i < FUZZ_NKEYS; ++i) {
    if (m[i].present) {
      order[n++] = i;
    }
  }
  qsort(order, n, sizeof(int), fuzz_key_cmp);

  IWKV_cursor cur = 0;
  iwrc rc = iwkv_cursor_open(db, &cur, IWKV_CURSOR_BEFORE_FIRST, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  for (int j = 0; j < n; ++j) {
    int i = order[j];
    rc = iwkv_cursor_to(cur, IWKV_CURSOR_NEXT);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    IWKV_val k = { 0 }, v = { 0 };
    rc = iwkv_cursor_get(cur, &k, &v);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_EQUAL_FATAL(k.size, fuzz_klen[i]);
    CU_ASSERT_EQUAL(memcmp(k.data, fuzz_key[i], fuzz_klen[i]), 0);
    CU_ASSERT_EQUAL_FATAL(v.size, m[i].size);
    if (m[i].size) {
      CU_ASSERT_EQUAL(memcmp(v.data, m[i].data, m[i].size), 0);
    }
    iwkv_kv_dispose(&k, &v);
  }

  rc = iwkv_cursor_to(cur, IWKV_CURSOR_NEXT);
  CU_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_NOTFOUND);
  rc = iwkv_cursor_close(&cur);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
}

//--------------------------  Open / reopen helpers

static void fuzz_opts_init(IWKV_OPTS *opts, const char *path, int mode) {
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
    opts->wal.check_crc_on_checkpoint = (mode == FUZZ_MODE_WAL);
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

static void fuzz_open(IWKV_OPTS *opts, IWKV *kvp, IWDB *dbp) {
  iwrc rc = iwkv_open(opts, kvp);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(*kvp, 1, 0, dbp);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
}

static void fuzz_close(IWKV *kvp, bool crash) {
  if (crash) {
    iwkvd_trigger_xor(IWKVD_WAL_NO_CHECKPOINT_ON_CLOSE);
    iwrc rc = iwkv_close(kvp);
    iwkvd_trigger_xor(IWKVD_WAL_NO_CHECKPOINT_ON_CLOSE);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  } else {
    iwrc rc = iwkv_close(kvp);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
}

//--------------------------  Operation fuzz driver

static void fuzz_cursor_mutate(IWDB db) {
  int i = (int) iwu_rand_range(FUZZ_NKEYS);
  if (!fuzz_live[i].present) {
    return;
  }
  IWKV_val key = { .data = fuzz_key[i], .size = fuzz_klen[i] };
  IWKV_cursor cur = 0;
  iwrc rc = iwkv_cursor_open(db, &cur, IWKV_CURSOR_EQ, &key);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  if (iwu_rand_range(100) < 60) {
    size_t vsz = fuzz_rand_val_size();
    fuzz_rand_fill(vsz);
    IWKV_val val = { .data = fuzz_val, .size = vsz };
    rc = iwkv_cursor_set(cur, &val, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    fuzz_rec_set(&fuzz_live[i], fuzz_val, vsz);
  } else {
    rc = iwkv_cursor_del(cur, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    fuzz_rec_free(&fuzz_live[i]);
  }
  rc = iwkv_cursor_close(&cur);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
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

  IWKV_OPTS opts;
  fuzz_opts_init(&opts, path, mode);

  IWKV kv = 0;
  IWDB db = 0;
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
        CU_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_KEY_EXISTS);
      } else {
        CU_ASSERT_EQUAL_FATAL(rc, 0);
        fuzz_rec_set(&fuzz_live[i], fuzz_val, vsz);
      }
    } else if (op < 75) { // del
      int i = (int) iwu_rand_range(FUZZ_NKEYS);
      iwkv_opflags of = (!wal && (iwu_rand_range(100) < 10)) ? IWKV_SYNC : 0;
      rc = fuzz_db_del(db, i, of);
      if (fuzz_live[i].present) {
        CU_ASSERT_EQUAL_FATAL(rc, 0);
        fuzz_rec_free(&fuzz_live[i]);
      } else {
        CU_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_NOTFOUND);
      }
    } else if (op < 90) { // get
      int i = (int) iwu_rand_range(FUZZ_NKEYS);
      fuzz_verify_key(db, i, fuzz_live);
    } else if (op < 95) { // sync
      rc = iwkv_sync(kv, 0);
      CU_ASSERT_EQUAL_FATAL(rc, 0);
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
      CU_ASSERT_EQUAL_FATAL(rc, 0);
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

// Child side of a corruption fuzzing attempt: the engine must either report
// an error or recover to a state it can traverse; it must never crash.
static void fuzz_corrupt_open_verify(const char *path) {
  IWKV_OPTS opts;
  memset(&opts, 0, sizeof(opts));
  opts.path = path;
  opts.wal.enabled = true;
  opts.wal.wal_buffer_sz = (size_t) (64 * 1024);
  opts.wal.checkpoint_buffer_sz = 1ULL << 40;
  opts.wal.savepoint_timeout_sec = UINT32_MAX;
  opts.wal.checkpoint_timeout_sec = UINT32_MAX;

  IWKV kv = 0;
  iwrc rc = iwkv_open(&opts, &kv);
  if (!rc) {
    IWDB db = 0;
    rc = iwkv_db(kv, 1, 0, &db);
    if (!rc && db) {
      IWKV_cursor cur = 0;
      rc = iwkv_cursor_open(db, &cur, IWKV_CURSOR_BEFORE_FIRST, 0);
      if (!rc) {
        uint32_t guard = 0;
        while ((iwkv_cursor_to(cur, IWKV_CURSOR_NEXT) == 0) && (guard++ < (1U << 20))) {
          IWKV_val k = { 0 }, v = { 0 };
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
  const char *path, uint8_t *db, size_t dbsz,
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
    fuzz_corrupt_open_verify(path);
    return FUZZ_CORRUPT_OK;
  }

  pid_t pid = fork();
  if (pid == 0) {
    fuzz_corrupt_open_verify(path);
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

  IWKV_OPTS opts;
  memset(&opts, 0, sizeof(opts));
  opts.path = srcpath;
  opts.oflags = IWKV_TRUNC | IWKV_NO_TRIM_ON_CLOSE;
  opts.wal.enabled = true;
  opts.wal.wal_buffer_sz = (size_t) 64 * 1024;
  opts.wal.checkpoint_buffer_sz = 1ULL << 20;
  opts.wal.savepoint_timeout_sec = UINT32_MAX;
  opts.wal.checkpoint_timeout_sec = UINT32_MAX;

  IWKV kv = 0;
  IWDB db = 0;
  fuzz_open(&opts, &kv, &db);

  uint8_t vbuf[4096];
  char kbuf[32];
  for (int i = 0; i < 128; ++i) {
    size_t vsz = 1 + (size_t) ((i * 37) % 2000);
    for (size_t j = 0; j < vsz; ++j) {
      vbuf[j] = (uint8_t) (i + j);
    }
    snprintf(kbuf, sizeof(kbuf), "%05d", i);
    IWKV_val key = { .data = kbuf, .size = strlen(kbuf) };
    IWKV_val val = { .data = vbuf, .size = vsz };
    iwrc rc = iwkv_put(db, &key, &val, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
  iwrc rc = iwkv_sync(kv, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  fuzz_close(&kv, keep_wal);

  unlink(path);
  unlink(walpath);
  // Copy the base image to the working path.
  size_t dbsz, walsz;
  uint8_t *dbbuf = fuzz_file_read(srcpath, &dbsz);
  uint8_t *walbuf = fuzz_file_read(srcwal, &walsz);
  CU_ASSERT_PTR_NOT_NULL_FATAL(dbbuf);
  CU_ASSERT_EQUAL_FATAL(fuzz_file_write(path, dbbuf, dbsz), 0);
  if (walbuf) {
    CU_ASSERT_EQUAL_FATAL(fuzz_file_write(walpath, walbuf, walsz), 0);
  }
  free(dbbuf);
  free(walbuf);
  unlink(srcpath);
  unlink(srcwal);
}

static void fuzz_corrupt_run(
  const char *srcpath, uint32_t seed, uint32_t env_seed,
  uint32_t rounds, bool keep_wal) {
  char walpath[512];
  const char *path = "iwkv_test12_corrupt.db";
  snprintf(walpath, sizeof(walpath), "%s-wal", srcpath);

  fuzz_corrupt_build(path, srcpath, keep_wal);

  size_t dbsz = 0, walsz = 0;
  uint8_t *dbbuf = fuzz_file_read(path, &dbsz);
  uint8_t *walbuf = fuzz_file_read(walpath, &walsz);
  CU_ASSERT_PTR_NOT_NULL_FATAL(dbbuf);

  uint32_t ncrash = 0, nhang = 0, nerr = 0;
  for (uint32_t r = 0; r < rounds; ++r) {
    // Reseed per round so a finding is reproducible by rerunning with the
    // same IWKV_FUZZ_SEED and IWKV_FUZZ_ROUNDS=r+1.
    iwu_rand_seed(seed + r * 2654435761u);
    int res = fuzz_corrupt_attempt(path, dbbuf, dbsz, walbuf, walsz);
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
    CU_ASSERT_EQUAL_FATAL(fuzz_file_write(path, dbbuf, dbsz), 0);
    if (walbuf) {
      CU_ASSERT_EQUAL_FATAL(fuzz_file_write(walpath, walbuf, walsz), 0);
    }
  }
  fprintf(stderr, "[iwkv_test12] corruption fuzz keep_wal=%d rounds=%u crashes=%u hangs=%u errors=%u\n",
          (int) keep_wal, rounds, ncrash, nhang, nerr);
  if (ncrash || nhang) {
    CU_FAIL("corruption fuzzing detected engine crashes/hangs");
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
    fprintf(stderr, "\niwkv_test12_4_file_fuzz skipped (set IWKV_FUZZ_ROUNDS to enable)\n");
    return;
  }
  fprintf(stderr, "\niwkv_test12_4_file_fuzz seed=%u rounds=%u\n", base, rounds);
  // WAL contains uncheckpointed records: corrupt both files.
  fuzz_corrupt_run("iwkv_test12_corrupt_src.db", base, base, rounds, true);
  // WAL was applied on close: corrupt the main database file only.
  fuzz_corrupt_run("iwkv_test12_corrupt_src2.db", base ^ 0x9e3779b9u, base, rounds, false);
}

// A malformed first-database address in the file header must be rejected
// instead of being dereferenced out of the mapped region.
static void iwkv_test12_5_malformed_dbaddr(void) {
  const char *path = "iwkv_test12_badaddr.db";
  const char *walpath = "iwkv_test12_badaddr.db-wal";
  unlink(path);
  unlink(walpath);

  IWKV_OPTS opts = { .path = path, .oflags = IWKV_TRUNC };
  IWKV kv = 0;
  IWDB db = 0;
  iwrc rc = iwkv_open(&opts, &kv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(kv, 1, 0, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_close(&kv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // Database header layout: [magic:u4][first_db_addr:u8][fmt_version:u4]
  // and it is stored after the FSM control header.
  FILE *f = fopen(path, "r+b");
  CU_ASSERT_PTR_NOT_NULL_FATAL(f);
  uint64_t badaddr = 0x0000002000000000ULL;
  CU_ASSERT_EQUAL_FATAL(fseek(f, IWFSM_CUSTOM_HDR_DATA_OFFSET + 4, SEEK_SET), 0);
  CU_ASSERT_EQUAL_FATAL(fwrite(&badaddr, 1, sizeof(badaddr), f), sizeof(badaddr));
  fclose(f);

  opts.oflags &= ~IWKV_TRUNC;
  rc = iwkv_open(&opts, &kv);
  CU_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_CORRUPTED);

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

  IWKV_OPTS opts = {
    .path = path,
    .oflags = IWKV_TRUNC,
    .wal = { .enabled = true }
  };
  IWKV kv = 0;
  IWDB db = 0;
  iwrc rc = iwkv_open(&opts, &kv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(kv, 1, 0, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_close(&kv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // The FSM control header starts with [magic:u4][block pow:u1]. An invalid
  // block pow makes the open fail right after `iwal_create()`.
  FILE *f = fopen(path, "r+b");
  CU_ASSERT_PTR_NOT_NULL_FATAL(f);
  uint8_t badpow = 166;
  CU_ASSERT_EQUAL_FATAL(fseek(f, 4, SEEK_SET), 0);
  CU_ASSERT_EQUAL_FATAL(fwrite(&badpow, 1, 1, f), 1);
  fclose(f);

  opts.oflags &= ~IWKV_TRUNC;
  rc = iwkv_open(&opts, &kv);
  CU_ASSERT_NOT_EQUAL_FATAL(rc, 0);

  unlink(path);
  unlink(walpath);
}

int main(void) {
  CU_pSuite pSuite = NULL;

  if (CUE_SUCCESS != CU_initialize_registry()) {
    return CU_get_error();
  }
  pSuite = CU_add_suite("iwkv_test12", init_suite, clean_suite);
  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }
  if (  (NULL == CU_add_test(pSuite, "iwkv_test12_1_sync", iwkv_test12_1_sync))
     || (NULL == CU_add_test(pSuite, "iwkv_test12_2_wal", iwkv_test12_2_wal))
     || (NULL == CU_add_test(pSuite, "iwkv_test12_3_wal_crash", iwkv_test12_3_wal_crash))
     || (NULL == CU_add_test(pSuite, "iwkv_test12_4_file_fuzz", iwkv_test12_4_file_fuzz))
     || (NULL == CU_add_test(pSuite, "iwkv_test12_5_malformed_dbaddr", iwkv_test12_5_malformed_dbaddr))
     || (NULL == CU_add_test(pSuite, "iwkv_test12_6_malformed_fsm_hdr", iwkv_test12_6_malformed_fsm_hdr))) {
    CU_cleanup_registry();
    return CU_get_error();
  }
  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  int ret = CU_get_error() || CU_get_number_of_failures();
  CU_cleanup_registry();
  return ret;
}
