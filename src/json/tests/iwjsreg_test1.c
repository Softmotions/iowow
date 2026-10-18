#include "iwlog.h"
#include "iowow.h"
#include "iwjsreg.h"
#include "iwlog.h"
#include "iwutils.h"
#include "tests.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>
#include <sys/stat.h>
#include <math.h>

int init_suite(void) {
  int rc = iw_init();
  return rc;
}

static void _iwjsreg_basic1(void) {
  const char *path = "iwjsreg_basic1.dat";
  unlink(path);

  struct iwjsreg *reg;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) {
    .path = path,
  }, &reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_str(reg, "key1", "val1");
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_i64(reg, "key2", 8217128L);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_bool(reg, "key3", true);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_close(&reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_open(&(struct iwjsreg_spec) {
    .path = path,
  }, &reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  int64_t val;
  rc = iwjsreg_get_i64(reg, "key2", &val);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(val, 8217128L);

  rc = iwjsreg_get_i64(reg, "key22", &val);
  IW_TEST_ASSERT_EQUAL(rc, IW_ERROR_NOT_EXISTS);

  char *buf;
  rc = iwjsreg_get_str(reg, "key1", &buf);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_STR_EQUAL(buf, "val1");
  free(buf);

  rc = iwjsreg_remove(reg, "key1");
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_get_i64(reg, "key1", &val);
  IW_TEST_ASSERT_EQUAL(rc, IW_ERROR_NOT_EXISTS);

  rc = iwjsreg_close(&reg);
  IW_TEST_ASSERT_EQUAL(rc, 0);
}

static void _iwjsreg_basic2(void) {
  const char *path = "iwjsreg_basic2.dat";
  unlink(path);

  struct iwjsreg *reg;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) {
    .path = path,
    .flags = IWJSREG_FORMAT_BINARY,
  }, &reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_str(reg, "key1", "val1");
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_i64(reg, "key2", 8217128L);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_bool(reg, "key3", true);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_close(&reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_open(&(struct iwjsreg_spec) {
    .path = path,
    .flags = IWJSREG_FORMAT_BINARY,
  }, &reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  int64_t val;
  rc = iwjsreg_get_i64(reg, "key2", &val);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(val, 8217128L);

  rc = iwjsreg_get_i64(reg, "key22", &val);
  IW_TEST_ASSERT_EQUAL(rc, IW_ERROR_NOT_EXISTS);

  char *buf;
  rc = iwjsreg_get_str(reg, "key1", &buf);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_STR_EQUAL(buf, "val1");
  free(buf);

  rc = iwjsreg_remove(reg, "key1");
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_get_i64(reg, "key1", &val);
  IW_TEST_ASSERT_EQUAL(rc, IW_ERROR_NOT_EXISTS);

  rc = iwjsreg_close(&reg);
  IW_TEST_ASSERT_EQUAL(rc, 0);
}

static void _iwjsreg_merge(void) {
  const char *path = "iwjsreg_merge.dat";
  unlink(path);

  struct iwxstr *xstr = iwxstr_create_empty();
  struct iwpool *pool = iwpool_create_empty();

  struct iwjsreg *reg;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) {
    .path = path,
    .flags = IWJSREG_FORMAT_BINARY,
  }, &reg);

  struct jbl_node *n, *n2;
  rc = jbn_from_json("{\"vaz\":1, \"gaz\":\"val\"}", &n, pool);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_merge(reg, "/foo/bar", n);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_merge(reg, "/foo/bar", n);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_merge(reg, "/foo/bar/zaz", n);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = jbn_from_json("{\"gaz\":null}", &n2, pool);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_merge(reg, "/foo/bar/zaz", n2);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_copy(reg, "", pool, &n2);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  fprintf(stderr, "\n");
  jbn_as_json(n2, jbl_xstr_json_printer, xstr, 0);

  IW_TEST_ASSERT_STR_EQUAL(iwxstr_ptr(xstr), "{\"foo\":{\"bar\":{\"vaz\":1,\"gaz\":\"val\",\"zaz\":{\"vaz\":1}}}}");

  rc = iwjsreg_sync(reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_close(&reg);
  IW_TEST_ASSERT_EQUAL(rc, 0);
  iwpool_destroy(pool);
  iwxstr_destroy(xstr);
}

// ---------------- Regression / consistency tests ----------------

// Reads and parses `path` as JSON. On success the parsed node is returned and
// `*out_pool` owns it. The caller must release it with iwpool_destroy().
static struct jbl_node* _load_json_file(const char *path, struct iwpool **out_pool, iwrc *rc) {
  *out_pool = 0;
  size_t len = 0;
  char *buf = iwu_file_read_as_buf_len(path, &len);
  if (!buf) {
    *rc = IW_ERROR_NOT_EXISTS;
    return 0;
  }
  struct iwpool *pool = iwpool_create_empty();
  struct jbl_node *root = 0;
  *rc = jbn_from_json(buf, &root, pool);
  free(buf);
  if (*rc) {
    iwpool_destroy(pool);
    return 0;
  }
  *out_pool = pool;
  return root;
}

// Ensure top-level key lookup/update/remove uses an exact match. A longer key
// starting with an already existing key must not overwrite/remove that key.
static void _iwjsreg_exact_keys(void) {
  const char *path = "iwjsreg_exact.dat";
  unlink(path);

  struct iwjsreg *reg;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_str(reg, "key", "v");
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_set_str(reg, "key2", "v2");
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_set_i64(reg, "n", 10);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_set_i64(reg, "n2", 20);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_set_bool(reg, "b", true);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_set_bool(reg, "b2", false);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  char *sv = 0;
  int64_t iv = 0;
  bool bv = false;

  rc = iwjsreg_get_str(reg, "key", &sv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_STR_EQUAL(sv, "v");
  free(sv); sv = 0;

  rc = iwjsreg_get_str(reg, "key2", &sv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_STR_EQUAL(sv, "v2");
  free(sv); sv = 0;

  rc = iwjsreg_get_i64(reg, "n", &iv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(iv, 10);
  rc = iwjsreg_get_i64(reg, "n2", &iv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(iv, 20);

  rc = iwjsreg_get_bool(reg, "b", &bv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_TRUE(bv);
  rc = iwjsreg_get_bool(reg, "b2", &bv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_FALSE(bv);

  // inc_i64 must not touch a shorter key that is a prefix of the requested one
  rc = iwjsreg_inc_i64(reg, "n2", 5, &iv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(iv, 25);
  rc = iwjsreg_get_i64(reg, "n", &iv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(iv, 10);

  // remove must not remove a key that is a prefix of the requested one
  rc = iwjsreg_remove(reg, "key");
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_get_str(reg, "key", &sv);
  IW_TEST_ASSERT_EQUAL(rc, IW_ERROR_NOT_EXISTS);
  rc = iwjsreg_get_str(reg, "key2", &sv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_STR_EQUAL(sv, "v2");
  free(sv); sv = 0;

  rc = iwjsreg_close(&reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  // Persisted state must match the in-memory one
  rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_get_str(reg, "key2", &sv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_STR_EQUAL(sv, "v2");
  free(sv);
  rc = iwjsreg_get_i64(reg, "n2", &iv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(iv, 25);
  rc = iwjsreg_close(&reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

// IWJSREG_AUTOSYNC must persist removals immediately, not only on close().
static void _iwjsreg_remove_autosync(void) {
  const char *path = "iwjsreg_remove_autosync.dat";
  unlink(path);

  struct iwjsreg *reg;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path, .flags = IWJSREG_AUTOSYNC }, &reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_i64(reg, "a", 1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_set_i64(reg, "b", 2);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_remove(reg, "a");
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  struct iwpool *pool = 0;
  struct jbl_node *root = _load_json_file(path, &pool, &rc);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  struct jbl_node *n = 0;
  rc = jbn_at(root, "/a", &n);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PATH_NOTFOUND);
  rc = jbn_at(root, "/b", &n);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(n->type, JBV_I64);
  IW_TEST_ASSERT_EQUAL(n->vi64, 2);
  iwpool_destroy(pool);

  rc = iwjsreg_close(&reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

// Replacing a container (object/array) node with a scalar must release the
// container payload while keeping the resulting JSON consistent.
static void _iwjsreg_overwrite_container(void) {
  const char *path = "iwjsreg_overwrite.dat";
  unlink(path);

  struct iwjsreg *reg;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  struct iwpool *pool = iwpool_create_empty();
  struct jbl_node *n = 0;
  rc = jbn_from_json("{\"a\":1}", &n, pool);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_merge(reg, "/obj", n);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = jbn_from_json("[1,2,3]", &n, pool);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_merge(reg, "/arr", n);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_i64(reg, "obj", 42);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_set_str(reg, "arr", "x");
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  struct jbl_node *out = 0;
  struct iwxstr *xstr = iwxstr_create_empty();
  rc = iwjsreg_copy(reg, "", pool, &out);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = jbn_as_json(out, jbl_xstr_json_printer, xstr, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_STR_EQUAL(iwxstr_ptr(xstr), "{\"obj\":42,\"arr\":\"x\"}");
  iwxstr_destroy(xstr);

  // Removing a container node must free the whole subtree
  rc = jbn_from_json("{\"b\":2}", &n, pool);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_merge(reg, "/obj2", n);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_remove(reg, "obj2");
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  struct jbl_node *nfound = 0;
  rc = iwjsreg_copy(reg, "/obj2", pool, &nfound);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PATH_NOTFOUND);

  rc = iwjsreg_close(&reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  iwpool_destroy(pool);
}

// Custom exclusive/shared lock functions supplied via iwjsreg_spec.
static atomic_long _spec_wlock_calls;
static atomic_long _spec_rlock_calls;
static atomic_long _spec_unlock_calls;

static iwrc _spec_wlock(void *d) {
  atomic_fetch_add(&_spec_wlock_calls, 1);
  int rci = pthread_rwlock_wrlock((pthread_rwlock_t*) d);
  return rci ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci) : 0;
}

static iwrc _spec_rlock(void *d) {
  atomic_fetch_add(&_spec_rlock_calls, 1);
  int rci = pthread_rwlock_rdlock((pthread_rwlock_t*) d);
  return rci ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci) : 0;
}

static iwrc _spec_unlock(void *d) {
  atomic_fetch_add(&_spec_unlock_calls, 1);
  int rci = pthread_rwlock_unlock((pthread_rwlock_t*) d);
  return rci ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci) : 0;
}

static void _iwjsreg_spec_locks(void) {
  const char *path = "iwjsreg_spec_locks.dat";
  unlink(path);

  atomic_store(&_spec_wlock_calls, 0);
  atomic_store(&_spec_rlock_calls, 0);
  atomic_store(&_spec_unlock_calls, 0);

  pthread_rwlock_t rwl;
  IW_TEST_ASSERT_EQUAL_FATAL(pthread_rwlock_init(&rwl, 0), 0);

  struct iwjsreg *reg;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) {
    .path = path,
    .wlock_fn = _spec_wlock,
    .rlock_fn = _spec_rlock,
    .unlock_fn = _spec_unlock,
    .fn_data = &rwl,
    .flags = IWJSREG_AUTOSYNC,
  }, &reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_i64(reg, "counter", 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  for (int i = 0; i < 100; ++i) {
    rc = iwjsreg_inc_i64(reg, "counter", 1, 0);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  }

  int64_t v = 0;
  rc = iwjsreg_get_i64(reg, "counter", &v);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(v, 100);

  rc = iwjsreg_close(&reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  pthread_rwlock_destroy(&rwl);

  IW_TEST_ASSERT_TRUE(atomic_load(&_spec_wlock_calls) > 0);
  IW_TEST_ASSERT_TRUE(atomic_load(&_spec_rlock_calls) > 0);
  IW_TEST_ASSERT_TRUE(atomic_load(&_spec_unlock_calls) > 0);

  rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_get_i64(reg, "counter", &v);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(v, 100);
  rc = iwjsreg_close(&reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

// Concurrent updates with AUTOSYNC: exclusive locking must prevent lost
// updates and the on-disk file must always stay a complete valid JSON document
// (atomic tmp-file + rename).
#define JSREG_NWRITERS 4
#define JSREG_NINCS    100

struct jsreg_conc_ctx {
  struct iwjsreg *reg;
  const char     *path;
  atomic_bool     stop;
  atomic_bool     failed;
  atomic_long     reads;
};

static void* _conc_writer(void *arg) {
  struct jsreg_conc_ctx *ctx = arg;
  for (int i = 0; i < JSREG_NINCS; ++i) {
    iwrc rc = iwjsreg_inc_i64(ctx->reg, "counter", 1, 0);
    if (rc) {
      atomic_store(&ctx->failed, true);
      return 0;
    }
  }
  return 0;
}

static void* _conc_reader(void *arg) {
  struct jsreg_conc_ctx *ctx = arg;
  struct timespec ts = { .tv_sec = 0, .tv_nsec = 200000 };
  do {
    size_t len = 0;
    char *buf = iwu_file_read_as_buf_len(ctx->path, &len);
    if (buf) {
      struct iwpool *pool = iwpool_create_empty();
      struct jbl_node *root = 0;
      iwrc rc = jbn_from_json(buf, &root, pool);
      if (rc || !root) {
        atomic_store(&ctx->failed, true);
      }
      iwpool_destroy(pool);
      free(buf);
    }
    atomic_fetch_add(&ctx->reads, 1);
    nanosleep(&ts, 0);
  } while (!atomic_load(&ctx->stop));
  return 0;
}

static void _iwjsreg_atomic_concurrent(void) {
  const char *path = "iwjsreg_atomic.dat";
  unlink(path);

  struct jsreg_conc_ctx ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.path = path;
  atomic_init(&ctx.stop, false);
  atomic_init(&ctx.failed, false);
  atomic_init(&ctx.reads, 0);

  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path, .flags = IWJSREG_AUTOSYNC }, &ctx.reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_set_i64(ctx.reg, "counter", 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  pthread_t reader;
  pthread_t writers[JSREG_NWRITERS];
  IW_TEST_ASSERT_EQUAL_FATAL(pthread_create(&reader, 0, _conc_reader, &ctx), 0);
  for (int i = 0; i < JSREG_NWRITERS; ++i) {
    IW_TEST_ASSERT_EQUAL_FATAL(pthread_create(&writers[i], 0, _conc_writer, &ctx), 0);
  }
  for (int i = 0; i < JSREG_NWRITERS; ++i) {
    pthread_join(writers[i], 0);
  }
  atomic_store(&ctx.stop, true);
  pthread_join(reader, 0);

  IW_TEST_ASSERT_FALSE(atomic_load(&ctx.failed));
  IW_TEST_ASSERT_TRUE(atomic_load(&ctx.reads) > 0);

  const int64_t expected = JSREG_NWRITERS * JSREG_NINCS;
  int64_t v = 0;
  rc = iwjsreg_get_i64(ctx.reg, "counter", &v);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(v, expected);

  rc = iwjsreg_close(&ctx.reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &ctx.reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_get_i64(ctx.reg, "counter", &v);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(v, expected);
  rc = iwjsreg_close(&ctx.reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  struct iwpool *pool = 0;
  struct jbl_node *root = _load_json_file(path, &pool, &rc);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  struct jbl_node *n = 0;
  rc = jbn_at(root, "/counter", &n);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(n->type, JBV_I64);
  IW_TEST_ASSERT_EQUAL(n->vi64, expected);
  iwpool_destroy(pool);
}

// Sync must flush the containing directory after the atomic rename (exercises
// the directory-component branch of the parent directory lookup).
static void _iwjsreg_nested_path(void) {
  const char *dir = "iwjsreg_nested";
  const char *path = "iwjsreg_nested/reg.dat";
  mkdir(dir, 0777);
  unlink(path);

  struct iwjsreg *reg;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_set_str(reg, "k", "v");
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_sync(reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_close(&reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  char *sv = 0;
  rc = iwjsreg_get_str(reg, "k", &sv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_STR_EQUAL(sv, "v");
  free(sv);
  rc = iwjsreg_close(&reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  unlink(path);
  rmdir(dir);
}

// Empty string values must round-trip through the JSON file.
static void _iwjsreg_empty_string(void) {
  const char *path = "iwjsreg_empty_string.dat";
  unlink(path);

  struct iwjsreg *reg;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_str(reg, "empty", "");
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_set_str(reg, "mix", "a");
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_close(&reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  char *sv = 0;
  rc = iwjsreg_get_str(reg, "empty", &sv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_STR_EQUAL(sv, "");
  free(sv); sv = 0;

  rc = iwjsreg_at_str(reg, "/empty", &sv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_STR_EQUAL(sv, "");
  free(sv);

  struct iwpool *pool = iwpool_create_empty();
  struct jbl_node *out = 0;
  rc = iwjsreg_copy(reg, "", pool, &out);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  struct iwxstr *xstr = iwxstr_create_empty();
  rc = jbn_as_json(out, jbl_xstr_json_printer, xstr, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_STR_EQUAL(iwxstr_ptr(xstr), "{\"empty\":\"\",\"mix\":\"a\"}");
  iwxstr_destroy(xstr);
  iwpool_destroy(pool);

  rc = iwjsreg_close(&reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}

// Replacing the whole tree must not use nodes after they are freed while
// tearing the previous tree down.
static void _iwjsreg_replace_root(void) {
  const char *path = "iwjsreg_replace_root.dat";
  unlink(path);

  struct iwjsreg *reg;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_i64(reg, "a", 1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_set_i64(reg, "b", 2);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_merge_str(reg, "/c/d", "x", -1);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  struct iwpool *pool = iwpool_create_empty();
  struct jbl_node *n = 0;
  rc = jbn_from_json("{\"z\":9}", &n, pool);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_replace(reg, "", n);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  int64_t v = 0;
  rc = iwjsreg_get_i64(reg, "z", &v);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(v, 9);
  rc = iwjsreg_get_i64(reg, "a", &v);
  IW_TEST_ASSERT_EQUAL(rc, IW_ERROR_NOT_EXISTS);

  rc = iwjsreg_close(&reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  iwpool_destroy(pool);

  rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_get_i64(reg, "z", &v);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(v, 9);
  rc = iwjsreg_close(&reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
}


// Value accessors by path and the integer counter.
static void _iwjsreg_at_inc(void) {
  const char *path = "iwjsreg_at_inc.dat";
  unlink(path);

  // Prepare a registry with a null value, an array and a nested object
  FILE *file = fopen(path, "w");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(file);
  fprintf(file, "{\"nul\":null,\"arr\":[1],\"obj\":{\"k\":\"v\"}}");
  fclose(file);

  struct iwjsreg *reg;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  int64_t iv = 0;
  double fv = 0;
  bool bv = false;
  char *sv = 0;

  // Increment of a missing counter
  rc = iwjsreg_inc_i64(reg, "cnt", 3, &iv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(iv, 3);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_get_i64(reg, "cnt", &iv), 0);
  IW_TEST_ASSERT_EQUAL(iv, 3);

  rc = iwjsreg_inc_i64(reg, "cnt", -1, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_get_i64(reg, "cnt", &iv), 0);
  IW_TEST_ASSERT_EQUAL(iv, 2);

  // An increment of a non integer property replaces its value
  rc = iwjsreg_set_str(reg, "strcnt", "abc");
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_inc_i64(reg, "strcnt", 5, &iv);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL(iv, 5);

  // Typed merge setters
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_merge_i64(reg, "/m/i", -7), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_merge_f64(reg, "/m/f", 1.5), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_merge_bool(reg, "/m/b", true), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_merge_str(reg, "/m/s", "str", -1), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_merge_str(reg, "/m/s2", "abcdef", 3), 0);

  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_i64(reg, "/m/i", &iv), 0);
  IW_TEST_ASSERT_EQUAL(iv, -7);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_f64(reg, "/m/f", &fv), 0);
  IW_TEST_ASSERT_DOUBLE_EQUAL(fv, 1.5, 0.0001);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_bool(reg, "/m/b", &bv), 0);
  IW_TEST_ASSERT_EQUAL(bv, true);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_str(reg, "/m/s", &sv), 0);
  IW_TEST_ASSERT_STR_EQUAL(sv, "str");
  free(sv); sv = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_str(reg, "/m/s2", &sv), 0);
  IW_TEST_ASSERT_STR_EQUAL(sv, "abc");
  free(sv); sv = 0;

  // Numeric conversions
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_i64(reg, "/m/f", &iv), 0);
  IW_TEST_ASSERT_EQUAL(iv, 1);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_f64(reg, "/m/i", &fv), 0);
  IW_TEST_ASSERT_DOUBLE_EQUAL(fv, -7.0, 0.0001);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_bool(reg, "/m/i", &bv), 0);
  IW_TEST_ASSERT_EQUAL(bv, true);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_str(reg, "/m/i", &sv), 0);
  IW_TEST_ASSERT_STR_EQUAL(sv, "-7");
  free(sv); sv = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_str(reg, "/m/b", &sv), 0);
  IW_TEST_ASSERT_STR_EQUAL(sv, "true");
  free(sv); sv = 0;

  // String to number conversion
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_merge_str(reg, "/m/num", "42", -1), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_i64(reg, "/m/num", &iv), 0);
  IW_TEST_ASSERT_EQUAL(iv, 42);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_merge_str(reg, "/m/fnum", "2.5", -1), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_f64(reg, "/m/fnum", &fv), 0);
  IW_TEST_ASSERT_DOUBLE_EQUAL(fv, 2.5, 0.0001);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_merge_str(reg, "/m/badnum", "zzz", -1), 0);
  IW_TEST_ASSERT_EQUAL(iwjsreg_at_i64(reg, "/m/badnum", &iv), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(iwjsreg_at_f64(reg, "/m/badnum", &fv), IW_ERROR_INVALID_ARGS);

  // Null values
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_i64(reg, "/nul", &iv), 0);
  IW_TEST_ASSERT_EQUAL(iv, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_f64(reg, "/nul", &fv), 0);
  IW_TEST_ASSERT_DOUBLE_EQUAL(fv, 0, 0.0001);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_bool(reg, "/nul", &bv), 0);
  IW_TEST_ASSERT_EQUAL(bv, false);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_str(reg, "/nul", &sv), 0);
  IW_TEST_ASSERT_STR_EQUAL(sv, "null");
  free(sv); sv = 0;

  // Containers are not convertible to scalars
  IW_TEST_ASSERT_EQUAL(iwjsreg_at_i64(reg, "/obj", &iv), IW_ERROR_TYPE_NOT_COMPATIBLE);
  IW_TEST_ASSERT_EQUAL(iwjsreg_at_f64(reg, "/arr", &fv), IW_ERROR_TYPE_NOT_COMPATIBLE);
  IW_TEST_ASSERT_EQUAL(iwjsreg_at_bool(reg, "/obj", &bv), IW_ERROR_TYPE_NOT_COMPATIBLE);
  IW_TEST_ASSERT_EQUAL(iwjsreg_at_str(reg, "/arr", &sv), IW_ERROR_TYPE_NOT_COMPATIBLE);
  IW_TEST_ASSERT_PTR_NULL(sv);

  // Missing paths
  IW_TEST_ASSERT_EQUAL(iwjsreg_at_i64(reg, "/zzz", &iv), JBL_ERROR_PATH_NOTFOUND);
  IW_TEST_ASSERT_EQUAL(iwjsreg_at_str(reg, "/zzz", &sv), JBL_ERROR_PATH_NOTFOUND);
  IW_TEST_ASSERT_PTR_NULL(sv);

  // Top level string getters convert scalars as well
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_set_i64(reg, "topi", 12), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_set_bool(reg, "topb", false), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_get_str(reg, "topi", &sv), 0);
  IW_TEST_ASSERT_STR_EQUAL(sv, "12");
  free(sv); sv = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_get_str(reg, "topb", &sv), 0);
  IW_TEST_ASSERT_STR_EQUAL(sv, "false");
  free(sv); sv = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_get_str(reg, "nul", &sv), 0);
  IW_TEST_ASSERT_STR_EQUAL(sv, "null");
  free(sv); sv = 0;
  IW_TEST_ASSERT_EQUAL(iwjsreg_get_str(reg, "arr", &sv), IW_ERROR_TYPE_NOT_COMPATIBLE);
  IW_TEST_ASSERT_EQUAL(iwjsreg_get_str(reg, "obj", &sv), IW_ERROR_TYPE_NOT_COMPATIBLE);
  IW_TEST_ASSERT_PTR_NULL(sv);
  IW_TEST_ASSERT_EQUAL(iwjsreg_get_str(reg, "nokey", &sv), IW_ERROR_NOT_EXISTS);

  // Floating point values are formatted as JSON numbers
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_merge_f64(reg, "/m/small", 0.000006), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_str(reg, "/m/small", &sv), 0);
  IW_TEST_ASSERT_STR_EQUAL(sv, "0.000006");
  free(sv); sv = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_merge_f64(reg, "/m/finf", INFINITY), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_str(reg, "/m/finf", &sv), 0);
  IW_TEST_ASSERT_STR_EQUAL(sv, "null");
  free(sv); sv = 0;

  // Non standard true/false strings
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_merge_str(reg, "/m/bt", "true", -1), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_bool(reg, "/m/bt", &bv), 0);
  IW_TEST_ASSERT_EQUAL(bv, true);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_bool(reg, "/m/s", &bv), 0);
  IW_TEST_ASSERT_EQUAL(bv, false);

  rc = iwjsreg_close(&reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  unlink(path);
}

// Merge/remove/replace/copy of nested values.
static void _iwjsreg_merge_variants(void) {
  const char *path = "iwjsreg_merge_variants.dat";
  unlink(path);

  struct iwjsreg *reg;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_merge_i64(reg, "/a/b", 1), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_merge_i64(reg, "/a/c", 2), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_merge_str(reg, "/a/d/e", "x", -1), 0);

  int64_t iv = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_i64(reg, "/a/b", &iv), 0);
  IW_TEST_ASSERT_EQUAL(iv, 1);

  // Merge remove
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_merge_remove(reg, "/a/b"), 0);
  IW_TEST_ASSERT_EQUAL(iwjsreg_at_i64(reg, "/a/b", &iv), JBL_ERROR_PATH_NOTFOUND);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_i64(reg, "/a/c", &iv), 0);

  // Merge remove of a missing path is a no-op
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_merge_remove(reg, "/a/zzz"), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_merge_remove(reg, "/yyy/zzz"), 0);

  // Replace the nested subtree
  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);
  struct jbl_node *repl = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_from_json("{\"n\":{\"x\":1},\"arr\":[1,2]}", &repl, pool), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_replace(reg, "/a", repl), 0);

  char *sv = 0;
  IW_TEST_ASSERT_EQUAL(iwjsreg_at_i64(reg, "/a/c", &iv), JBL_ERROR_PATH_NOTFOUND);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_merge_str(reg, "/a/n/y", "two", -1), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_str(reg, "/a/n/y", &sv), 0);
  IW_TEST_ASSERT_STR_EQUAL(sv, "two");
  free(sv); sv = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_i64(reg, "/a/n/x", &iv), 0);
  IW_TEST_ASSERT_EQUAL(iv, 1);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_i64(reg, "/a/arr/1", &iv), 0);
  IW_TEST_ASSERT_EQUAL(iv, 2);

  // Copy of a subtree
  struct jbl_node *copy = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_copy(reg, "/a", pool, &copy), 0);
  struct iwxstr *xstr = iwxstr_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(xstr);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_as_json(copy, jbl_xstr_json_printer, xstr, 0), 0);
  IW_TEST_ASSERT_STR_EQUAL(iwxstr_ptr(xstr), "{\"n\":{\"x\":1,\"y\":\"two\"},\"arr\":[1,2]}");
  iwxstr_clear(xstr);

  // Copy of the whole registry
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_copy(reg, 0, pool, &copy), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_as_json(copy, jbl_xstr_json_printer, xstr, 0), 0);
  IW_TEST_ASSERT_STR_EQUAL(iwxstr_ptr(xstr),
                           "{\"a\":{\"n\":{\"x\":1,\"y\":\"two\"},\"arr\":[1,2]}}");
  iwxstr_destroy(xstr);

  // Copy of a missing path
  IW_TEST_ASSERT_EQUAL(iwjsreg_copy(reg, "/zzz", pool, &copy), JBL_ERROR_PATH_NOTFOUND);

  rc = iwjsreg_close(&reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  // The merge results are persisted
  rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_at_str(reg, "/a/n/y", &sv), 0);
  IW_TEST_ASSERT_STR_EQUAL(sv, "two");
  free(sv);
  rc = iwjsreg_close(&reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  iwpool_destroy(pool);
  unlink(path);
}

// A malformed registry file is reported and does not leak resources.
static void _iwjsreg_broken_file(void) {
  const char *path = "iwjsreg_broken_file.dat";
  unlink(path);

  FILE *file = fopen(path, "w");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(file);
  fprintf(file, "{\"a\":[1,2,}");
  fclose(file);

  struct iwjsreg *reg = 0;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &reg);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_PARSE_JSON);
  IW_TEST_ASSERT_PTR_NULL(reg);

  // A too short binary registry
  file = fopen(path, "wb");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(file);
  fprintf(file, "x");
  fclose(file);

  rc = iwjsreg_open(&(struct iwjsreg_spec) {
    .path = path,
    .flags = IWJSREG_FORMAT_BINARY,
  }, &reg);
  IW_TEST_ASSERT_EQUAL(rc, JBL_ERROR_INVALID_BUFFER);
  IW_TEST_ASSERT_PTR_NULL(reg);

  // A binary registry holding a non JSON value
  file = fopen(path, "wb");
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(file);
  fprintf(file, "not a binn buffer");
  fclose(file);

  rc = iwjsreg_open(&(struct iwjsreg_spec) {
    .path = path,
    .flags = IWJSREG_FORMAT_BINARY,
  }, &reg);
  IW_TEST_ASSERT_NOT_EQUAL(rc, 0);
  IW_TEST_ASSERT_PTR_NULL(reg);

  // Invalid arguments
  IW_TEST_ASSERT_EQUAL(iwjsreg_open(0, &reg), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, 0), IW_ERROR_INVALID_ARGS);
  IW_TEST_ASSERT_EQUAL(iwjsreg_open(&(struct iwjsreg_spec) { 0 }, &reg), IW_ERROR_INVALID_ARGS);

  unlink(path);
}

// A read-only registry must not modify its file.
static void _iwjsreg_readonly(void) {
  const char *path = "iwjsreg_readonly.dat";
  unlink(path);

  struct iwjsreg *reg;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_set_i64(reg, "a", 1), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_close(&reg), 0);

  char *before = iwu_file_read_as_buf(path);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(before);

  rc = iwjsreg_open(&(struct iwjsreg_spec) {
    .path = path,
    .flags = IWJSREG_READONLY,
  }, &reg);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);

  int64_t iv = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_get_i64(reg, "a", &iv), 0);
  IW_TEST_ASSERT_EQUAL(iv, 1);

  // Modifications of a read-only registry are rejected
  IW_TEST_ASSERT_EQUAL(iwjsreg_set_str(reg, "a", "x"), IW_ERROR_READONLY);
  IW_TEST_ASSERT_EQUAL(iwjsreg_set_str(reg, "new", "x"), IW_ERROR_READONLY);
  IW_TEST_ASSERT_EQUAL(iwjsreg_set_i64(reg, "a", 2), IW_ERROR_READONLY);
  IW_TEST_ASSERT_EQUAL(iwjsreg_set_bool(reg, "b", true), IW_ERROR_READONLY);
  IW_TEST_ASSERT_EQUAL(iwjsreg_inc_i64(reg, "a", 1, 0), IW_ERROR_READONLY);
  IW_TEST_ASSERT_EQUAL(iwjsreg_remove(reg, "a"), IW_ERROR_READONLY);
  IW_TEST_ASSERT_EQUAL(iwjsreg_merge_i64(reg, "/x/y", 1), IW_ERROR_READONLY);
  IW_TEST_ASSERT_EQUAL(iwjsreg_merge_str(reg, "/x", "v", -1), IW_ERROR_READONLY);
  IW_TEST_ASSERT_EQUAL(iwjsreg_merge_remove(reg, "/a"), IW_ERROR_READONLY);

  struct iwpool *pool = iwpool_create_empty();
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pool);
  struct jbl_node *n = 0;
  IW_TEST_ASSERT_EQUAL_FATAL(jbn_from_json("{\"z\":1}", &n, pool), 0);
  IW_TEST_ASSERT_EQUAL(iwjsreg_replace(reg, "/a", n), IW_ERROR_READONLY);
  iwpool_destroy(pool);

  // The registry content is not changed
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_get_i64(reg, "a", &iv), 0);
  IW_TEST_ASSERT_EQUAL(iv, 1);
  char *sv = 0;
  IW_TEST_ASSERT_EQUAL(iwjsreg_get_str(reg, "new", &sv), IW_ERROR_NOT_EXISTS);
  IW_TEST_ASSERT_EQUAL(iwjsreg_get_i64(reg, "x", &iv), IW_ERROR_NOT_EXISTS);

  // Synchronization of an unmodified read-only registry is a no-op
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_sync(reg), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwjsreg_close(&reg), 0);

  char *after = iwu_file_read_as_buf(path);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(after);
  IW_TEST_ASSERT_STR_EQUAL(after, before);

  free(before);
  free(after);
  unlink(path);
}

static const struct iw_test_case cases[] = {
  IW_TEST_CASE_AS("iwjsreg_basic1", _iwjsreg_basic1),
  IW_TEST_CASE_AS("iwjsreg_basic2", _iwjsreg_basic2),
  IW_TEST_CASE_AS("iwjsreg_merge", _iwjsreg_merge),
  IW_TEST_CASE_AS("iwjsreg_exact_keys", _iwjsreg_exact_keys),
  IW_TEST_CASE_AS("iwjsreg_remove_autosync", _iwjsreg_remove_autosync),
  IW_TEST_CASE_AS("iwjsreg_overwrite_container", _iwjsreg_overwrite_container),
  IW_TEST_CASE_AS("iwjsreg_spec_locks", _iwjsreg_spec_locks),
  IW_TEST_CASE_AS("iwjsreg_nested_path", _iwjsreg_nested_path),
  IW_TEST_CASE_AS("iwjsreg_empty_string", _iwjsreg_empty_string),
  IW_TEST_CASE_AS("iwjsreg_replace_root", _iwjsreg_replace_root),
  IW_TEST_CASE_AS("iwjsreg_atomic_concurrent", _iwjsreg_atomic_concurrent),
  IW_TEST_CASE_AS("iwjsreg_at_inc", _iwjsreg_at_inc),
  IW_TEST_CASE_AS("iwjsreg_merge_variants", _iwjsreg_merge_variants),
  IW_TEST_CASE_AS("iwjsreg_readonly", _iwjsreg_readonly),
  IW_TEST_CASE_AS("iwjsreg_broken_file", _iwjsreg_broken_file),
};

int main(int argc, char *argv[]) {
  return iw_test_run(argc, argv, IW_TEST_SUITE("iwjsreg", cases, init_suite, 0));
}

