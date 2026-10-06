#include "iwlog.h"
#include "iowow.h"
#include "iwjsreg.h"
#include "iwlog.h"
#include "iwutils.h"
#include <CUnit/Basic.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>
#include <sys/stat.h>

int init_suite(void) {
  int rc = iw_init();
  return rc;
}

int clean_suite(void) {
  return 0;
}

static void _iwjsreg_basic1(void) {
  const char *path = "iwjsreg_basic1.dat";
  unlink(path);

  struct iwjsreg *reg;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) {
    .path = path,
  }, &reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_str(reg, "key1", "val1");
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_i64(reg, "key2", 8217128L);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_bool(reg, "key3", true);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_close(&reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_open(&(struct iwjsreg_spec) {
    .path = path,
  }, &reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  int64_t val;
  rc = iwjsreg_get_i64(reg, "key2", &val);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(val, 8217128L);

  rc = iwjsreg_get_i64(reg, "key22", &val);
  CU_ASSERT_EQUAL(rc, IW_ERROR_NOT_EXISTS);

  char *buf;
  rc = iwjsreg_get_str(reg, "key1", &buf);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_STRING_EQUAL(buf, "val1");
  free(buf);

  rc = iwjsreg_remove(reg, "key1");
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_get_i64(reg, "key1", &val);
  CU_ASSERT_EQUAL(rc, IW_ERROR_NOT_EXISTS);

  rc = iwjsreg_close(&reg);
  CU_ASSERT_EQUAL(rc, 0);
}

static void _iwjsreg_basic2(void) {
  const char *path = "iwjsreg_basic2.dat";
  unlink(path);

  struct iwjsreg *reg;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) {
    .path = path,
    .flags = IWJSREG_FORMAT_BINARY,
  }, &reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_str(reg, "key1", "val1");
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_i64(reg, "key2", 8217128L);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_bool(reg, "key3", true);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_close(&reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_open(&(struct iwjsreg_spec) {
    .path = path,
    .flags = IWJSREG_FORMAT_BINARY,
  }, &reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  int64_t val;
  rc = iwjsreg_get_i64(reg, "key2", &val);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(val, 8217128L);

  rc = iwjsreg_get_i64(reg, "key22", &val);
  CU_ASSERT_EQUAL(rc, IW_ERROR_NOT_EXISTS);

  char *buf;
  rc = iwjsreg_get_str(reg, "key1", &buf);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_STRING_EQUAL(buf, "val1");
  free(buf);

  rc = iwjsreg_remove(reg, "key1");
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_get_i64(reg, "key1", &val);
  CU_ASSERT_EQUAL(rc, IW_ERROR_NOT_EXISTS);

  rc = iwjsreg_close(&reg);
  CU_ASSERT_EQUAL(rc, 0);
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
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_merge(reg, "/foo/bar", n);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_merge(reg, "/foo/bar", n);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_merge(reg, "/foo/bar/zaz", n);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = jbn_from_json("{\"gaz\":null}", &n2, pool);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_merge(reg, "/foo/bar/zaz", n2);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_copy(reg, "", pool, &n2);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  fprintf(stderr, "\n");
  jbn_as_json(n2, jbl_xstr_json_printer, xstr, 0);

  CU_ASSERT_STRING_EQUAL(iwxstr_ptr(xstr), "{\"foo\":{\"bar\":{\"vaz\":1,\"gaz\":\"val\",\"zaz\":{\"vaz\":1}}}}");

  rc = iwjsreg_sync(reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_close(&reg);
  CU_ASSERT_EQUAL(rc, 0);
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
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_str(reg, "key", "v");
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_set_str(reg, "key2", "v2");
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_set_i64(reg, "n", 10);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_set_i64(reg, "n2", 20);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_set_bool(reg, "b", true);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_set_bool(reg, "b2", false);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  char *sv = 0;
  int64_t iv = 0;
  bool bv = false;

  rc = iwjsreg_get_str(reg, "key", &sv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_STRING_EQUAL(sv, "v");
  free(sv); sv = 0;

  rc = iwjsreg_get_str(reg, "key2", &sv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_STRING_EQUAL(sv, "v2");
  free(sv); sv = 0;

  rc = iwjsreg_get_i64(reg, "n", &iv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(iv, 10);
  rc = iwjsreg_get_i64(reg, "n2", &iv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(iv, 20);

  rc = iwjsreg_get_bool(reg, "b", &bv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_TRUE(bv);
  rc = iwjsreg_get_bool(reg, "b2", &bv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_FALSE(bv);

  // inc_i64 must not touch a shorter key that is a prefix of the requested one
  rc = iwjsreg_inc_i64(reg, "n2", 5, &iv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(iv, 25);
  rc = iwjsreg_get_i64(reg, "n", &iv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(iv, 10);

  // remove must not remove a key that is a prefix of the requested one
  rc = iwjsreg_remove(reg, "key");
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_get_str(reg, "key", &sv);
  CU_ASSERT_EQUAL(rc, IW_ERROR_NOT_EXISTS);
  rc = iwjsreg_get_str(reg, "key2", &sv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_STRING_EQUAL(sv, "v2");
  free(sv); sv = 0;

  rc = iwjsreg_close(&reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // Persisted state must match the in-memory one
  rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_get_str(reg, "key2", &sv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_STRING_EQUAL(sv, "v2");
  free(sv);
  rc = iwjsreg_get_i64(reg, "n2", &iv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(iv, 25);
  rc = iwjsreg_close(&reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
}

// IWJSREG_AUTOSYNC must persist removals immediately, not only on close().
static void _iwjsreg_remove_autosync(void) {
  const char *path = "iwjsreg_remove_autosync.dat";
  unlink(path);

  struct iwjsreg *reg;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path, .flags = IWJSREG_AUTOSYNC }, &reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_i64(reg, "a", 1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_set_i64(reg, "b", 2);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_remove(reg, "a");
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  struct iwpool *pool = 0;
  struct jbl_node *root = _load_json_file(path, &pool, &rc);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  struct jbl_node *n = 0;
  rc = jbn_at(root, "/a", &n);
  CU_ASSERT_EQUAL(rc, JBL_ERROR_PATH_NOTFOUND);
  rc = jbn_at(root, "/b", &n);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(n->type, JBV_I64);
  CU_ASSERT_EQUAL(n->vi64, 2);
  iwpool_destroy(pool);

  rc = iwjsreg_close(&reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
}

// Replacing a container (object/array) node with a scalar must release the
// container payload while keeping the resulting JSON consistent.
static void _iwjsreg_overwrite_container(void) {
  const char *path = "iwjsreg_overwrite.dat";
  unlink(path);

  struct iwjsreg *reg;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  struct iwpool *pool = iwpool_create_empty();
  struct jbl_node *n = 0;
  rc = jbn_from_json("{\"a\":1}", &n, pool);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_merge(reg, "/obj", n);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = jbn_from_json("[1,2,3]", &n, pool);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_merge(reg, "/arr", n);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_i64(reg, "obj", 42);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_set_str(reg, "arr", "x");
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  struct jbl_node *out = 0;
  struct iwxstr *xstr = iwxstr_create_empty();
  rc = iwjsreg_copy(reg, "", pool, &out);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = jbn_as_json(out, jbl_xstr_json_printer, xstr, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_STRING_EQUAL(iwxstr_ptr(xstr), "{\"obj\":42,\"arr\":\"x\"}");
  iwxstr_destroy(xstr);

  // Removing a container node must free the whole subtree
  rc = jbn_from_json("{\"b\":2}", &n, pool);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_merge(reg, "/obj2", n);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_remove(reg, "obj2");
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  struct jbl_node *nfound = 0;
  rc = iwjsreg_copy(reg, "/obj2", pool, &nfound);
  CU_ASSERT_EQUAL(rc, JBL_ERROR_PATH_NOTFOUND);

  rc = iwjsreg_close(&reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
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
  CU_ASSERT_EQUAL_FATAL(pthread_rwlock_init(&rwl, 0), 0);

  struct iwjsreg *reg;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) {
    .path = path,
    .wlock_fn = _spec_wlock,
    .rlock_fn = _spec_rlock,
    .unlock_fn = _spec_unlock,
    .fn_data = &rwl,
    .flags = IWJSREG_AUTOSYNC,
  }, &reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_i64(reg, "counter", 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  for (int i = 0; i < 100; ++i) {
    rc = iwjsreg_inc_i64(reg, "counter", 1, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }

  int64_t v = 0;
  rc = iwjsreg_get_i64(reg, "counter", &v);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(v, 100);

  rc = iwjsreg_close(&reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  pthread_rwlock_destroy(&rwl);

  CU_ASSERT_TRUE(atomic_load(&_spec_wlock_calls) > 0);
  CU_ASSERT_TRUE(atomic_load(&_spec_rlock_calls) > 0);
  CU_ASSERT_TRUE(atomic_load(&_spec_unlock_calls) > 0);

  rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_get_i64(reg, "counter", &v);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(v, 100);
  rc = iwjsreg_close(&reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
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
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_set_i64(ctx.reg, "counter", 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  pthread_t reader;
  pthread_t writers[JSREG_NWRITERS];
  CU_ASSERT_EQUAL_FATAL(pthread_create(&reader, 0, _conc_reader, &ctx), 0);
  for (int i = 0; i < JSREG_NWRITERS; ++i) {
    CU_ASSERT_EQUAL_FATAL(pthread_create(&writers[i], 0, _conc_writer, &ctx), 0);
  }
  for (int i = 0; i < JSREG_NWRITERS; ++i) {
    pthread_join(writers[i], 0);
  }
  atomic_store(&ctx.stop, true);
  pthread_join(reader, 0);

  CU_ASSERT_FALSE(atomic_load(&ctx.failed));
  CU_ASSERT_TRUE(atomic_load(&ctx.reads) > 0);

  const int64_t expected = JSREG_NWRITERS * JSREG_NINCS;
  int64_t v = 0;
  rc = iwjsreg_get_i64(ctx.reg, "counter", &v);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(v, expected);

  rc = iwjsreg_close(&ctx.reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &ctx.reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_get_i64(ctx.reg, "counter", &v);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(v, expected);
  rc = iwjsreg_close(&ctx.reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  struct iwpool *pool = 0;
  struct jbl_node *root = _load_json_file(path, &pool, &rc);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  struct jbl_node *n = 0;
  rc = jbn_at(root, "/counter", &n);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(n->type, JBV_I64);
  CU_ASSERT_EQUAL(n->vi64, expected);
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
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_set_str(reg, "k", "v");
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_sync(reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_close(&reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  char *sv = 0;
  rc = iwjsreg_get_str(reg, "k", &sv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_STRING_EQUAL(sv, "v");
  free(sv);
  rc = iwjsreg_close(&reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  unlink(path);
  rmdir(dir);
}

// Empty string values must round-trip through the JSON file.
static void _iwjsreg_empty_string(void) {
  const char *path = "iwjsreg_empty_string.dat";
  unlink(path);

  struct iwjsreg *reg;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_str(reg, "empty", "");
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_set_str(reg, "mix", "a");
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_close(&reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  char *sv = 0;
  rc = iwjsreg_get_str(reg, "empty", &sv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_STRING_EQUAL(sv, "");
  free(sv); sv = 0;

  rc = iwjsreg_at_str(reg, "/empty", &sv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_STRING_EQUAL(sv, "");
  free(sv);

  struct iwpool *pool = iwpool_create_empty();
  struct jbl_node *out = 0;
  rc = iwjsreg_copy(reg, "", pool, &out);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  struct iwxstr *xstr = iwxstr_create_empty();
  rc = jbn_as_json(out, jbl_xstr_json_printer, xstr, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_STRING_EQUAL(iwxstr_ptr(xstr), "{\"empty\":\"\",\"mix\":\"a\"}");
  iwxstr_destroy(xstr);
  iwpool_destroy(pool);

  rc = iwjsreg_close(&reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
}

// Replacing the whole tree must not use nodes after they are freed while
// tearing the previous tree down.
static void _iwjsreg_replace_root(void) {
  const char *path = "iwjsreg_replace_root.dat";
  unlink(path);

  struct iwjsreg *reg;
  iwrc rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwjsreg_set_i64(reg, "a", 1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_set_i64(reg, "b", 2);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_merge_str(reg, "/c/d", "x", -1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  struct iwpool *pool = iwpool_create_empty();
  struct jbl_node *n = 0;
  rc = jbn_from_json("{\"z\":9}", &n, pool);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_replace(reg, "", n);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  int64_t v = 0;
  rc = iwjsreg_get_i64(reg, "z", &v);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(v, 9);
  rc = iwjsreg_get_i64(reg, "a", &v);
  CU_ASSERT_EQUAL(rc, IW_ERROR_NOT_EXISTS);

  rc = iwjsreg_close(&reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  iwpool_destroy(pool);

  rc = iwjsreg_open(&(struct iwjsreg_spec) { .path = path }, &reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwjsreg_get_i64(reg, "z", &v);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(v, 9);
  rc = iwjsreg_close(&reg);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
}

int main(void) {
  CU_pSuite pSuite = NULL;
  if (CUE_SUCCESS != CU_initialize_registry()) {
    return CU_get_error();
  }
  pSuite = CU_add_suite("iwjsreg", init_suite, clean_suite);
  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }
  int ret = 0;
  if (  NULL == CU_add_test(pSuite, "iwjsreg_basic1", _iwjsreg_basic1)
     || NULL == CU_add_test(pSuite, "iwjsreg_basic2", _iwjsreg_basic2)
     || NULL == CU_add_test(pSuite, "iwjsreg_merge", _iwjsreg_merge)
     || NULL == CU_add_test(pSuite, "iwjsreg_exact_keys", _iwjsreg_exact_keys)
     || NULL == CU_add_test(pSuite, "iwjsreg_remove_autosync", _iwjsreg_remove_autosync)
     || NULL == CU_add_test(pSuite, "iwjsreg_overwrite_container", _iwjsreg_overwrite_container)
     || NULL == CU_add_test(pSuite, "iwjsreg_spec_locks", _iwjsreg_spec_locks)
     || NULL == CU_add_test(pSuite, "iwjsreg_nested_path", _iwjsreg_nested_path)
     || NULL == CU_add_test(pSuite, "iwjsreg_empty_string", _iwjsreg_empty_string)
     || NULL == CU_add_test(pSuite, "iwjsreg_replace_root", _iwjsreg_replace_root)
     || NULL == CU_add_test(pSuite, "iwjsreg_atomic_concurrent", _iwjsreg_atomic_concurrent)) {
    CU_cleanup_registry();
    return CU_get_error();
  }
  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  ret = CU_get_error() || CU_get_number_of_failures();
  CU_cleanup_registry();
  return ret;
}
