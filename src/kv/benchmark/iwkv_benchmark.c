//#include "bmbase.c"
#include "iwkv.h"
#include "iwutils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct BMCTX BMCTX;

typedef bool (bench_method(BMCTX *bmctx));

#define RND_DATA_SZ 1048576
char RND_DATA[RND_DATA_SZ];

struct BM {
  char *rnd_data;
  size_t rnd_data_len;
  void (*print_env)(void);
  void *(*db_open)(BMCTX *ctx, bool freshdb);
  bool (*db_close)(BMCTX *ctx);
  bool (*db_put)(BMCTX *ctx, const IWKV_val *key, const IWKV_val *val);
  bool (*db_get)(BMCTX *ctx, const IWKV_val *key, IWKV_val *val);
  bool (*db_del)(BMCTX *ctx, const IWKV_val *key);
} bm;

struct BMCTX {
  bool success;
  char *name;
  uint64_t start_ms;
  uint64_t end_ms;
  uint64_t numrec;
  uint64_t flags;
  void *db;
  void *extra;
  bench_method *method;
  int rnd_data_pos;
};

static BMCTX *bmctx_create(const char *name, bench_method *method, uint64_t flags, void *extra) {
  BMCTX *bmctx = calloc(1, sizeof(*bmctx));
  bmctx->name = strdup(name);
  bmctx->method = method;
  return bmctx;
}

static void bmctx_dispose(BMCTX *ctx) {
  free(ctx->name);
  free(ctx);
}

static void bmctx_fill_rndbuf(BMCTX *ctx, char *buf, int len) {
  assert(len <= RND_DATA_SZ);
  if (ctx->rnd_data_pos + len > RND_DATA_SZ) {
    ctx->rnd_data_pos = 0;
  }
  memcpy(buf, RND_DATA + ctx->rnd_data_pos, len);
  ctx->rnd_data_pos += len;
}

static bool bm_check() {
  if (!bm.print_env) {
    fprintf(stderr, "print_env function is not initialized\n");
    return false;
  }
  if (!bm.db_open) {
    fprintf(stderr, "db_open function is not initialized\n");
    return false;
  }
  if (!bm.db_close) {
    fprintf(stderr, "db_close function is not initialized\n");
    return false;
  }
  if (!bm.db_put) {
    fprintf(stderr, "db_put function is not initialized\n");
    return false;
  }
  if (!bm.db_get) {
    fprintf(stderr, "db_get function is not initialized\n");
    return false;
  }
  if (!bm.db_del) {
    fprintf(stderr, "db_del function is not initialized\n");
    return false;
  }
  return true;
}

static void bm_init() {
#ifndef NDEBUG
  fprintf(stdout,
          "WARNING: Assertions are enabled; benchmarks can be slow\n");
#endif
  if (!bm_check()) {
    fprintf(stderr, "Benchmark `bm` structure is not configured properly\n");
    exit(1);
  }
  // Fill up random data array
  for (int i = 0; i < RND_DATA_SZ; ++i) {
    RND_DATA[i] = ' ' + iwu_rand_range(95); // ascii space ... ~
  }
}

static void bm_dispose() {
}

static void bm_all_run() {
  bm.print_env();
}

// -------------------------------------------------------------------

typedef struct BM_IWKVDB {
  IWKV iwkv;
  IWDB db;
} BM_IWKVDB;

void print_env() {
  printf("IWKV\n");
}

void *db_open(BMCTX *ctx, bool freshdb) {
  IWKV_OPTS opts = {
    .path = "iwkv_bench.db"
  };
  if (freshdb) {
    opts.oflags = IWKV_TRUNC;
  }
  BM_IWKVDB *bmdb = malloc(sizeof(*bmdb));
  iwrc rc = iwkv_open(&opts, &bmdb->iwkv);
  if (rc) {
    iwlog_ecode_error2(rc, "Failed to open iwkv file");
    return 0;
  }
  rc = iwkv_db(bmdb->iwkv, 1, 0, &bmdb->db);
  if (rc) {
    iwlog_ecode_error2(rc, "Failed to open iwkv db: 1");
    return 0;
  }
  return bmdb;
}

bool db_close(BMCTX *ctx) {
  if (!ctx->db) {
    return false;
  }
  BM_IWKVDB *bmdb = ctx->db;
  iwrc rc = iwkv_close(&bmdb->iwkv);
  if (rc) {
    return false;
  }
  free(bmdb);
  return true;
}

bool db_put(BMCTX *ctx, const IWKV_val *key, const IWKV_val *val) {
  BM_IWKVDB *bmdb = ctx->db;
  iwrc rc = iwkv_put(bmdb->db, key, val, 0);
  if (rc) {
    iwlog_ecode_error2(rc, "iwkv_put failed");
    return false;
  }
  return true;
}

bool db_get(BMCTX *ctx, const IWKV_val *key, IWKV_val *val) {
  BM_IWKVDB *bmdb = ctx->db;
  iwrc rc = iwkv_get(bmdb->db, key, val);
  if (rc) {
    iwlog_ecode_error2(rc, "iwkv_get failed");
    return false;
  }
  return true;
}

bool db_del(BMCTX *ctx, const IWKV_val *key) {
  BM_IWKVDB *bmdb = ctx->db;
  iwrc rc = iwkv_del(bmdb->db, key);
  if (rc) {
    iwlog_ecode_error2(rc, "iwkv_del failed");
    return false;
  }
  return true;
}

int main(int argc, char **argv) {
  bm.print_env = print_env;
  bm.db_open = db_open;
  bm.db_close = db_close;
  bm.db_put = db_put;
  bm.db_get = db_get;
  bm.db_del = db_del;
  bm_init();
  bm_all_run();
  bm_dispose();
}
