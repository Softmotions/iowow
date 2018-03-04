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
} bm;

struct BMCTX {
  bool success;
  char *name;
  uint64_t start_ms;
  uint64_t end_ms;
  uint64_t numrec;
  uint64_t flags;
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
    fprintf(stderr, "Benchmark `bm` structure is not configured properly");
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

void print_env() {
}

int main(int argc, char **argv) {
  bm.print_env = print_env;
  bm_init();
  bm_all_run();
  bm_dispose();
}
