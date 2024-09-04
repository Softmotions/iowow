#include "bmbase.c"
#include <kclangc.h>

#define DEFAULT_DB "kyc_bench.kct"

typedef struct BM_KYC {
  KCDB *db;
} BM_KYC;

static void env_setup() {
  fprintf(stderr, " engine: KyotoCabinet %s\n", KCVERSION);
}

uint64_t db_size_bytes(BMCTX *ctx) {
  const char *path = bm.param_db ? bm.param_db : DEFAULT_DB;
  IWP_FILE_STAT fst;
  iwrc rc = iwp_fstat(path, &fst);
  if (rc) {
    iwlog_ecode_error3(rc);
    return 0;
  }
  return fst.size;
}

static void* db_open(BMCTX *ctx) {
  if (ctx->db) {
    return 0; // db is not closed properly
  }
  bool wal_enabled = false;
  for (int i = 0; i < bm.argc; ++i) {
    if (!strcmp(bm.argv[i], "-w")) {
      wal_enabled = true;
    }
  }
  const char *path = bm.param_db ? bm.param_db : DEFAULT_DB;
  BM_KYC *bmdb = malloc(sizeof(*bmdb));
  bmdb->db = kcdbnew();
  uint32_t mode = KCOWRITER | KCOCREATE;
  if (ctx->freshdb) {
    mode |= KCOTRUNCATE;
  }
  if (wal_enabled) {
    mode |= KCOAUTOTRAN;
  }
  if (!kcdbopen(bmdb->db, path, mode)) {
    kcdbdel(bmdb->db);
    free(bmdb);
    return 0;
  }
  return bmdb;
}

static bool db_close(BMCTX *ctx) {
  if (!ctx->db) {
    return false;
  }
  BM_KYC *bmdb = ctx->db;
  int32_t rc = kcdbclose(bmdb->db);
  if (!rc) {
    fprintf(stderr, "db_close: %s\n", kcdbemsg(bmdb->db));
    return false;
  }
  kcdbdel(bmdb->db);
  free(bmdb);
  return true;
}

static bool db_put(BMCTX *ctx, const IWKV_val *key, const IWKV_val *val, bool sync) {
  BM_KYC *bmdb = ctx->db;
  int32_t rc = kcdbset(bmdb->db, key->data, key->size, val->data, val->size);
  if (!rc) {
    fprintf(stderr, "db_put: %s\n", kcdbemsg(bmdb->db));
    return false;
  }
  if (sync) {
    rc = kcdbsync(bmdb->db, true, 0, 0);
    if (!rc) {
      fprintf(stderr, "db_put:kcdbsync: %s\n", kcdbemsg(bmdb->db));
      return false;
    }
  }
  return true;
}

static bool db_get(BMCTX *ctx, const IWKV_val *key, IWKV_val *val, bool *found) {
  BM_KYC *bmdb = ctx->db;
  size_t sp = 0;
  char *vbuf = kcdbget(bmdb->db, key->data, key->size, &sp);
  val->data = vbuf;
  val->size = sp;
  *found = (val->data != 0);
  return true;
}

static bool db_del(BMCTX *ctx, const IWKV_val *key, bool sync) {
  BM_KYC *bmdb = ctx->db;
  kcdbremove(bmdb->db, key->data, key->size);
  if (sync) {
    int32_t rc = kcdbsync(bmdb->db, true, 0, 0);
    if (!rc) {
      fprintf(stderr, "db_del:kcdbsync: %s\n", kcdbemsg(bmdb->db));
      return false;
    }
  }
  return true;
}

static bool db_read_seq(BMCTX *ctx, bool reverse) {
  int32_t rc = true;
  BM_KYC *bmdb = ctx->db;
  KCCUR *cur = kcdbcursor(bmdb->db);
  if (!cur) {
    return false;
  }
  if (reverse) {
    rc = kccurjumpback(cur);
  } else {
    rc = kccurjump(cur);
  }
  if (!rc) {
    if (kcdbecode(bmdb->db) == KCENOREC) {
      kccurdel(cur);
      return true;
    }
  }
  if (!rc) {
    fprintf(stderr, "db_read_seq: %s\n", kcdbemsg(bmdb->db));
    kccurdel(cur);
    return false;
  }
  for (int i = 0; i < bm.param_num && rc; ++i) {
    if (reverse) {
      rc = kccurstepback(cur);
    } else {
      rc = kccurstep(cur);
    }
  }
  if (kcdbecode(bmdb->db) != KCENOREC) {
    fprintf(stderr, "db_read_seq: %s\n", kcdbemsg(bmdb->db));
  }
  kccurdel(cur);
  return true;
}

static bool db_cursor_to_key(BMCTX *ctx, const IWKV_val *key, IWKV_val *val, bool *found) {
  int32_t rc = true;
  BM_KYC *bmdb = ctx->db;
  KCCUR *cur = kcdbcursor(bmdb->db);
  *found = false;
  rc = kccurjumpkey(cur, key->data, key->size);
  if (rc) {
    *found = true;
  }
  if (!rc && (kcdbecode(bmdb->db) != KCENOREC)) {
    fprintf(stderr, "db_cursor_to_key: %s\n", kcdbemsg(bmdb->db));
    kccurdel(cur);
    return false;
  }
  val->data = kccurgetvalue(cur, &val->size, 0);
  kccurdel(cur);
  return true;
}

int main(int argc, char **argv) {
  if (argc < 1) {
    return -1;
  }
  g_program = argv[0];
  bm.env_setup = env_setup;
  bm.db_size_bytes = db_size_bytes;
  bm.val_free = kcfree;
  bm.db_open = db_open;
  bm.db_close = db_close;
  bm.db_put = db_put;
  bm.db_get = db_get;
  bm.db_del = db_del;
  bm.db_read_seq = db_read_seq;
  bm.db_cursor_to_key = db_cursor_to_key;
  if (!bm_bench_run(argc, argv)) {
    return 1;
  }
  return 0;
}
