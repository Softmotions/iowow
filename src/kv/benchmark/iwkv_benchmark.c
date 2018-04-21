#include "bmbase.c"
#include "iowow.h"

#define DEFAULT_DB "iwkv_bench.db"

typedef struct BM_IWKVDB {
  IWKV iwkv;
  IWDB db;
} BM_IWKVDB;

static void env_setup() {
  iwrc rc = iw_init();
  if (rc) {
    iwlog_ecode_error2(rc, "Failed to init iwkv: iwkv_init()");
    exit(1);
  }
  fprintf(stderr, " engine: IWKV %s\n", iowow_version_full());
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

static void *db_open(BMCTX *ctx) {
  if (ctx->db) {
    return 0; // db is not closed properly
  }
  IWKV_OPTS opts = {
    .wal = {
      .enabled = true,
      .check_crc_on_checkpoint = false,
      .checkpoint_timeout_ms = 0,
      .wal_buffer_sz = 64 * 1024,
      .checkpoint_buffer_sz = 128 * 1024 * 1024
    }
  };
  opts.path = bm.param_db ? bm.param_db : DEFAULT_DB;
  
  if (ctx->freshdb) {
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

static bool db_close(BMCTX *ctx) {
  if (!ctx->db) {
    return false;
  }
  BM_IWKVDB *bmdb = ctx->db;
  iwrc rc = iwkv_close(&bmdb->iwkv);
  if (rc) {
    iwlog_ecode_error2(rc, "db_close");
    return false;
  }
  free(bmdb);
  return true;
}

static bool db_put(BMCTX *ctx, const IWKV_val *key, const IWKV_val *val, bool sync) {
  BM_IWKVDB *bmdb = ctx->db;
  iwrc rc = iwkv_put(bmdb->db, key, val, sync ? IWKV_SYNC : 0);
  if (rc) {
    iwlog_ecode_error2(rc, "db_put");
    return false;
  }
  return true;
}

static bool db_get(BMCTX *ctx, const IWKV_val *key, IWKV_val *val, bool *found) {
  BM_IWKVDB *bmdb = ctx->db;
  *found = true;
  iwrc rc = iwkv_get(bmdb->db, key, val);
  if (rc == IWKV_ERROR_NOTFOUND) {
    *found = false;
    rc = 0;
  }
  if (rc) {
    iwlog_ecode_error2(rc, "db_get");
    return false;
  }
  return true;
}

static bool db_del(BMCTX *ctx, const IWKV_val *key, bool sync) {
  BM_IWKVDB *bmdb = ctx->db;
  iwrc rc = iwkv_del(bmdb->db, key);
  if (rc == IWKV_ERROR_NOTFOUND) {
    rc = 0;
  }
  if (rc) {
    iwlog_ecode_error2(rc, "db_del");
    return false;
  }
  return true;
}

static bool db_read_seq(BMCTX *ctx, bool reverse) {
  BM_IWKVDB *bmdb = ctx->db;
  bool ret = true;
  IWKV_cursor cur;
  iwrc rc = iwkv_cursor_open(bmdb->db, &cur,
                             (reverse ? IWKV_CURSOR_AFTER_LAST : IWKV_CURSOR_BEFORE_FIRST), 0);
  if (rc) {
    iwlog_ecode_error2(rc, "db_read_seq::iwkv_cursor_open failed");
    return false;
  }
  for (int i = 0; i < bm.param_num && !rc; ++i) {
    rc = iwkv_cursor_to(cur, reverse ? IWKV_CURSOR_PREV : IWKV_CURSOR_NEXT);
  }
  iwkv_cursor_close(&cur);
  if (rc == IWKV_ERROR_NOTFOUND) {
    rc = 0;
  }
  if (rc) {
    ret = false;
    iwlog_ecode_error2(rc, "db_read_seq");
  }
  return ret;
}

static bool db_cursor_to_key(BMCTX *ctx, const IWKV_val *key, IWKV_val *val, bool *found) {
  BM_IWKVDB *bmdb = ctx->db;
  bool ret = true;
  IWKV_cursor cur;
  *found = true;
  iwrc rc = iwkv_cursor_open(bmdb->db, &cur, IWKV_CURSOR_EQ, key);
  if (!rc) {
    rc = iwkv_cursor_val(cur, val);
    if (rc) {
      ret = false;
      iwlog_ecode_error2(rc, "db_cursor_to_key::iwkv_cursor_val failed");
    }
    iwkv_cursor_close(&cur);
  } else if (rc == IWKV_ERROR_NOTFOUND) {
    *found = false;
    iwkv_cursor_close(&cur);
  } else {
    iwlog_ecode_error2(rc, "db_cursor_to_key::iwkv_cursor_open failed");
    ret = false;
  }
  return ret;
}

int main(int argc, char *argv[]) {
  if (argc < 1) return -1;
  g_program = argv[0];
  bm.env_setup = env_setup;
  bm.db_size_bytes = db_size_bytes;
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
