#include "bmbase.c"
#include <tcbdb.h>

#define DEFAULT_DB "tc_bench.tc"

struct BMTC {
  TCBDB *db;
} btc;
typedef struct BMTC BMTC;

static void env_setup() {
  fprintf(stderr, " engine: TokyoCabinet %s\n", _TC_VERSION);
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
  if (ctx->db || btc.db) {
    return 0; // db is not closed properly
  }
  const char *path = bm.param_db ? bm.param_db : DEFAULT_DB;
  int omode = BDBOWRITER | BDBOCREAT;
  if (ctx->freshdb) {
    omode |= BDBOTRUNC;
  }
  btc.db = tcbdbnew();
  if (!btc.db) {
    return 0;
  }
  tcbdbsetxmsiz(btc.db, 1024ULL * 1024 * 1024 * 10);
  tcbdbtune(btc.db, 0, 0, 32749 * 4, 8, 10, BDBTLARGE);
  if (!tcbdbopen(btc.db, path, omode)) {
    tcbdbdel(btc.db);
    btc.db = 0;
    return 0;
  }
  return &btc;
}

static bool db_close(BMCTX *ctx) {
  if (!ctx->db) {
    return false;
  }
  BMTC *btc = ctx->db;
  bool ret = tcbdbclose(btc->db);
  tcbdbdel(btc->db);
  btc->db = 0;
  return ret;
}

static bool db_put(BMCTX *ctx, const IWKV_val *key, const IWKV_val *val, bool sync) {
  BMTC *btc = ctx->db;
  if (!tcbdbput(btc->db, key->data, key->size, val->data, val->size)) {
    fprintf(stderr, "db_put: %s\n", tcbdberrmsg(tcbdbecode(btc->db)));
    return false;
  }
  if (sync) {
    return tcbdbsync(btc->db);
  }
  return true;
}

static bool db_get(BMCTX *ctx, const IWKV_val *key, IWKV_val *val, bool *found) {
  BMTC *btc = ctx->db;
  int sp = 0;
  char *vbuf = tcbdbget(btc->db, key->data, key->size, &sp);
  val->data = vbuf;
  val->size = sp;
  *found = (val->data != 0);
  return true;
}

static bool db_del(BMCTX *ctx, const IWKV_val *key, bool sync) {
  BMTC *btc = ctx->db;
  tcbdbout(btc->db, key->data, key->size);
  if (sync) {
    if (!tcbdbsync(btc->db)) {
      fprintf(stderr, "db_del: %s\n", tcbdberrmsg(tcbdbecode(btc->db)));
      return false;
    }
  }
  return true;
}

static bool db_read_seq(BMCTX *ctx, bool reverse) {
  BMTC *btc = ctx->db;
  BDBCUR *cur = tcbdbcurnew(btc->db);
  if (!cur) {
    return false;
  }
  if (reverse) {
    tcbdbcurlast(cur);
  } else {
    tcbdbcurfirst(cur);
  }
  for (int i = 0; i < bm.param_num; ++i) {
    if (reverse) {
      tcbdbcurprev(cur);
    } else {
      tcbdbcurnext(cur);
    }
  }
  tcbdbcurdel(cur);
  return true;
}

static bool db_cursor_to_key(BMCTX *ctx, const IWKV_val *key, IWKV_val *val, bool *found) {
  BMTC *btc = ctx->db;
  BDBCUR *cur = tcbdbcurnew(btc->db);
  if (!cur) {
    return false;
  }
  if (!tcbdbcurjump(cur, key->data, key->size)) {
    *found = false;
  } else {
    *found = true;
    int sp;
    val->data = tcbdbcurval(cur, &sp);
    val->size = sp;
  }
  tcbdbcurdel(cur);
  return true;
}

int main(int argc, char **argv) {
  if (argc < 1) {
    return -1;
  }
  g_program = argv[0];
  bm.env_setup = env_setup;
  bm.db_size_bytes = db_size_bytes;
  bm.val_free = free;
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
