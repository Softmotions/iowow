#include "bmbase.c"
#include <lmdb.h>
#include <unistd.h>
#include <errno.h>

static_assert(sizeof(size_t) == 8, "sizeof(size_t) == 8 bytes");

#define E(expr_, ret_) \
  if ((rc = (expr_)) != MDB_SUCCESS) { \
    fprintf(stderr, "%s:%d %s\n", __FILE__, __LINE__, mdb_strerror(rc)); \
    return ret_; \
  }

#define B(expr_) E(expr_, 0)

#define DEFAULT_DB "lmdb_bench.db"

typedef struct BM_LEVELDB {
  MDB_env *env;
  MDB_dbi  dbi;
} BM_LMDB;

static void env_setup() {
  int major, minor, patch;
  mdb_version(&major, &minor, &patch);
  fprintf(stderr, " engine: LMDB %d.%d.%d\n", major, minor, patch);
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
  int rc;
  if (ctx->db) {
    return 0; // db is not closed properly
  }
  const char *path = bm.param_db ? bm.param_db : DEFAULT_DB;
  if (ctx->freshdb) { // completely remove db folder
    rc = unlink(path);
    if (rc && (errno != ENOENT)) {
      E(errno, 0);
    }
  }
  MDB_txn *txn;
  BM_LMDB *bmdb = malloc(sizeof(*bmdb));
  E(mdb_env_create(&bmdb->env), 0);
  E(mdb_env_set_maxreaders(bmdb->env, 1), 0);
  E(mdb_env_set_mapsize(bmdb->env, 1024ULL * 1024 * 1024 * 100), 0); // 100 GB
  E(mdb_env_open(bmdb->env, path, MDB_FIXEDMAP | MDB_NOSUBDIR | MDB_NOSYNC, 0664), 0);
  E(mdb_txn_begin(bmdb->env, NULL, 0, &txn), 0);
  E(mdb_dbi_open(txn, NULL, 0, &bmdb->dbi), 0);
  E(mdb_txn_commit(txn), 0);
  return bmdb;
}

static bool db_close(BMCTX *ctx) {
  int rc;
  if (!ctx->db) {
    return false;
  }
  BM_LMDB *bmdb = ctx->db;
  B(mdb_env_sync(bmdb->env, 1));
  mdb_dbi_close(bmdb->env, bmdb->dbi);
  mdb_env_close(bmdb->env);
  free(bmdb);
  return true;
}

static bool db_put(BMCTX *ctx, const IWKV_val *key, const IWKV_val *val, bool sync) {
  int rc;
  BM_LMDB *bmdb = ctx->db;
  MDB_txn *txn;
  MDB_val mkey, mval;
  mkey.mv_data = key->data;
  mkey.mv_size = key->size;
  mval.mv_data = val->data;
  mval.mv_size = val->size;
  B(mdb_txn_begin(bmdb->env, NULL, 0, &txn));
  B(mdb_put(txn, bmdb->dbi, &mkey, &mval, 0));
  B(mdb_txn_commit(txn));
  if (sync) {
    B(mdb_env_sync(bmdb->env, 1));
  }
  return true;
}

static bool db_get(BMCTX *ctx, const IWKV_val *key, IWKV_val *val, bool *found) {
  int rc;
  MDB_txn *txn;
  MDB_val mkey, mval;
  BM_LMDB *bmdb = ctx->db;
  mkey.mv_data = key->data;
  mkey.mv_size = key->size;
  B(mdb_txn_begin(bmdb->env, NULL, MDB_RDONLY, &txn));
  rc = mdb_get(txn, bmdb->dbi, &mkey, &mval);
  if (!rc) {
    *found = true;
    val->size = mval.mv_size;
    val->data = malloc(val->size);
    memcpy(val->data, mval.mv_data, mval.mv_size);
  } else if (rc == MDB_NOTFOUND) {
    *found = false;
    rc = 0;
  }
  mdb_txn_abort(txn);
  B(rc);
  return true;
}

static bool db_del(BMCTX *ctx, const IWKV_val *key, bool sync) {
  int rc;
  MDB_txn *txn;
  MDB_val mkey;
  BM_LMDB *bmdb = ctx->db;
  mkey.mv_data = key->data;
  mkey.mv_size = key->size;
  B(mdb_txn_begin(bmdb->env, NULL, 0, &txn));
  rc = mdb_del(txn, bmdb->dbi, &mkey, 0);
  if (rc == MDB_NOTFOUND) {
    rc = 0;
  }
  B(mdb_txn_commit(txn));
  if (sync) {
    B(mdb_env_sync(bmdb->env, 1));
  }
  return true;
}

static bool db_read_seq(BMCTX *ctx, bool reverse) {
  int rc = 0;
  MDB_txn *txn;
  MDB_cursor *cur;
  MDB_val mkey, mval;
  BM_LMDB *bmdb = ctx->db;
  B(mdb_txn_begin(bmdb->env, NULL, MDB_RDONLY, &txn));
  B(mdb_cursor_open(txn, bmdb->dbi, &cur));
  B(mdb_cursor_get(cur, &mkey, &mval, reverse ? MDB_LAST : MDB_FIRST));
  for (int i = 0; i < bm.param_num - 1 && !rc; ++i) {
    rc = mdb_cursor_get(cur, &mkey, &mval, reverse ? MDB_PREV : MDB_NEXT);
  }
  if (rc == MDB_NOTFOUND) {
    rc = 0;
  }
  mdb_cursor_close(cur);
  mdb_txn_abort(txn);
  B(rc);
  return true;
}

static bool db_cursor_to_key(BMCTX *ctx, const IWKV_val *key, IWKV_val *val, bool *found) {
  int rc = 0;
  MDB_txn *txn;
  MDB_cursor *cur;
  MDB_val mkey, mval;
  BM_LMDB *bmdb = ctx->db;
  mkey.mv_data = key->data;
  mkey.mv_size = key->size;
  B(mdb_txn_begin(bmdb->env, NULL, MDB_RDONLY, &txn));
  B(mdb_cursor_open(txn, bmdb->dbi, &cur));
  rc = mdb_cursor_get(cur, &mkey, &mval, MDB_SET);
  if (rc == MDB_NOTFOUND) {
    *found = false;
    val->data = 0;
    val->size = 0;
    rc = 0;
  } else if (!rc) {
    *found = true;
    val->data = malloc(mval.mv_size);
    ;
    memcpy(val->data, mval.mv_data, mval.mv_size);
  }
  mdb_cursor_close(cur);
  mdb_txn_abort(txn);
  B(rc);
  return true;
}

int main(int argc, char **argv) {
  if (argc < 1) {
    return -1;
  }
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
