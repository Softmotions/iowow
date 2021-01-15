#include "bmbase.c"
#include <db.h>

#define DEFAULT_DB "bdb_bench.db"


typedef struct BM_BDB {
  DB *dbp;
} BM_BDB;

static void env_setup() {
  fprintf(stderr, " engine: %s\n", DB_VERSION_STRING);
}

static uint64_t db_size_bytes(BMCTX *ctx) {
  const char *path = bm.param_db ? bm.param_db : DEFAULT_DB;
  IWP_FILE_STAT fst;
  iwrc rc = iwp_fstat(path, &fst);
  if (rc) {
    iwlog_ecode_error3(rc);
    return 0;
  }
  return fst.size;
}

static void val_free(void *data) {
  free(data);
}

static void *db_open(BMCTX *ctx) {
  if (ctx->db) {
    return 0; // db is not closed properly
  }
  const char *path = bm.param_db ? bm.param_db : DEFAULT_DB;
  BM_BDB *bmdb = malloc(sizeof(*bmdb));
  int ret = db_create(&bmdb->dbp, 0, 0);
  if (ret) {
    fprintf(stderr, "db_create: %s\n", db_strerror(ret));
    free(bmdb);
    return 0;
  }
  int32_t mode = DB_CREATE;
  if (ctx->freshdb) {
    mode |= DB_TRUNCATE;
  }
  ret = bmdb->dbp->open(bmdb->dbp, 0, path, 0, DB_BTREE, mode, 0664);
  if (ret) {
    fprintf(stderr, "db_open: %s\n", db_strerror(ret));
    free(bmdb);
    return 0;
  }
  return bmdb;
}

static bool db_close(BMCTX *ctx) {
  if (!ctx->db) {
    return false;
  }
  BM_BDB *bmdb = ctx->db;
  int ret = bmdb->dbp->close(bmdb->dbp, 0);
  if (ret) {
    fprintf(stderr, "db_close: %s\n", db_strerror(ret));
    return false;
  }
  free(bmdb);
  return true;
}

static bool db_put(BMCTX *ctx, const IWKV_val *key, const IWKV_val *val, bool sync) {
  BM_BDB *bmdb = ctx->db;
  DBT bkey = { .data = key->data, .size = key->size };
  DBT bval = { .data = val->data, .size = val->size };
  int ret = bmdb->dbp->put(bmdb->dbp, 0, &bkey, &bval, 0);
  if (ret) {
    fprintf(stderr, "db_put: %s\n", db_strerror(ret));
    return false;
  }
  if (sync) {
    ret = bmdb->dbp->sync(bmdb->dbp, 0);
    if (ret) {
      fprintf(stderr, "db_sync: %s\n", db_strerror(ret));
      return false;
    }
  }
  return true;
}

static bool db_get(BMCTX *ctx, const IWKV_val *key, IWKV_val *val, bool *found) {
  BM_BDB *bmdb = ctx->db;
  DBT bkey = { .data = key->data, .size = key->size };
  DBT bval = { .flags = DB_DBT_MALLOC };
  int ret = bmdb->dbp->get(bmdb->dbp, 0, &bkey, &bval, 0);
  val->data = bval.data;
  val->size = bval.size;
  if (ret == DB_NOTFOUND) {
    *found = false;
    ret = 0;
  } else if (ret) {
    *found = false;
    fprintf(stderr, "db_get: %s\n", db_strerror(ret));
  } else {
    *found = true;
  }
  return ret == 0;
}

static bool db_del(BMCTX *ctx, const IWKV_val *key, bool sync) {
  BM_BDB *bmdb = ctx->db;
  DBT bkey = { .data = key->data, .size = key->size };
  int ret = bmdb->dbp->del(bmdb->dbp, 0, &bkey, 0);
  if (ret == DB_NOTFOUND) {
    ret = 0;
  } else if (ret) {
    fprintf(stderr, "db_del: %s\n", db_strerror(ret));
    return false;
  }
  if (sync) {
    ret = bmdb->dbp->sync(bmdb->dbp, 0);
    if (ret) {
      fprintf(stderr, "db_del: %s\n", db_strerror(ret));
      return false;
    }
  }
  return true;
}

static bool db_read_seq(BMCTX *ctx, bool reverse) {
  BM_BDB *bmdb = ctx->db;
  DBC *curp;
  DBT bkey = { .flags = DB_DBT_MALLOC };
  DBT bval = { .flags = DB_DBT_MALLOC };
  int ret = bmdb->dbp->cursor(bmdb->dbp, 0, &curp, 0);
  if (ret) {
    fprintf(stderr, "db_read_seq: %s\n", db_strerror(ret));
    return false;
  }
  ret = curp->get(curp, &bkey, &bval, reverse ? DB_LAST : DB_FIRST);
  if (ret == DB_NOTFOUND) {
    ret = 0;
  }
  if (bkey.data) {
    free(bkey.data);
  }
  if (bval.data) {
    free(bval.data);
  }

  for (int i = 0; i < bm.param_num - 1 && !ret; ++i) {
    bkey.data = 0;
    bval.data = 0;
    ret = curp->get(curp, &bkey, &bval, reverse ? DB_PREV : DB_NEXT);
    if (ret == DB_NOTFOUND) {
      ret = 0;
      break;
    } else if (ret) {
      fprintf(stderr, "db_read_seq: %s\n", db_strerror(ret));
    }
    if (bkey.data) {
      free(bkey.data);
    }
    if (bval.data) {
      free(bval.data);
    }
  }

  curp->close(curp);
  return ret == 0;
}

static bool db_cursor_to_key(BMCTX *ctx, const IWKV_val *key, IWKV_val *val, bool *found) {
  BM_BDB *bmdb = ctx->db;
  DBC *curp;
  DBT bkey = { .data = key->data, .size = key->size };
  DBT bval = { .flags = DB_DBT_MALLOC };
  int ret = bmdb->dbp->cursor(bmdb->dbp, 0, &curp, 0);
  if (ret) {
    fprintf(stderr, "db_cursor_to_key: %s\n", db_strerror(ret));
    return false;
  }
  ret = curp->get(curp, &bkey, &bval, DB_SET);
  if (ret == DB_NOTFOUND) {
    *found = false;
    ret = 0;
  } else if (ret) {
    *found = false;
    fprintf(stderr, "db_cursor_to_key: %s\n", db_strerror(ret));
  } else {
    *found = true;
    val->data = bval.data;
    val->size = bval.size;
  }
  curp->close(curp);
  return ret == 0;
}

int main(int argc, char **argv) {
  if (argc < 1) {
    return -1;
  }
  g_program = argv[0];
  bm.env_setup = env_setup;
  bm.db_size_bytes = db_size_bytes;
  bm.val_free = val_free;
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
