#include "bmbase.c"
#include <leveldb/c.h>

typedef struct BM_LEVELDB {
  leveldb_t *db;
  leveldb_options_t *options;
} BM_LEVELDB;


static void env_setup() {
  printf("LevelDB %d.%d\n", leveldb_major_version(), leveldb_minor_version());
}

static void *db_open(BMCTX *ctx) {
  if (ctx->db) {
    return 0; // db is not closed properly
  }
  char *err = 0;
  const char *path;
  if (bm.param_db) {
    path = bm.param_db;
  } else {
    path = "leveldb_bench.db";
  }
  BM_LEVELDB *bmdb = malloc(sizeof(*bmdb));
  bmdb->options = leveldb_options_create();
  leveldb_options_set_create_if_missing(bmdb->options, 1);
  if (ctx->freshdb) {
    leveldb_destroy_db(bmdb->options, path, &err);
    if (err) {
      leveldb_free(err);
      err = 0;
    }
  }
  bmdb->db = leveldb_open(bmdb->options, path, &err);
  if (err) {
    leveldb_options_destroy(bmdb->options);
    fprintf(stderr, "Failed to open db: %s\n", err);
    leveldb_free(err);
    free(bmdb);
    return 0;
  }
  return bmdb;
}

static bool db_close(BMCTX *ctx) {
  if (!ctx->db) {
    return false;
  }
  BM_LEVELDB *bmdb = ctx->db;
  leveldb_close(bmdb->db);
  leveldb_options_destroy(bmdb->options);
  return true;
}

static bool db_put(BMCTX *ctx, const IWKV_val *key, const IWKV_val *val, bool sync) {
  BM_LEVELDB *bmdb = ctx->db;
  return true;
}

static bool db_get(BMCTX *ctx, const IWKV_val *key, IWKV_val *val, bool *found) {
  BM_LEVELDB *bmdb = ctx->db;
  return true;
}

static bool db_del(BMCTX *ctx, const IWKV_val *key, bool *found) {
  BM_LEVELDB *bmdb = ctx->db;
  return true;
}

int main(int argc, char **argv) {
  setlocale(LC_ALL, "en_US.UTF-8");
  if (argc < 1) return -1;
  g_program = argv[0];
  bm.env_setup = env_setup;
  bm.db_open = db_open;
  bm.db_close = db_close;
  bm.db_put = db_put;
  bm.db_get = db_get;
  bm.db_del = db_del;

  return 0;
}

