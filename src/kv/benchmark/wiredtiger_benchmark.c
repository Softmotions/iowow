#include "bmbase.c"
#include <dirent.h>
#include <wiredtiger.h>

#define DEFAULT_DB "wiretiger_bench.sb"

struct BMWT {
  WT_CONNECTION *conn;
  WT_SESSION    *session;
  WT_CURSOR     *cursor;
} bmwt;

typedef struct BMWT BMWT;

static bool db_close(BMCTX *ctx);

static void env_setup() {
  fprintf(stderr, " engine: %s\n", WIREDTIGER_VERSION_STRING);
}

uint64_t db_size_bytes(BMCTX *ctx) {
  char buf[PATH_MAX + 1];
  DIR *d;
  uint64_t sz = 0;
  struct dirent *dir;
  const char *path = bm.param_db ? bm.param_db : DEFAULT_DB;
  d = opendir(path);
  if (d) {
    while ((dir = readdir(d))) {
      snprintf(buf, sizeof(buf), "%s/%s", path, dir->d_name);
      IWP_FILE_STAT fst;
      iwrc rc = iwp_fstat(buf, &fst);
      if (rc) {
        iwlog_ecode_error3(rc);
        return 0;
      }
      if (fst.ftype == IWP_TYPE_FILE) {
        sz += fst.size;
      }
    }
    closedir(d);
  }
  return sz;
}

static void *db_open(BMCTX *ctx) {
  if (ctx->db || bmwt.conn) {
    return 0; // db is not closed properly
  }
  bool wal_enabled = false;
  for (int i = 0; i < bm.argc; ++i) {
    if (!strcmp(bm.argv[i], "-w")) {
      wal_enabled = true;
    }
  }
  const char *path = bm.param_db ? bm.param_db : DEFAULT_DB;
  if (ctx->freshdb) {
    iwp_removedir(path);
  }
  iwp_mkdirs(path);
  const char *common_config = "create,cache_size=1Gb,transaction_sync=(enabled=false)";
  const char *wal_config = "checkpoint_sync=false";
  if (wal_enabled) {
    wal_config = "log=(enabled,recover=on),checkpoint=(wait=300,log_size=1Gb),checkpoint_sync=true";
  }
  char config[512];
  snprintf(config, sizeof(config), "%s,%s", common_config, wal_config);

  // fprintf(stderr, "%s\n", config);

  int rc = wiredtiger_open(path, 0, config, &bmwt.conn);
  RCGO(rc, finish);

  rc = bmwt.conn->open_session(bmwt.conn, 0, 0, &bmwt.session);
  RCGO(rc, finish);

  rc = bmwt.session->create(bmwt.session, "table:test",
                            "split_pct=100,leaf_item_max=1KB,"
                            "type=lsm,internal_page_max=4KB,leaf_page_max=4KB");
  RCGO(rc, finish);

  rc = bmwt.session->open_cursor(bmwt.session, "table:test", 0, 0, &bmwt.cursor);

finish:
  if (rc) {
    fprintf(stderr, "db_open %s\n", wiredtiger_strerror(rc));
    ctx->db = &bmwt;
    db_close(ctx);
    ctx->db = 0;
    return 0;
  }
  return &bmwt;
}

static bool db_close(BMCTX *ctx) {
  if (!ctx->db) {
    return false;
  }
  bool ret = true;
  BMWT *bmwt = ctx->db;
  if (bmwt->cursor) {
    int rc = bmwt->cursor->close(bmwt->cursor);
    if (rc) {
      fprintf(stderr, "db_close cursor %s\n", wiredtiger_strerror(rc));
      ret = false;
    }
  }
  if (bmwt->session) {
    int rc = bmwt->session->close(bmwt->session, 0);
    if (rc) {
      fprintf(stderr, "db_close session %s\n", wiredtiger_strerror(rc));
      ret = false;
    }
  }
  if (bmwt->conn) {
    int rc = bmwt->conn->close(bmwt->conn, 0);
    if (rc) {
      fprintf(stderr, "db_close conn %s\n", wiredtiger_strerror(rc));
      ret = false;
    }
  }
  bmwt->conn = 0;
  bmwt->session = 0;
  bmwt->cursor = 0;
  return ret;
}

static bool db_put(BMCTX *ctx, const IWKV_val *key, const IWKV_val *val, bool sync) {
  BMWT *bmwt = ctx->db;
  WT_ITEM k, v;
  k.data = key->data;
  k.size = key->size;
  v.data = val->data;
  v.size = val->size;

  bmwt->cursor->set_key(bmwt->cursor, &k);
  bmwt->cursor->set_value(bmwt->cursor, &v);
  int rc = bmwt->cursor->insert(bmwt->cursor);
  RCGO(rc, finish);
  if (sync) {
    rc = bmwt->session->log_flush(bmwt->session, "background=off");
  }
finish:
  if (rc) {
    fprintf(stderr, "db_put %s\n", wiredtiger_strerror(rc));
  }
  return rc == 0;
}

static bool db_get(BMCTX *ctx, const IWKV_val *key, IWKV_val *val, bool *found) {
  BMWT *bmwt = ctx->db;
  WT_ITEM k, v;
  k.data = key->data;
  k.size = key->size;
  bmwt->cursor->set_key(bmwt->cursor, &k);
  int rc = bmwt->cursor->search(bmwt->cursor);
  if (rc == WT_NOTFOUND) {
    rc = 0;
    *found = false;
  } else if (!rc) {
    *found = true;
    rc = bmwt->cursor->get_value(bmwt->cursor, &v);
  }
  if (rc) {
    fprintf(stderr, "db_get %s\n", wiredtiger_strerror(rc));
  }
  return rc == 0;
}

static bool db_del(BMCTX *ctx, const IWKV_val *key, bool sync) {
  BMWT *bmwt = ctx->db;
  WT_ITEM k;
  k.data = key->data;
  k.size = key->size;
  bmwt->cursor->set_key(bmwt->cursor, &k);
  int rc = bmwt->cursor->remove(bmwt->cursor);
  if (rc == WT_NOTFOUND) {
    rc = 0;
  }
  RCGO(rc, finish);
  if (sync) {
    rc = bmwt->session->log_flush(bmwt->session, "background=off");
  }
finish:
  if (rc) {
    fprintf(stderr, "db_del %s\n", wiredtiger_strerror(rc));
  }
  return rc == 0;
}

static bool db_read_seq(BMCTX *ctx, bool reverse) {
  BMWT *bmwt = ctx->db;
  WT_ITEM v;
  int rc = bmwt->cursor->reset(bmwt->cursor);
  RCGO(rc, finish);
  for (int i = 0; i < bm.param_num && !rc; ++i) {
    if (reverse) {
      rc = bmwt->cursor->prev(bmwt->cursor);
    } else {
      rc = bmwt->cursor->next(bmwt->cursor);
    }
    if (rc == WT_NOTFOUND) {
      rc = 0;
      break;
    }
    if (!rc) {
      rc = bmwt->cursor->get_value(bmwt->cursor, &v);
    }
  }
finish:
  if (rc) {
    fprintf(stderr, "db_read_seq %s\n", wiredtiger_strerror(rc));
  }
  return rc == 0;
}

static bool db_cursor_to_key(BMCTX *ctx, const IWKV_val *key, IWKV_val *val, bool *found) {
  return db_get(ctx, key, val, found);
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
