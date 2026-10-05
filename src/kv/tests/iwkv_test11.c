#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwkv_tests.h"
#include "iwkv_internal.h"

#include <sys/stat.h>

// Defined in `src/kv/iwal.c` (IW_TESTS only)
iwrc iwal_test_checkpoint(IWKV iwkv);
void iwal_test_set_bkp_main_copy(IWKV iwkv, bool active);

#define NREC        8192
#define KBUFSZ      64
#define VALBUF_SZ   20000

static char    kbuf[KBUFSZ];
static uint8_t vbuf[VALBUF_SZ];

int init_suite(void) {
  return iwkv_init();
}

int clean_suite(void) {
  return 0;
}

// Logical state model
static bool present[NREC];
static int  version[NREC];

static size_t val_len(int i, int ver) {
  if (ver == 1) {
    return 1 + (size_t) (((uint32_t) i * 2654435761u) % 3000);
  }
  return 1 + (size_t) (((uint32_t) i * 40503u) % 9000);
}

static void val_fill(uint8_t *buf, size_t len, int i, int ver) {
  for (size_t j = 0; j < len; ++j) {
    buf[j] = (uint8_t) ((uint32_t) i * 131u + (uint32_t) j * 17u + (uint32_t) ver * 97u);
  }
}

static void key_of(int i) {
  snprintf(kbuf, KBUFSZ, "%08d", i);
}

static iwrc put_ver(IWDB db, int i, int ver) {
  key_of(i);
  IWKV_val key = { .data = kbuf, .size = strlen(kbuf) };
  size_t len = val_len(i, ver);
  if (len > VALBUF_SZ) {
    return IW_ERROR_INVALID_ARGS;
  }
  val_fill(vbuf, len, i, ver);
  IWKV_val val = { .data = vbuf, .size = len };
  return iwkv_put(db, &key, &val, 0);
}

static iwrc put_custom(IWDB db, int i, size_t len, int seed) {
  key_of(i);
  IWKV_val key = { .data = kbuf, .size = strlen(kbuf) };
  if (len > VALBUF_SZ) {
    return IW_ERROR_INVALID_ARGS;
  }
  val_fill(vbuf, len, i, seed);
  IWKV_val val = { .data = vbuf, .size = len };
  return iwkv_put(db, &key, &val, 0);
}

static void iwkv_test11_1(void) {
  const char *path = "iwkv_test11_1.db";
  const char *walpath = "iwkv_test11_1.db-wal";
  IWKV iwkv;
  IWDB db;
  IWKV_OPTS opts = {
    .path = path,
    .oflags = IWKV_TRUNC | IWKV_NO_TRIM_ON_CLOSE,
    .wal = {
      .enabled = true,
      .wal_buffer_sz = 64 * 1024,
      .checkpoint_buffer_sz = 1ULL << 40,
      .savepoint_timeout_sec = UINT32_MAX,
      .checkpoint_timeout_sec = UINT32_MAX
    }
  };

  unlink(path);
  unlink(walpath);

  iwrc rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  memset(present, 0, sizeof(present));
  memset(version, 0, sizeof(version));

  // Insert most keys, including a mix of small and large values.
  for (int i = 0; i < NREC; ++i) {
    if ((i % 7) == 3) {
      continue;
    }
    rc = put_ver(db, i, 1);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    present[i] = true;
    version[i] = 1;
  }
  // Overwrite every 5th key with a larger value.
  for (int i = 0; i < NREC; i += 5) {
    if (!present[i]) {
      continue;
    }
    rc = put_ver(db, i, 2);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    version[i] = 2;
  }
  // Delete every 3rd key.
  for (int i = 0; i < NREC; i += 3) {
    if (!present[i]) {
      continue;
    }
    key_of(i);
    IWKV_val key = { .data = kbuf, .size = strlen(kbuf) };
    rc = iwkv_del(db, &key, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    present[i] = false;
  }

  // Make all changes durable as a WAL savepoint, then simulate a crash:
  // close without running the checkpoint on close.
  rc = iwkv_sync(iwkv, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  iwkvd_trigger_xor(IWKVD_WAL_NO_CHECKPOINT_ON_CLOSE);
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  iwkvd_trigger_xor(IWKVD_WAL_NO_CHECKPOINT_ON_CLOSE);

  // WAL must be non empty and has to be replayed on open.
  struct stat st;
  rc = stat(walpath, &st);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_TRUE(st.st_size > 0);

  opts.oflags &= ~IWKV_TRUNC;
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // WAL was applied and truncated during recovery.
  rc = stat(walpath, &st);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(st.st_size, 0);

  rc = iwkv_db(iwkv, 1, 0, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  for (int i = 0; i < NREC; ++i) {
    key_of(i);
    IWKV_val key = { .data = kbuf, .size = strlen(kbuf) };
    IWKV_val val = { 0 };
    rc = iwkv_get(db, &key, &val);
    if (present[i]) {
      CU_ASSERT_EQUAL_FATAL(rc, 0);
      size_t len = val_len(i, version[i]);
      CU_ASSERT_EQUAL_FATAL(val.size, len);
      val_fill(vbuf, len, i, version[i]);
      CU_ASSERT_NSTRING_EQUAL(val.data, vbuf, len);
      iwkv_val_dispose(&val);
    } else {
      CU_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_NOTFOUND);
    }
  }

  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
}

static void iwkv_test11_2(void) {
  const char *path = "iwkv_test11_2.db";
  const char *walpath = "iwkv_test11_2.db-wal";
  IWKV iwkv;
  IWDB db;
  IWKV_OPTS opts = {
    .path = path,
    .oflags = IWKV_TRUNC | IWKV_NO_TRIM_ON_CLOSE,
    .wal = {
      .enabled = true,
      .checkpoint_buffer_sz = 1ULL << 40,
      .savepoint_timeout_sec = UINT32_MAX,
      .checkpoint_timeout_sec = UINT32_MAX
    }
  };

  unlink(path);
  unlink(walpath);

  iwrc rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  for (int i = 0; i < 1024; ++i) {
    if (i == 0) {
      rc = put_custom(db, i, 2000, 1);
    } else {
      rc = put_ver(db, i, 1);
    }
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }

  // Apply WAL to the main database file and truncate the WAL. This is
  // also needed to bring the file to a stable size so that the following
  // in-place update does not trigger a file-growth checkpoint.
  rc = iwal_test_checkpoint(iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  struct stat st;
  rc = stat(walpath, &st);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(st.st_size, 0);

  // In-place shrink of an existing value must be recorded in WAL.
  rc = put_custom(db, 0, 10, 2);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  // WAL records are buffered in memory, flush them with a savepoint.
  rc = iwkv_sync(iwkv, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = stat(walpath, &st);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_TRUE(st.st_size > 0);

  // Apply WAL to the main database file and truncate the WAL.
  rc = iwal_test_checkpoint(iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = stat(walpath, &st);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(st.st_size, 0);

  // Data must survive the WAL truncation (it is in the main file now).
  for (int i = 0; i < 1024; ++i) {
    key_of(i);
    IWKV_val key = { .data = kbuf, .size = strlen(kbuf) };
    IWKV_val val = { 0 };
    rc = iwkv_get(db, &key, &val);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    if (i == 0) {
      CU_ASSERT_EQUAL_FATAL(val.size, 10);
      val_fill(vbuf, 10, 0, 2);
      CU_ASSERT_NSTRING_EQUAL(val.data, vbuf, 10);
    } else {
      size_t len = val_len(i, 1);
      CU_ASSERT_EQUAL_FATAL(val.size, len);
    }
    iwkv_val_dispose(&val);
  }

  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // Reopen without WAL recovery help: data must be in the main database file.
  opts.oflags &= ~IWKV_TRUNC;
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  for (int i = 0; i < 1024; ++i) {
    key_of(i);
    IWKV_val key = { .data = kbuf, .size = strlen(kbuf) };
    IWKV_val val = { 0 };
    rc = iwkv_get(db, &key, &val);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    iwkv_val_dispose(&val);
  }
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
}

static void iwkv_test11_3(void) {
  const char *path = "iwkv_test11_3.db";
  const char *walpath = "iwkv_test11_3.db-wal";
  const char *bkpath = "iwkv_test11_3_bkp.db";
  const char *bkwalpath = "iwkv_test11_3_bkp.db-wal";
  IWKV iwkv;
  IWDB db;
  IWKV_OPTS opts = {
    .path = path,
    .oflags = IWKV_TRUNC | IWKV_NO_TRIM_ON_CLOSE,
    .wal = {
      .enabled = true,
      .checkpoint_buffer_sz = 1ULL << 40,
      .savepoint_timeout_sec = UINT32_MAX,
      .checkpoint_timeout_sec = UINT32_MAX
    }
  };

  unlink(path);
  unlink(walpath);
  unlink(bkpath);
  unlink(bkwalpath);

  iwrc rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  for (int i = 0; i < 100; ++i) {
    rc = put_custom(db, i, 100 + (size_t) i, 1);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }

  // Online backup appends a WOP_RESET mark to the WAL and establishes
  // rollforward_offset. A following open must recover a consistent state
  // from the main file and WAL.
  uint64_t ts = 0;
  rc = iwkv_online_backup(iwkv, &ts, bkpath);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  for (int i = 100; i < 200; ++i) {
    rc = put_custom(db, i, 100 + (size_t) i, 1);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
  rc = iwkv_sync(iwkv, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // Simulate a crash: no checkpoint on close.
  iwkvd_trigger_xor(IWKVD_WAL_NO_CHECKPOINT_ON_CLOSE);
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  iwkvd_trigger_xor(IWKVD_WAL_NO_CHECKPOINT_ON_CLOSE);

  struct stat st;
  rc = stat(walpath, &st);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_TRUE(st.st_size > 0);

  // Recover main database from WAL.
  opts.oflags &= ~IWKV_TRUNC;
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = stat(walpath, &st);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL(st.st_size, 0);

  rc = iwkv_db(iwkv, 1, 0, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  for (int i = 0; i < 200; ++i) {
    key_of(i);
    IWKV_val key = { .data = kbuf, .size = strlen(kbuf) };
    IWKV_val val = { 0 };
    rc = iwkv_get(db, &key, &val);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    size_t len = 100 + (size_t) i;
    CU_ASSERT_EQUAL_FATAL(val.size, len);
    val_fill(vbuf, len, i, 1);
    CU_ASSERT_NSTRING_EQUAL(val.data, vbuf, len);
    iwkv_val_dispose(&val);
  }
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // The backup must contain the state at backup time.
  opts.path = bkpath;
  opts.oflags &= ~IWKV_TRUNC;
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  for (int i = 0; i < 100; ++i) {
    key_of(i);
    IWKV_val key = { .data = kbuf, .size = strlen(kbuf) };
    IWKV_val val = { 0 };
    rc = iwkv_get(db, &key, &val);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_EQUAL_FATAL(val.size, 100 + (size_t) i);
    iwkv_val_dispose(&val);
  }
  for (int i = 100; i < 200; ++i) {
    key_of(i);
    IWKV_val key = { .data = kbuf, .size = strlen(kbuf) };
    IWKV_val val = { 0 };
    rc = iwkv_get(db, &key, &val);
    CU_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_NOTFOUND);
  }
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
}

static void iwkv_test11_4(void) {
  const char *path = "iwkv_test11_4.db";
  const char *walpath = "iwkv_test11_4.db-wal";
  IWKV iwkv;
  IWDB db;
  IWKV_OPTS opts = {
    .path = path,
    .oflags = IWKV_TRUNC,
    .wal = {
      .enabled = true,
      .checkpoint_buffer_sz = 1ULL << 40,
      .savepoint_timeout_sec = UINT32_MAX,
      .checkpoint_timeout_sec = UINT32_MAX
    }
  };

  unlink(path);
  unlink(walpath);

  // Create a valid database file.
  iwrc rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = put_custom(db, 0, 10, 1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // Replace the (truncated) WAL with a handcrafted one containing a
  // WBSET record with an out-of-bounds range, followed by a savepoint
  // which makes the recovery parser visit the malformed record.
  FILE *f = fopen(walpath, "wb");
  CU_ASSERT_PTR_NOT_NULL_FATAL(f);
  WBSEP wbsep = { .id = WOP_SEP, .crc = 0, .len = 0 };
  WBSET wbset = { .id = WOP_SET, .val = 0, .off = 0, .len = (off_t) -1 };
  WBSAVEPOINT wbsp = { .id = WOP_SAVEPOINT, .ts = 1 };
  CU_ASSERT_EQUAL(fwrite(&wbsep, 1, sizeof(wbsep), f), sizeof(wbsep));
  CU_ASSERT_EQUAL(fwrite(&wbset, 1, sizeof(wbset), f), sizeof(wbset));
  CU_ASSERT_EQUAL(fwrite(&wbsp, 1, sizeof(wbsp), f), sizeof(wbsp));
  fclose(f);

  // Opening must detect the corrupted WAL instead of writing out of bounds.
  opts.oflags &= ~IWKV_TRUNC;
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_NOT_EQUAL(rc, 0);
  CU_ASSERT_EQUAL(rc, IWKV_ERROR_CORRUPTED_WAL_FILE);

  unlink(path);
  unlink(walpath);
}

typedef struct T115 {
  IWDB         db;
  volatile int done;
  iwrc         rc;
} T115;

static void* t115_writer(void *ctx_) {
  T115 *ctx = ctx_;
  const size_t sz = 4UL * 1024 * 1024;
  uint8_t *buf = malloc(sz);
  if (!buf) {
    ctx->rc = IW_ERROR_ALLOC;
    ctx->done = 1;
    return 0;
  }
  memset(buf, 0x3c, sz);
  IWKV_val key = { .data = (void*) "growkey", .size = 7 };
  IWKV_val val = { .data = buf, .size = sz };
  ctx->rc = iwkv_put(ctx->db, &key, &val, 0);
  free(buf);
  ctx->done = 1;
  return 0;
}

// A write that needs to grow the main file while an online backup main-file
// copy is in progress must wait for the copy to finish instead of writing
// past the currently mapped region.
static void iwkv_test11_5(void) {
  const char *path = "iwkv_test11_5.db";
  const char *walpath = "iwkv_test11_5.db-wal";
  IWKV iwkv;
  IWDB db;
  IWKV_OPTS opts = {
    .path = path,
    .oflags = IWKV_TRUNC | IWKV_NO_TRIM_ON_CLOSE,
    .wal = {
      .enabled = true,
      .checkpoint_buffer_sz = 1ULL << 40,
      .savepoint_timeout_sec = UINT32_MAX,
      .checkpoint_timeout_sec = UINT32_MAX
    }
  };

  unlink(path);
  unlink(walpath);

  iwrc rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  iwal_test_set_bkp_main_copy(iwkv, true);
  T115 ctx = { .db = db, .done = 0, .rc = 0 };
  pthread_t t;
  int rci = pthread_create(&t, 0, t115_writer, &ctx);
  CU_ASSERT_EQUAL_FATAL(rci, 0);
  // Wait for the writer to reach the deferred resize wait.
  for (int i = 0; i < 2000 && !ctx.done; ++i) {
    iwp_sleep(1);
  }
  CU_ASSERT_FALSE(ctx.done);
  iwal_test_set_bkp_main_copy(iwkv, false);
  pthread_join(t, 0);
  CU_ASSERT_EQUAL_FATAL(ctx.rc, 0);

  IWKV_val key = { .data = (void*) "growkey", .size = 7 };
  IWKV_val val = { 0 };
  rc = iwkv_get(db, &key, &val);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL_FATAL(val.size, 4UL * 1024 * 1024);
  iwkv_val_dispose(&val);

  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  unlink(path);
  unlink(walpath);
}

int main(void) {
  CU_pSuite pSuite = NULL;

  if (CUE_SUCCESS != CU_initialize_registry()) {
    return CU_get_error();
  }
  pSuite = CU_add_suite("iwkv_test11", init_suite, clean_suite);
  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }
  if (  (NULL == CU_add_test(pSuite, "iwkv_test11_1", iwkv_test11_1))
     || (NULL == CU_add_test(pSuite, "iwkv_test11_2", iwkv_test11_2))
     || (NULL == CU_add_test(pSuite, "iwkv_test11_3", iwkv_test11_3))
     || (NULL == CU_add_test(pSuite, "iwkv_test11_4", iwkv_test11_4))
     || (NULL == CU_add_test(pSuite, "iwkv_test11_5", iwkv_test11_5))) {
    CU_cleanup_registry();
    return CU_get_error();
  }
  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  int ret = CU_get_error() || CU_get_number_of_failures();
  CU_cleanup_registry();
  return ret;
}
