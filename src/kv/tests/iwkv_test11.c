#include "iwkv.h"
#include "iwlog.h"
#include "iwkv_tests.h"
#include "iwkv_internal.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

// Defined in `src/kv/iwal.c` (IW_TESTS only)
iwrc iwal_test_checkpoint(struct iwkv *iwkv);
void iwal_test_set_bkp_main_copy(struct iwkv *iwkv, bool active);
void iwal_test_crash_on_rollforward(int nops);

#define NREC      8192
#define KBUFSZ    64
#define VALBUF_SZ 20000

static char kbuf[KBUFSZ];
static uint8_t vbuf[VALBUF_SZ];

int init_suite(void) {
  return iwkv_init();
}

int clean_suite(void) {
  return 0;
}

// Logical state model
static bool present[NREC];
static int version[NREC];

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

static iwrc put_ver(struct iwdb *db, int i, int ver) {
  key_of(i);
  struct iwkv_val key = { .data = kbuf, .size = strlen(kbuf) };
  size_t len = val_len(i, ver);
  if (len > VALBUF_SZ) {
    return IW_ERROR_INVALID_ARGS;
  }
  val_fill(vbuf, len, i, ver);
  struct iwkv_val val = { .data = vbuf, .size = len };
  return iwkv_put(db, &key, &val, 0);
}

static iwrc put_custom(struct iwdb *db, int i, size_t len, int seed) {
  key_of(i);
  struct iwkv_val key = { .data = kbuf, .size = strlen(kbuf) };
  if (len > VALBUF_SZ) {
    return IW_ERROR_INVALID_ARGS;
  }
  val_fill(vbuf, len, i, seed);
  struct iwkv_val val = { .data = vbuf, .size = len };
  return iwkv_put(db, &key, &val, 0);
}

static void iwkv_test11_1(void) {
  const char *path = "iwkv_test11_1.db";
  const char *walpath = "iwkv_test11_1.db-wal";
  struct iwkv *iwkv;
  struct iwdb *db;
  struct iwkv_opts opts = {
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
    struct iwkv_val key = { .data = kbuf, .size = strlen(kbuf) };
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
    struct iwkv_val key = { .data = kbuf, .size = strlen(kbuf) };
    struct iwkv_val val = { 0 };
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
  struct iwkv *iwkv;
  struct iwdb *db;
  struct iwkv_opts opts = {
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
    struct iwkv_val key = { .data = kbuf, .size = strlen(kbuf) };
    struct iwkv_val val = { 0 };
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
    struct iwkv_val key = { .data = kbuf, .size = strlen(kbuf) };
    struct iwkv_val val = { 0 };
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
  struct iwkv *iwkv;
  struct iwdb *db;
  struct iwkv_opts opts = {
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
    struct iwkv_val key = { .data = kbuf, .size = strlen(kbuf) };
    struct iwkv_val val = { 0 };
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
    struct iwkv_val key = { .data = kbuf, .size = strlen(kbuf) };
    struct iwkv_val val = { 0 };
    rc = iwkv_get(db, &key, &val);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_EQUAL_FATAL(val.size, 100 + (size_t) i);
    iwkv_val_dispose(&val);
  }
  for (int i = 100; i < 200; ++i) {
    key_of(i);
    struct iwkv_val key = { .data = kbuf, .size = strlen(kbuf) };
    struct iwkv_val val = { 0 };
    rc = iwkv_get(db, &key, &val);
    CU_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_NOTFOUND);
  }
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
}

static void iwkv_test11_4(void) {
  const char *path = "iwkv_test11_4.db";
  const char *walpath = "iwkv_test11_4.db-wal";
  struct iwkv *iwkv;
  struct iwdb *db;
  struct iwkv_opts opts = {
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
  struct walhdr whdr = { .magic = IWAL_HDR_MAGIC, .flags = 0 };
  struct wbsep wbsep = { .id = WOP_SEP, .crc = 0, .len = 0 };
  struct wbset wbset = { .id = WOP_SET, .val = 0, .off = 0, .len = (off_t) -1 };
  struct wbsavepoint wbsp = { .id = WOP_SAVEPOINT, .ts = 1 };
  CU_ASSERT_EQUAL(fwrite(&whdr, 1, sizeof(whdr), f), sizeof(whdr));
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

// Corrupts the CRC field of the first WAL segment separator (WBSEP).
static void corrupt_first_wbsep_crc(const char *walpath) {
  FILE *f = fopen(walpath, "r+b");
  CU_ASSERT_PTR_NOT_NULL_FATAL(f);
  struct walhdr whdr;
  CU_ASSERT_EQUAL_FATAL(fread(&whdr, 1, sizeof(whdr), f), sizeof(whdr));
  CU_ASSERT_EQUAL_FATAL(whdr.magic, IWAL_HDR_MAGIC);
  CU_ASSERT_TRUE_FATAL((whdr.flags & IWAL_HDR_F_CRC) != 0);
  struct wbsep wb;
  CU_ASSERT_EQUAL_FATAL(fread(&wb, 1, sizeof(wb), f), sizeof(wb));
  CU_ASSERT_EQUAL_FATAL(wb.id, WOP_SEP);
  CU_ASSERT_TRUE_FATAL(wb.crc != 0);
  long off = ftell(f) - (long) sizeof(wb) + (long) offsetof(struct wbsep, crc);
  wb.crc ^= 0x01010101U;
  CU_ASSERT_EQUAL_FATAL(fseek(f, off, SEEK_SET), 0);
  CU_ASSERT_EQUAL_FATAL(fwrite(&wb.crc, 1, sizeof(wb.crc), f), sizeof(wb.crc));
  fclose(f);
}

// CRC verification is only performed when recovering from a failure or an
// online backup. A live checkpoint (and the main file resize rollforward) must
// not verify persisted checksums, while recovery may be told to skip them.
static void iwkv_test11_8(void) {
  const char *path = "iwkv_test11_8.db";
  const char *walpath = "iwkv_test11_8.db-wal";
  struct iwkv_opts opts = {
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
  struct iwkv *iwkv = 0;
  struct iwdb *db = 0;
  struct stat st;
  iwrc rc;

  // (a) A live checkpoint must not verify WAL checksums.
  unlink(path);
  unlink(walpath);
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  for (int i = 0; i < 64; ++i) {
    rc = put_custom(db, i, 64, 1);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
  rc = iwkv_sync(iwkv, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  corrupt_first_wbsep_crc(walpath);
  rc = iwal_test_checkpoint(iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  for (int i = 0; i < 64; ++i) {
    key_of(i);
    struct iwkv_val key = { .data = kbuf, .size = strlen(kbuf) };
    struct iwkv_val val = { 0 };
    rc = iwkv_get(db, &key, &val);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_EQUAL_FATAL(val.size, 64);
    iwkv_val_dispose(&val);
  }
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL_FATAL(stat(walpath, &st), 0);
  CU_ASSERT_EQUAL(st.st_size, 0); // Truncated -> no header, no recovery.

  // (b) skip_crc_check_on_recovery allows recovery of a CRC-corrupted WAL.
  opts.oflags = IWKV_TRUNC | IWKV_NO_TRIM_ON_CLOSE;
  opts.wal.skip_crc_check_on_recovery = true;
  unlink(path);
  unlink(walpath);
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  for (int i = 0; i < 64; ++i) {
    rc = put_custom(db, i, 64, 2);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
  rc = iwkv_sync(iwkv, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  iwkvd_trigger_xor(IWKVD_WAL_NO_CHECKPOINT_ON_CLOSE);
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  iwkvd_trigger_xor(IWKVD_WAL_NO_CHECKPOINT_ON_CLOSE);
  corrupt_first_wbsep_crc(walpath);
  opts.oflags = IWKV_NO_TRIM_ON_CLOSE;
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  for (int i = 0; i < 64; ++i) {
    key_of(i);
    struct iwkv_val key = { .data = kbuf, .size = strlen(kbuf) };
    struct iwkv_val val = { 0 };
    rc = iwkv_get(db, &key, &val);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    iwkv_val_dispose(&val);
  }
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // (c) With verification enabled the same corruption must abort recovery.
  opts.oflags = IWKV_TRUNC | IWKV_NO_TRIM_ON_CLOSE;
  opts.wal.skip_crc_check_on_recovery = false;
  unlink(path);
  unlink(walpath);
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  for (int i = 0; i < 64; ++i) {
    rc = put_custom(db, i, 64, 3);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
  rc = iwkv_sync(iwkv, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  iwkvd_trigger_xor(IWKVD_WAL_NO_CHECKPOINT_ON_CLOSE);
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  iwkvd_trigger_xor(IWKVD_WAL_NO_CHECKPOINT_ON_CLOSE);
  corrupt_first_wbsep_crc(walpath);
  opts.oflags = IWKV_NO_TRIM_ON_CLOSE;
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL(rc, IWKV_ERROR_CORRUPTED_WAL_FILE);
  if (!rc) {
    iwkv_close(&iwkv);
  }

  unlink(path);
  unlink(walpath);
}

// A non-empty WAL without the new header (written by an older build) must be
// rejected as corrupted instead of being silently misparsed.
static void iwkv_test11_9(void) {
  const char *path = "iwkv_test11_9.db";
  const char *walpath = "iwkv_test11_9.db-wal";
  struct iwkv_opts opts = {
    .path = path,
    .oflags = IWKV_TRUNC,
    .wal = {
      .enabled = true,
      .savepoint_timeout_sec = UINT32_MAX,
      .checkpoint_timeout_sec = UINT32_MAX
    }
  };
  unlink(path);
  unlink(walpath);
  struct iwkv *iwkv = 0;
  struct iwdb *db = 0;
  iwrc rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = put_custom(db, 0, 32, 1);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  FILE *f = fopen(walpath, "wb");
  CU_ASSERT_PTR_NOT_NULL_FATAL(f);
  struct wbsep wbsep = { .id = WOP_SEP, .crc = 0, .len = 0 };
  struct wbsavepoint wbsp = { .id = WOP_SAVEPOINT, .ts = 1 };
  CU_ASSERT_EQUAL(fwrite(&wbsep, 1, sizeof(wbsep), f), sizeof(wbsep));
  CU_ASSERT_EQUAL(fwrite(&wbsp, 1, sizeof(wbsp), f), sizeof(wbsp));
  fclose(f);

  opts.oflags &= ~IWKV_TRUNC;
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL(rc, IWKV_ERROR_CORRUPTED_WAL_FILE);
  if (!rc) {
    iwkv_close(&iwkv);
  }
  unlink(path);
  unlink(walpath);
}

typedef struct T115 {
  struct iwdb *db;
  volatile int done;
  iwrc rc;
} T115;

static void* t115_writer(void *ctx_) {
  struct T115 *ctx = ctx_;
  const size_t sz = 4UL * 1024 * 1024;
  uint8_t *buf = malloc(sz);
  if (!buf) {
    ctx->rc = IW_ERROR_ALLOC;
    ctx->done = 1;
    return 0;
  }
  memset(buf, 0x3c, sz);
  struct iwkv_val key = { .data = (void*) "growkey", .size = 7 };
  struct iwkv_val val = { .data = buf, .size = sz };
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
  struct iwkv *iwkv;
  struct iwdb *db;
  struct iwkv_opts opts = {
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
  struct T115 ctx = { .db = db, .done = 0, .rc = 0 };
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

  struct iwkv_val key = { .data = (void*) "growkey", .size = 7 };
  struct iwkv_val val = { 0 };
  rc = iwkv_get(db, &key, &val);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  CU_ASSERT_EQUAL_FATAL(val.size, 4UL * 1024 * 1024);
  iwkv_val_dispose(&val);

  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  unlink(path);
  unlink(walpath);
}

// Regression test for the mid-operation growth/shrink checkpoint.
//
// A resize is requested from inside an in-progress operation. Committing the
// whole WAL prefix at that point (the old behaviour) produced a main file that
// was a partially applied operation and could not be repaired by recovery,
// because recovery is redo-only and stops at the last savepoint.
//
// `_resize_rollforward_exl()` now commits only the prefix up to the last
// savepoint and re-applies the uncommitted tail into the private mapping, so the
// main file only ever advances to a savepoint. This test commits the updates
// with `iwkv_sync()` (a savepoint), then crashes the process inside the
// rollforward triggered by the following growth write, reopens the database and
// verifies that the committed updates survived while the in-progress operation
// was discarded without corrupting the database.
static void iwkv_test11_6_impl(int crash_after) {
  const char *path = "iwkv_test11_6.db";
  const char *walpath = "iwkv_test11_6.db-wal";

  unlink(path);
  unlink(walpath);

  pid_t pid = fork();
  CU_ASSERT_NOT_EQUAL_FATAL(pid, -1);
  if (pid == 0) {
    struct iwkv_opts opts = {
      .path = path,
      .oflags = IWKV_TRUNC | IWKV_NO_TRIM_ON_CLOSE,
      .wal = {
        .enabled = true,
        .wal_buffer_sz = 8192,
        .checkpoint_buffer_sz = 1ULL << 40,
          .savepoint_timeout_sec = UINT32_MAX,
          .checkpoint_timeout_sec = UINT32_MAX
      }
    };
    struct iwkv *iwkv = 0;
    struct iwdb *db = 0;
    iwrc rc = iwkv_open(&opts, &iwkv);
    if (rc) {
      _exit(10);
    }
    rc = iwkv_db(iwkv, 1, 0, &db);
    if (rc) {
      _exit(11);
    }

    uint8_t v1[64];
    for (int i = 0; i < 16; ++i) {
      for (size_t j = 0; j < sizeof(v1); ++j) {
        v1[j] = (uint8_t) (i + (int) j);
      }
      char kb[32];
      snprintf(kb, sizeof(kb), "%08d", i);
      struct iwkv_val k = { .data = kb, .size = strlen(kb) };
      struct iwkv_val v = { .data = v1, .size = sizeof(v1) };
      rc = iwkv_put(db, &k, &v, 0);
      if (rc) {
        _exit(12);
      }
    }
    // Move the base state into the main file and truncate the WAL. Everything
    // after this point lives only in the private mmap and in the WAL.
    rc = iwal_test_checkpoint(iwkv);
    if (rc) {
      _exit(13);
    }

    uint8_t v2[400];
    for (int i = 0; i < 16; ++i) {
      for (size_t j = 0; j < sizeof(v2); ++j) {
        v2[j] = (uint8_t) (i * 7 + (int) j * 3 + 0xA5);
      }
      char kb[32];
      snprintf(kb, sizeof(kb), "%08d", i);
      struct iwkv_val k = { .data = kb, .size = strlen(kb) };
      struct iwkv_val v = { .data = v2, .size = sizeof(v2) };
      rc = iwkv_put(db, &k, &v, 0);
      if (rc) {
        _exit(14);
      }
    }
    // Make the updates durable with a savepoint. The main file is still at the
    // base checkpoint; the WAL now holds [updates][savepoint].
    rc = iwkv_sync(iwkv, 0);
    if (rc) {
      _exit(16);
    }

    iwal_test_crash_on_rollforward(crash_after);

    static uint8_t big[4 * 1024 * 1024];
    memset(big, 0x5a, sizeof(big));
    struct iwkv_val k = { .data = (void*) "bigkey", .size = 6 };
    struct iwkv_val v = { .data = big, .size = sizeof(big) };
    rc = iwkv_put(db, &k, &v, 0);
    (void) rc;
    _exit(15); // The crash hook did not fire: no growth checkpoint happened.
  }

  int status = 0;
  waitpid(pid, &status, 0);
  CU_ASSERT_TRUE_FATAL(WIFEXITED(status));
  CU_ASSERT_EQUAL_FATAL(WEXITSTATUS(status), 99);

  struct iwkv_opts opts = {
    .path = path,
    .oflags = IWKV_NO_TRIM_ON_CLOSE,
    .wal = {
      .enabled = true,
      .checkpoint_buffer_sz = 1ULL << 40,
        .savepoint_timeout_sec = UINT32_MAX,
        .checkpoint_timeout_sec = UINT32_MAX
    }
  };
  struct iwkv *iwkv = 0;
  struct iwdb *db = 0;
  iwrc rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // All records that the interrupted checkpoint had fsynced to the WAL must be
  // recovered. With a savepoint written before the rollforward they are replayed
  // onto the partially written main file and the update is visible.
  uint8_t v2[400];
  for (int i = 0; i < 16; ++i) {
    for (size_t j = 0; j < sizeof(v2); ++j) {
      v2[j] = (uint8_t) (i * 7 + (int) j * 3 + 0xA5);
    }
    char kb[32];
    snprintf(kb, sizeof(kb), "%08d", i);
    struct iwkv_val k = { .data = kb, .size = strlen(kb) };
    struct iwkv_val v = { 0 };
    rc = iwkv_get(db, &k, &v);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_EQUAL_FATAL(v.size, sizeof(v2));
    CU_ASSERT_NSTRING_EQUAL(v.data, v2, sizeof(v2));
    iwkv_val_dispose(&v);
  }

  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  unlink(path);
  unlink(walpath);
}

static void iwkv_test11_6(void) {
  for (int n = 1; n <= 4; ++n) {
    iwkv_test11_6_impl(n);
  }
}

// Regression test for CRC32 protection of compact WBPATCH records.
//
// When `crc` is enabled, every WBPATCH payload must carry a
// CRC32 checksum and recovery must reject a record whose checksum does not
// match. The segment (WBSEP) checksums are zeroed here so that only the
// per-record WBPATCH checksum can detect the corrupted payload.
static void iwkv_test11_7(void) {
  const char *path = "iwkv_test11_7.db";
  const char *walpath = "iwkv_test11_7.db-wal";
  struct iwkv *iwkv;
  struct iwdb *db;
  struct iwkv_opts opts = {
    .path = path,
    .oflags = IWKV_TRUNC | IWKV_NO_TRIM_ON_CLOSE,
    .wal = {
      .enabled = true,
      .no_crc = false,
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

  // Repeated in-place skiplist block updates produce WBPATCH records on flush.
  for (int i = 0; i < 512; ++i) {
    rc = put_custom(db, i, 32 + (size_t) (i % 64), 1);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
  rc = iwkv_sync(iwkv, 0); // Flush pending writes and write a savepoint.
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // Simulate a crash: keep the WAL, do not checkpoint on close.
  iwkvd_trigger_xor(IWKVD_WAL_NO_CHECKPOINT_ON_CLOSE);
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  iwkvd_trigger_xor(IWKVD_WAL_NO_CHECKPOINT_ON_CLOSE);

  // Parse the WAL: disable segment checksums and locate a WBPATCH record.
  FILE *f = fopen(walpath, "r+b");
  CU_ASSERT_PTR_NOT_NULL_FATAL(f);
  CU_ASSERT_EQUAL_FATAL(fseek(f, 0, SEEK_END), 0);
  long fsz = ftell(f);
  CU_ASSERT_TRUE_FATAL(fsz > 0);
  uint8_t *wal = malloc((size_t) fsz);
  CU_ASSERT_PTR_NOT_NULL_FATAL(wal);
  CU_ASSERT_EQUAL_FATAL(fseek(f, 0, SEEK_SET), 0);
  CU_ASSERT_EQUAL_FATAL(fread(wal, 1, (size_t) fsz, f), (size_t) fsz);

  bool found = false;
  off_t patch_pos = 0;
  struct wbpatch patch = { 0 };
  // Validate and skip the WAL file header.
  CU_ASSERT_TRUE_FATAL((off_t) fsz >= (off_t) sizeof(struct walhdr));
  {
    struct walhdr whdr;
    memcpy(&whdr, wal, sizeof(whdr));
    CU_ASSERT_EQUAL_FATAL(whdr.magic, IWAL_HDR_MAGIC);
    CU_ASSERT_TRUE_FATAL((whdr.flags & IWAL_HDR_F_CRC) != 0);
  }
  for (off_t off = (off_t) sizeof(struct walhdr); off < (off_t) fsz; ) {
    uint8_t id = wal[off];
    if (id == WOP_SEP) {
      struct wbsep wb;
      if (off + (off_t) sizeof(wb) > (off_t) fsz) {
        break;
      }
      memcpy(&wb, wal + off, sizeof(wb));
      wb.crc = 0; // Isolate the per-record checksum.
      memcpy(wal + off, &wb, sizeof(wb));
      off += sizeof(wb);
    } else if (id == WOP_SET) {
      off += sizeof(struct wbset);
    } else if (id == WOP_COPY) {
      off += sizeof(struct wbcopy);
    } else if (id == WOP_WRITE) {
      struct wbwrite wb;
      if (off + (off_t) sizeof(wb) > (off_t) fsz) {
        break;
      }
      memcpy(&wb, wal + off, sizeof(wb));
      off += sizeof(wb) + wb.len;
    } else if (id == WOP_PATCH) {
      struct wbpatch wb;
      if (off + (off_t) sizeof(wb) > (off_t) fsz) {
        break;
      }
      memcpy(&wb, wal + off, sizeof(wb));
      if (wb.len && wb.crc && (off + (off_t) sizeof(wb) + wb.len <= (off_t) fsz)) {
        found = true;
        patch = wb;
        patch_pos = off;
        break;
      }
      off += sizeof(wb) + wb.len;
    } else if (id == WOP_RESIZE) {
      off += sizeof(struct wbresize);
    } else if (id == WOP_SAVEPOINT) {
      off += sizeof(struct wbsavepoint);
    } else if (id == WOP_RESET) {
      off += sizeof(struct wbreset);
    } else {
      break;
    }
  }
  CU_ASSERT_TRUE_FATAL(found); // WBPATCH must carry a CRC32 checksum.

  // Corrupt the last payload byte of the patch record.
  wal[patch_pos + (off_t) sizeof(struct wbpatch) + patch.len - 1] ^= 0xFF;
  CU_ASSERT_EQUAL_FATAL(fseek(f, 0, SEEK_SET), 0);
  CU_ASSERT_EQUAL_FATAL(fwrite(wal, 1, (size_t) fsz, f), (size_t) fsz);
  fclose(f);
  free(wal);

  // Recovery must reject the record with the mismatching checksum.
  opts.oflags &= ~IWKV_TRUNC;
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL(rc, IWKV_ERROR_CORRUPTED_WAL_FILE);
  if (!rc) {
    iwkv_close(&iwkv);
  }

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
     || (NULL == CU_add_test(pSuite, "iwkv_test11_5", iwkv_test11_5))
     || (NULL == CU_add_test(pSuite, "iwkv_test11_6", iwkv_test11_6))
     || (NULL == CU_add_test(pSuite, "iwkv_test11_7", iwkv_test11_7))
     || (NULL == CU_add_test(pSuite, "iwkv_test11_8", iwkv_test11_8))
     || (NULL == CU_add_test(pSuite, "iwkv_test11_9", iwkv_test11_9))) {
    CU_cleanup_registry();
    return CU_get_error();
  }
  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  int ret = CU_get_error() || CU_get_number_of_failures();
  CU_cleanup_registry();
  return ret;
}
