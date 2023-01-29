#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwkv_tests.h"
#include "iwkv_internal.h"
#include "iwth.h"

iwrc iwal_test_checkpoint(IWKV iwkv);

#define KBUFSZ 1024
#define VBUFSZ 1024
static char kbuf[KBUFSZ];
static char vbuf[VBUFSZ];

int init_suite(void) {
  unlink("./iwkv_test8_1_bkp.db-wal");
  unlink("./iwkv_test8_1.db-wal");
  unlink("./iwkv_test8_2_bkp.db-wal");
  unlink("./iwkv_test8_2_check.db-wal");
  unlink("./iwkv_test8_2.db-wal");
  unlink("./iwkv_test8_1_bkp.db");
  unlink("./iwkv_test8_2_bkp.db");
  unlink("./iwkv_test8_2_check.db");
  unlink("./iwkv_test8_2.db");
  return iwkv_init();
}

int clean_suite(void) {
  return 0;
}

static void iwkv_test8_1(void) {
  IWKV iwkv;
  IWDB db;
  IWKV_val key = { 0 };
  IWKV_val val = { 0 };
  IWKV_OPTS opts = {
    .path      = "iwkv_test8_1.db",
    .oflags    = IWKV_TRUNC,
    .wal       = {
      .enabled = true
    }
  };
  uint64_t ts;

  iwrc rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  for (int i = 0; i < 1000; ++i) {
    snprintf(kbuf, KBUFSZ, "%d", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    val.data = vbuf;
    val.size = strlen(val.data);
    rc = iwkv_put(db, &key, &val, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // Now reopen
  opts.oflags &= ~IWKV_TRUNC;
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_online_backup(iwkv, &ts, "iwkv_test8_1_bkp.db");
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // Open backup
  opts.path = "iwkv_test8_1_bkp.db";
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  for (int i = 0; i < 1000; ++i) {
    int cret = 0;
    snprintf(kbuf, KBUFSZ, "%d", i);
    snprintf(vbuf, VBUFSZ, "%03dval", i);
    key.data = kbuf;
    key.size = strlen(key.data);
    int vlen = strlen(vbuf);
    rc = iwkv_get(db, &key, &val);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    IW_CMP(cret, vbuf, vlen, val.data, val.size);
    CU_ASSERT_EQUAL_FATAL(cret, 0);
    iwkv_val_dispose(&val);
  }
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
}

typedef struct T82 {
  pthread_t t;
  pthread_barrier_t barrier;
  pthread_cond_t    cond;
  pthread_mutex_t   mtx;
  IWKV iwkv;
  IWKV iwkvcheck;
} T82;

static void *t82(void *ctx_) {
  T82 *ctx = ctx_;
  IWKV_val key = { 0 };
  IWKV_val val = { 0 };

  iwrc rc = iwkv_open(&(IWKV_OPTS) {
    .path = "iwkv_test8_2_check.db",
    .oflags = IWKV_TRUNC,
  }, &ctx->iwkvcheck);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  IWDB db, dbc;
  rc = iwkv_db(ctx->iwkv, 1, 0, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  rc = iwkv_db(ctx->iwkvcheck, 1, 0, &dbc);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  int i = 0;
  for ( ; i < 500000; ++i) {
    snprintf(kbuf, KBUFSZ, "%dkey", i);
    key.data = kbuf;
    key.size = strlen(key.data);

    uint64_t ts;
    rc = iwp_current_time_ms(&ts, false);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    val.data = &ts;
    val.size = sizeof(ts);

    rc = iwkv_put(db, &key, &val, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);

    rc = iwkv_put(dbc, &key, &val, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }

  pthread_barrier_wait(&ctx->barrier);

  int c = i + 10000;
  for ( ; i < c; ++i) {

    if (i == c - 9800) { // Force checkpoint during online-backup
      rc = iwal_test_checkpoint(ctx->iwkv);
      CU_ASSERT_EQUAL_FATAL(rc, 0);
    }

    snprintf(kbuf, KBUFSZ, "%dkey", i);
    key.data = kbuf;
    key.size = strlen(key.data);

    uint64_t ts;
    rc = iwp_current_time_ms(&ts, false);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    val.data = &ts;
    val.size = sizeof(ts);

    rc = iwkv_put(db, &key, &val, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);

    rc = iwkv_put(dbc, &key, &val, 0);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
  }

  rc = iwkv_close(&ctx->iwkvcheck);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  return 0;
}

static void iwkv_test8_2(void) {
  IWKV_OPTS opts = {
    .path      = "iwkv_test8_2.db",
    .oflags    = IWKV_TRUNC,
    .wal       = {
      .enabled = true
    }
  };

  T82 ctx = { 0 };
  iwrc rc = iwkv_open(&opts, &ctx.iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  int rci = pthread_barrier_init(&ctx.barrier, 0, 2);
  CU_ASSERT_EQUAL_FATAL(rci, 0);
  rci = pthread_create(&ctx.t, 0, t82, &ctx);
  CU_ASSERT_EQUAL_FATAL(rci, 0);

  pthread_barrier_wait(&ctx.barrier);

  uint64_t bkts = 0, ts = 0;
  rc = iwkv_online_backup(ctx.iwkv, &bkts, "iwkv_test8_2_bkp.db");
  CU_ASSERT_EQUAL_FATAL(rc, 0);


  pthread_join(ctx.t, 0);
  rc = iwkv_close(&ctx.iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  size_t sp;
  int cnt1 = 0, cnt2 = 0;
  IWKV iwkv;
  IWKV_cursor cur;
  IWDB db;

  // Now restore our backup
  opts.path = "iwkv_test8_2_bkp.db";
  opts.oflags &= ~IWKV_TRUNC;
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_cursor_open(db, &cur, IWKV_CURSOR_BEFORE_FIRST, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  do {
    rc = iwkv_cursor_to(cur, IWKV_CURSOR_NEXT);
    if (!rc) {
      iwkv_cursor_copy_val(cur, &ts, sizeof(ts), &sp);
      CU_ASSERT_EQUAL_FATAL(sp, sizeof(ts));
      if (ts < bkts) {
        cnt1++;
      }
    }
  } while (!rc);
  CU_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_NOTFOUND);
  iwkv_cursor_close(&cur);
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  // Check DB
  opts.path = "iwkv_test8_2_check.db";
  rc = iwkv_open(&opts, &iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_db(iwkv, 1, 0, &db);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  rc = iwkv_cursor_open(db, &cur, IWKV_CURSOR_BEFORE_FIRST, 0);
  CU_ASSERT_EQUAL_FATAL(rc, 0);
  do {
    rc = iwkv_cursor_to(cur, IWKV_CURSOR_NEXT);
    if (!rc) {
      iwkv_cursor_copy_val(cur, &ts, sizeof(ts), &sp);
      CU_ASSERT_EQUAL_FATAL(sp, sizeof(ts));
      if (ts < bkts) {
        cnt2++;
      }
    }
  } while (!rc);
  CU_ASSERT_EQUAL_FATAL(rc, IWKV_ERROR_NOTFOUND);
  iwkv_cursor_close(&cur);
  rc = iwkv_close(&iwkv);
  CU_ASSERT_EQUAL_FATAL(rc, 0);

  fprintf(stderr, "\n%d", cnt1);
  fprintf(stderr, "\n%d\n", cnt2);

  CU_ASSERT_TRUE(cnt1 > 500000);
  CU_ASSERT_EQUAL(cnt1, cnt2);

  pthread_barrier_destroy(&ctx.barrier);
}

int main(void) {
  CU_pSuite pSuite = NULL;

  /* Initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry()) {
    return CU_get_error();
  }

  /* Add a suite to the registry */
  pSuite = CU_add_suite("iwkv_test8", init_suite, clean_suite);

  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Add the tests to the suite */
  if (  (NULL == CU_add_test(pSuite, "iwkv_test8_1", iwkv_test8_1))
     || (NULL == CU_add_test(pSuite, "iwkv_test8_2", iwkv_test8_2))) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Run all tests using the CUnit Basic interface */
  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  int ret = CU_get_error() || CU_get_number_of_failures();
  CU_cleanup_registry();
  return ret;
}
