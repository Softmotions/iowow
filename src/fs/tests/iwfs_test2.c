//
/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2024 Softmotions Ltd <info@softmotions.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *************************************************************************************************/


#include "iowow.h"
#include "log/iwlog.h"
#include "fs/iwfsmfile.h"
#include "utils/iwutils.h"
#include "platform/iwp.h"

#include "iwcfg.h"
#include <CUnit/Basic.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>

static pthread_mutex_t records_mtx;

#define UNLINK() \
  unlink("test_fsm_open_close.fsm");  \
  unlink("test_fsm_uniform_alloc.fsm"); \
  unlink("test_block_allocation1.fsm"); \
  unlink("test_block_allocation2.fsm")

int init_suite(void) {
  pthread_mutex_init(&records_mtx, 0);
  int rc = iw_init();
  UNLINK();
  return rc;
}

int clean_suite(void) {
  pthread_mutex_destroy(&records_mtx);
  UNLINK();
  return 0;
}

uint64_t iwfs_fsmdbg_number_of_free_areas(IWFS_FSM *f);
uint64_t iwfs_fsmdbg_find_next_set_bit(
  const uint64_t *addr,
  uint64_t        offset_bit,
  uint64_t        max_offset_bit,
  int            *found);
uint64_t iwfs_fsmdbg_find_prev_set_bit(
  const uint64_t *addr,
  uint64_t        offset_bit,
  uint64_t        min_offset_bit,
  int            *found);
void iwfs_fsmdbg_dump_fsm_tree(IWFS_FSM *f, const char *hdr);
iwrc iwfs_fsmdbg_state(IWFS_FSM *f, IWFS_FSMDBG_STATE *d);
iwrc iwfs_fsmdb_dump_fsm_bitmap(IWFS_FSM *f, int blimit);

void test_fsm_bitmap(void) {
#define BMSZ1 16
  uint64_t buf[BMSZ1];
  memset(buf, 0, BMSZ1 * sizeof(uint64_t));
  int found = 0;

  uint64_t val = IW_HTOILL(0x3UL); /* 0000011 */
  uint64_t res = iwfs_fsmdbg_find_next_set_bit(&val, 0, sizeof(uint64_t) * 8, &found);
  CU_ASSERT_EQUAL(found, 1);
  CU_ASSERT_EQUAL(res, 0);

  res = iwfs_fsmdbg_find_next_set_bit(&val, 1, sizeof(uint64_t) * 8, &found);
  CU_ASSERT_EQUAL(found, 1);
  CU_ASSERT_EQUAL(res, 1);

  res = iwfs_fsmdbg_find_next_set_bit(&val, 2, sizeof(uint64_t) * 8, &found);
  CU_ASSERT_EQUAL(found, 0);
  CU_ASSERT_EQUAL(res, 0);

  val = 0x3UL << 2; /* 0001100 */
  val = IW_HTOILL(val);
  res = iwfs_fsmdbg_find_next_set_bit(&val, 0, sizeof(uint64_t) * 8, &found);
  CU_ASSERT_EQUAL(found, 1);
  CU_ASSERT_EQUAL(res, 2);

  val = 0x3UL << 2; /* 0001100 */
  val = IW_HTOILL(val);
  res = iwfs_fsmdbg_find_next_set_bit(&val, 2, sizeof(uint64_t) * 8, &found);
  CU_ASSERT_EQUAL(found, 1);
  CU_ASSERT_EQUAL(res, 2);

  val = 0x3UL << 2; /* 0001100 */
  val = IW_HTOILL(val);
  res = iwfs_fsmdbg_find_next_set_bit(&val, 3, sizeof(uint64_t) * 8, &found);
  CU_ASSERT_EQUAL(found, 1);
  CU_ASSERT_EQUAL(res, 3);

  val = 0x3UL << 2; /* 0001100 */
  val = IW_HTOILL(val);
  res = iwfs_fsmdbg_find_next_set_bit(&val, 4, sizeof(uint64_t) * 8, &found);
  CU_ASSERT_EQUAL(found, 0);
  CU_ASSERT_EQUAL(res, 0);

  val = 0x3UL << 2; /* 0001100 */
  val = IW_HTOILL(val);
  res = iwfs_fsmdbg_find_prev_set_bit(&val, 2, 0, &found);
  CU_ASSERT_EQUAL(found, 0);
  CU_ASSERT_EQUAL(res, 0);

  val = 0x3UL << 2; /* 0001100 */
  val = IW_HTOILL(val);
  res = iwfs_fsmdbg_find_prev_set_bit(&val, 3, 0, &found);
  CU_ASSERT_EQUAL(found, 1);
  CU_ASSERT_EQUAL(res, 2);

  val = 0x2UL; /* 00000010 */
  val = IW_HTOILL(val);
  res = iwfs_fsmdbg_find_next_set_bit(&val, 0, sizeof(uint64_t) * 8, &found);
  CU_ASSERT_EQUAL(found, 1);
  CU_ASSERT_EQUAL(res, 1);

  val = 0x2UL; /* 00000010 */
  val = IW_HTOILL(val);
  res = iwfs_fsmdbg_find_next_set_bit(&val, 1, sizeof(uint64_t) * 8, &found);
  CU_ASSERT_EQUAL(found, 1);
  CU_ASSERT_EQUAL(res, 1);

  val = 0x4UL; /* 00000100 */
  val = IW_HTOILL(val);
  res = iwfs_fsmdbg_find_next_set_bit(&val, 0, sizeof(uint64_t) * 8, &found);
  CU_ASSERT_EQUAL(found, 1);
  CU_ASSERT_EQUAL(res, 2);

  val = 0x4UL; /* 00000100 */
  val = IW_HTOILL(val);
  res = iwfs_fsmdbg_find_next_set_bit(&val, 1, sizeof(uint64_t) * 8, &found);
  CU_ASSERT_EQUAL(found, 1);
  CU_ASSERT_EQUAL(res, 2);

  val = 0x4UL; /* 00000100 */
  val = IW_HTOILL(val);
  res = iwfs_fsmdbg_find_next_set_bit(&val, 2, sizeof(uint64_t) * 8, &found);
  CU_ASSERT_EQUAL(found, 1);
  CU_ASSERT_EQUAL(res, 2);

  val = ~0UL;
  val = IW_HTOILL(val);
  res = iwfs_fsmdbg_find_prev_set_bit(&val, 0, 0, &found);
  CU_ASSERT_EQUAL(found, 0);
  CU_ASSERT_EQUAL(res, 0);

  val = 0x1UL; /* 00000001 */
  val = IW_HTOILL(val);
  res = iwfs_fsmdbg_find_prev_set_bit(&val, 1, 0, &found);
  CU_ASSERT_EQUAL(found, 1);
  CU_ASSERT_EQUAL(res, 0);

  val = 0x2UL; /* 00000010 */
  val = IW_HTOILL(val);
  res = iwfs_fsmdbg_find_prev_set_bit(&val, 10, 0, &found);
  CU_ASSERT_EQUAL(found, 1);
  CU_ASSERT_EQUAL(res, 1);

  buf[0] = IW_HTOILL(0x1UL);
  res = iwfs_fsmdbg_find_prev_set_bit(buf, sizeof(uint64_t) * 8 + 15, 0, &found);
  CU_ASSERT_EQUAL(found, 1);
  CU_ASSERT_EQUAL(res, 0);

  buf[0] = IW_HTOILL(0x2UL);
  res = iwfs_fsmdbg_find_prev_set_bit(buf, sizeof(uint64_t) * 8 + 15, 0, &found);
  CU_ASSERT_EQUAL(found, 1);
  CU_ASSERT_EQUAL(res, 1);

  buf[0] = IW_HTOILL(0x4UL);
  res = iwfs_fsmdbg_find_prev_set_bit(buf, sizeof(uint64_t) * 8 + 15, 0, &found);
  CU_ASSERT_EQUAL(found, 1);
  CU_ASSERT_EQUAL(res, 2);

  buf[0] = IW_HTOILL(0x8UL);
  res = iwfs_fsmdbg_find_prev_set_bit(buf, sizeof(uint64_t) * 8 + 15, 0, &found);
  CU_ASSERT_EQUAL(found, 1);
  CU_ASSERT_EQUAL(res, 3);

  buf[1] = IW_HTOILL(0x2UL);
  res = iwfs_fsmdbg_find_prev_set_bit(buf, 2 * sizeof(uint64_t) * 8 + 17, 0, &found);
  CU_ASSERT_EQUAL(found, 1);
  CU_ASSERT_EQUAL(res, 64 + 1);

  /* 0[0100000000000..|00]000 */
  buf[0] = IW_HTOILL(0x4UL);
  buf[1] = IW_HTOILL(0x0UL);
  buf[2] = IW_HTOILL(0x0UL);
  res = iwfs_fsmdbg_find_prev_set_bit(buf, (sizeof(uint64_t) * 8 + 2), 0, &found);
  CU_ASSERT_EQUAL(found, 1);
  CU_ASSERT_EQUAL(res, 2);

  buf[0] = IW_HTOILL(0x4UL);
  buf[1] = IW_HTOILL(0x4UL);
  buf[2] = IW_HTOILL(0x0UL);
  res = iwfs_fsmdbg_find_prev_set_bit(buf, sizeof(uint64_t) * 8 + 5, 0, &found);
  CU_ASSERT_EQUAL(found, 1);
  CU_ASSERT_EQUAL(res, 64 + 2);
}

void test_fsm_open_close(void) {
  iwrc rc;
  IWFS_FSM_OPTS opts = {
    .exfile         = {
      .file         = { .path = "test_fsm_open_close.fsm", .lock_mode = IWP_WLOCK },
      .rspolicy     = iw_exfile_szpolicy_fibo,
      .initial_size = 0
    },
    .bpow           = 6,
    .hdrlen         = 64,
    .oflags         = IWFSM_STRICT
  };

  size_t aunit = iwp_alloc_unit();
  IWFS_FSMDBG_STATE state1, state2;
  IWFS_FSM fsm;
  rc = iwfs_fsmfile_open(&fsm, &opts);
  CU_ASSERT_FALSE_FATAL(rc);
  rc = iwfs_fsmdbg_state(&fsm, &state1);
  CU_ASSERT_FALSE(rc);
  CU_ASSERT_TRUE((aunit * 8 - state1.lfbklen) * 64 == 2 * aunit);  // allocated first 2 pages
  rc = fsm.close(&fsm);
  CU_ASSERT_FALSE_FATAL(rc);

  rc = iwfs_fsmfile_open(&fsm, &opts);
  CU_ASSERT_FALSE_FATAL(rc);
  rc = iwfs_fsmdbg_state(&fsm, &state2);
  CU_ASSERT_FALSE(rc);
  CU_ASSERT_TRUE((aunit * 8 - state2.lfbklen) * 64 == 2 * aunit);
  CU_ASSERT_EQUAL(state1.bmlen, state2.bmlen);
  CU_ASSERT_EQUAL(state1.bmoff, state2.bmoff);
  CU_ASSERT_EQUAL(state1.lfbklen, state2.lfbklen);
  CU_ASSERT_EQUAL(state1.lfbkoff, state2.lfbkoff);
  CU_ASSERT_EQUAL(state1.state.block_size, state2.state.block_size);
  CU_ASSERT_EQUAL(state1.state.blocks_num, state2.state.blocks_num);
  CU_ASSERT_EQUAL(state1.state.hdrlen, state2.state.hdrlen);
  CU_ASSERT_EQUAL(state1.state.oflags, state2.state.oflags);
  CU_ASSERT_EQUAL(state1.state.exfile.fsize, state2.state.exfile.fsize);
  CU_ASSERT_EQUAL(state1.state.exfile.fsize, 2 * aunit);
  rc = fsm.close(&fsm);
  CU_ASSERT_FALSE_FATAL(rc);
}

void test_fsm_uniform_alloc_impl(int mmap_all);

void test_fsm_uniform_alloc(void) {
  test_fsm_uniform_alloc_impl(0);
}

void test_fsm_uniform_alloc_mmap_all(void) {
  test_fsm_uniform_alloc_impl(1);
}

void test_fsm_uniform_alloc_impl(int mmap_all) {
  iwrc rc;
  IWFS_FSMDBG_STATE state1, state2;
  IWFS_FSM_OPTS opts = {
    .exfile        = {
      .file        = {
        .path      = "test_fsm_uniform_alloc.fsm",
        .lock_mode = IWP_WLOCK,
        .omode     = IWFS_OTRUNC
      },
      .rspolicy    = iw_exfile_szpolicy_fibo
    },
    .bpow          = 6,
    .hdrlen        = 64,
    .oflags        = IWFSM_STRICT,
    .mmap_all      = mmap_all
  };

  typedef struct {
    off_t addr;
    off_t len;
  } ASLOT;

  const int bsize = 512;
#define bcnt 4096
  ASLOT aslots[bcnt];

  IWFS_FSM fsm;
  rc = iwfs_fsmfile_open(&fsm, &opts);
  CU_ASSERT_FALSE_FATAL(rc);

  rc = iwfs_fsmdbg_state(&fsm, &state1);
  CU_ASSERT_FALSE_FATAL(rc);
  CU_ASSERT_EQUAL_FATAL(state1.state.exfile.file.ostatus, IWFS_OPEN_NEW);

  for (int i = 0; i < bcnt; ++i) {
    aslots[i].addr = 0;
    rc = fsm.allocate(&fsm, bsize, &aslots[i].addr, &aslots[i].len, 0);
    CU_ASSERT_FALSE_FATAL(rc);
  }
  rc = iwfs_fsmdbg_state(&fsm, &state1);
  CU_ASSERT_FALSE_FATAL(rc);

  if (iwp_alloc_unit() == 4096) { // todo check for system with different alloc units
    CU_ASSERT_EQUAL(state1.bmlen, 8192);
    CU_ASSERT_EQUAL(state1.bmoff, 2097152);
    CU_ASSERT_EQUAL(state1.lfbklen, 32632);
    CU_ASSERT_EQUAL(state1.lfbkoff, 32904);
    CU_ASSERT_EQUAL(state1.state.blocks_num, 65536);
    CU_ASSERT_EQUAL(state1.state.free_segments_num, 2);
    CU_ASSERT_EQUAL(state1.state.avg_alloc_size, 8);
    CU_ASSERT_EQUAL(state1.state.alloc_dispersion, 0);
  }


  rc = fsm.close(&fsm);
  CU_ASSERT_FALSE_FATAL(rc);

  return;

  opts.exfile.file.omode = IWFS_OREAD;
  rc = iwfs_fsmfile_open(&fsm, &opts);
  CU_ASSERT_FALSE_FATAL(rc);

  rc = iwfs_fsmdbg_state(&fsm, &state2);
  CU_ASSERT_FALSE_FATAL(rc);
  CU_ASSERT_EQUAL_FATAL(state2.state.exfile.file.ostatus, IWFS_OPEN_EXISTING);
  CU_ASSERT_FALSE(state2.state.exfile.file.opts.omode & IWFS_OWRITE);

  CU_ASSERT_EQUAL(state1.bmlen, state2.bmlen);
  CU_ASSERT_EQUAL(state1.bmoff, state2.bmoff);
  CU_ASSERT_EQUAL(state1.lfbklen, state2.lfbklen);
  CU_ASSERT_EQUAL(state1.lfbkoff, state2.lfbkoff);
  CU_ASSERT_EQUAL(state1.state.blocks_num, state2.state.blocks_num);
  CU_ASSERT_EQUAL(state1.state.free_segments_num, state2.state.free_segments_num);
  CU_ASSERT_EQUAL(state1.state.avg_alloc_size, state2.state.avg_alloc_size);
  CU_ASSERT_EQUAL(state1.state.alloc_dispersion, state2.state.alloc_dispersion);

  uint32_t ibuf;
  off_t ilen;
  rc = fsm.allocate(&fsm, sizeof(ibuf), (void*) &ibuf, &ilen, 0);
  CU_ASSERT_EQUAL(rc, IW_ERROR_READONLY);

  rc = fsm.close(&fsm);
  CU_ASSERT_FALSE_FATAL(rc);

  opts.exfile.file.omode = IWFS_OWRITE;
  rc = iwfs_fsmfile_open(&fsm, &opts);
  CU_ASSERT_FALSE_FATAL(rc);

  rc = iwfs_fsmdbg_state(&fsm, &state1);
  CU_ASSERT_FALSE_FATAL(rc);

  if (iwp_alloc_unit() == 4096) { // todo check for system with different alloc units
    CU_ASSERT_EQUAL(state1.bmlen, 8192);
    CU_ASSERT_EQUAL(state1.bmoff, 2097152);
    CU_ASSERT_EQUAL(state1.lfbklen, 32632);
    CU_ASSERT_EQUAL(state1.lfbkoff, 32904);
    CU_ASSERT_EQUAL(state1.state.blocks_num, 65536);
    CU_ASSERT_EQUAL(state1.state.free_segments_num, 2);
    CU_ASSERT_EQUAL(state1.state.avg_alloc_size, 8);
    CU_ASSERT_EQUAL(state1.state.alloc_dispersion, 0);
  }

  int i = 0;
  for ( ; i < bcnt; ++i) {
    rc = fsm.deallocate(&fsm, aslots[i].addr, aslots[i].len);
    if (rc) {
      iwlog_ecode_error3(rc);
    }
    CU_ASSERT_FALSE_FATAL(rc);
  }

  rc = fsm.close(&fsm);
  CU_ASSERT_FALSE_FATAL(rc);

  if (iwp_alloc_unit() == 4096) {
    IWP_FILE_STAT st;
    rc = iwp_fstat("test_fsm_uniform_alloc.fsm", &st);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_EQUAL(st.size, iwp_alloc_unit() * 3);
  }
}

typedef struct FSMREC {
  int64_t offset;
  int64_t length;
  int     locked;
  struct FSMREC *prev;
  struct FSMREC *next;
} FSMREC;

typedef struct {
  int       maxrecs;
  int       avgrecsz;
  IWFS_FSM *fsm;
  volatile int numrecs;
  FSMREC      *reclist;
  FSMREC      *head;
  int blkpow;
} FSMRECTASK;

//!!!! TODO this test is not good for multithreaded env, refactoring needed

static void* recordsthr(void *op) {
  FSMRECTASK *task = op;
  iwrc rc;
  FSMREC *rec, *tmp;
  IWFS_FSM *fsm = task->fsm;
  size_t sp;

  const int maxrsize = IW_ROUNDUP(task->avgrecsz * 3, 1 << task->blkpow);
  char *rdata = malloc(maxrsize);
  char *rdata2 = malloc(maxrsize);
  int numrec;
  int a;

  pthread_mutex_lock(&records_mtx);
  numrec = task->numrecs;
  pthread_mutex_unlock(&records_mtx);

  while (numrec < task->maxrecs) {
    rec = malloc(sizeof(*rec));
    memset(rec, 0, sizeof(*rec));
    rec->locked = 1;
    do {
      rec->length = iwu_rand_dnorm((double) task->avgrecsz, task->avgrecsz / 3.0);
    } while (rec->length <= 0 || rec->length > maxrsize);

    /* Allocate record */
    rc = fsm->allocate(fsm, rec->length, &rec->offset, &rec->length, 0);
    if (rc) {
      iwlog_ecode_error3(rc);
    }
    CU_ASSERT_FALSE_FATAL(rc);
    memset(rdata, (rec->offset >> task->blkpow), maxrsize);
    CU_ASSERT_TRUE_FATAL(maxrsize >= rec->length);
    rc = fsm->write(fsm, rec->offset, rdata, rec->length, &sp);
    if (rc) {
      iwlog_ecode_error3(rc);
    }
    CU_ASSERT_FALSE_FATAL(rc);
    CU_ASSERT_EQUAL_FATAL(rec->length, sp);

    pthread_mutex_lock(&records_mtx);
    if (task->reclist != rec) {
      tmp = task->reclist;
      task->reclist = rec;
      task->reclist->prev = tmp;
      tmp->next = task->reclist;
      rec->locked = 0;
    }
    ++(task->numrecs);
    numrec = task->numrecs;
    pthread_mutex_unlock(&records_mtx);
  }

  rec = task->reclist;

  while (rec && rec->prev) {
    a = rand() % 3;
    if ((a == 0) || (a == 1)) { /* realloc */
      pthread_mutex_lock(&records_mtx);
      if (rec->locked) {
        rec = rec->next;
        pthread_mutex_unlock(&records_mtx);
        continue;
      }
      rec->locked = 1;
      pthread_mutex_unlock(&records_mtx);

      rc = fsm->deallocate(fsm, rec->offset, rec->length);
      if (rc) {
        iwlog_ecode_error3(rc);
      }
      CU_ASSERT_FALSE_FATAL(rc);

      /* allocate */
      do {
        rec->length = iwu_rand_dnorm((double) task->avgrecsz, task->avgrecsz / 3.0);
      } while (rec->length <= 0 || rec->length > maxrsize);

      rc = fsm->allocate(fsm, rec->length, &rec->offset, &rec->length, 0);
      if (rc) {
        iwlog_ecode_error3(rc);
        CU_ASSERT_FALSE(rc);
        break;
      }

      if (rec->length <= maxrsize) {
        /* Write a record */
        memset(rdata, (rec->offset >> task->blkpow), maxrsize);
        rc = fsm->write(fsm, rec->offset, rdata, rec->length, &sp);
        if (rc) {
          iwlog_ecode_error3(rc);
        }
        CU_ASSERT_FALSE_FATAL(rc);
      } else {
        /* printf("Ops %lld %lld\n\n", rl >> task->blkpow, rec->length >>
         * task->blkpow); */
        CU_ASSERT_TRUE_FATAL(0);
        assert(0);
      }

      pthread_mutex_lock(&records_mtx);
      rec->locked = 0;
      pthread_mutex_unlock(&records_mtx);
    } else {
      // TODO

      //            rc = fsm->lread(fsm, rec->offset, rdata, rec->length, &sp);
      //            CU_ASSERT_FALSE_FATAL(rc);
      //            CU_ASSERT_EQUAL_FATAL(sp, rec->length);
      //            memset(rdata2, (rec->offset >> task->blkpow), maxrsize);
      //            int cmp = memcmp(rdata, rdata2, rec->length);
      //            CU_ASSERT_FALSE_FATAL(cmp);
    }
    rec = rec->prev;
  }
  free(rdata);
  free(rdata2);
  return 0;
}

void test_block_allocation_impl(int mmap_all, int nthreads, int numrec, int avgrecsz, int blkpow, const char *path) {
  iwrc rc;
  pthread_t *tlist = malloc(nthreads * sizeof(pthread_t));

  IWFS_FSM_OPTS opts = {
    .exfile     = {
      .file     = { .path = path, .omode = IWFS_OTRUNC },
      .rspolicy = iw_exfile_szpolicy_fibo
    },
    .bpow       = blkpow,
    .oflags     = IWFSM_STRICT,
    .mmap_all   = mmap_all
  };

  FSMRECTASK task;
  FSMREC *rec, *prev;
  IWFS_FSM fsm;
  rc = iwfs_fsmfile_open(&fsm, &opts);
  CU_ASSERT_FALSE_FATAL(rc);

  memset(&task, 0, sizeof(task));
  task.numrecs = 0;
  task.maxrecs = numrec;
  task.avgrecsz = avgrecsz;
  task.fsm = &fsm;
  task.reclist = malloc(sizeof(*task.reclist));
  memset(task.reclist, 0, sizeof(*task.reclist));
  task.head = task.reclist;
  task.blkpow = opts.bpow;

  for (int i = 0; i < nthreads; ++i) {
    CU_ASSERT_EQUAL_FATAL(pthread_create(&tlist[i], 0, recordsthr, &task), 0);
  }
  for (int i = 0; i < nthreads; ++i) {
    pthread_join(tlist[i], 0);
  }

  /* Cleanup */
  rec = task.reclist;
  while (rec) {
    prev = rec->prev;
    free(rec);
    rec = prev;
  }
  rc = fsm.close(&fsm);
  CU_ASSERT_FALSE_FATAL(rc);
  free(tlist);
}

void test_block_allocation1_impl(int mmap_all);

void test_block_allocation1(void) {
  test_block_allocation1_impl(0);
}

void test_block_allocation1_mmap_all(void) {
  test_block_allocation1_impl(1);
}

void test_block_allocation1_impl(int mmap_all) {
  iwrc rc;
  IWFS_FSM fsm;
  int psize = iwp_alloc_unit();
  IWFS_FSM_OPTS opts = {
    .exfile    = {
      .file    = {
        .path  = "test_block_allocation1.fsm",
        .omode = IWFS_OTRUNC
      }
    },
    .hdrlen    = psize - 2 * 64,
    .bpow      = 6,
    .oflags    = IWFSM_STRICT,
    .mmap_all  = mmap_all
  };

  off_t oaddr = 0;
  off_t olen;
  // off_t sp, sp2;
  int bsize = (1 << opts.bpow); /* byte block */
  const int hoff = (2 * psize);

  rc = iwfs_fsmfile_open(&fsm, &opts);
  CU_ASSERT_FALSE_FATAL(rc);

  /* Next alloc status:
     xxxxxxx */
  rc = fsm.allocate(&fsm, 3 * bsize, &oaddr, &olen, 0);
  CU_ASSERT_FALSE_FATAL(rc);
  CU_ASSERT_EQUAL(oaddr, hoff + 0);
  CU_ASSERT_EQUAL(olen, 3 * bsize);

  rc = fsm.allocate(&fsm, 4 * bsize, &oaddr, &olen, 0);
  CU_ASSERT_FALSE_FATAL(rc);
  CU_ASSERT_EQUAL(oaddr, hoff + 3 * bsize);
  CU_ASSERT_EQUAL(olen, 4 * bsize);

  rc = fsm.deallocate(&fsm, 1 * bsize, 1 * bsize);
  CU_ASSERT_EQUAL(rc, IWFS_ERROR_FSM_SEGMENTATION);


  /* Next alloc status:
     x*xxxxx */
  rc = fsm.deallocate(&fsm, hoff + 1 * bsize, 1 * bsize);
  CU_ASSERT_FALSE_FATAL(rc);

  /* Next alloc status:
     xxxxxxx */
  rc = fsm.allocate(&fsm, 1 * bsize, &oaddr, &olen, 0);
  CU_ASSERT_FALSE_FATAL(rc);
  CU_ASSERT_EQUAL(oaddr, hoff + 1 * bsize);
  CU_ASSERT_EQUAL(olen, 1 * bsize);

  /* Next alloc status:
     x**xxxx */
  rc = fsm.deallocate(&fsm, oaddr, 2 * bsize);
  CU_ASSERT_FALSE_FATAL(rc);

  /* Next alloc status:
     x**x**x */
  rc = fsm.deallocate(&fsm, hoff + 4 * bsize, 2 * bsize);
  CU_ASSERT_FALSE_FATAL(rc);

  oaddr = hoff + 5 * bsize; /* Test a free block location suggestion */
  rc = fsm.allocate(&fsm, 2 * bsize, &oaddr, &olen, 0);
  CU_ASSERT_FALSE_FATAL(rc);
  CU_ASSERT_EQUAL(oaddr, hoff + 4 * bsize);
  CU_ASSERT_EQUAL(olen, 2 * bsize);

  /* Next alloc status:
     x**x**x */
  rc = fsm.deallocate(&fsm, hoff + 4 * bsize, 2 * bsize);
  CU_ASSERT_FALSE_FATAL(rc);

  /* Next alloc status:
     x*****x */
  CU_ASSERT_EQUAL(iwfs_fsmdbg_number_of_free_areas(&fsm), 3);
  rc = fsm.deallocate(&fsm, hoff + 3 * bsize, 1 * bsize);
  CU_ASSERT_FALSE_FATAL(rc);
  CU_ASSERT_EQUAL(iwfs_fsmdbg_number_of_free_areas(&fsm), 2);

  /* Next alloc status:
     xxxxxxx */
  oaddr = hoff;
  rc = fsm.allocate(&fsm, 5 * bsize, &oaddr, &olen, 0);
  CU_ASSERT_FALSE_FATAL(rc);
  CU_ASSERT_EQUAL(oaddr, hoff + 1 * bsize);
  CU_ASSERT_EQUAL(olen, 5 * bsize);
  CU_ASSERT_EQUAL(iwfs_fsmdbg_number_of_free_areas(&fsm), 1);

  // Test reallocate
  /* Next alloc status:
   * xxx*** */
  rc = fsm.deallocate(&fsm, hoff + 4 * bsize, 3 * bsize);
  CU_ASSERT_FALSE_FATAL(rc);
  rc = fsm.deallocate(&fsm, hoff, 1 * bsize);
  CU_ASSERT_FALSE_FATAL(rc);
  CU_ASSERT_EQUAL(iwfs_fsmdbg_number_of_free_areas(&fsm), 2);

  /* Next alloc status:
   * xx**** */
  oaddr = hoff + 1 * bsize;
  olen = 3 * bsize;
  rc = fsm.reallocate(&fsm, 2 * bsize, &oaddr, &olen, 0);
  CU_ASSERT_FALSE_FATAL(rc);
  CU_ASSERT_EQUAL(oaddr, hoff + 1 * bsize);
  CU_ASSERT_EQUAL(olen, 2 * bsize);
  CU_ASSERT_EQUAL(iwfs_fsmdbg_number_of_free_areas(&fsm), 2);

  /* Next alloc status:
   * xxxxxx */
  //  rc = fsm.reallocate(&fsm, 6 * bsize, &oaddr, &olen, 0);
  //  CU_ASSERT_FALSE_FATAL(rc);
  //  CU_ASSERT_EQUAL(oaddr, hoff + 1 * bsize);
  //  CU_ASSERT_EQUAL(olen, 6 * bsize);
  //
  //  /* Next alloc status:
  //     *xx***x */
  //  rc = fsm.deallocate(&fsm, hoff + 3 * bsize, 3 * bsize);
  //  CU_ASSERT_FALSE_FATAL(rc);

  // todo
  //  oaddr = hoff + 1 * bsize;
  //  olen = 1 * bsize;
  //  rc = fsm.reallocate(&fsm, 2 * bsize, &oaddr, &olen, 0);
  //  CU_ASSERT_EQUAL(oaddr, hoff);
  //  CU_ASSERT_EQUAL(olen, 2 * bsize);

  rc = fsm.close(&fsm);
  CU_ASSERT_FALSE_FATAL(rc);
}

void test_block_allocation2_impl(int mmap_all);

void test_block_allocation2(void) {
  test_block_allocation2_impl(0);
}

void test_block_allocation2_mmap_all(void) {
  test_block_allocation2_impl(1);
}

void test_block_allocation2_impl(int mmap_all) {
  test_block_allocation_impl(mmap_all, 4, 50000, 493, 6, "test_block_allocation2.fsm");
  test_block_allocation_impl(mmap_all, 4, 50000, 5, 6, "test_block_allocation2.fsm");
}

int main(void) {
  CU_pSuite pSuite = NULL;

  /* Initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry()) {
    return CU_get_error();
  }

  /* Add a suite to the registry */
  pSuite = CU_add_suite("iwfs_test2", init_suite, clean_suite);

  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Add the tests to the suite */
  if (  (NULL == CU_add_test(pSuite, "test_fsm_bitmap", test_fsm_bitmap))
     || (NULL == CU_add_test(pSuite, "test_fsm_open_close", test_fsm_open_close))
     || (NULL == CU_add_test(pSuite, "test_fsm_uniform_alloc", test_fsm_uniform_alloc))
     || (NULL == CU_add_test(pSuite, "test_fsm_uniform_alloc_mmap_all", test_fsm_uniform_alloc_mmap_all))
     || (NULL == CU_add_test(pSuite, "test_block_allocation1", test_block_allocation1))
     || (NULL == CU_add_test(pSuite, "test_block_allocation1_mmap_all", test_block_allocation1_mmap_all))
     || (NULL == CU_add_test(pSuite, "test_block_allocation2", test_block_allocation2))
     || (NULL == CU_add_test(pSuite, "test_block_allocation2_mmap_all", test_block_allocation2_mmap_all))) {
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
