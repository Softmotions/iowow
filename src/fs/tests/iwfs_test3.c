#include "iowow.h"
#include "log/iwlog.h"
#include "fs/iwfsmfile.h"
#include "utils/iwutils.h"

#include "iwcfg.h"
#include "iwtests.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "kbtree.h"

#define NRECS 10000
#define RECSZ (10 * 1024)

#define UNLINK()                        \
        unlink("test_fsm_stress.data"); \
        unlink("test_fsm_stress1.fsm"); \
        unlink("test_fsm_stress2.fsm")

typedef struct SREC {
  int   id;
  off_t addr;
  off_t rsz;
  off_t alc_addr;
  off_t alc_len;
  bool  freed;
  bool  reallocated;
} SREC;

#define _srec_cmp(r1, r2) ((r1).id - (r2).id)

KBTREE_INIT(rt, struct SREC, _srec_cmp)

FILE *fstress1;
kbtree_t(rt) * rt;

int init_suite(void) {
  UNLINK();
  int rc = iw_init();
  RCRET(rc);

  rt = kb_init(rt, KB_DEFAULT_SIZE);

  off_t addr = 0;
  uint64_t ts;
  rc = iwp_current_time_ms(&ts, false);
  RCRET(rc);
  ts = IW_SWAB64(ts);
  ts >>= 32;
  iwu_rand_seed(ts);

  printf("Generating stress data file: test_fsm_stress.data, random seed: %" PRIu64 "\n", ts);
  fstress1 = fopen("test_fsm_stress.data", "w+");
  char *buf = malloc(RECSZ + 1);
  for (int i = 0, j; i < NRECS; ++i) {
    int rsz = iwu_rand_range(RECSZ + 1);
    if (rsz < 1) {
      rsz = 1;
    }
    for (j = 0; j < rsz; ++j) {
      buf[j] = ' ' + iwu_rand_range(95);
    }
    buf[j] = '\0';
    fprintf(fstress1, "%08d:%s\n", i, buf);
    struct SREC rec = {
      .id = i,
      .addr = addr,
      .rsz = rsz,
      .freed = false
    };
    addr += (8 + 1 + rsz + 1);
    kb_putp(rt, rt, &rec);
  }
  free(buf);
  return rc;
}

void clean_suite(void) {
  if (fstress1) {
    fclose(fstress1);
    fstress1 = 0;
  }
  kb_destroy(rt, rt);
  UNLINK();
  return;
}

void test_stress(char *path, int bpow, bool mmap_all) {
  struct iwfs_fsm fsm;
  struct iwfs_fsm_opts opts = {
    .exfile = {
      .file = {
        .path = path,
        .omode = IWFS_OTRUNC
      }
    },
    .hdrlen = 62,
    .bpow = bpow,
    .oflags = IWFSM_STRICT,
    .mmap_all = mmap_all
  };
  iwrc rc = iwfs_fsmfile_open(&fsm, &opts);
  IW_TEST_ASSERT_FALSE_FATAL(rc);

  fprintf(stderr, "\nRunning allocations...\n");

  char *buf = malloc(2 * RECSZ + 1);
  for (int i = 0; i < NRECS; ++i) {
    size_t sp;
    struct SREC k = { .id = i };
    iwfs_fsm_aflags aflags = IWFSM_SOLID_ALLOCATED_SPACE | IWFSM_ALLOC_NO_OVERALLOCATE;
    uint32_t rop = iwu_rand_u32();
    if ((i > 0) && (!(rop % 3) || !(rop % 5))) {
      k.id = iwu_rand_range(i);
      struct SREC *pr = kb_getp(rt, rt, &k);
      IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(pr);
      if (!pr->freed) {
        if ((rop % 3)) { // deallocate previous
          //fprintf(stderr, "%05d D %ld:%ld\n", pr->id, pr->alc_addr, pr->alc_len);
          pr->freed = true;
          rc = fsm.deallocate(&fsm, pr->alc_addr, pr->alc_len);
          IW_TEST_ASSERT_FALSE_FATAL(rc);
        } else if (!pr->reallocated && !(rop % 5)) { // reallocate previous
          //fprintf(stderr, "%05d R %ld:%ld\n", pr->id, pr->alc_addr, pr->alc_len);
          pr->reallocated = true;
          uint32_t nlen = iwu_rand_range(2 * pr->rsz + 1);
          if (nlen < 1) {
            nlen = 1;
          }
          rc = fsm.reallocate(&fsm, nlen, &pr->alc_addr, &pr->alc_len, IWFSM_SOLID_ALLOCATED_SPACE);
          IW_TEST_ASSERT_FALSE_FATAL(rc);
          if (pr->alc_len > pr->rsz) {
            rc = fsm.read(&fsm, pr->alc_addr, buf, pr->rsz, &sp);
            IW_TEST_ASSERT_FALSE_FATAL(rc);
            IW_TEST_ASSERT_EQUAL_FATAL(pr->rsz, sp);
            off_t wsz = pr->alc_len - pr->rsz;
            while (wsz > 0) {
              int wc = MIN(wsz, pr->rsz);
              rc = fsm.write(&fsm, pr->alc_addr + pr->alc_len - wsz, buf, wc, &sp);
              IW_TEST_ASSERT_FALSE_FATAL(rc);
              IW_TEST_ASSERT_EQUAL_FATAL(wc, sp);
              wsz -= wc;
            }
          }
        }
      }
    }

    k.id = i;
    struct SREC *r = kb_getp(rt, rt, &k);
    IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(r);
    fseek(fstress1, r->addr + 8 + 1, SEEK_SET);
    fread(buf, r->rsz, 1, fstress1);
    buf[r->rsz + 1] = '\0';

    rc = fsm.allocate(&fsm, r->rsz, &r->alc_addr, &r->alc_len, aflags);
    //fprintf(stderr, "%05d A %ld:%ld\n", i, r->alc_addr, r->alc_len);
    IW_TEST_ASSERT_FALSE_FATAL(rc);
    IW_TEST_ASSERT_TRUE_FATAL(r->alc_len >= r->rsz);
    rc = fsm.write(&fsm, r->alc_addr, buf, r->rsz, &sp);
    IW_TEST_ASSERT_FALSE_FATAL(rc);
    IW_TEST_ASSERT_EQUAL_FATAL(sp, r->rsz);

    if (r->alc_len > r->rsz) {
      off_t wsz = r->alc_len - r->rsz;
      while (wsz > 0) {
        int wc = MIN(wsz, r->rsz);
        rc = fsm.write(&fsm, r->alc_addr + r->alc_len - wsz, buf, wc, &sp);
        IW_TEST_ASSERT_FALSE_FATAL(rc);
        IW_TEST_ASSERT_EQUAL_FATAL(wc, sp);
        wsz -= wc;
      }
    }
  }
  IW_TEST_ASSERT_FALSE_FATAL(fsm.close(&fsm));

  fprintf(stderr, "Checking data\n");
  opts.exfile.file.omode = 0;
  rc = iwfs_fsmfile_open(&fsm, &opts);
  IW_TEST_ASSERT_FALSE_FATAL(rc);

  char *buf2 = malloc(2 * RECSZ + 1);
  for (int i = 0; i < NRECS; ++i) {
    size_t sp;
    struct SREC k = { .id = i };
    struct SREC *r = kb_getp(rt, rt, &k);
    IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(r);
    if (r->freed) {
      continue;
    }
    IW_TEST_ASSERT_TRUE(r->alc_len <= 2 * RECSZ + 1);
    fseek(fstress1, r->addr + 8 + 1, SEEK_SET);
    fread(buf, r->rsz, 1, fstress1);
    buf[r->rsz + 1] = '\0';

    off_t rn = MIN(r->rsz, r->alc_len);
    if (r->alc_len < r->rsz) {
      IW_TEST_ASSERT_TRUE_FATAL(r->reallocated);
    }
    memset(buf2, 0, rn); // 20736
    rc = fsm.read(&fsm, r->alc_addr, buf2, rn, &sp);
    IW_TEST_ASSERT_FALSE_FATAL(rc);
    IW_TEST_ASSERT_EQUAL_FATAL(rn, sp);
    int ri = memcmp(buf, buf2, rn);
    IW_TEST_ASSERT_EQUAL_FATAL(ri, 0);

    if (rn < r->alc_len) {
      while (rn < r->alc_len) {
        off_t rz = MIN(r->alc_len - rn, r->rsz);
        rc = fsm.read(&fsm, r->alc_addr + rn, buf2, rz, &sp);
        IW_TEST_ASSERT_FALSE_FATAL(rc);
        ri = memcmp(buf, buf2, rz);
        IW_TEST_ASSERT_EQUAL_FATAL(ri, 0);
        rn += rz;
      }
    }
  }
  free(buf2);
  free(buf);
  IW_TEST_ASSERT_FALSE_FATAL(fsm.close(&fsm));
}

static void test_stress1(void) {
  test_stress("test_fsm_stress1.fsm", 6, true);
}

static void test_stress2(void) {
  test_stress("test_fsm_stress2.fsm", 6, false);
}

static const struct iw_test_case cases[] = {
  IW_TEST_CASE(test_stress1),
  IW_TEST_CASE(test_stress2),
};

int main(int argc, char *argv[]) {
  return iw_test_run(argc, argv, IW_TEST_SUITE("iwfs_test3", cases, init_suite, clean_suite));
}

