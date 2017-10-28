
#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwfsmfile.h"
#include "iwcfg.h"

// Size of KV fsm block as power of 2
#define KVBPOW 6

// Length of KV fsm header in bytes
#define KVHDRLEN 255

// Number of KV blocks in KVBLK
#define KVBLK_IDXNUM 63

// Initial KVBLK size power of 2 (256 bytes)
#define KVBLK_SZPOW 8

// KVBLK header size: blen:u1 + pplen:u2
#define KVBLK_HDRSZ (1 + 2)

struct IWKV {
  IWFS_FSM fsm;
};

// Key/Value pair
typedef struct KV {
  uint8_t *key;
  uint8_t *val;
  size_t keysz;
  size_t valsz;
} KV;

// KV index: Offset and length.
typedef struct KVPP {
  uint32_t off; /**< KV block offset relative to `end` of KVBLK */
  uint32_t len; /**< Length of  */
} KVPP;

// KVBLK: [blen:u1,pplen:u2,[pp1:vn,pl1:vn,...,pp63,pl63]____[[pair],...]]
typedef struct KVBLK {
  IWKV iwkv;
  off_t addr;              /**< Block address */
  uint32_t maxoff;         /**< Maximal pair offset */
  uint16_t pplen;          /**< Size of KV pairs index in bytes */
  uint8_t szpow;           /**< Block size power of 2 */
  KVPP pp[KVBLK_IDXNUM];   /**< KV pairs index */
} KVBLK;

static iwrc _kvblk_create(IWKV iwkv, KVBLK **oblk) {
  iwrc rc = 0;
  off_t baddr = 0, blen;
  int step = 0;
  IWFS_FSM *fsm = &iwkv->fsm;
  KVBLK *kblk;
  rc = fsm->allocate(fsm, (1 << KVBLK_SZPOW), &baddr, &blen, IWFSM_ALLOC_NO_OVERALLOCATE | IWFSM_SOLID_ALLOCATED_SPACE);
  RCGO(rc, finish);
  ++step; // 1
  kblk = calloc(1, sizeof(*kblk));
  if (!kblk) {
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    goto finish;
  }
  kblk->iwkv = iwkv;
  kblk->addr = baddr;
  kblk->szpow = KVBLK_SZPOW;
  kblk->pplen = 2 * IW_VNUMSIZE(0) * KVBLK_IDXNUM;
finish:
  if (rc) {
    if (step > 0) {
      IWRC(fsm->deallocate(fsm, baddr, blen), rc);
    }
    *oblk = 0;
  }
  return rc;
}

static void _kvblk_release(KVBLK **blkp) {
  assert(blkp && *blkp);
  free(*blkp);
  *blkp = 0;
}

static iwrc _kvblk_destroy(KVBLK **blkp) {
  assert(blkp && *blkp);
  iwrc rc = 0;
  KVBLK *blk =  *blkp;
  IWKV iwkv = blk->iwkv;
  IWFS_FSM *fsm = &iwkv->fsm;
  assert(iwkv && blk->szpow && blk->addr);
  rc = fsm->deallocate(fsm, blk->addr, 1 << blk->szpow);
  _kvblk_release(blkp);
  return rc;
}

static iwrc _kvblk_compact(KVBLK *kblk) {
  iwrc rc = 0;
  // todo:
  return rc;
}

static iwrc _kvblk_addpair(KVBLK *kblk, const IWKV_val *key, const IWKV_val *value) {
  iwrc rc = 0;
  size_t psz = key->size + value->size + IW_VNUMSIZE(key->size); // required size
  off_t end = KVBLK_HDRSZ + kblk->pplen;

  return rc;
}

static const char *_kv_ecodefn(locale_t locale, uint32_t ecode) {
  if (!(ecode > _IWKV_ERROR_START && ecode < _IWKV_ERROR_END)) {
    return 0;
  }
  switch (ecode) {
    case IWKV_ERROR_NOTFOUND:
      return "Key not found. (IWKV_ERROR_NOTFOUND)";
  }
  return 0;
}

iwrc iwkv_init(void) {
  static int _kv_initialized = 0;
  iwrc rc = iw_init();
  if (rc) return rc;
  if (!__sync_bool_compare_and_swap(&_kv_initialized, 0, 1)) {
    return 0;  // initialized already
  }
  return iwlog_register_ecodefn(_kv_ecodefn);
}

iwrc iwkv_open(IWKV_OPTS *opts, IWKV *iwkvp) {
  assert(iwkvp && opts);
  iwrc rc = 0;
  *iwkvp = calloc(1, sizeof(struct IWKV));
  if (!*iwkvp) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  IWKV iwkv = *iwkvp;
  iwkv_openflags oflags = opts->oflags;
  iwfs_omode omode = IWFS_OREAD;
  if (oflags & IWKV_TRUNC) {
    oflags &= ~IWKV_RDONLY;
    omode |= IWFS_OTRUNC;
  }
  if (!(oflags & IWKV_RDONLY)) {
    omode |= IWFS_OWRITE;
  }
  IWFS_FSM_OPTS fsmopts = {
    .rwlfile = {
      .exfile  = {
        .file = {
          .path       = opts->path,
          .omode      = omode,
          .lock_mode  = (oflags & IWKV_RDONLY) ? IWP_RLOCK : IWP_WLOCK
        },
        .rspolicy     = iw_exfile_szpolicy_fibo
      }
    },
    .bpow = KVBPOW,              // 64 bytes block size
    .hdrlen = KVHDRLEN,          // Size of custom file header
    .oflags = ((oflags & (IWKV_NOLOCKS | IWKV_RDONLY)) ? IWFSM_NOLOCKS : 0)
  };
  rc = iwfs_fsmfile_open(&iwkv->fsm, &fsmopts);
  RCGO(rc, finish);


finish:
  return rc;
}

iwrc iwkv_close(IWKV *iwkvp) {
  assert(iwkvp);
  iwrc rc = 0;
  IWKV iwkv = *iwkvp;
  rc = iwkv->fsm.close(&iwkv->fsm);
  free(*iwkvp);
  *iwkvp = 0;
  return rc;
}
