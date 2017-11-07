
#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwfsmfile.h"
#include "iwcfg.h"
#include <stdbool.h>
#include <pthread.h>

// Max key + value size: 255Mb
#define MAX_KVSZ 0xfffffff

// Max database file size: ~255Gb
#define MAX_DBSZ 0x3fffffffc0

// Size of KV fsm block as power of 2
#define FSM_BPOW 6

// Length of KV fsm header in bytes
#define KVHDRSZ 255

// Number of skip list levels
#define SLEVELS 30

// Lower key length in SBLK
#define SBLK_LKLEN 62

// Size of `SBLK` as power of 2
#define SBLK_SZPOW 8

// Number of `KV` blocks in KVBLK
#define KVBLK_IDXNUM 63

// Initial `KVBLK` size power of 2 (256 bytes)
#define KVBLK_SZPOW 8

// KVBLK header size: blen:u1,idxsz:u2
#define KVBLK_HDRSZ 3

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
typedef struct KVP {
  uint32_t off;   /**< KV block offset relative to `end` of KVBLK */
  uint32_t len;   /**< Length of  */
  uint8_t  ridx;  /**< Index position of persisted element */
} KVP;

// KVBLK: [blen:u1,idxsz:u2,[pp1:vn,pl1:vn,...,pp63,pl63]____[[pair],...]]
typedef struct KVBLK {
  IWKV iwkv;
  pthread_rwlock_t rwlk;   /**< Block rwlock */
  off_t addr;              /**< Block address */
  uint32_t maxoff;         /**< Max pair offset */
  uint16_t idxsz;          /**< Size of KV pairs index in bytes */
  int8_t zidx;             /**< Index of first empty pair slot, or -1 */
  uint8_t szpow;           /**< Block size power of 2 */
  KVP pidx[KVBLK_IDXNUM];  /**< KV pairs index */
} KVBLK;

// SBLK: [flg:u1,kblk:u4,p0:u4,n0-n29:u4,lkl:u1,lk:u62,pnum:u1,[pi1:u1,...pi63]]:u256
typedef struct SBLK {
  KVBLK *kvblk;               /**< Associated KVBLK */
  off_t addr;                 /**< Block address */
  uint32_t n[SLEVELS];        /**< Next pointers */
  uint32_t p0;                /**< Prev pointer at zero level */
  uint8_t flg;                /**< Flags */
  uint8_t lkl;                /**< Lower key length */
  uint8_t lk[SBLK_LKLEN];     /**< Lower key value */
  uint8_t pnum;               /**< Number of active pairs in `piN` array */
  uint8_t pi[KVBLK_IDXNUM];   /**< Key/value pairs indexes in `KVBLK` */
} SBLK;

//--------------------------  KVBLK

static iwrc _kvblk_create(IWKV iwkv, KVBLK **oblk) {
  iwrc rc = 0;
  off_t baddr = 0, blen;
  int step = 0, rci;
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
  kblk->idxsz = 2 * IW_VNUMSIZE(0) * KVBLK_IDXNUM;
  rci = pthread_rwlock_init(&kblk->rwlk, 0);
  if (rci) {
    rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
    goto finish;
  }
  *oblk = kblk;
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
  pthread_rwlock_destroy(&(*blkp)->rwlk);
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

static iwrc _kvblk_getkey(uint8_t *mm, KVBLK *kb, int idx, IWKV_val *key) {
  assert(mm && idx >= 0 && idx < KVBLK_IDXNUM);
  int32_t klen;
  int step;
  KVP *kvp = &kb->pidx[idx];
  if (!kvp->len) {
    key->data = 0;
    key->size = 0;
    return 0;
  }
  // [klen:vn,key,value]
  uint8_t *rp = mm + (1 << kb->szpow) - kvp->off;
  IW_READVNUMBUF(rp, klen, step);
  rp += step;
  if (klen < 1 || klen > kvp->len || klen > kvp->off) {
    return IWKV_ERROR_CORRUPTED;
  }
  key->size = klen;
  key->data = malloc(key->size);
  if (!key->data) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  memcpy(key->data, rp, key->size);
  rp += key->size;
  return 0;
}

static iwrc _kvblk_getpair(uint8_t *mm, KVBLK *kb, int idx, IWKV_val *key, IWKV_val *val) {
  assert(mm && idx >= 0 && idx < KVBLK_IDXNUM);
  int32_t klen;
  int step;
  KVP *kvp = &kb->pidx[idx];
  if (!kvp->len) {
    key->data = 0;
    key->size = 0;
    val->data = 0;
    val->size = 0;
    return 0;
  }
  // [klen:vn,key,value]
  uint8_t *rp = mm + (1 << kb->szpow) - kvp->off;
  IW_READVNUMBUF(rp, klen, step);
  rp += step;
  if (klen < 1 || klen > kvp->len || klen > kvp->off) {
    return IWKV_ERROR_CORRUPTED;
  }
  key->size = klen;
  key->data = malloc(key->size);
  if (!key->data) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  memcpy(key->data, rp, key->size);
  rp += key->size;
  if (kvp->len > klen) {
    val->size = kvp->len - klen;
    val->data = malloc(val->size);
    if (!val->data) {
      iwrc rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
      free(key->data);
      key->data = 0;
      key->size = 0;
      val->size = 0;
      return rc;
    }
    memcpy(val->data, rp, val->size);
  } else {
    val->data = 0;
    val->size = 0;
  }
  return 0;
}

static iwrc _kvblk_at2(IWKV iwkv, off_t addr, uint8_t *mm, KVBLK **blkp) {
  iwrc rc = 0;
  uint8_t *rp, *sp;
  uint16_t sv;
  int step = 0, rci;
  IWFS_FSM *fsm = &iwkv->fsm;
  KVBLK *kb = malloc(sizeof(*kb));
  if (!kb) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  rci = pthread_rwlock_init(&kb->rwlk, 0);
  if (rci) {
    rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
    goto finish;
  }
  rp = mm + addr;
  kb->iwkv = iwkv;
  kb->addr = addr;
  kb->maxoff = 0;
  kb->zidx = -1;
  IW_READBV(rp, kb->szpow, kb->szpow);
  IW_READSV(rp, sv, kb->idxsz);
  if (kb->idxsz > 2 * 4 * KVBLK_IDXNUM) {
    rc = IWKV_ERROR_CORRUPTED;
    goto finish;
  }
  sp = rp;
  for (int i = 0; i < KVBLK_IDXNUM; ++i) {
    IW_READVNUMBUF(rp, kb->pidx[i].off, step);
    rp += step;
    IW_READVNUMBUF(rp, kb->pidx[i].len, step);
    rp += step;
    if (rp - sp > kb->idxsz) {
      rc = IWKV_ERROR_CORRUPTED;
      goto finish;
    }
    kb->pidx[i].ridx = i;
    if (kb->pidx[i].len) {
      if (!kb->pidx[i].off) {
        rc = IWKV_ERROR_CORRUPTED;
        goto finish;
      }
      if (kb->pidx[i].off > kb->maxoff) {
        kb->maxoff = kb->pidx[i].off;
      }
    } else if (kb->zidx == -1) {
      kb->zidx = i;
    }
  }
  *blkp = kb;
finish:
  if (rc) {
    _kvblk_release(&kb);
  }
  return rc;
}

static iwrc _kvblk_at(IWKV iwkv, off_t addr, KVBLK **blkp) {
  iwrc rc;
  uint8_t *mm;
  size_t sz;
  IWFS_FSM *fsm = &iwkv->fsm;
  *blkp = 0;
  rc = fsm->get_mmap(fsm, 0, &mm, &sz);
  if (rc) return rc;
  rc = _kvblk_at2(iwkv, addr, mm, blkp);
  IWRC(fsm->release_mmap(fsm), rc);
  return rc;
}


static void _kvblk_sync(KVBLK *kb, uint8_t *mm) {
  uint8_t *szp;
  uint16_t sp;
  uint8_t *wp = mm + kb->addr;
  memcpy(wp, &kb->szpow, 1);
  wp += 1;
  szp = wp;
  wp += sizeof(uint16_t);
  for (int i = 0; i < KVBLK_IDXNUM; ++i) {
    KVP *kvp = &kb->pidx[i];
    IW_SETVNUMBUF(sp, wp, kvp->off);
    wp += sp;
    IW_SETVNUMBUF(sp, wp, kvp->len);
    wp += sp;
  }
  sp = wp - szp - sizeof(uint16_t);
  sp = IW_HTOIS(sp);
  memcpy(szp, &sp, sizeof(uint16_t));
}

IW_INLINE off_t _kvblk_compacted_offset(KVBLK *kb) {
  off_t coff = 0;
  for (int i = 0; i < KVBLK_IDXNUM; ++i) {
    KVP *kvp = kb->pidx + i;
    coff += kvp->len;
  }
  return coff;
}

static int _kvblk_sort_kv(const void *v1, const void *v2) {
  uint32_t o1 = ((KVP *) v1)->off > 0 ? ((KVP *) v1)->off : -1UL;
  uint32_t o2 = ((KVP *) v2)->off > 0 ? ((KVP *) v1)->off : -1UL;
  return o1 > o2 ? 1 : o1 < o2 ? -1 : 0;
}

static iwrc _kvblk_compact(KVBLK *kb) {
  iwrc rc = 0;
  uint8_t *mm, i;
  size_t sp;
  IWFS_FSM *fsm = &kb->iwkv->fsm;
  off_t coff = _kvblk_compacted_offset(kb);
  if (coff == kb->maxoff) { // already compacted
    return 0;
  }
  KVP tidx[KVBLK_IDXNUM];
  memcpy(tidx, kb->pidx, KVBLK_IDXNUM * sizeof(kb->pidx[0]));
  rc = fsm->get_mmap(fsm, 0, &mm, &sp);
  if (rc) return rc;
  mm = mm + kb->addr + (1 << kb->szpow);
  qsort(tidx, KVBLK_IDXNUM, sizeof(KVP), _kvblk_sort_kv);
  coff = 0;
  for (i = 0; i < KVBLK_IDXNUM; ++i) {
    KVP *kvp = kb->pidx + tidx[i].ridx;
    off_t noff = coff + kvp->len;
    if (kvp->off > noff) {
      memmove(mm - noff, mm - kvp->off, kvp->len);
      kvp->off = noff;
    }
    coff += kvp->len;
  }
  for (i = 0; i < KVBLK_IDXNUM; ++i) {
    if (!kb->pidx[i].len)  {
      kb->zidx = i;
      break;
    }
  }
  if (i == KVBLK_IDXNUM) {
    kb->zidx = -1;
  }
  _kvblk_sync(kb, mm);
  IWRC(fsm->release_mmap(fsm), rc);
  return rc;
}

void _kvblk_rmpair(KVBLK *kb, uint8_t idx, uint8_t *mm, bool sync) {
  if (kb->pidx[idx].off >= kb->maxoff) {
    kb->maxoff = 0;
    for (int i = 0; i < KVBLK_IDXNUM; ++i) {
      if (kb->pidx[i].off > kb->maxoff) {
        kb->maxoff = kb->pidx[i].off;
      }
    }
  }
  kb->pidx[idx].len = 0;
  kb->pidx[idx].off = 0;
  kb->zidx = idx;
  if (sync) {
    _kvblk_sync(kb, mm);
  }
}

static iwrc _kvblk_addkv(KVBLK *kb, const IWKV_val *key, const IWKV_val *val, int8_t *oidx) {
  iwrc rc = 0;
  off_t msz;    // max available free space
  off_t rsz;    // required size to add new key/value pair
  off_t noff;   // offset of new kvpair from end of block
  uint8_t *mm, *wp;
  size_t i, sp;
  KVP *kvp;
  IWFS_FSM *fsm = &kb->iwkv->fsm;
  off_t psz = (key->size + val->size) + IW_VNUMSIZE(key->size); // required size
  bool compacted = false;
  
  *oidx = -1;
  
  if (psz > MAX_KVSZ) {
    return IWKV_ERROR_MAXKVSZ;
  }
  if (kb->zidx < 0) {
    return _IWKV_ERROR_KVBLOCK_FULL;
  }
  
start:
  msz = (1 << kb->szpow) - KVBLK_HDRSZ - kb->idxsz - kb->maxoff;
  noff = kb->maxoff + psz;
  rsz = psz + IW_VNUMSIZE(noff) + IW_VNUMSIZE(psz) - 2;
  if (msz < rsz) { // not enough space
    if (!compacted) {
      rc = _kvblk_compact(kb);
      RCGO(rc, finish);
      compacted = true;
      goto start;
    } else { // resize the whole block
      off_t nsz = (rsz - msz) + (1 << kb->szpow);
      uint8_t npow = kb->szpow;
      while ((1 << ++npow) < nsz);
      off_t naddr = kb->addr,
            nlen = (1 << npow);
      rc = fsm->reallocate(fsm, nlen, &naddr, &nlen, IWFSM_ALLOC_NO_OVERALLOCATE | IWFSM_SOLID_ALLOCATED_SPACE);
      RCGO(rc, finish);
      assert(nlen == (1 << npow));
      // Move pairs area
      // [hdr..[pairs]] =reallocate=> [hdr..[pairs]_____] =memove=> [hdr.._____[pairs]]
      rc = fsm->get_mmap(fsm, 0, &mm, &sp);
      RCGO(rc, finish);
      memmove(mm + naddr + nlen - kb->maxoff, mm + naddr + (1 << kb->szpow) - kb->maxoff, kb->maxoff);
      fsm->release_mmap(fsm);
      kb->addr = naddr;
      kb->szpow = npow;
      goto start;
    }
  }
  *oidx = kb->zidx;
  kvp = &kb->pidx[kb->zidx];
  kvp->len = psz;
  kvp->off = noff;
  kvp->ridx = kb->zidx;
  kb->maxoff = noff;
  for (i = kb->zidx + 1; i < KVBLK_IDXNUM; ++i) {
    if (!kb->pidx[i].len) {
      kb->zidx = i;
      break;
    }
  }
  if (i == KVBLK_IDXNUM) {
    kb->zidx = -1;
  }
  rc = fsm->get_mmap(fsm, 0, &mm, &sp);
  RCGO(rc, finish);
  wp = mm + kb->addr + (1 << kb->szpow) - kvp->off;
  // [klen:vn,key,value]
  IW_SETVNUMBUF(sp, wp, key->size);
  wp += sp;
  memcpy(wp, key->data, key->size);
  wp += key->size;
  memcpy(wp, val->data, val->size);
  _kvblk_sync(kb, mm);
  fsm->release_mmap(fsm);
  
finish:
  return rc;
}

static iwrc _kvblk_updatev(KVBLK *kb, int8_t *idxp, const IWKV_val *key, const IWKV_val *val) {
  assert(*idxp < KVBLK_IDXNUM);
  uint8_t *mm = 0, *wp, *sp;
  int32_t klen, i;
  size_t sz;
  int8_t idx = *idxp;
  bool sync = false;
  KVP *kvp = &kb->pidx[idx];
  IWFS_FSM *fsm = &kb->iwkv->fsm;
  size_t rsize = IW_VNUMSIZE(key->size) + key->size + val->size; // required size
  iwrc rc = fsm->get_mmap(fsm, 0, &mm, &sz);
  RCGO(rc, finish);
  wp = mm + kb->addr + (1 << kb->szpow) - kvp->off;
  sp = wp;
  IW_READVNUMBUF(wp, klen, sz);
  wp += sz;
  if (klen != key->size || !memcmp(wp, key->data, key->size)) {
    rc = IWKV_ERROR_CORRUPTED;
    goto finish;
  }
  wp += klen;
  if (rsize <= kvp->len) {
    memcpy(wp, val->data, val->size);
    wp += val->size;
    sync = (wp - sp) != kvp->len;
    kvp->len = wp - sp;
  } else {
    KVP tidx[KVBLK_IDXNUM];
    memcpy(tidx, kb->pidx, KVBLK_IDXNUM * sizeof(kb->pidx[0]));
    qsort(tidx, KVBLK_IDXNUM, sizeof(KVP), _kvblk_sort_kv);
    for (i = 0; i < KVBLK_IDXNUM; ++i) {
      if (tidx[i].ridx == idx) {
        if (tidx[i].off - (i > 0 ? tidx[i - 1].off : 0) >= rsize) {
          memcpy(wp, val->data, val->size);
          wp += val->size;
          sync = true;
          kvp->len = wp - sp;
        } else {
          sync = false; // sync will be done by _kvblk_addkv
          _kvblk_rmpair(kb, idx, mm, false);
          rc = fsm->release_mmap(fsm);
          mm = 0;
          RCGO(rc, finish);
          rc = _kvblk_addkv(kb, key, val, idxp);
        }
        break;
      }
    }
  }
  
finish:
  if (!rc && sync) {
    _kvblk_sync(kb, mm);
  }
  if (mm) {
    IWRC(fsm->release_mmap(fsm), rc);
  }
  return rc;
}

//--------------------------  SBLK

typedef enum {
  SBLK_NOSYNC_KBLK = 1,
} sblk_sync_flags_t;

static void _sblk_release(SBLK **sblkp) {
  assert(sblkp && *sblkp);
  free(*sblkp);
  *sblkp = 0;
}

static iwrc _sblk_destroy(SBLK **sblkp) {
  assert(sblkp && *sblkp && (*sblkp)->kvblk);
  iwrc rc = 0;
  SBLK *sblk = *sblkp;
  IWKV iwkv = sblk->kvblk->iwkv;
  IWFS_FSM *fsm = &iwkv->fsm;
  assert(sblk->addr);
  if (sblk->kvblk) {
    rc = _kvblk_destroy(&sblk->kvblk);
  }
  IWRC(fsm->deallocate(fsm, sblk->addr, 1 << SBLK_SZPOW), rc);
  _sblk_release(sblkp);
  return rc;
}

static iwrc _sblk_sync(SBLK *sblk, sblk_sync_flags_t sf) {
  assert(sblk && sblk->kvblk && sblk->addr);
  uint8_t *mm, *wp, *sp;
  uint32_t lv;
  uint64_t llv;
  size_t sz;
  IWKV iwkv = sblk->kvblk->iwkv;
  IWFS_FSM *fsm = &iwkv->fsm;
  iwrc rc = fsm->get_mmap(fsm, 0, &mm, &sz);
  if (rc) return rc;
  // SBLK: [flg:u1,kblk:u4,p0:u4,n0-n29:u4,lkl:u1,lk:u62,pnum:u1,[pi1:u1,...pi63]]:u256
  wp = mm + sblk->addr;
  sp = wp;
  memcpy(wp, &sblk->flg, 1);
  wp += 1;
  IW_WRITELV(wp, lv, sblk->kvblk->addr);
  IW_WRITELV(wp, lv, sblk->p0);
  for (int i = 0; i < SLEVELS; ++i) {
    IW_WRITELV(wp, lv, sblk->n[i]);
  }
  memcpy(wp, &sblk->lkl, 1);
  wp += 1;
  memset(wp, 0, SBLK_LKLEN);
  assert(sblk->lkl <= SBLK_LKLEN);
  if (sblk->lkl) {
    memcpy(wp, sblk->lk, sblk->lkl);
  }
  wp += SBLK_LKLEN;
  memcpy(wp, &sblk->pnum, 1);
  wp += 1;
  memcpy(wp, sblk->pi, KVBLK_IDXNUM);
  wp += KVBLK_IDXNUM;
  assert(wp - sp == (1 << SBLK_SZPOW));
  if (!(sf & SBLK_NOSYNC_KBLK)) {
    _kvblk_sync(sblk->kvblk, mm);
  }
  fsm->release_mmap(fsm);
  return rc;
}

static iwrc _sblk_create(IWKV iwkv, SBLK **oblk) {
  iwrc rc;
  off_t baddr = 0, blen;
  IWFS_FSM *fsm = &iwkv->fsm;
  SBLK *sblk;
  KVBLK *kvblk;
  
  rc = _kvblk_create(iwkv, &kvblk);
  if (rc) return rc;
  
  rc = fsm->allocate(fsm, (1 << KVBLK_SZPOW), &baddr, &blen, IWFSM_ALLOC_NO_OVERALLOCATE | IWFSM_SOLID_ALLOCATED_SPACE);
  RCGO(rc, finish);
  
  sblk = calloc(1, sizeof(*sblk));
  if (!sblk) {
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    goto finish;
  }
  sblk->addr = baddr;
  sblk->kvblk = kvblk;
  rc = _sblk_sync(sblk, SBLK_NOSYNC_KBLK);
  RCGO(rc, finish);
  
finish:
  if (rc) {
    IWRC(_kvblk_destroy(&kvblk), rc);
    if (sblk) {
      sblk->kvblk = 0;
      IWRC(_sblk_destroy(&sblk), rc);
    }
  }
  return rc;
}

static iwrc _sblk_at(IWKV iwkv, off_t addr, SBLK **sblkp) {
  iwrc rc;
  uint8_t *mm = 0, *rp, *sp;
  uint32_t lv, kblkn;
  uint64_t llv;
  size_t sz;
  IWFS_FSM *fsm = &iwkv->fsm;
  SBLK *sblk = calloc(1, sizeof(*sblk));
  if (!sblk) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  rc = fsm->get_mmap(fsm, 0, &mm, &sz);
  RCGO(rc, finish);
  rp = mm + addr;
  sp = rp;
  
  // SBLK: [flg:u1,kblk:u4,p0:u4,n0-n29:u4,lkl:u1,lk:u62,pnum:u1,[pi1:u1,...pi63]]:u256
  memcpy(&sblk->flg, rp, 1);
  rp += 1;
  
  if (sblk->flg) { // zero now
    rc = IWKV_ERROR_CORRUPTED;
    goto finish;
  }
  
  IW_READLV(rp, lv, kblkn);
  assert(kblkn);
  
  rc = _kvblk_at2(iwkv, (((uint64_t) kblkn) << FSM_BPOW), mm, &sblk->kvblk);
  RCGO(rc, finish);
  
  IW_READLV(rp, lv, sblk->p0);
  for (int i = 0; i < SLEVELS; ++i) {
    IW_READLV(rp, lv, sblk->n[i]);
  }
  memcpy(&sblk->lkl, rp, 1);
  rp += 1;
  if (sblk->lkl) {
    if (sblk->lkl > SBLK_LKLEN) {
      rc = IWKV_ERROR_CORRUPTED;
      goto finish;
    }
    memcpy(sblk->lk, rp, sblk->lkl);
  }
  rp += SBLK_LKLEN;
  memcpy(&sblk->pnum, rp, 1);
  rp += 1;
  
  memcpy(sblk->pi, rp, KVBLK_IDXNUM);
  rp += KVBLK_IDXNUM;
  
  assert(rp - sp == (1 << SBLK_SZPOW));
  *sblkp = sblk;
  
finish:
  if (mm) {
    fsm->release_mmap(fsm);
  }
  if (rc) {
    *sblkp = 0;
    _sblk_release(&sblk);
  }
  return rc;
}


static int _sblk_insert_pi(SBLK *sblk, int8_t nidx, const IWKV_val *key, uint8_t *mm) {
  int idx = 0,
      lb = 0,
      up = sblk->pnum - 1,
      nels = sblk->pnum;
      
  if (nels < 1) {
    sblk->pi[0] = nidx;
    sblk->pnum++;
    return 0;
  }
  

  // todo !!!

  return idx;
}

//#define EL(idx_) (elsptr + (idx_) * elsize)
//
//  off_t idx = 0,
//        lb = 0,
//        ub = nels - 1;
//  char *elsptr = els;
//
//  if (nels == 0) {
//    memcpy(els, eptr, elsize);
//    return idx;
//  }
//  while (1) {
//    int cr;
//    idx = (ub + lb) / 2;
//    cr = cmp(EL(idx), eptr);
//    if (!cr) {
//      break;
//    } else if (cr < 0) {
//      lb = idx + 1;
//      if (lb > ub) {
//        idx = lb;
//        break;
//      }
//    } else {
//      ub = idx - 1;
//      if (lb > ub) {
//        break;
//      }
//    }
//  }
//  memmove(EL(idx + 1), EL(idx), nels - idx);
//  memcpy(EL(idx), eptr, elsize);
//


// [flg:u1,kblk:u4,p0:u4,n0-n29:u4,lkl:u1,lk:u62,pnum:u1,[pi1:u1,...pi63]]:u256  // SBLK Skip block
static iwrc _sblk_addkv(SBLK *sblk, const IWKV_val *key, const IWKV_val *val, int8_t *oidx) {
  iwrc rc;
  int8_t idx;
  size_t sz;
  uint8_t *mm;
  KVBLK *kvblk = sblk->kvblk;
  IWFS_FSM *fsm = &kvblk->iwkv->fsm;
  bool newlk = !sblk->lkl;
  if (sblk->pnum >= KVBLK_IDXNUM) {
    return _IWKV_ERROR_KVBLOCK_FULL;
  }
  rc = _kvblk_addkv(kvblk, key, val, &idx);
  if (rc) return rc;
  rc = fsm->get_mmap(fsm, 0, &mm, &sz);
  if (rc) return rc;
  if (!newlk) {
    newlk = (memcmp(key->data, sblk->lk, MIN(key->size, sblk->lkl)) < 0);
  }
  if (newlk) { // set the new lowest key
    sblk->lkl = MIN(SBLK_LKLEN, key->size);
    memcpy(sblk->lk, key->data, sblk->lkl);
  }
  _sblk_insert_pi(sblk, idx, key, mm);
  fsm->release_mmap(fsm);
  return rc;
}


static const char *_kv_ecodefn(locale_t locale, uint32_t ecode) {
  if (!(ecode > _IWKV_ERROR_START && ecode < _IWKV_ERROR_END)) {
    return 0;
  }
  switch (ecode) {
    case IWKV_ERROR_NOTFOUND:
      return "Key not found. (IWKV_ERROR_NOTFOUND)";
    case IWKV_ERROR_MAXKVSZ:
      return "Size of Key+value must be lesser than 0xfffffff bytes (IWKV_ERROR_MAXKVSZ)";
    case IWKV_ERROR_CORRUPTED:
      return "Database file invalid or corrupted (IWKV_ERROR_CORRUPTED)";
  }
  return 0;
}

//--------------------------  PUBLIC API

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
    .bpow = FSM_BPOW,              // 64 bytes block size
    .hdrlen = KVHDRSZ,          // Size of custom file header
    .oflags = ((oflags & (IWKV_NOLOCKS | IWKV_RDONLY)) ? IWFSM_NOLOCKS : 0),
    .mmap_all = 1
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

void iwkv_disposekv(IWKV_val *key, IWKV_val *val) {
  assert(key && val);
  if (key->data) {
    free(key->data);
  }
  if (val->data) {
    free(val->data);
  }
  key->size = 0;
  key->data = 0;
  val->size = 0;
  val->data = 0;
}
