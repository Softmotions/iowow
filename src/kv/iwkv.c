
#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwfsmfile.h"
#include "iwcfg.h"
#include <stdbool.h>

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

// Max key + value size
#define KVBLK_MAXKVSZ 0xfffffff

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
  uint32_t off; /**< KV block offset relative to `end` of KVBLK */
  uint32_t len; /**< Length of  */
} KVP;

// KVBLK: [blen:u1,idxsz:u2,[pp1:vn,pl1:vn,...,pp63,pl63]____[[pair],...]]
typedef struct KVBLK {
  IWKV iwkv;
  off_t addr;              /**< Block address */
  uint32_t maxoff;         /**< Max pair offset */
  uint16_t idxsz;          /**< Size of KV pairs index in bytes */
  int8_t zidx;             /**< Index of first empty pair slot, or -1 */
  uint8_t szpow;           /**< Block size power of 2 */
  KVP pidx[KVBLK_IDXNUM];  /**< KV pairs index */
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
  kblk->idxsz = 2 * IW_VNUMSIZE(0) * KVBLK_IDXNUM;
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
  rc = fsm->get_mmap(fsm, 0, &mm, &sp);
  if (rc) return rc;
  qsort(kb->pidx, KVBLK_IDXNUM, sizeof(KVP), _kvblk_sort_kv);

  // todo

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

void _kvblk_rmpair(KVBLK *kb, uint8_t idx, uint8_t *mm) {
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
  _kvblk_sync(kb, mm);
}

static iwrc _kvblk_addpair(KVBLK *kb, const IWKV_val *key, const IWKV_val *value) {
  iwrc rc = 0;
  off_t msz;    // max available free space
  off_t rsz;    // required size to add new key/value pair
  off_t noff;   // offset of new kvpair from end of block
  uint8_t *mm, *wp;
  size_t i, sp;
  KVP *kvp;
  IWFS_FSM *fsm = &kb->iwkv->fsm;
  off_t psz = (key->size + value->size) + IW_VNUMSIZE(key->size); // required size
  bool compacted = false;

  if (psz > KVBLK_MAXKVSZ) {
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
  kvp = &kb->pidx[kb->zidx];
  kvp->len = psz;
  kvp->off = noff;
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
  memcpy(wp, value->data, value->size);
  _kvblk_sync(kb, mm);
  fsm->release_mmap(fsm);

finish:
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
