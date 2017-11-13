
#include "iwkv.h"
#include "iwlog.h"
#include "iwarr.h"
#include "iwutils.h"
#include "iwfsmfile.h"
#include "iwcfg.h"
#include "khash.h"
#include <stdbool.h>
#include <pthread.h>

// IWK magic number in file header
#define IWKV_MAGIC 0x69776b76

// IWDB magic number
#define IWDB_MAGIC 0x69776462

// Max key + value size: 255Mb
#define IWKV_MAX_KVSZ 0xfffffff

// Max database file size: ~255Gb
#define IWKV_MAX_DBSZ 0x3fffffffc0

// Size of KV fsm block as power of 2
#define IWKV_FSM_BPOW 6

// Length of KV fsm header in bytes
#define KVHDRSZ 255

// Number of skip list levels
#define SLEVELS 30

// Lower key length in SBLK
#define SBLK_LKLEN 62

// Size of `SBLK` as power of 2
#define SBLK_SZPOW 8

// Size of `IWDB` as power of 2
#define DB_SZPOW 8

// Number of `KV` blocks in KVBLK
#define KVBLK_IDXNUM 63

// Initial `KVBLK` size power of 2 (256 bytes)
#define KVBLK_INISZPOW 8

// KVBLK header size: blen:u1,idxsz:u2
#define KVBLK_HDRSZ 3

struct IWKV;
struct IWDB;

typedef uint32_t blkn_t;
typedef uint32_t dbid_t;

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
  uint32_t len;   /**< Length of kv pair block */
  uint8_t  ridx;  /**< Position of the auctually persisted slot in `KVBLK` */
} KVP;

// KVBLK: [blen:u1,idxsz:u2,[pp1:vn,pl1:vn,...,pp63,pl63]____[[pair],...]]
typedef struct KVBLK {
  IWDB db;
  off_t addr;                 /**< Block address */
  uint32_t maxoff;            /**< Max pair offset */
  uint16_t idxsz;             /**< Size of KV pairs index in bytes */
  int8_t zidx;                /**< Index of first empty pair slot, or -1 */
  uint8_t szpow;              /**< Block size power of 2 */
  KVP pidx[KVBLK_IDXNUM];     /**< KV pairs index */
} KVBLK;

// SBLK: [kblk:u4,lvl:u1,p0:u4,n0-n29:u4,lkl:u1,lk:u62,pnum:u1,[pi1:u1,...pi63]]:u256
typedef struct SBLK {
  KVBLK *kvblk;               /**< Associated KVBLK */
  off_t addr;                 /**< Block address */
  blkn_t n[SLEVELS];          /**< Next pointers blkn */
  blkn_t p0;                  /**< Prev pointer at zero level blkn */
  uint8_t lvl;                /**< Skip list level for this block */
  uint8_t lkl;                /**< Lower key length */
  uint8_t lk[SBLK_LKLEN];     /**< Lower key value */
  uint8_t pnum;               /**< Number of active pairs in `piN` array */
  uint8_t pi[KVBLK_IDXNUM];   /**< Key/value pairs indexes in `KVBLK` */
  bool pinned;
} SBLK;

typedef enum {
  RMKV_SYNC = 0x1,
  RMKV_NO_RESIZE = 0x2
} kvblk_rmkv_opts_t;

/** Address lock node */
typedef struct ALN {
  pthread_rwlock_t rwl;     /**< RW lock */
  int64_t refs;             /**< Locked address refs count */
} ALN;

KHASH_MAP_INIT_INT(ALN, ALN *)

typedef enum {
  IWDB_DUP_VALS = 0x1       /**<  Duplicated values allowed */
} iwdb_flags_t;

/** Database instance */
struct IWDB {
  IWKV iwkv;
  iwdb_flags_t flg;         /**< Database flags */
  pthread_mutex_t mtx_ctl;  /**< Main control mutex */
  uint64_t addr;            /**< Address of IWDB meta block */
  uint64_t next_addr;       /**< Next IWDB addr */
  struct IWDB *next;        /**< Next IWDB meta */
  struct IWDB *prev;        /**< Prev IWDB meta */
  khash_t(ALN) *aln;        /**< Block id -> ALN node mapping */
  dbid_t id;                /**< Database ID */
  blkn_t n[SLEVELS];        /**< Next pointers blknum */
  uint8_t lvl;              /**< Upper skip list level used */
};

KHASH_MAP_INIT_INT(DBS, IWDB)

/** Root IWKV instance */
struct IWKV {
  pthread_rwlock_t rwl_api; /**< API RW lock */
  IWFS_FSM fsm;             /**< FSM pool */
  blkn_t  metablk;          /**< Database meta block */
  khash_t(DBS) *dbs;        /**< Database id -> IWDB mapping */
  IWDB dblast;              /**< Last database in chain */
  IWDB dbfirst;             /**< First database in chain */
  bool isopen;              /**< True if kvstore is in OPEN state */
};

typedef enum {
  IWLCTX_PUT = 0x1,         /**< Put key value operation */
  IWLCTX_DEL = 0x2,         /**< Delete key operation */
} iwlctx_op_t;


typedef enum {
  IWLCTX_DB_LOCKED = 0x1
} iwlctx_state_t;

/** Database lookup context */
typedef struct IWLCTX {
  IWDB db;
  IWKV_val *key;            /**< Search key */
  IWKV_val *val;            /**< Update value */
  SBLK *lower;              /**< Next to upper bound block */
  SBLK *upper;              /**< Upper bound block */
  SBLK *plower[SLEVELS];    /**< Pinned lower nodes per level: block[level index]
                                 filled when `IWLCTX_SAVE_TPATH` status is set */
  SBLK *pupper[SLEVELS];    /**< Pinned upper nodes per level */
  int8_t lvl;               /**< Current level */
  int8_t nlvl;              /**< Level of new inserted `SBLK` node. -1 if no new node inserted */
  iwlctx_op_t op;           /**< Context operation flags */
  iwlctx_state_t smask;     /**< Context state mask */
} IWLCTX;

#define IWKV_ENSURE_OPEN(iwkv_) \
  if (!iwkv_ || !(iwkv_->isopen)) return IW_ERROR_INVALID_STATE;

//--------------------------  IWDB

IW_INLINE iwrc _aln_write_upgrade(IWDB db, off_t addr) {
  ALN *aln = 0;
  int rci;
  blkn_t blkn = addr >> IWKV_FSM_BPOW;
  rci = pthread_mutex_lock(&db->mtx_ctl);
  if (rci) return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  khiter_t ki = kh_get(ALN, db->aln, blkn);
  if (ki != kh_end(db->aln)) {
    aln = kh_value(db->aln, ki);
    assert(aln);
    pthread_rwlock_unlock(&aln->rwl);
    rci = pthread_rwlock_wrlock(&aln->rwl);
    if (rci) {
      pthread_mutex_unlock(&db->mtx_ctl);
      return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
    }
  }
  pthread_mutex_unlock(&db->mtx_ctl);
  return aln ? 0 : IW_ERROR_FAIL;
}

IW_INLINE iwrc _aln_release(IWDB db, off_t addr) {
  blkn_t blkn = addr >> IWKV_FSM_BPOW;
  int rci = pthread_mutex_lock(&db->mtx_ctl);
  if (rci) return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  khiter_t ki = kh_get(ALN, db->aln, blkn);
  if (ki != kh_end(db->aln)) {
    ALN *aln = kh_value(db->aln, ki);
    assert(aln);
    pthread_rwlock_unlock(&aln->rwl);
    if (--aln->refs < 1) {
      kh_del(ALN, db->aln, ki);
      free(aln);
    }
  }
  pthread_mutex_unlock(&db->mtx_ctl);
  return 0;
}

IW_INLINE iwrc _aln_acquire_read(IWDB db, off_t addr) {
  ALN *aln;
  int rci;
  iwrc rc = 0;
  blkn_t blkn = addr >> IWKV_FSM_BPOW;
  rci = pthread_mutex_lock(&db->mtx_ctl);
  if (rci) return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  khiter_t ki = kh_get(ALN, db->aln, blkn);
  if (ki == kh_end(db->aln)) {
    aln = malloc(sizeof(*aln));
    if (!aln) {
      rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
      goto finish;
    }
    aln->refs = 1;
    pthread_rwlock_init(&aln->rwl, 0);
  } else {
    aln = kh_value(db->aln, ki);
    aln->refs++;
  }
finish:
  pthread_mutex_unlock(&db->mtx_ctl);
  if (!rc) {
    rci = pthread_rwlock_rdlock(&aln->rwl);
    if (rci) {
      return iwrc_set_errno(IW_ERROR_ALLOC, rci);
    }
  }
  return rc;
}

static iwrc _db_at(IWKV iwkv, IWDB *dbp, off_t addr, uint8_t *mm) {
  iwrc rc = 0;
  uint8_t *rp;
  uint32_t lv;
  int rci;
  IWDB db = calloc(1, sizeof(struct IWDB));
  *dbp = 0;
  if (!db) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  rci = pthread_mutex_init(&db->mtx_ctl, 0);
  if (rci) {
    free(db);
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  // [magic:u4,next_blk:u4,dbid:u4,n0-n29:u4]
  db->addr = addr;
  db->iwkv = iwkv;
  rp = mm + addr;
  IW_READLV(rp, lv, lv);
  if (lv != IWDB_MAGIC) {
    rc = IWKV_ERROR_CORRUPTED;
    goto finish;
  }
  IW_READBV(rp, lv, db->flg);
  IW_READLV(rp, lv, db->next_addr);
  db->next_addr = db->next_addr << IWKV_FSM_BPOW; // blknum -> addr
  IW_READLV(rp, lv, db->id);
  for (int i = 0; i < SLEVELS; ++i) {
    IW_READLV(rp, lv, db->n[i]);
  }
  *dbp = db;
finish:
  if (rc)  {
    pthread_mutex_destroy(&db->mtx_ctl);
    free(db);
  }
  return rc;
}

static void _db_sync(IWDB db, uint8_t *mm) {
  uint32_t lv;
  uint8_t *wp = mm + db->addr;
  db->next_addr = db->next ? db->next->addr : 0;
  // [magic:u4,next_blk:u4,dbid:u4,n0-n29:u4]
  IW_WRITELV(wp, lv, IWDB_MAGIC);
  IW_WRITEBV(wp, lv, db->flg);
  IW_WRITELV(wp, lv, db->next_addr);
  IW_WRITELV(wp, lv, db->id);
  for (int i = 0; i < SLEVELS; ++i) {
    IW_WRITELV(wp, lv, db->n[i]);
  }
}

static iwrc _db_load_chain(IWKV iwkv, off_t addr, uint8_t *mm) {
  iwrc rc;
  if (!addr) {
    return 0;
  }
  int rci;
  IWDB db = 0, ndb;
  do {
    rc = _db_at(iwkv, &ndb, addr, mm);
    if (rc) {
      return rc;
    }
    if (db) {
      db->next = ndb;
      ndb->prev = db;
    } else {
      iwkv->dbfirst = ndb;
    }
    db = ndb;
    addr = db->next_addr;
    iwkv->dblast = db;
    khiter_t k = kh_put(DBS, iwkv->dbs, db->id, &rci);
    if (!rci) {
      kh_value(iwkv->dbs, k) = db;
    } else {
      rc = IW_ERROR_FAIL;
      return rc;
    }
  } while (db->next_addr);
  return rc;
}

static void _db_release_lwapi(IWDB *dbp) {
  assert(dbp && *dbp);
  pthread_mutex_destroy(&(*dbp)->mtx_ctl);
  kh_destroy(ALN, (*dbp)->aln);
  free(*dbp);
  *dbp = 0;
}

static iwrc _db_destroy_lwapi(IWDB *dbp) {
  iwrc rc;
  uint8_t *mm;
  size_t sp;
  IWDB db = *dbp;
  IWDB prev = db->prev;
  IWDB next = db->next;
  IWFS_FSM *fsm = &db->iwkv->fsm;
  
  kh_del(DBS, db->iwkv->dbs, db->id);
  rc = fsm->acquire_mmap(fsm, 0, &mm, &sp);
  if (prev) {
    prev->next = next;
    _db_sync(prev, mm);
  }
  if (next) {
    next->prev = prev;
    _db_sync(next, mm);
  }
  fsm->release_mmap(fsm);
  if (db->iwkv->dbfirst && db->iwkv->dbfirst->addr == db->addr) {
    uint64_t llv;
    db->iwkv->dbfirst = next;
    llv = next ? next->addr : 0;
    llv = IW_HTOILL(llv);
    rc = fsm->writehdr(fsm, sizeof(uint32_t) /*skip magic*/, &llv, sizeof(llv));
  }
  if (db->iwkv->dblast && db->iwkv->dblast->addr == db->addr) {
    db->iwkv->dblast = prev;
  }
  
  // TODO!!!: dispose all of `SBLK` & `KVBLK` blocks used by db
  IWRC(fsm->deallocate(fsm, db->addr, (1 << DB_SZPOW)), rc);
  _db_release_lwapi(dbp);
  return rc;
}

static iwrc _db_create_lwapi(IWKV iwkv, dbid_t dbid, IWDB *odb) {
  iwrc rc = 0;
  int rci;
  size_t sp;
  uint8_t *mm;
  off_t baddr = 0, blen;
  IWFS_FSM *fsm = &iwkv->fsm;
  *odb = 0;
  IWDB db = calloc(1, sizeof(struct IWDB));
  if (!db) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  rc = fsm->allocate(fsm, (1 << DB_SZPOW), &baddr, &blen,
                     IWFSM_ALLOC_NO_OVERALLOCATE | IWFSM_SOLID_ALLOCATED_SPACE);
  if (rc) {
    _db_release_lwapi(&db);
    return rc;
  }
  db->iwkv = iwkv;
  db->addr = baddr;
  db->id = dbid;
  db->prev = iwkv->dblast;
  db->aln = kh_init(ALN);
  
  if (!iwkv->dbfirst) {
    uint64_t llv;
    iwkv->dbfirst = db;
    llv = db->addr;
    llv = IW_HTOILL(llv);
    rc = fsm->writehdr(fsm, sizeof(uint32_t) /*skip magic*/, &llv, sizeof(llv));
  } else if (iwkv->dblast) {
    iwkv->dblast->next = db;
    iwkv->dblast = db;
  }
  khiter_t k = kh_put(DBS, iwkv->dbs, db->id, &rci);
  if (!rci) {
    kh_value(iwkv->dbs, k) = db;
  } else {
    RCGO(IW_ERROR_FAIL, finish);
  }
  rc = fsm->acquire_mmap(fsm, 0, &mm, &sp);
  RCGO(rc, finish);
  _db_sync(db, mm);
  if (db->prev) {
    _db_sync(db->prev, mm);
  }
  fsm->release_mmap(fsm);
  *odb = db;
  
finish:
  if (rc) {
    fsm->deallocate(fsm, baddr, blen);
    _db_release_lwapi(&db);
  }
  return rc;
}

//--------------------------  KVBLK

static iwrc _kvblk_create(IWDB db, KVBLK **oblk) {
  iwrc rc = 0;
  off_t baddr = 0, blen;
  int step = 0;
  IWFS_FSM *fsm = &db->iwkv->fsm;
  KVBLK *kblk;
  rc = fsm->allocate(fsm, (1 << KVBLK_INISZPOW), &baddr, &blen,
                     IWFSM_ALLOC_NO_OVERALLOCATE | IWFSM_SOLID_ALLOCATED_SPACE);
  RCGO(rc, finish);
  ++step; // 1
  kblk = calloc(1, sizeof(*kblk));
  if (!kblk) {
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    goto finish;
  }
  kblk->db = db;
  kblk->addr = baddr;
  kblk->szpow = KVBLK_INISZPOW;
  kblk->idxsz = 2 * IW_VNUMSIZE(0) * KVBLK_IDXNUM;
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

static void _kvblk_release(KVBLK **kbp) {
  assert(kbp && *kbp);
  free(*kbp);
  *kbp = 0;
}

static iwrc _kvblk_destroy(KVBLK **kbp) {
  assert(kbp && *kbp);
  iwrc rc = 0;
  KVBLK *blk =  *kbp;
  IWKV iwkv = blk->db->iwkv;
  IWFS_FSM *fsm = &iwkv->fsm;
  assert(iwkv && blk->szpow && blk->addr);
  rc = fsm->deallocate(fsm, blk->addr, 1ULL << blk->szpow);
  _kvblk_release(kbp);
  return rc;
}

IW_INLINE void _kvblk_peekey(const KVBLK *kb,
                             uint8_t idx,
                             const uint8_t *mm,
                             uint8_t **okbuf,
                             uint32_t *oklen) {
  assert(idx < KVBLK_IDXNUM);
  if (kb->pidx[idx].len) {
    uint32_t klen, step;
    const uint8_t *rp = mm + kb->addr + (1ULL << kb->szpow) - kb->pidx[idx].off;
    IW_READVNUMBUF(rp, klen, step);
    rp += step;
    *okbuf = (uint8_t *) rp;
    *oklen = klen;
  } else {
    *okbuf = 0;
    *oklen = 0;
  }
}

static iwrc _kvblk_getkey(KVBLK *kb, uint8_t *mm, int idx, IWKV_val *key) {
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
  uint8_t *rp = mm + (1ULL << kb->szpow) - kvp->off;
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

static iwrc _kvblk_getkv(uint8_t *mm, KVBLK *kb, int idx, IWKV_val *key, IWKV_val *val) {
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
  uint8_t *rp = mm + (1ULL << kb->szpow) - kvp->off;
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

static iwrc _kvblk_at2(IWDB db, off_t addr, uint8_t *mm, KVBLK **blkp) {
  iwrc rc = 0;
  uint8_t *rp, *sp;
  uint16_t sv;
  int step = 0, rci;
  IWFS_FSM *fsm = &db->iwkv->fsm;
  KVBLK *kb = malloc(sizeof(*kb));
  if (!kb) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  rp = mm + addr;
  kb->db = db;
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

static iwrc _kvblk_at(IWDB db, off_t addr, KVBLK **blkp) {
  iwrc rc;
  uint8_t *mm;
  size_t sz;
  IWFS_FSM *fsm = &db->iwkv->fsm;
  *blkp = 0;
  rc = fsm->acquire_mmap(fsm, 0, &mm, &sz);
  RCRET(rc);
  rc = _kvblk_at2(db, addr, mm, blkp);
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
  kb->idxsz = sp;
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

static iwrc _kvblk_compact(KVBLK *kb, uint8_t *mm) {
  iwrc rc = 0;
  uint8_t i;
  size_t sp;
  IWFS_FSM *fsm = &kb->db->iwkv->fsm;
  off_t coff = _kvblk_compacted_offset(kb);
  if (coff == kb->maxoff) { // already compacted
    return 0;
  }
  KVP tidx[KVBLK_IDXNUM];
  memcpy(tidx, kb->pidx, KVBLK_IDXNUM * sizeof(kb->pidx[0]));
  mm = mm + kb->addr + (1ULL << kb->szpow);
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
  return rc;
}

IW_INLINE uint64_t _kvblk_datasize(KVBLK *kb) {
  uint64_t dsz = KVBLK_HDRSZ + kb->idxsz;
  for (int i = 0; i < KVBLK_IDXNUM; ++i) {
    dsz += kb->pidx[i].len;
  }
  return dsz;
}

IW_INLINE off_t _kvblk_maxkvoff(KVBLK *kb) {
  off_t off = 0;
  for (int i = 0; i < KVBLK_IDXNUM; ++i) {
    if (kb->pidx[i].off > off) {
      off = kb->pidx[i].off;
    }
  }
  return off;
}

iwrc _kvblk_rmkv(KVBLK *kb, uint8_t idx, kvblk_rmkv_opts_t opts) {
  iwrc rc = 0;
  uint8_t *mm = 0;
  uint64_t sz;
  IWFS_FSM *fsm = &kb->db->iwkv->fsm;
  rc = fsm->acquire_mmap(fsm, 0, &mm, &sz);
  RCRET(rc);
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
  if (!(RMKV_NO_RESIZE & opts)) {
    uint64_t kbsz = 1ULL << kb->szpow;
    uint64_t dsz = _kvblk_datasize(kb);
    uint8_t dpow = 1;
    sz = kbsz / 2;
    while ((kb->szpow - dpow) > KVBLK_INISZPOW && dsz < sz / 2) {
      sz = sz / 2;
      dpow++;
    }
    if ((kb->szpow - dpow) > KVBLK_INISZPOW && dsz < kbsz / 2) { // We can shrink kvblock
      rc = _kvblk_compact(kb, mm);
      RCGO(rc, finish);
      off_t naddr = kb->addr, nlen = kbsz;
      off_t maxoff = _kvblk_maxkvoff(kb);
      memmove(mm + kb->addr + sz - maxoff,
              mm + kb->addr + kbsz - maxoff,
              maxoff);
      fsm->release_mmap(fsm);
      mm = 0;
      rc = fsm->reallocate(fsm, sz, &naddr, &nlen, IWFSM_ALLOC_NO_OVERALLOCATE | IWFSM_SOLID_ALLOCATED_SPACE);
      RCGO(rc, finish);
      kb->addr = naddr;
      kb->szpow = kb->szpow - dpow;
      opts |= RMKV_SYNC;
      rc = fsm->acquire_mmap(fsm, 0, &mm, &sz);
      RCGO(rc, finish);
    }
  }
  if (RMKV_SYNC & opts) {
    _kvblk_sync(kb, mm);
  }
finish:
  if (mm) {
    fsm->release_mmap(fsm);
  }
  return rc;
}

static iwrc _kvblk_addkv(KVBLK *kb, const IWKV_val *key, const IWKV_val *val, int8_t *oidx) {
  iwrc rc = 0;
  off_t msz;    // max available free space
  off_t rsz;    // required size to add new key/value pair
  off_t noff;   // offset of new kvpair from end of block
  uint8_t *mm, *wp;
  size_t i, sp;
  KVP *kvp;
  IWFS_FSM *fsm = &kb->db->iwkv->fsm;
  off_t psz = (key->size + val->size) + IW_VNUMSIZE(key->size); // required size
  bool compacted = false;
  *oidx = -1;
  
  if (psz > IWKV_MAX_KVSZ) {
    return IWKV_ERROR_MAXKVSZ;
  }
  if (kb->zidx < 0) {
    return _IWKV_ERROR_KVBLOCK_FULL;
  }
  
start:
  msz = (1ULL << kb->szpow) - KVBLK_HDRSZ - kb->idxsz - kb->maxoff;
  noff = kb->maxoff + psz;
  rsz = psz + IW_VNUMSIZE(noff) + IW_VNUMSIZE(psz) - 2;
  if (msz < rsz) { // not enough space
    if (!compacted) {
      rc = fsm->acquire_mmap(fsm, 0, &mm, &sp);
      RCGO(rc, finish);
      rc = _kvblk_compact(kb, mm);
      fsm->release_mmap(fsm);
      RCGO(rc, finish);
      compacted = true;
      goto start;
    } else { // resize the whole block
      off_t nsz = (rsz - msz) + (1ULL << kb->szpow);
      uint8_t npow = kb->szpow;
      while ((1ULL << ++npow) < nsz);
      off_t naddr = kb->addr,
            nlen = (1ULL << kb->szpow);
      rc = fsm->reallocate(fsm, (1ULL << npow), &naddr, &nlen, IWFSM_ALLOC_NO_OVERALLOCATE | IWFSM_SOLID_ALLOCATED_SPACE);
      RCGO(rc, finish);
      assert(nlen == (1ULL << npow));
      // Move pairs area
      // [hdr..[pairs]] =reallocate=> [hdr..[pairs]_____] =memove=> [hdr.._____[pairs]]
      rc = fsm->acquire_mmap(fsm, 0, &mm, &sp);
      RCGO(rc, finish);
      memmove(mm + naddr + nlen - kb->maxoff, mm + naddr + (1ULL << kb->szpow) - kb->maxoff, kb->maxoff);
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
  rc = fsm->acquire_mmap(fsm, 0, &mm, &sp);
  RCGO(rc, finish);
  wp = mm + kb->addr + (1ULL << kb->szpow) - kvp->off;
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
  IWFS_FSM *fsm = &kb->db->iwkv->fsm;
  size_t rsize = IW_VNUMSIZE(key->size) + key->size + val->size; // required size
  iwrc rc = fsm->acquire_mmap(fsm, 0, &mm, &sz);
  RCGO(rc, finish);
  wp = mm + kb->addr + (1ULL << kb->szpow) - kvp->off;
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
          fsm->release_mmap(fsm);
          mm = 0;
          rc = _kvblk_rmkv(kb, idx, RMKV_NO_RESIZE);
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

IW_INLINE void _sblk_release(SBLK **sblkp) {
  assert(sblkp && *sblkp);
  _aln_release((*sblkp)->kvblk->db, (*sblkp)->addr);
  free(*sblkp);
  *sblkp = 0;
}

static iwrc _sblk_destroy(SBLK **sblkp) {
  assert(sblkp && *sblkp && (*sblkp)->kvblk);
  iwrc rc = 0;
  SBLK *sblk = *sblkp;
  IWKV iwkv = sblk->kvblk->db->iwkv;
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
  IWKV iwkv = sblk->kvblk->db->iwkv;
  IWFS_FSM *fsm = &iwkv->fsm;
  iwrc rc = fsm->acquire_mmap(fsm, 0, &mm, &sz);
  RCRET(rc);
  // SBLK: [kblk:u4,lvl:u1,p0:u4,n0-n29:u4,lkl:u1,lk:u62,pnum:u1,[pi1:u1,...pi63]]:u256
  wp = mm + sblk->addr;
  sp = wp;
  IW_WRITELV(wp, lv, sblk->kvblk->addr);
  memcpy(wp, &sblk->lvl, 1);
  wp += 1;
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

IW_INLINE uint8_t _sblk_genlevel() {
  uint8_t lvl;
  uint32_t r = rand();
  for (lvl = 0; lvl < SLEVELS && !(r & 1); ++lvl) {
    r >>= 1;
  }
  return (lvl >= SLEVELS) ? SLEVELS - 1 : lvl;
}

static iwrc _sblk_create(IWDB db, int8_t nlevel, SBLK **oblk) {
  iwrc rc;
  off_t baddr = 0, blen;
  IWFS_FSM *fsm = &db->iwkv->fsm;
  SBLK *sblk;
  KVBLK *kvblk;
  
  rc = _kvblk_create(db, &kvblk);
  RCRET(rc);
  
  rc = fsm->allocate(fsm, (1 << KVBLK_INISZPOW), &baddr, &blen,
                     IWFSM_ALLOC_NO_OVERALLOCATE | IWFSM_SOLID_ALLOCATED_SPACE);
  RCGO(rc, finish);
  sblk = calloc(1, sizeof(*sblk));
  if (!sblk) {
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    goto finish;
  }
  sblk->addr = baddr;
  sblk->lvl = nlevel;
  sblk->kvblk = kvblk;
  rc = _sblk_sync(sblk, SBLK_NOSYNC_KBLK);
  RCGO(rc, finish);
  
finish:
  IWRC(_aln_acquire_read(db, sblk->addr), rc);
  if (rc) {
    IWRC(_kvblk_destroy(&kvblk), rc);
    if (sblk) {
      sblk->kvblk = 0;
      IWRC(_sblk_destroy(&sblk), rc);
    }
  }
  return rc;
}

static iwrc _sblk_at(IWDB db, off_t addr, SBLK **sblkp) {
  iwrc rc;
  uint8_t *mm = 0, *rp, *sp;
  blkn_t kblkn;
  uint32_t lv;
  uint64_t llv;
  size_t sz;
  IWFS_FSM *fsm = &db->iwkv->fsm;
  SBLK *sblk = calloc(1, sizeof(*sblk));
  if (!sblk) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  sblk->addr = addr;
  rc = _aln_acquire_read(db, sblk->addr);
  if (rc) {
    return rc;
  }
  rc = fsm->acquire_mmap(fsm, 0, &mm, &sz);
  RCGO(rc, finish);
  rp = mm + addr;
  sp = rp;
  
  // SBLK: [kblk:u4,lvl:u1,p0:u4,n0-n29:u4,lkl:u1,lk:u62,pnum:u1,[pi1:u1,...pi63]]:u256
  IW_READLV(rp, lv, kblkn);
  assert(kblkn);
  
  memcpy(&sblk->lvl, rp, 1);
  rp += 1;
  
  rc = _kvblk_at2(db, (((uint64_t) kblkn) << IWKV_FSM_BPOW), mm, &sblk->kvblk);
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

static int _sblk_find_pi(SBLK *sblk, const IWKV_val *key, const uint8_t *mm) {
  uint8_t *k;
  uint32_t kl;
  int idx = 0,
      lb = 0,
      ub = sblk->pnum - 1;
  if (sblk->pnum < 1) {
    return -1;
  }
  while (1) {
    int cr;
    idx = (ub + lb) / 2;
    _kvblk_peekey(sblk->kvblk, idx, mm, &k, &kl);
    assert(kl > 0);
    IW_CMP(cr, k, kl, key->data, key->size);
    if (!cr) {
      return idx;
    } else if (cr < 0) {
      lb = idx + 1;
      if (lb > ub) {
        return -1;
      }
    } else {
      ub = idx - 1;
      if (lb > ub) {
        return sblk->pnum;
      }
    }
  }
  return idx;
}

static int _sblk_insert_pi(SBLK *sblk, int8_t nidx, const IWKV_val *key, const uint8_t *mm) {
  uint8_t *k;
  uint32_t kl;
  int idx = 0,
      lb = 0,
      ub = sblk->pnum - 1,
      nels = sblk->pnum;
  if (nels < 1) {
    sblk->pi[0] = nidx;
    sblk->pnum++;
    return 0;
  }
  while (1) {
    int cr;
    idx = (ub + lb) / 2;
    _kvblk_peekey(sblk->kvblk, idx, mm, &k, &kl);
    assert(kl > 0);
    IW_CMP(cr, k, kl, key->data, key->size);
    if (!cr) {
      break;
    } else if (cr < 0) {
      lb = idx + 1;
      if (lb > ub) {
        idx = lb;
        break;
      }
    } else {
      ub = idx - 1;
      if (lb > ub) {
        break;
      }
    }
  }
  memmove(sblk->pi + idx + 1, sblk->pi + idx, nels - idx);
  sblk->pi[idx] = nidx;
  return idx;
}

static iwrc _sblk_addkv(SBLK *sblk, const IWKV_val *key, const IWKV_val *val, int8_t *oidx) {
  iwrc rc;
  int8_t idx;
  size_t sz;
  uint8_t *mm;
  KVBLK *kvblk = sblk->kvblk;
  IWFS_FSM *fsm = &kvblk->db->iwkv->fsm;
  if (sblk->pnum >= KVBLK_IDXNUM) {
    return _IWKV_ERROR_KVBLOCK_FULL;
  }
  rc = _kvblk_addkv(kvblk, key, val, &idx);
  RCRET(rc);
  rc = fsm->acquire_mmap(fsm, 0, &mm, &sz);
  RCRET(rc);
  if (_sblk_insert_pi(sblk, idx, key, mm) == 0) { // the lowest key inserted
    sblk->lkl = MIN(SBLK_LKLEN, key->size);
    memcpy(sblk->lk, key->data, sblk->lkl);
  }
  fsm->release_mmap(fsm);
  return rc;
}

static iwrc _sblk_rmkv(SBLK *sblk, uint8_t idx) {
  iwrc rc;
  KVBLK *kvblk = sblk->kvblk;
  IWFS_FSM *fsm = &kvblk->db->iwkv->fsm;
  assert(idx < sblk->pnum);
  uint8_t kidx = sblk->pi[idx]; // get kvblk index
  assert(kidx < KVBLK_IDXNUM);
  rc = _kvblk_rmkv(kvblk, kidx, 0);
  RCRET(rc);
  if (idx < sblk->pnum - 1 && sblk->pnum > 1) {
    memmove(sblk->pi + idx, sblk->pi + idx + 1, sblk->pnum - idx - 1);
  }
  sblk->pnum--;
  rc = _sblk_sync(sblk, 0);
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
    case IWKV_ERROR_MAXDBSZ:
      return "Database file size reached its maximal limit: 0x3fffffffc0 bytes (IWKV_ERROR_MAXDBSZ)";
    case IWKV_ERROR_CORRUPTED:
      return "Database file invalid or corrupted (IWKV_ERROR_CORRUPTED)";
  }
  return 0;
}

//--------------------------  IWLCTX (CRUD)

IW_INLINE int _lx_compare_upper_with_key(IWLCTX *lx, uint8_t *mm) {
  int res;
  uint8_t *k;
  uint32_t kl;
  SBLK *sblk = lx->upper;
  IWKV_val *key = lx->key;
  if (sblk->pnum < 1) { // empty block
    return -1;
  }
  if (key->size < sblk->lkl) {
    IW_CMP(res, sblk->lk, sblk->lkl, key->data, key->size);
    return res;
  }
  _kvblk_peekey(sblk->kvblk, sblk->pi[0] /* lower key index */, mm, &k, &kl);
  if (!kl) {
    return -1;
  }
  IW_CMP(res, k, kl, key->data, key->size);
  return res;
}

static iwrc _lx_roll_forward(IWLCTX *lx) {
  iwrc rc = 0;
  assert(lx->lower);
  uint8_t *mm;
  size_t sp;
  IWFS_FSM *fsm  = &lx->db->iwkv->fsm;
  rc = fsm->acquire_mmap(fsm, 0, &mm, &sp);
  RCRET(rc);
  while (1) {
    if (!lx->lower->n[lx->lvl]) {
      break;
    }
    rc = _sblk_at(lx->db, lx->lower->n[lx->lvl], &lx->upper);
    RCRET(rc);
    if (_lx_compare_upper_with_key(lx, mm) > 0) { // upper > key
      break;
    } else {
      if (!lx->lower->pinned) {
        _sblk_release(&lx->lower);
      }
      lx->lower = lx->upper;
      lx->upper = 0;
    }
  }
  IWRC(fsm->release_mmap(fsm), rc);
  return rc;
}

static iwrc _lx_find_bounds(IWLCTX *lx) {
  iwrc rc;
  IWDB db = lx->db;
  rc = _aln_acquire_read(db, db->addr);
  RCRET(rc);
  lx->smask |= IWLCTX_DB_LOCKED;
  if (!db->n[db->lvl]) { // empty skiplist chain
    return 0;
  }
  rc = _sblk_at(db, db->n[db->lvl], &lx->lower);
  RCRET(rc);
  for (int l = db->lvl; l >= 0; --l) {
    lx->lvl = l;
    rc = _lx_roll_forward(lx);
    RCGO(rc, finish);
    if (lx->upper) {
      blkn_t ub = lx->upper->addr >> IWKV_FSM_BPOW;
      assert(lx->lower->n[l] == ub);
      while (l > 0) { // skip down the current upper node
        if (lx->lower->n[--l] != ub) {
          ++l;
          break;
        }
      }
      lx->lvl = l;
    }
    if (lx->nlvl >= l) {
      lx->lower->pinned = true;
      lx->plower[l] = lx->lower;
      if (lx->upper) {
        lx->upper->pinned = true;
        lx->pupper[l] = lx->upper;
      }
    } else if (l > 0 && lx->upper) {
      _sblk_release(&lx->upper);
    }
  }
finish:
  return rc;
}

static void _lx_release(IWLCTX *lx) {
  if (lx->nlvl > -1) {
    for (int i = SLEVELS - 1; i >= 0; --i) {
      if (lx->pupper[i]) {
        _sblk_release(&lx->pupper[i]);
      }
      if (lx->plower[i]) {
        _sblk_release(&lx->plower[i]);
      }
    }
  } else {
    if (lx->upper) {
      _sblk_release(&lx->upper);
    }
    if (lx->lower) {
      _sblk_release(&lx->lower);
    }
  }
  if (lx->smask & IWLCTX_DB_LOCKED) {
    _aln_release(lx->db, lx->db->addr);
  }
}

static iwrc _lx_put_lr(IWLCTX *lx) {
  assert(lx);
  iwrc rc = 0;
  
  return rc;
}

//--------------------------  PUBLIC API

iwrc iwkv_init(void) {
  static int _kv_initialized = 0;
  iwrc rc = iw_init();
  RCRET(rc);
  if (!__sync_bool_compare_and_swap(&_kv_initialized, 0, 1)) {
    return 0;  // initialized already
  }
  return iwlog_register_ecodefn(_kv_ecodefn);
}

iwrc iwkv_open(IWKV_OPTS *opts, IWKV *iwkvp) {
  assert(iwkvp && opts);
  iwrc rc = 0;
  uint32_t lv;
  uint64_t llv;
  uint8_t *rp, *mm;
  size_t sp;
  *iwkvp = calloc(1, sizeof(struct IWKV));
  if (!*iwkvp) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  IWKV iwkv = *iwkvp;
  pthread_rwlock_init(&iwkv->rwl_api, 0);
  iwkv_openflags oflags = opts->oflags;
  iwfs_omode omode = IWFS_OREAD;
  if (oflags & IWKV_TRUNC) {
    oflags &= ~IWKV_RDONLY;
    omode |= IWFS_OTRUNC;
  }
  if (!(oflags & IWKV_RDONLY)) {
    omode |= IWFS_OWRITE;
  }
  IWFS_FSM_STATE fsmstate;
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
    .bpow = IWKV_FSM_BPOW,      // 64 bytes block size
    .hdrlen = KVHDRSZ,          // Size of custom file header
    .oflags = ((oflags & (IWKV_NOLOCKS | IWKV_RDONLY)) ? IWFSM_NOLOCKS : 0),
    .mmap_all = 1
    //!!!! todo implement: .maxoff = IWKV_MAX_DBSZ
  };
  rc = iwfs_fsmfile_open(&iwkv->fsm, &fsmopts);
  RCGO(rc, finish);
  IWFS_FSM *fsm  = &iwkv->fsm;
  iwkv->dbs = kh_init(DBS);
  rc = fsm->state(fsm, &fsmstate);
  RCGO(rc, finish);
  
  if (fsmstate.rwlfile.exfile.file.ostatus & IWFS_OPEN_NEW) {
    // Write magic number
    lv = IWKV_MAGIC;
    lv = IW_HTOIL(lv);
    rc = fsm->writehdr(fsm, 0, &lv, sizeof(lv));
    RCGO(rc, finish);
    fsm->sync(fsm, 0);
  } else {
    uint8_t hdr[KVHDRSZ];
    rc = fsm->readhdr(fsm, 0, hdr, KVHDRSZ);
    RCGO(rc, finish);
    rp = hdr;
    memcpy(&lv, rp, sizeof(lv));
    rp += sizeof(lv);
    lv = IW_ITOHL(lv);
    if (lv != IWKV_MAGIC) {
      rc = IWKV_ERROR_CORRUPTED;
      goto finish;
    }
    memcpy(&llv, rp, sizeof(llv));
    llv = IW_ITOHLL(llv);
    rc = fsm->acquire_mmap(fsm, 0, &mm, &sp);
    RCGO(rc, finish);
    rc = _db_load_chain(iwkv, llv, mm);
    fsm->release_mmap(fsm);
  }
  (*iwkvp)->isopen = true;
finish:
  if (rc) {
    (*iwkvp)->isopen = true;
    IWRC(iwkv_close(iwkvp), rc);
  }
  return rc;
}

iwrc iwkv_sync(IWKV iwkv) {
  IWKV_ENSURE_OPEN(iwkv);
  iwrc rc = 0;
  IWFS_FSM *fsm  = &iwkv->fsm;
  int rci = pthread_rwlock_rdlock(&iwkv->rwl_api);
  if (rci) rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  IWRC(fsm->sync(fsm, IWFS_FDATASYNC), rc);
  pthread_rwlock_unlock(&iwkv->rwl_api);
  return rc;
}

iwrc iwkv_close(IWKV *iwkvp) {
  IWKV_ENSURE_OPEN((*iwkvp));
  iwrc rc = 0;
  IWKV iwkv = *iwkvp;
  int rci = pthread_rwlock_wrlock(&iwkv->rwl_api);
  if (rci) rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  iwkv->isopen = false;
  IWDB db = iwkv->dbfirst;
  while (db) {
    IWDB ndb = db->next;
    _db_release_lwapi(&db);
    db = ndb;
  }
  IWRC(iwkv->fsm.close(&iwkv->fsm), rc);
  if (iwkv->dbs) {
    kh_destroy(DBS, iwkv->dbs);
    iwkv->dbs = 0;
  }
  free(iwkv);
  *iwkvp = 0;
  pthread_rwlock_unlock(&iwkv->rwl_api);
  return rc;
}

iwrc iwkv_db(IWKV iwkv, uint32_t dbid, IWDB *dbp) {
  IWKV_ENSURE_OPEN(iwkv);
  IWDB db;
  iwrc rc = 0;
  *dbp = 0;
  int rci = pthread_rwlock_rdlock(&iwkv->rwl_api);
  if (rci) return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  khiter_t ki = kh_get(DBS, iwkv->dbs, dbid);
  if (ki != kh_end(iwkv->dbs)) {
    db = kh_value(iwkv->dbs, ki);
  }
  rci = pthread_rwlock_unlock(&iwkv->rwl_api);
  if (rci) return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  if (db) {
    *dbp = db;
    return 0;
  }
  rci = pthread_rwlock_wrlock(&iwkv->rwl_api);
  if (rci) return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  ki = kh_get(DBS, iwkv->dbs, dbid);
  if (ki != kh_end(iwkv->dbs)) {
    db = kh_value(iwkv->dbs, ki);
  }
  if (db) {
    *dbp = db;
  } else {
    rc = _db_create_lwapi(iwkv, dbid, dbp);
  }
  rci = pthread_rwlock_unlock(&iwkv->rwl_api);
  if (rci) IWRC(iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci), rc);
  return rc;
}

iwrc iwkv_db_destroy(IWDB *dbp) {
  assert(dbp && *dbp);
  iwrc rc = 0;
  IWKV iwkv = (*dbp)->iwkv;
  IWKV_ENSURE_OPEN(iwkv);
  int rci = pthread_rwlock_wrlock(&iwkv->rwl_api);
  if (rci) return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  rc = _db_destroy_lwapi(dbp);
  rci = pthread_rwlock_unlock(&iwkv->rwl_api);
  if (rci) IWRC(iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci), rc);
  return rc;
}

iwrc iwkv_put(IWDB db, IWKV_val *key, IWKV_val *val, iwkv_putflags flags) {
  iwrc rc;
  IWKV iwkv = db->iwkv;
  IWLCTX lx = {0};
  lx.db = db;
  lx.key = key;
  lx.val = val;
  lx.nlvl = -1;
  int rci = pthread_rwlock_rdlock(&iwkv->rwl_api);
  if (rci) return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  //rc = 
  
  rci = pthread_rwlock_unlock(&iwkv->rwl_api);
  if (rci) IWRC(iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci), rc);
  return rc;
}

void iwkv_kv_dispose(IWKV_val *key, IWKV_val *val) {
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
