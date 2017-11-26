
#include "iwkv.h"
#include "iwlog.h"
#include "iwarr.h"
#include "iwutils.h"
#include "iwfsmfile.h"
#include "iwcfg.h"
#include "khash.h"
#include <stdbool.h>
#include <pthread.h>

// IWKV magic number
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
#define SBLK_LKLEN 61

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

// Max non KV size [blen:u1,idxsz:u2,[ps1:vn,pl1:vn,...,ps63,pl63]
#define KVBLK_MAX_NKV_SZ (KVBLK_HDRSZ + KVBLK_IDXNUM * 8)

#define IWKV_ISLIGHT_ERROR(rc_) \
  ((rc_) == IWKV_ERROR_NOTFOUND || (rc_) == IWKV_ERROR_KEY_EXISTS)

#define ADDR2BLK(addr_) ((addr_) >> IWKV_FSM_BPOW)

#define BLK2ADDR(blk_) (((off_t) (blk_)) << IWKV_FSM_BPOW)

volatile int8_t iwkv_next_level = -1;

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

typedef enum {
  KVBLK_DURTY = 0x1
} kvblk_flags_t;

// KVBLK: [blen:u1,idxsz:u2,[pp1:vn,pl1:vn,...,pp63,pl63]____[[pair],...]]
typedef struct KVBLK {
  IWDB db;
  off_t addr;                 /**< Block address */
  uint32_t maxoff;            /**< Max pair offset */
  uint16_t idxsz;             /**< Size of KV pairs index in bytes */
  int8_t zidx;                /**< Index of first empty pair slot, or -1 */
  uint8_t szpow;              /**< Block size power of 2 */
  KVP pidx[KVBLK_IDXNUM];     /**< KV pairs index */
  kvblk_flags_t flags;        /**< Temporal flags */
} KVBLK;

typedef enum {
  SBLK_FULL_LKEY = 0x1,       /**< The lowest `SBLK` key is fully contained in `SBLK`. Persistent flag. */
  SBLK_PINNED = 0x2,          /**< `SBLK` pinned and should not be released in `_lx_find_bounds` */
  SBLK_WRITE_UPGRADED = 0x4,  /**< `SBLK` locks upgraded for write operations */
  SBLK_DURTY = 0x8,           /**< `SBLK` is duty, sync required to persist */
  SBLK_NO_LOCK = 0x10       /**< Do not use locks when accessing `SBLK`, used in debug print routines */
} sblk_flags_t;

#define SBLK_PERSISTENT_FLAGS (SBLK_FULL_LKEY)

// SBLK: [u1:flags,kblk:u4,lvl:u1,p0:u4,n0-n29:u4,lkl:u1,lk:u61,pnum:u1,[pi1:u1,...pi63]]:u256
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
  sblk_flags_t flags;         /**< Temporal flags */
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
  blkn_t last_sblkn;        /**< Last block in skiplist chain */
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
  iwkv_openflags oflags;    /**< Open flags */
};

typedef enum {
  IWLCTX_PUT = 0x1,         /**< Put key value operation */
  IWLCTX_DEL = 0x2,         /**< Delete key operation */
} iwlctx_op_t;


typedef enum {
  IWLCTX_DB_RDLOCKED = 0x1,
  IWLCTX_DB_WRITE_UPGRADED = 0x2,
} iwlctx_state_t;

/** Database lookup context */
typedef struct IWLCTX {
  IWDB db;
  const IWKV_val *key;      /**< Search key */
  IWKV_val *val;            /**< Update value */
  SBLK *lower;              /**< Next to upper bound block */
  SBLK *upper;              /**< Upper bound block */
  SBLK *nb;                 /**< New block */
  SBLK *plower[SLEVELS];    /**< Pinned lower nodes per level: block[level index]
                                 filled when `IWLCTX_SAVE_TPATH` status is set */
  SBLK *pupper[SLEVELS];    /**< Pinned upper nodes per level */
  int8_t lvl;               /**< Current level */
  int8_t nlvl;              /**< Level of new inserted `SBLK` node. -1 if no new node inserted */
  iwlctx_op_t op;           /**< Context operation flags */
  iwkv_opflags opf;         /**< Operation flags */
  iwlctx_state_t smask;     /**< Context state mask */
  sblk_flags_t sbflags;
} IWLCTX;

void iwkvd_kvblk(FILE *f, KVBLK *kb);
void iwkvd_sblk(FILE *f, SBLK *sb, int flags);
void iwkvd_db(FILE *f, IWDB db, int flags);

#define IWKV_ENSURE_OPEN(iwkv_) \
  if (!iwkv_ || !(iwkv_->isopen)) return IW_ERROR_INVALID_STATE;

#define IWKV_API_RLOCK(iwkv_, rci_) \
  rci_ = pthread_rwlock_rdlock(&(iwkv_)->rwl_api); \
  if (rci_) return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci_)

#define IWKV_API_WLOCK(iwkv_, rci_) \
  rci_ = pthread_rwlock_wrlock(&(iwkv_)->rwl_api); \
  if (rci_) return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci_)

#define IWKV_API_UNLOCK(iwkv_, rci_, rc_)  \
  rci_ = pthread_rwlock_unlock(&(iwkv_)->rwl_api); \
  if (rci_) IWRC(iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci_), rc_)

IW_INLINE void _kv_dispose(IWKV_val *key, IWKV_val *val) {
  if (key) {
    if (key->data) {
      free(key->data);
    }
    key->size = 0;
    key->data = 0;
  }
  if (val) {
    if (val->data) {
      free(val->data);
    }
    val->size = 0;
    val->data = 0;
  }
}

//--------------------------  IWDB

IW_INLINE iwrc _aln_write_upgrade(IWDB db, off_t addr) {
  ALN *aln = 0;
  int rci;
  blkn_t blkn = ADDR2BLK(addr);
  rci = pthread_mutex_lock(&db->mtx_ctl);
  if (rci) return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  khiter_t ki = kh_get(ALN, db->aln, blkn);
  if (ki != kh_end(db->aln)) {
    aln = kh_value(db->aln, ki);
    assert(aln);
    rci = pthread_rwlock_unlock(&aln->rwl);
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
  blkn_t blkn = ADDR2BLK(addr);
  int rci = pthread_mutex_lock(&db->mtx_ctl);
  if (rci) return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  khiter_t k = kh_get(ALN, db->aln, blkn);
  if (k != kh_end(db->aln)) {
    ALN *aln = kh_value(db->aln, k);
    assert(aln);
    pthread_rwlock_unlock(&aln->rwl);
    if (--aln->refs < 1) {
      kh_del(ALN, db->aln, k);
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
  blkn_t blkn = ADDR2BLK(addr);
  rci = pthread_mutex_lock(&db->mtx_ctl);
  if (rci) return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  khiter_t k = kh_get(ALN, db->aln, blkn);
  if (k == kh_end(db->aln)) {
    aln = malloc(sizeof(*aln));
    if (!aln) {
      rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
      goto finish;
    }
    k = kh_put(ALN, db->aln, blkn, &rci);
    if (rci != -1) {
      kh_value(db->aln, k) = aln;
    } else {
      rc = IW_ERROR_FAIL;
      free(aln);
      goto finish;
    }
    aln->refs = 1;
    pthread_rwlock_init(&aln->rwl, 0);
  } else {
    aln = kh_value(db->aln, k);
    aln->refs++;
  }
finish:
  pthread_mutex_unlock(&db->mtx_ctl);
  if (!rc) {
    rci = pthread_rwlock_rdlock(&aln->rwl);
    if (rci) {
      return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
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
  db->aln = kh_init(ALN);
  rp = mm + addr;
  IW_READLV(rp, lv, lv);
  if (lv != IWDB_MAGIC) {
    rc = IWKV_ERROR_CORRUPTED;
    goto finish;
  }
  IW_READBV(rp, lv, db->flg);
  IW_READLV(rp, lv, db->next_addr);
  db->next_addr = BLK2ADDR(db->next_addr); // blknum -> addr
  IW_READLV(rp, lv, db->id);
  for (int i = 0; i < SLEVELS; ++i) {
    IW_READLV(rp, lv, db->n[i]);
    if (db->n[i]) {
      db->lvl = i;
    }
  }
  *dbp = db;
finish:
  if (rc)  {
    kh_destroy(ALN, (*dbp)->aln);
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
  IW_WRITELV(wp, lv, ADDR2BLK(db->next_addr));
  IW_WRITELV(wp, lv, db->id);
  for (int i = 0; i < SLEVELS; ++i) {
    IW_WRITELV(wp, lv, db->n[i]);
  }
}

static iwrc _db_sync2(IWDB db) {
  uint8_t *mm;
  IWFS_FSM *fsm = &db->iwkv->fsm;
  iwrc rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCRET(rc);
  _db_sync(db, mm);
  return fsm->release_mmap(fsm);
}

static iwrc _db_load_chain(IWKV iwkv, off_t addr, uint8_t *mm) {
  iwrc rc;
  int rci;
  IWDB db = 0, ndb;
  if (!addr) {
    return 0;
  }
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
    if (rci != -1) {
      kh_value(iwkv->dbs, k) = db;
    } else {
      rc = IW_ERROR_FAIL;
      return rc;
    }
  } while (db->next_addr);
  return rc;
}

static void _db_release_lw(IWDB *dbp) {
  assert(dbp && *dbp);
  pthread_mutex_destroy(&(*dbp)->mtx_ctl);
  kh_destroy(ALN, (*dbp)->aln);
  free(*dbp);
  *dbp = 0;
}

static iwrc _db_destroy_lw(IWDB *dbp) {
  iwrc rc;
  uint8_t *mm;
  IWDB db = *dbp;
  IWDB prev = db->prev;
  IWDB next = db->next;
  IWFS_FSM *fsm = &db->iwkv->fsm;

  kh_del(DBS, db->iwkv->dbs, db->id);
  rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
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
  _db_release_lw(dbp);
  return rc;
}

static iwrc _db_create_lw(IWKV iwkv, dbid_t dbid, iwdb_flags_t flg, IWDB *odb) {
  iwrc rc;
  int rci;
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
    _db_release_lw(&db);
    return rc;
  }
  db->iwkv = iwkv;
  db->flg = flg;
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
  }
  iwkv->dblast = db;
  khiter_t k = kh_put(DBS, iwkv->dbs, db->id, &rci);
  if (rci != -1) {
    kh_value(iwkv->dbs, k) = db;
  } else {
    RCGO(IW_ERROR_FAIL, finish);
  }
  rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
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
    _db_release_lw(&db);
  }
  return rc;
}

//--------------------------  KVBLK

static iwrc _kvblk_create(IWDB db, int8_t kvbpow, KVBLK **oblk) {
  KVBLK *kblk;
  off_t baddr = 0, blen;
  IWFS_FSM *fsm = &db->iwkv->fsm;
  if (kvbpow < KVBLK_INISZPOW) {
    kvbpow = KVBLK_INISZPOW;
  }
  iwrc rc = fsm->allocate(fsm, (1ULL << kvbpow), &baddr, &blen,
                          IWFSM_ALLOC_NO_OVERALLOCATE | IWFSM_SOLID_ALLOCATED_SPACE);
  RCRET(rc);
  kblk = calloc(1, sizeof(*kblk));
  if (!kblk) {
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    IWRC(fsm->deallocate(fsm, baddr, blen), rc);
    *oblk = 0;
    return rc;
  }
  kblk->db = db;
  kblk->addr = baddr;
  kblk->szpow = KVBLK_INISZPOW;
  kblk->idxsz = 2 * IW_VNUMSIZE(0) * KVBLK_IDXNUM;
  *oblk = kblk;
  return rc;
}

IW_INLINE void _kvblk_release(KVBLK **kbp) {
  assert(kbp && *kbp);
  free(*kbp);
  *kbp = 0;
}

IW_INLINE iwrc _kvblk_destroy(KVBLK **kbp) {
  assert(kbp && *kbp && (*kbp)->db && (*kbp)->szpow && (*kbp)->addr);
  KVBLK *blk = *kbp;
  IWFS_FSM *fsm = &blk->db->iwkv->fsm;
  iwrc rc = fsm->deallocate(fsm, blk->addr, 1ULL << blk->szpow);
  _kvblk_release(kbp);
  return rc;
}

IW_INLINE void _kvblk_peek_key(const KVBLK *kb,
                               uint8_t idx,
                               const uint8_t *mm,
                               uint8_t **obuf,
                               uint32_t *olen) {
  assert(idx < KVBLK_IDXNUM);
  if (kb->pidx[idx].len) {
    uint32_t klen, step;
    const uint8_t *rp = mm + kb->addr + (1ULL << kb->szpow) - kb->pidx[idx].off;
    IW_READVNUMBUF(rp, klen, step);
    assert(klen);
    rp += step;
    *obuf = (uint8_t *) rp;
    *olen = klen;
  } else {
    *obuf = 0;
    *olen = 0;
  }
}

IW_INLINE void _kvblk_peek_val(const KVBLK *kb,
                               uint8_t idx,
                               const uint8_t *mm,
                               uint8_t **obuf,
                               uint32_t *olen) {
  assert(idx < KVBLK_IDXNUM);
  if (kb->pidx[idx].len) {
    uint32_t klen, step;
    const uint8_t *rp = mm + kb->addr + (1ULL << kb->szpow) - kb->pidx[idx].off;
    IW_READVNUMBUF(rp, klen, step);
    rp += step;
    rp += klen;
    *obuf = (uint8_t *) rp;
    *olen = kb->pidx[idx].len - klen - step;
  } else {
    *obuf = 0;
    *olen = 0;
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
  uint8_t *rp = mm + kb->addr + (1ULL << kb->szpow) - kvp->off;
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

static iwrc _kvblk_getvalue(KVBLK *kb, uint8_t *mm, int idx, IWKV_val *val) {
  assert(mm && idx >= 0 && idx < KVBLK_IDXNUM);
  int32_t klen;
  int step;
  KVP *kvp = &kb->pidx[idx];
  if (!kvp->len) {
    val->data = 0;
    val->size = 0;
    return 0;
  }
  // [klen:vn,key,value]
  uint8_t *rp = mm + kb->addr + (1ULL << kb->szpow) - kvp->off;
  IW_READVNUMBUF(rp, klen, step);
  rp += step;
  if (klen < 1 || klen > kvp->len || klen > kvp->off) {
    return IWKV_ERROR_CORRUPTED;
  }
  rp += klen;
  if (kvp->len > klen + step) {
    val->size = kvp->len - klen - step;
    val->data = malloc(val->size);
    if (!val->data) {
      iwrc rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
      val->data = 0;
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
  uint8_t *rp = mm + kb->addr + (1ULL << kb->szpow) - kvp->off;
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
  rp += klen;
  if (kvp->len > klen + step) {
    val->size = kvp->len - klen - step;
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
  uint8_t *rp, *sp;
  uint16_t sv;
  int step;
  iwrc rc = 0;
  KVBLK *kb = calloc(1, sizeof(*kb));

  *blkp = 0;
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
  if (IW_UNLIKELY(kb->idxsz > 2 * 4 * KVBLK_IDXNUM)) {
    rc = IWKV_ERROR_CORRUPTED;
    goto finish;
  }
  sp = rp;
  for (int i = 0; i < KVBLK_IDXNUM; ++i) {
    IW_READVNUMBUF(rp, kb->pidx[i].off, step);
    rp += step;
    IW_READVNUMBUF(rp, kb->pidx[i].len, step);
    rp += step;
    if (IW_UNLIKELY(rp - sp > kb->idxsz)) {
      rc = IWKV_ERROR_CORRUPTED;
      goto finish;
    }
    kb->pidx[i].ridx = i;
    if (kb->pidx[i].len) {
      if (IW_UNLIKELY(!kb->pidx[i].off)) {
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

IW_INLINE iwrc _kvblk_at(IWDB db, off_t addr, KVBLK **blkp) {
  iwrc rc;
  uint8_t *mm;
  IWFS_FSM *fsm = &db->iwkv->fsm;
  *blkp = 0;
  rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCRET(rc);
  rc = _kvblk_at2(db, addr, mm, blkp);
  IWRC(fsm->release_mmap(fsm), rc);
  return rc;
}

static void _kvblk_sync(KVBLK *kb, uint8_t *mm) {
  if (!(kb->flags & KVBLK_DURTY)) {
    return;
  }
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
  kb->flags &= ~KVBLK_DURTY;
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
  uint32_t o2 = ((KVP *) v2)->off > 0 ? ((KVP *) v2)->off : -1UL;
  return o1 > o2 ? 1 : o1 < o2 ? -1 : 0;
}

static void _kvblk_compact(KVBLK *kb, uint8_t *mm) {
  uint8_t i;
  off_t coff = _kvblk_compacted_offset(kb);
  if (coff == kb->maxoff) { // already compacted
    return;
  }
  KVP tidx[KVBLK_IDXNUM];
  uint8_t *wp = mm + kb->addr + (1ULL << kb->szpow);
  memcpy(tidx, kb->pidx, sizeof(tidx));
  qsort(tidx, KVBLK_IDXNUM, sizeof(KVP), _kvblk_sort_kv);
  coff = 0;
  for (i = 0; i < KVBLK_IDXNUM && tidx[i].off; ++i) {
#ifndef NDEBUG
    if (i > 0) {
      assert(tidx[i - 1].off < tidx[i].off);
    }
#endif
    KVP *kvp = &kb->pidx[tidx[i].ridx];
    off_t noff = coff + kvp->len;
    if (kvp->off > noff) {
      memmove(wp - noff, wp - kvp->off, kvp->len);
      kvp->off = noff;
    }
    coff += kvp->len;
    kb->maxoff = coff;
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
  kb->flags |= KVBLK_DURTY;
  _kvblk_sync(kb, mm);
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
  uint64_t sz;
  iwrc rc = 0;
  uint8_t *mm = 0;
  IWFS_FSM *fsm = &kb->db->iwkv->fsm;
  if (kb->pidx[idx].off >= kb->maxoff) {
    kb->maxoff = 0;
    for (int i = 0; i < KVBLK_IDXNUM; ++i) {
      if (i != idx && kb->pidx[i].off > kb->maxoff) {
        kb->maxoff = kb->pidx[i].off;
      }
    }
  }
  kb->pidx[idx].len = 0;
  kb->pidx[idx].off = 0;
  if (kb->zidx < 0 || idx < kb->zidx) {
    kb->zidx = idx;
  }
  kb->flags |= KVBLK_DURTY;
  if (!(RMKV_NO_RESIZE & opts)) {
    rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
    RCGO(rc, finish);
    uint64_t kbsz = 1ULL << kb->szpow;
    uint64_t dsz = _kvblk_datasize(kb);
    uint8_t dpow = 1;
    sz = kbsz / 2;
    while ((kb->szpow - dpow) > KVBLK_INISZPOW && dsz < sz / 2) {
      sz = sz / 2;
      dpow++;
    }
    if ((kb->szpow - dpow) >= KVBLK_INISZPOW && dsz < kbsz / 2) { // We can shrink kvblock
      _kvblk_compact(kb, mm);
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
    }
  }
  if (RMKV_SYNC & opts) {
    if (!mm) {
      rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
      RCGO(rc, finish);
    }
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
      rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
      RCGO(rc, finish);
      _kvblk_compact(kb, mm);
      compacted = true;
      fsm->release_mmap(fsm);
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
      rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
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
  kb->flags |= KVBLK_DURTY;
  for (i = 0; i < KVBLK_IDXNUM; ++i) {
    if (!kb->pidx[i].len && i != kb->zidx) {
      kb->zidx = i;
      break;
    }
  }
  if (i >= KVBLK_IDXNUM) {
    kb->zidx = -1;
  }
  rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCGO(rc, finish);
  wp = mm + kb->addr + (1ULL << kb->szpow) - kvp->off;
  // [klen:vn,key,value]
  IW_SETVNUMBUF(sp, wp, key->size);
  wp += sp;
  memcpy(wp, key->data, key->size);
  wp += key->size;
  memcpy(wp, val->data, val->size);
  fsm->release_mmap(fsm);
finish:
  return rc;
}

static iwrc _kvblk_updatev(KVBLK *kb, int8_t *idxp, const IWKV_val *key, const IWKV_val *val) {
  assert(*idxp < KVBLK_IDXNUM);
  int32_t klen, i;
  size_t sz;
  int8_t idx = *idxp;
  uint8_t *mm, *wp, *sp;
  KVP *kvp = &kb->pidx[idx];
  IWFS_FSM *fsm = &kb->db->iwkv->fsm;
  size_t rsize = IW_VNUMSIZE(key->size) + key->size + val->size; // required size
  iwrc rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCRET(rc);
  wp = mm + kb->addr + (1ULL << kb->szpow) - kvp->off;
  sp = wp;
  IW_READVNUMBUF(wp, klen, sz);
  wp += sz;
  if (klen != key->size || memcmp(wp, key->data, key->size)) {
    rc = IWKV_ERROR_CORRUPTED;
    goto finish;
  }
  wp += klen;
  if (rsize <= kvp->len) {
    memcpy(wp, val->data, val->size);
    wp += val->size;
    if ((wp - sp) != kvp->len) {
      kvp->len = wp - sp;
      kb->flags |= KVBLK_DURTY;
    }
  } else {
    KVP tidx[KVBLK_IDXNUM];
    uint32_t koff = kb->pidx[idx].off;
    memcpy(tidx, kb->pidx, KVBLK_IDXNUM * sizeof(kb->pidx[0]));
    qsort(tidx, KVBLK_IDXNUM, sizeof(KVP), _kvblk_sort_kv);
    kb->flags |= KVBLK_DURTY;
    for (i = 0; i < KVBLK_IDXNUM; ++i) {
      if (tidx[i].off == koff) {
        if (koff - (i > 0 ? tidx[i - 1].off : 0) >= rsize) {
          memcpy(wp, val->data, val->size);
          wp += val->size;
          kvp->len = wp - sp;
        } else {
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
  if (mm) {
    IWRC(fsm->release_mmap(fsm), rc);
  }
  return rc;
}

//--------------------------  SBLK

IW_INLINE void _sblk_release(SBLK **sblkp) {
  assert(sblkp && *sblkp);
  if (!((*sblkp)->flags & SBLK_NO_LOCK)) {
    _aln_release((*sblkp)->kvblk->db, (*sblkp)->addr);
  }
  _kvblk_release(&(*sblkp)->kvblk);
  free(*sblkp);
  *sblkp = 0;
}

IW_INLINE iwrc _sblk_destroy(SBLK **sblkp) {
  assert(sblkp && *sblkp && (*sblkp)->kvblk && (*sblkp)->addr);
  iwrc rc;
  SBLK *sblk = *sblkp;
  IWFS_FSM *fsm = &sblk->kvblk->db->iwkv->fsm;
  off_t kvb_addr = sblk->kvblk->addr, sblk_addr = sblk->addr;
  uint8_t kvb_szpow = sblk->kvblk->szpow;
  _sblk_release(sblkp);
  rc = fsm->deallocate(fsm, sblk_addr, 1 << SBLK_SZPOW);
  IWRC(fsm->deallocate(fsm, kvb_addr, 1ULL << kvb_szpow), rc);
  return rc;
}

static iwrc _sblk_sync(SBLK *sblk) {
  assert(sblk && sblk->kvblk && sblk->addr);
  uint32_t lv;
  uint8_t *mm, *wp, bv;
#ifndef NDEBUG
  uint8_t *sp;
#endif
  IWKV iwkv = sblk->kvblk->db->iwkv;
  IWFS_FSM *fsm = &iwkv->fsm;
  if (!(sblk->flags & SBLK_DURTY) && !(sblk->kvblk->flags & KVBLK_DURTY)) {
    return 0;
  }
  iwrc rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCRET(rc);
  if (sblk->flags & SBLK_DURTY) {
    // SBLK: [u1:flags,kblk:u4,lvl:u1,p0:u4,n0-n29:u4,lkl:u1,lk:u61,pnum:u1,[pi1:u1,...pi63]]:u256
    wp = mm + sblk->addr;
#ifndef NDEBUG
    sp = wp;
#endif
    bv = sblk->flags & SBLK_PERSISTENT_FLAGS;
    memcpy(wp, &bv, 1);
    wp += 1;

    IW_WRITELV(wp, lv, ADDR2BLK(sblk->kvblk->addr));
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
  }
  if (sblk->kvblk->flags & KVBLK_DURTY) {
    _kvblk_sync(sblk->kvblk, mm);
  }
  fsm->release_mmap(fsm);
  sblk->flags &= ~SBLK_DURTY;
  return rc;
}

uint8_t _sblk_genlevel() {
  int8_t lvl;
  if (iwkv_next_level >= 0) {
    lvl = iwkv_next_level;
    iwkv_next_level = -1;
    return lvl;
  }
  uint32_t r = iwu_rand_u32();
  for (lvl = 0; lvl < SLEVELS && !(r & 1); ++lvl) {
    r >>= 1;
  }
  return IW_UNLIKELY(lvl >= SLEVELS) ? SLEVELS - 1 : lvl;
}

static iwrc _sblk_create(IWDB db, int8_t nlevel, int8_t kvbpow, SBLK **oblk) {
  iwrc rc;
  SBLK *sblk;
  KVBLK *kvblk;
  off_t baddr = 0, blen;
  IWFS_FSM *fsm = &db->iwkv->fsm;

  *oblk = 0;
  rc = _kvblk_create(db, kvbpow, &kvblk);
  RCRET(rc);
  rc = fsm->allocate(fsm, 1 << SBLK_SZPOW, &baddr, &blen,
                     IWFSM_ALLOC_NO_OVERALLOCATE | IWFSM_SOLID_ALLOCATED_SPACE);
  if (IW_UNLIKELY(rc)) {
    IWRC(_kvblk_destroy(&kvblk), rc);
    return rc;
  }
  sblk = calloc(1, sizeof(*sblk));
  if (!sblk) {
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    IWRC(_kvblk_destroy(&kvblk), rc);
    IWRC(fsm->deallocate(fsm, baddr, blen), rc);
    return rc;
  }
  sblk->addr = baddr;
  sblk->lvl = nlevel;
  sblk->kvblk = kvblk;
  sblk->flags |= SBLK_DURTY;
  rc = _aln_acquire_read(db, sblk->addr);
  if (!rc) {
    *oblk = sblk;
  }
  return rc;
}

static iwrc _sblk_at_dbg(IWDB db, off_t addr, SBLK **sblkp) {
  iwrc rc;
  blkn_t kblkn;
  uint32_t lv;
  uint8_t *mm, *rp;
#ifndef NDEBUG
  uint8_t *sp;
#endif
  IWFS_FSM *fsm = &db->iwkv->fsm;
  SBLK *sblk = calloc(1, sizeof(*sblk));
  if (!sblk) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  sblk->addr = addr;
  rc = fsm->probe_mmap(fsm, 0, &mm, 0);
  RCGO(rc, finish);
  rp = mm + addr;
#ifndef NDEBUG
  sp = rp;
#endif
  // SBLK: [u1:flags,kblk:u4,lvl:u1,p0:u4,n0-n29:u4,lkl:u1,lk:u61,pnum:u1,[pi1:u1,...pi63]]:u256
  memcpy(&sblk->flags, rp, 1);
  rp += 1;

  sblk->flags |= SBLK_NO_LOCK;

  IW_READLV(rp, lv, kblkn);
  assert(kblkn);
  memcpy(&sblk->lvl, rp, 1);
  rp += 1;
  rc = _kvblk_at2(db, BLK2ADDR(kblkn), mm, &sblk->kvblk);
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
  if (rc) {
    *sblkp = 0;
    _sblk_release(&sblk);
  }
  return rc;
}

static iwrc _sblk_at(IWDB db, off_t addr, sblk_flags_t flags, SBLK **sblkp) {
  iwrc rc;
  blkn_t kblkn;
  uint32_t lv;
  uint8_t *mm, *rp;
#ifndef NDEBUG
  uint8_t *sp;
#endif
  IWFS_FSM *fsm = &db->iwkv->fsm;
  SBLK *sblk = calloc(1, sizeof(*sblk));
  if (!sblk) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  sblk->addr = addr;
  if (!(flags & SBLK_NO_LOCK)) {
    rc = _aln_acquire_read(db, sblk->addr);
    RCRET(rc);
  }
  rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCGO(rc, finish);
  rp = mm + addr;
#ifndef NDEBUG
  sp = rp;
#endif
  // SBLK: [u1:flags,kblk:u4,lvl:u1,p0:u4,n0-n29:u4,lkl:u1,lk:u61,pnum:u1,[pi1:u1,...pi63]]:u256
  memcpy(&sblk->flags, rp, 1);
  rp += 1;

  sblk->flags |= flags;

  IW_READLV(rp, lv, kblkn);
  assert(kblkn);
  memcpy(&sblk->lvl, rp, 1);
  rp += 1;
  rc = _kvblk_at2(db, BLK2ADDR(kblkn), mm, &sblk->kvblk);
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
  fsm->release_mmap(fsm);
  if (rc) {
    *sblkp = 0;
    _sblk_release(&sblk);
  }
  return rc;
}

static int _sblk_find_pi(SBLK *sblk, const IWKV_val *key, const uint8_t *mm, bool *found) {
  uint8_t *k;
  uint32_t kl;
  int idx = 0,
      lb = 0,
      ub = sblk->pnum - 1;
  *found = false;
  if (sblk->pnum < 1) {
    return 0;
  }
  while (1) {
    int cr;
    idx = (ub + lb) / 2;
    _kvblk_peek_key(sblk->kvblk, sblk->pi[idx], mm, &k, &kl);
    assert(kl > 0);
    IW_CMP(cr, k, kl, key->data, key->size);
    if (!cr) {
      *found = true;
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
    _kvblk_peek_key(sblk->kvblk, sblk->pi[idx], mm, &k, &kl);
    assert(kl > 0);
    IW_CMP(cr, k, kl, key->data, key->size);
    if (!cr) {
      break;
    } else if (cr < 0) {
      lb = idx + 1;
      if (lb > ub) {
        idx = lb;
        sblk->pnum++;
        break;
      }
    } else {
      ub = idx - 1;
      if (lb > ub) {
        sblk->pnum++;
        break;
      }
    }
  }
  if (nels - idx > 0) {
    memmove(sblk->pi + idx + 1, sblk->pi + idx, nels - idx);
  }
  sblk->pi[idx] = nidx;
  return idx;
}

IW_INLINE iwrc _sblk_addkv2(SBLK *sblk, int8_t idx, const IWKV_val *key, const IWKV_val *val) {
  assert(key && key->size && key->data && val && idx >= 0);
  int8_t kvidx;
  KVBLK *kvblk = sblk->kvblk;
  IWFS_FSM *fsm = &kvblk->db->iwkv->fsm;
  if (sblk->pnum >= KVBLK_IDXNUM) {
    return _IWKV_ERROR_KVBLOCK_FULL;
  }
  iwrc rc = _kvblk_addkv(kvblk, key, val, &kvidx);
  RCRET(rc);
  if (sblk->pnum - idx > 0) {
    memmove(sblk->pi + idx + 1, sblk->pi + idx, sblk->pnum - idx);
  }
  if (idx == 0) {
    sblk->lkl = MIN(SBLK_LKLEN, key->size);
    memcpy(sblk->lk, key->data, sblk->lkl);
    if (key->size <= SBLK_LKLEN) {
      sblk->flags |= SBLK_FULL_LKEY;
    } else {
      sblk->flags &= ~SBLK_FULL_LKEY;
    }
  }
  sblk->pi[idx] = kvidx;
  sblk->pnum++;
  sblk->flags |= SBLK_DURTY;
  return 0;
}

IW_INLINE iwrc _sblk_addkv(SBLK *sblk, const IWKV_val *key, const IWKV_val *val) {
  assert(key && key->size && key->data && val);
  iwrc rc;
  int8_t kvidx;
  uint8_t *mm;
  KVBLK *kvblk = sblk->kvblk;
  IWFS_FSM *fsm = &kvblk->db->iwkv->fsm;
  if (sblk->pnum >= KVBLK_IDXNUM) {
    return _IWKV_ERROR_KVBLOCK_FULL;
  }
  rc = _kvblk_addkv(kvblk, key, val, &kvidx);
  RCRET(rc);
  rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCRET(rc);
  if (_sblk_insert_pi(sblk, kvidx, key, mm) == 0) { // the lowest key inserted
    sblk->lkl = MIN(SBLK_LKLEN, key->size);
    memcpy(sblk->lk, key->data, sblk->lkl);
    if (key->size <= SBLK_LKLEN) {
      sblk->flags |= SBLK_FULL_LKEY;
    } else {
      sblk->flags &= ~SBLK_FULL_LKEY;
    }
  }
  fsm->release_mmap(fsm);
  sblk->flags |= SBLK_DURTY;
  return 0;
}

IW_INLINE iwrc _sblk_updatekv(SBLK *sblk, int8_t idx, const IWKV_val *key, const IWKV_val *val) {
  assert(idx >= 0 && idx < sblk->pnum);
  iwrc rc;
  KVBLK *kvblk = sblk->kvblk;
  int8_t kvidx = sblk->pi[idx];
  rc = _kvblk_updatev(kvblk, &kvidx, key, val);
  RCRET(rc);
  sblk->pi[idx] = kvidx;
  sblk->flags |= SBLK_DURTY;
  return 0;
}

IW_INLINE iwrc _sblk_rmkv(SBLK *sblk, uint8_t idx) {
  iwrc rc;
  KVBLK *kvblk = sblk->kvblk;
  IWFS_FSM *fsm = &kvblk->db->iwkv->fsm;
  assert(idx < sblk->pnum && sblk->pi[idx] < KVBLK_IDXNUM);
  rc = _kvblk_rmkv(kvblk, sblk->pi[idx], 0);
  RCRET(rc);
  sblk->pnum--;
  sblk->flags |= SBLK_DURTY;
  if (idx < sblk->pnum && sblk->pnum > 0) {
    memmove(sblk->pi + idx, sblk->pi + idx + 1, sblk->pnum - idx);
  }
  if (idx == 0) {
    // Lowest key removed, replace it with the next key or reset
    if (sblk->pnum > 0) {
      uint32_t klen;
      uint8_t *kbuf, *mm;
      rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
      RCRET(rc);
      _kvblk_peek_key(sblk->kvblk, sblk->pi[idx], mm, &kbuf, &klen);
      sblk->lkl = MIN(SBLK_LKLEN, klen);
      memcpy(sblk->lk, kbuf, sblk->lkl);
      fsm->release_mmap(fsm);
      if (sblk->lkl <= SBLK_LKLEN) {
        sblk->flags |= SBLK_FULL_LKEY;
      } else {
        sblk->flags &= ~SBLK_FULL_LKEY;
      }
    } else {
      sblk->lkl = 0;
    }
  }
  return rc;
}

IW_INLINE iwrc _sblk_create2(IWDB db,
                             int8_t nlevel,
                             int8_t kvbpow,
                             const IWKV_val *key,
                             IWKV_val *val,
                             SBLK **oblk) {
  SBLK *sblk;
  *oblk = 0;
  iwrc rc = _sblk_create(db, nlevel, kvbpow, &sblk);
  RCRET(rc);
  rc = _sblk_addkv(sblk, key, val);
  if (rc) {
    _sblk_destroy(&sblk);
  } else {
    *oblk = sblk;
  }
  return rc;
}

IW_INLINE iwrc _sblk_write_upgrade(SBLK *sblk) {
  iwrc rc = (sblk->flags & (SBLK_WRITE_UPGRADED | SBLK_NO_LOCK)) ? 0 : _aln_write_upgrade(sblk->kvblk->db, sblk->addr);
  if (!rc) {
    sblk->flags |= SBLK_WRITE_UPGRADED;
  }
  return rc;
}

IW_INLINE iwrc _db_write_upgrade(IWLCTX *lx) {
  iwrc rc = (lx->smask & IWLCTX_DB_WRITE_UPGRADED) ? 0 : _aln_write_upgrade(lx->db, lx->db->addr);
  if (!rc) {
    lx->smask |= IWLCTX_DB_WRITE_UPGRADED;
  }
  return rc;
}

static const char *_kv_ecodefn(locale_t locale, uint32_t ecode) {
  if (!(ecode > _IWKV_ERROR_START && ecode < _IWKV_ERROR_END)) {
    return 0;
  }
  switch (ecode) {
    case IWKV_ERROR_NOTFOUND:
      return "Key not found. (IWKV_ERROR_NOTFOUND)";
    case IWKV_ERROR_KEY_EXISTS:
      return "Key exists. (IWKV_ERROR_KEY_EXISTS)";
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

IW_INLINE int _lx_sblk_cmp_key(IWLCTX *lx, SBLK *sblk, uint8_t *mm) {
  int res;
  uint8_t *k;
  uint32_t kl;
  const IWKV_val *key = lx->key;
  if (sblk->pnum < 1) { // empty block
    return -1;
  }
  if (key->size < sblk->lkl) {
    IW_CMP(res, sblk->lk, sblk->lkl, key->data, key->size);
    return res;
  }
  if (sblk->flags & SBLK_FULL_LKEY) {
    k = sblk->lk;
    kl = sblk->lkl;
  } else {
    _kvblk_peek_key(sblk->kvblk, sblk->pi[0] /* lower key index */, mm, &k, &kl);
    if (!kl) {
      return -1;
    }
  }
  IW_CMP(res, k, kl, key->data, key->size);
  return res;
}

static iwrc _lx_roll_forward(IWLCTX *lx) {
  SBLK *sblk;
  blkn_t blkn;
  uint8_t *mm, lvl = lx->lvl;
  IWDB db = lx->db;
  IWFS_FSM *fsm  = &db->iwkv->fsm;
  iwrc rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCRET(rc);
  while ((blkn = (lx->lower ? lx->lower->n[lvl] : db->n[lvl]))) {
    off_t blkaddr = BLK2ADDR(blkn);
    if (IW_UNLIKELY(lx->nlvl != -1 && lvl < lx->nlvl)) {
      int8_t ulvl = lvl + 1;
      if (lx->pupper[ulvl] && lx->pupper[ulvl]->addr == blkaddr) {
        sblk = lx->pupper[ulvl];
      } else if (lx->plower[ulvl] && lx->plower[ulvl]->addr == blkaddr) {
        sblk = lx->plower[ulvl];
      } else {
        rc = _sblk_at(db, blkaddr, lx->sbflags, &sblk);
      }
    } else {
      if (lx->upper && lx->upper->addr == blkaddr) {
        break;
      } else {
        rc = _sblk_at(db, blkaddr, lx->sbflags, &sblk);
      }
    }
    RCGO(rc, finish);
    if (_lx_sblk_cmp_key(lx, sblk, mm) > 0) { // upper > key
      if (lx->upper && !(lx->upper->flags & SBLK_PINNED)) {
        _sblk_release(&lx->upper);
      }
      lx->upper = sblk;
      break;
    } else {
      if (lx->lower && !(lx->lower->flags & SBLK_PINNED)) {
        _sblk_release(&lx->lower);
      }
      lx->lower = sblk;
    }
  }
finish:
  IWRC(fsm->release_mmap(fsm), rc);
  return rc;
}

static iwrc _lx_find_bounds(IWLCTX *lx) {
  iwrc rc;
  SBLK *sblk;
  IWDB db = lx->db;
  if (!(lx->smask & IWLCTX_DB_RDLOCKED)) {
    rc = _aln_acquire_read(db, db->addr);
    RCRET(rc);
    lx->smask |= IWLCTX_DB_RDLOCKED;
  }
  if (IW_UNLIKELY(!db->n[db->lvl])) { // empty skiplist chain
    return 0;
  }
  for (int lvl = db->lvl; lvl >= 0;) {
    lx->lvl = lvl;
    rc = _lx_roll_forward(lx);
    RCRET(rc);
    blkn_t ub = lx->upper ? ADDR2BLK(lx->upper->addr) : 0;
    do {
      lx->lvl = lvl;
      if (lx->nlvl >= lvl) {
        if (lx->upper) {
          lx->upper->flags |= SBLK_PINNED;
          lx->pupper[lvl] = lx->upper;
        }
        if (lx->lower) {
          lx->lower->flags |= SBLK_PINNED;
          lx->plower[lvl] = lx->lower;
        }
      }
    } while (lvl-- > 0 && (lx->lower ? lx->lower->n[lvl] : db->n[lvl]) == ub);
  }
  return rc;
}

static void _lx_release(IWLCTX *lx) {
  SBLK *laddr = 0;
  if (lx->nb && lx->nb != lx->lower) {
    _sblk_release(&lx->nb);
  }
  if (lx->nlvl > -1) {
    for (int i = 0; i <= lx->nlvl; ++i) {
      if (lx->pupper[i]) {
        if (lx->pupper[i] != laddr) {
          laddr = lx->pupper[i];
          _sblk_release(&lx->pupper[i]);
        }
        lx->pupper[i] = 0;
      }
    }
    for (int i = 0; i <= lx->nlvl; ++i) {
      if (lx->plower[i]) {
        if (lx->plower[i] != laddr) {
          laddr = lx->plower[i];
          _sblk_release(&lx->plower[i]);
        }
        lx->plower[i] = 0;
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
  lx->upper = 0;
  lx->lower = 0;
  if (lx->smask & IWLCTX_DB_RDLOCKED) {
    lx->smask &= ~IWLCTX_DB_RDLOCKED;
    _aln_release(lx->db, lx->db->addr);
  }
}

static iwrc _lx_split_addkv(IWLCTX *lx, int idx, SBLK *sblk) {
  assert(lx && lx->nlvl > -1);
  iwrc rc;
  SBLK *nb = 0;
  uint8_t kvbpow = 0;
  IWDB db = lx->db;
  IWFS_FSM *fsm = &lx->db->iwkv->fsm;
  int pivot = (KVBLK_IDXNUM / 2) + 1; // 32
  blkn_t nblk;

  if (sblk->pnum < KVBLK_IDXNUM) {
    rc = _sblk_write_upgrade(sblk);
    RCRET(rc);
    rc = _sblk_addkv(sblk, lx->key, lx->val);
    RCRET(rc);
    return _sblk_sync(sblk);
  }

  if (idx == sblk->pnum && lx->upper && lx->upper->pnum < KVBLK_IDXNUM) {
    // Good to place lv into right(upper) block
    rc = _sblk_write_upgrade(lx->upper);
    RCRET(rc);
    rc = _sblk_addkv(lx->upper, lx->key, lx->val);
    RCRET(rc);
    return _sblk_sync(lx->upper);
  }

  if (idx > 0 && idx < sblk->pnum) {
    // Partial split required
    // Compute space required for the new sblk which stores kv pairs after pivot `idx`
    size_t sz = 0;
    for (int i = pivot; i < sblk->pnum; ++i) {
      sz += sblk->kvblk->pidx[sblk->pi[i]].len;
    }
    if (idx > pivot) {
      sz += IW_VNUMSIZE(lx->key->size) + lx->key->size + lx->val->size;
    }
    kvbpow = iwlog2_64(KVBLK_MAX_NKV_SZ + sz);
  }

  rc = _sblk_write_upgrade(sblk);
  RCRET(rc);

  // Ok we need a new node
  rc = _sblk_create(db, lx->nlvl, kvbpow, &nb);
  RCRET(rc);
  nblk = ADDR2BLK(nb->addr);

  if (idx == sblk->pnum) {
    // Upper side
    rc = _sblk_addkv(nb, lx->key, lx->val);
    RCGO(rc, finish);
  } else if (idx == 0) {
    // Lowest side
    SBLK sblkp, nbkp; //backup
    KVBLK *nkvb = nb->kvblk;
    memcpy(&sblkp, sblk, sizeof(*sblk));
    memcpy(&nbkp, nb, sizeof(*nb));
    nb->kvblk = sblk->kvblk;
    nb->lkl = sblk->lkl;
    nb->pnum = sblk->pnum;
    nb->flags = sblk->flags;
    nb->p0 = ADDR2BLK(sblk->addr);
    memcpy(nb->lk, sblk->lk, sblk->lkl);
    memcpy(nb->pi, sblk->pi, sblk->pnum);
    memcpy(nb->n, sblk->n, sizeof(sblk->n));
    memset(sblk->pi, 0, sizeof(sblk->pi));
    sblk->kvblk = nkvb;
    sblk->pnum = 0;
    sblk->lkl = 0;
    sblk->flags &= ~SBLK_FULL_LKEY;
    sblk->flags |= SBLK_DURTY;
    nb->flags |= SBLK_DURTY;
    // Link nodes
    for (int i = 0; i <= nb->lvl; ++i) {
      sblk->n[i] = ADDR2BLK(nb->addr);
    }
    if (nb->n[0]) {
      if (lx->pupper[0] && nb->n[0] == ADDR2BLK(lx->pupper[0]->addr)) {
        lx->pupper[0]->p0 = ADDR2BLK(nb->addr);
        lx->pupper[0]->flags |= SBLK_DURTY;
      } else {
        SBLK *ub;
        rc = _sblk_at(lx->db, BLK2ADDR(nb->n[0]), 0, &ub);
        RCGO(rc, restore1);
        rc = _sblk_write_upgrade(ub);
        RCGO(rc, restore1);
        ub->p0 = ADDR2BLK(nb->addr);
        rc = _sblk_sync(ub);
        RCGO(rc, restore1);
        _sblk_release(&ub);
      }
    }
    rc = _sblk_addkv(sblk, lx->key, lx->val);
    if (rc) {
restore1:
      // Restore initial state
      memcpy(sblk, &sblkp, sizeof(*sblk));
      memcpy(nb, &nbkp, sizeof(*nb));
      goto finish;
    }
  } else {
    // We are in the middle
    // Do partial split
    // Move kv pairs into new `nb`
    uint8_t *mm;
    IWKV_val key, val;
    for (int i = pivot, end = sblk->pnum; i < end; ++i) {
      rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
      RCBREAK(rc);
      rc = _kvblk_getkv(mm, sblk->kvblk, sblk->pi[i], &key, &val);
      assert(key.size);
      fsm->release_mmap(fsm);
      RCBREAK(rc);
      rc = _sblk_addkv(nb, &key, &val);
      _kv_dispose(&key, &val);
      RCBREAK(rc);
      sblk->kvblk->pidx[sblk->pi[i]].len = 0;
      sblk->kvblk->pidx[sblk->pi[i]].off = 0;
      sblk->pnum--;
      if (i == pivot) {
        sblk->kvblk->zidx = sblk->pi[i];
      }
    }
    // sync maxoff
    sblk->kvblk->maxoff = 0;
    for (int i = 0; i < KVBLK_IDXNUM; ++i) {
      if (sblk->kvblk->pidx[i].off > sblk->kvblk->maxoff) {
        sblk->kvblk->maxoff = sblk->kvblk->pidx[i].off;
      }
    }
    if (idx > pivot) {
      rc = _sblk_addkv(nb, lx->key, lx->val);
    } else {
      rc = _sblk_addkv(sblk, lx->key, lx->val);
    }
    RCGO(rc, finish);
  }
  // Link blocks
  if (idx > 0) {
    nb->p0 = ADDR2BLK(sblk->addr);
    for (int i = lx->nlvl; i >= 0; --i) {
      if (lx->plower[i]) {
        lx->plower[i]->n[i] = nblk;
        lx->plower[i]->flags |= SBLK_DURTY;
      }
      if (lx->pupper[i]) {
        if (i == 0) {
          lx->pupper[i]->p0 = nblk;
          lx->pupper[i]->flags |= SBLK_DURTY;
        }
        nb->n[i] = ADDR2BLK(lx->pupper[i]->addr);
      }
    }
  }
  // Sync blocks
  for (int i = lx->nlvl; i >= 0; --i) {
    for (int j = 0; j < 2; ++j) {
      SBLK *sb = (j % 2) ? lx->pupper[i] : lx->plower[i];
      if (sb && (sb->flags & SBLK_DURTY)) {
        rc = _sblk_write_upgrade(sb);
        RCGO(rc, finish);
        rc = _sblk_sync(sb);
        RCGO(rc, finish);
      }
    }
  }
finish:
  if (rc) {
    lx->nb = 0;
    IWRC(_sblk_destroy(&nb), rc);
  } else {
    lx->nb = nb;
    IWRC(_sblk_sync(nb), rc);
  }
  return rc;
}

IW_INLINE WUR iwrc _lx_addkv(IWLCTX *lx, SBLK *sblk) {
  int idx;
  bool found;
  uint8_t *mm;
  IWFS_FSM *fsm = &lx->db->iwkv->fsm;
  iwrc rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCGO(rc, finish);
  idx = _sblk_find_pi(sblk, lx->key, mm, &found);
  fsm->release_mmap(fsm);
  if (found && (lx->opf & IWKV_NO_OVERWRITE)) {
    rc = IWKV_ERROR_KEY_EXISTS;
    goto finish;
  }
  if (IW_UNLIKELY(!found && sblk->pnum >= KVBLK_IDXNUM)) {
    if (lx->nlvl < 0) {
      return _IWKV_ERROR_REQUIRE_NLEVEL;
    }
    rc = _lx_split_addkv(lx, idx, sblk);
    RCGO(rc, finish);
  } else {
    rc = _sblk_write_upgrade(sblk);
    RCGO(rc, finish);
    if (!found) {
      rc = _sblk_addkv2(sblk, idx, lx->key, lx->val);
    } else {
      rc = _sblk_updatekv(sblk, idx, lx->key, lx->val);
    }
    RCGO(rc, finish);
    rc = _sblk_sync(sblk);
    RCGO(rc, finish);
  }
finish:
  return rc;
}

iwrc _lx_put_lr(IWLCTX *lx) {
  iwrc rc;
  IWDB db = lx->db;
  int8_t nlvl = -1;
  bool dbsync = false;

start:
  rc = _lx_find_bounds(lx);
  RCGO(rc, finish);

  if (IW_LIKELY(lx->lower)) {
    rc = _lx_addkv(lx, lx->lower);
    if (rc == _IWKV_ERROR_REQUIRE_NLEVEL) {
      rc = 0;
      _lx_release(lx);
      lx->nlvl = _sblk_genlevel();
      goto start;
    }
  } else if (lx->upper) {
    // lower than the first block in db
    SBLK *ub = 0;
    rc = _lx_addkv(lx, lx->upper);
    if (rc == _IWKV_ERROR_REQUIRE_NLEVEL) {
      lx->nlvl = _sblk_genlevel();
      for (int i = lx->nlvl; i >= 0; --i) {
        lx->plower[i] = lx->upper;
        if (lx->upper->n[i]) {
          if (!ub || lx->upper->n[i] != ADDR2BLK(ub->addr)) {
            rc = _sblk_at(db, BLK2ADDR(lx->upper->n[i]), 0, &ub);
            RCGO(rc, finish);
          }
          lx->pupper[i] = ub;
        }
      }
      rc = _lx_addkv(lx, lx->upper);
      RCGO(rc, finish);
    }
  } else {
    // empty db
    nlvl = _sblk_genlevel();
    rc = _sblk_create2(db, nlvl, 0, lx->key, lx->val, &lx->nb);
    RCGO(rc, finish);
    rc = _sblk_sync(lx->nb);
    RCGO(rc, finish);
  }
  if (lx->nb) {
    int exlv = -1;
    blkn_t nblk = ADDR2BLK(lx->nb->addr);
    if (IW_UNLIKELY(nlvl >= 0)) { // first sblock in sv
      exlv = 0;
    } else if (lx->nb->lvl > db->lvl) { // new node with higher lever than in db
      exlv = db->lvl + 1;
    }
    if (!lx->nb->n[0] && lx->db->last_sblkn != nblk) {
      rc = _db_write_upgrade(lx);
      RCGO(rc, finish);
      db->last_sblkn = nblk;
      dbsync = true;
    }
    if (exlv >= 0 && exlv <= lx->nb->lvl) {
      rc = _db_write_upgrade(lx);
      RCGO(rc, finish);
      for (int i = exlv; i <= lx->nb->lvl; ++i) {
        db->n[i] = nblk;
      }
      db->lvl = lx->nb->lvl;
      dbsync = true;
    }
    if (dbsync) {
      rc = _db_sync2(db);
    }
  }
finish:
  _lx_release(lx);
  return rc;
}

IW_INLINE iwrc _lx_get_lr(IWLCTX *lx) {
  iwrc rc = _lx_find_bounds(lx);
  RCRET(rc);
  if (lx->lower) {
    uint8_t *mm;
    IWFS_FSM *fsm = &lx->db->iwkv->fsm;
    bool found;
    rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
    RCRET(rc);
    int idx = _sblk_find_pi(lx->lower, lx->key, mm, &found);
    if (found) {
      idx = lx->lower->pi[idx];
      rc = _kvblk_getvalue(lx->lower->kvblk, mm, idx, lx->val);
    } else {
      rc = IWKV_ERROR_NOTFOUND;
    }
    fsm->release_mmap(fsm);
  } else {
    lx->val->size = 0;
    lx->val->data = 0;
    rc = IWKV_ERROR_NOTFOUND;
  }
  _lx_release(lx);
  return rc;
}

iwrc _lx_del_lr(IWLCTX *lx, bool wl) {
  int idx, rci;
  bool found;
  uint8_t *mm;
  iwrc rc;
  IWFS_FSM *fsm = &lx->db->iwkv->fsm;

  rc = _lx_find_bounds(lx);
  RCRET(rc);
  if (!lx->lower) {
    _lx_release(lx);
    return IWKV_ERROR_NOTFOUND;
  }
  rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCRET(rc);
  idx = _sblk_find_pi(lx->lower, lx->key, mm, &found);
  fsm->release_mmap(fsm);
  if (!found) {
    _lx_release(lx);
    return IWKV_ERROR_NOTFOUND;
  }
  rc = _sblk_write_upgrade(lx->lower);
  RCRET(rc);
  rc = _sblk_rmkv(lx->lower, idx);
  if (IW_LIKELY(lx->lower->pnum > 0)) {
    IWRC(_sblk_sync(lx->lower), rc);
  } else {
    if (!wl) {
      _lx_release(lx);
      lx->nlvl = lx->lower->lvl;
      lx->sbflags = SBLK_NO_LOCK;
      return _IWKV_ERROR_REQUIRE_WL;
    }
    // todo:
  }
// finish:
  _lx_release(lx);
  return rc;
}

//--------------------------  PUBLIC API

iwrc iwkv_init(void) {
  static int _kv_initialized = 0;
  if (!__sync_bool_compare_and_swap(&_kv_initialized, 0, 1)) {
    return 0;  // initialized already
  }
  int64_t t;
  iwrc rc = iw_init();
  RCRET(rc);
  rc = iwp_current_time_ms(&t);
  RCRET(rc);
  iwu_rand_seed(t / 1000);
  return iwlog_register_ecodefn(_kv_ecodefn);
}

iwrc iwkv_open(const IWKV_OPTS *opts, IWKV *iwkvp) {
  assert(iwkvp && opts);
  iwrc rc = 0;
  uint32_t lv;
  uint64_t llv;
  uint8_t *rp, *mm;
  rc = iwkv_init();
  RCRET(rc);
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
  iwkv->oflags = oflags;
  IWFS_FSM_STATE fsmstate;
  IWFS_FSM_OPTS fsmopts = {
    .exfile = {
      .file = {
        .path       = opts->path,
        .omode      = omode,
        .lock_mode  = (oflags & IWKV_RDONLY) ? IWP_RLOCK : IWP_WLOCK
      },
      .rspolicy     = iw_exfile_szpolicy_fibo
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

  if (fsmstate.exfile.file.ostatus & IWFS_OPEN_NEW) {
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
    rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
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
  if (iwkv->oflags & IWKV_RDONLY) {
    return IW_ERROR_READONLY;
  }
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
  int rci;
  iwrc rc = 0;
  IWKV iwkv = *iwkvp;
  IWKV_API_WLOCK(iwkv, rci);
  iwkv->isopen = false;
  IWDB db = iwkv->dbfirst;
  while (db) {
    IWDB ndb = db->next;
    _db_release_lw(&db);
    db = ndb;
  }
  IWRC(iwkv->fsm.close(&iwkv->fsm), rc);
  if (iwkv->dbs) {
    kh_destroy(DBS, iwkv->dbs);
    iwkv->dbs = 0;
  }
  IWKV_API_UNLOCK(iwkv, rci, rc);
  pthread_rwlock_destroy(&iwkv->rwl_api);
  free(iwkv);
  *iwkvp = 0;
  return rc;
}

iwrc iwkv_db(IWKV iwkv, uint32_t dbid, iwdb_flags_t flags, IWDB *dbp) {
  IWKV_ENSURE_OPEN(iwkv);
  int rci;
  iwrc rc = 0;
  IWDB db = 0;
  *dbp = 0;
  IWKV_API_RLOCK(iwkv, rci);
  khiter_t ki = kh_get(DBS, iwkv->dbs, dbid);
  if (ki != kh_end(iwkv->dbs)) {
    db = kh_value(iwkv->dbs, ki);
  }
  IWKV_API_UNLOCK(iwkv, rci, rc);
  RCRET(rc);
  if (db) {
    *dbp = db;
    return 0;
  }
  if (iwkv->oflags & IWKV_RDONLY) {
    return IW_ERROR_READONLY;
  }
  IWKV_API_WLOCK(iwkv, rci);
  ki = kh_get(DBS, iwkv->dbs, dbid);
  if (ki != kh_end(iwkv->dbs)) {
    db = kh_value(iwkv->dbs, ki);
  }
  if (db) {
    *dbp = db;
  } else {
    rc = _db_create_lw(iwkv, dbid, flags, dbp);
  }
  IWKV_API_UNLOCK(iwkv, rci, rc);
  return rc;
}

iwrc iwkv_db_destroy(IWDB *dbp) {
  assert(dbp && *dbp);
  int rci;
  iwrc rc = 0;
  IWKV iwkv = (*dbp)->iwkv;
  if (iwkv->oflags & IWKV_RDONLY) {
    return IW_ERROR_READONLY;
  }
  IWKV_ENSURE_OPEN(iwkv);
  IWKV_API_WLOCK(iwkv, rci);
  rc = _db_destroy_lw(dbp);
  IWKV_API_UNLOCK(iwkv, rci, rc);
  return rc;
}

iwrc iwkv_put(IWDB db, const IWKV_val *key, const IWKV_val *val, iwkv_opflags opflags) {
  if (!db || !key || !key->size || !val) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (db->iwkv->oflags & IWKV_RDONLY) {
    return IW_ERROR_READONLY;
  }
  int rci;
  iwrc rc = 0;
  IWLCTX lx = {
    .db = db,
    .key = key,
    .val = (IWKV_val *) val,
    .nlvl = -1,
    .op = IWLCTX_PUT,
    .opf = opflags
  };
  IWKV_API_RLOCK(db->iwkv, rci);
  rc = _lx_put_lr(&lx);
  IWKV_API_UNLOCK(db->iwkv, rci, rc);
  return rc;
}

iwrc iwkv_get(IWDB db, const IWKV_val *key, IWKV_val *oval) {
  if (!db || !key || !oval) {
    return IW_ERROR_INVALID_ARGS;
  }
  int rci;
  iwrc rc = 0;
  IWLCTX lx = {
    .db = db,
    .key = key,
    .val = oval,
    .nlvl = -1
  };
  oval->size = 0;
  IWKV_API_RLOCK(db->iwkv, rci);
  rc = _lx_get_lr(&lx);
  IWKV_API_UNLOCK(db->iwkv, rci, rc);
  return rc;
}

iwrc iwkv_del(IWDB db, const IWKV_val *key) {
  if (!db || !key) {
    return IW_ERROR_INVALID_ARGS;
  }
  int rci;
  iwrc rc = 0;
  IWLCTX lx = {
    .db = db,
    .key = key,
    .nlvl = -1,
    .op = IWLCTX_DEL
  };
  IWKV_API_RLOCK(db->iwkv, rci);
  rc = _lx_del_lr(&lx, false);
  IWKV_API_UNLOCK(db->iwkv, rci, rc);
  if (rc == _IWKV_ERROR_REQUIRE_WL) {
    IWKV_API_WLOCK(db->iwkv, rci);
    rc = _lx_del_lr(&lx, true);
    IWKV_API_UNLOCK(db->iwkv, rci, rc);
  }
  return rc;
}

void iwkv_kv_dispose(IWKV_val *key, IWKV_val *val) {
  _kv_dispose(key, val);
}

//--------------------------  DEBUG STAFF

void iwkvd_kvblk(FILE *f, KVBLK *kb) {
  assert(f && kb && kb->addr);
  uint8_t *mm;
  uint8_t *kbuf, *vbuf;
  uint32_t klen, vlen;
  IWFS_FSM *fsm = &kb->db->iwkv->fsm;
  blkn_t blkn = ADDR2BLK(kb->addr);
  fprintf(f, "\n === KVBLK[%u] maxoff=%u, zidx=%d, idxsz=%d, szpow=%u, flg=%x, db=%d\n",
          blkn, kb->maxoff, kb->zidx, kb->idxsz, kb->szpow, kb->flags, kb->db->id);

  iwrc rc = fsm->probe_mmap(fsm, 0, &mm, 0);
  if (rc) {
    iwlog_ecode_error3(rc);
    return;
  }
  for (int i = 0; i < KVBLK_IDXNUM; ++i) {
    KVP *kvp = &kb->pidx[i];
    _kvblk_peek_key(kb, i, mm, &kbuf, &klen);
    _kvblk_peek_val(kb, i, mm, &vbuf, &vlen);
    fprintf(f, "\n    %02d: [%04d, %02d, %02d]: %.*s:%.*s",
            i, kvp->off, kvp->len, kvp->ridx,
            klen, kbuf, vlen, vbuf);
  }
  fprintf(f, "\n");
}

void iwkvd_sblk(FILE *f, SBLK *sb, int flags) {
  assert(sb && sb->addr && sb->kvblk);
  char lkbuf[SBLK_LKLEN + 1] = {0};
  if (sb->lkl) {
    memcpy(lkbuf, sb->lk, sb->lkl);
  }
  uint8_t *mm;
  uint8_t *kbuf, *vbuf;
  uint32_t klen, vlen;
  IWFS_FSM *fsm = &sb->kvblk->db->iwkv->fsm;
  blkn_t blkn = ADDR2BLK(sb->addr);
  fprintf(f, "\n === SBLK[%u] lvl=%d, pnum=%d, flg=%x, kvzidx=%d, db=%d",
          blkn,
          ((IWKVD_PRINT_NO_LEVEVELS & flags) ? -1 : sb->lvl),
          sb->pnum, sb->flags, sb->kvblk->zidx, sb->kvblk->db->id);
  fprintf(f, "\n === SBLK[%u] szpow=%d, lkl=%d, lk=%s\n", blkn, sb->kvblk->szpow, sb->lkl, lkbuf);
  iwrc rc = fsm->probe_mmap(fsm, 0, &mm, 0);
  if (rc) {
    iwlog_ecode_error3(rc);
    return;
  }
  for (int i = 0, j = 0; i < sb->pnum; ++i, ++j) {
    if (j == 3) {
      fputc('\n', f);
      j = 0;
    }
    if (j == 0) {
      fprintf(f, " === SBLK[%u]", blkn);
    }
    _kvblk_peek_key(sb->kvblk, sb->pi[i], mm, &kbuf, &klen);
    if (flags & IWKVD_PRINT_VALS) {
      _kvblk_peek_val(sb->kvblk, sb->pi[i], mm, &vbuf, &vlen);
      fprintf(f, "    [%02d,%02d] %.*s:%.*s", i, sb->pi[i], klen, kbuf, vlen, vbuf);
    } else {
      fprintf(f, "    [%02d,%02d] %.*s", i, sb->pi[i], klen, kbuf);
    }
  }
  fprintf(f, "\n\n");
}

void iwkvd_db(FILE *f, IWDB db, int flags) {
  assert(db);
  SBLK *sb;
  iwrc rc;
  blkn_t dblk = ADDR2BLK(db->addr);
  blkn_t blk = db->n[0];
  fprintf(f, "\n\n== DB[%d] lvl=%d, blk=%u, flg=%x",
          db->id,
          ((IWKVD_PRINT_NO_LEVEVELS & flags) ? -1 : db->lvl),
          dblk,
          db->flg);
  while (blk) {
    rc = _sblk_at_dbg(db, BLK2ADDR(blk), &sb);
    if (rc) {
      iwlog_ecode_error3(rc);
      return;
    }
    iwkvd_sblk(f, sb, flags);
    if (!sb->n[0]) {
      _sblk_release(&sb);
      break;
    } else {
      blk = sb->n[0];
    }
    _sblk_release(&sb);
  }
}
