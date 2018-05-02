#include "iwkv.h"
#include "iwlog.h"
#include "iwarr.h"
#include "iwutils.h"
#include "iwfsmfile.h"
#include "iwdlsnr.h"
#include "iwal.h"
#include "khash.h"
#include "ksort.h"
#include <pthread.h>
#include <stdatomic.h>

#include "iwcfg.h"

// IWKV magic number
#define IWKV_MAGIC 0x69776b76

// IWKV file format version
#define IWKV_FORMAT 0

// IWDB magic number
#define IWDB_MAGIC 0x69776462

// Max key + value size: 255Mb
#define IWKV_MAX_KVSZ 0xfffffff

#ifdef IW_32
// Max database file size on 32 bit systems: 2Gb
# define IWKV_MAX_DBSZ 0x7fffffff
#else
// Max database file size: ~512Gb
# define IWKV_MAX_DBSZ 0x7fffffff80
#endif

// Size of KV fsm block as power of 2
#define IWKV_FSM_BPOW 7

// Length of KV fsm header in bytes
#define KVHDRSZ 255

// [u1:flags,lvl:u1,lkl:u1,pnum:u1,p0:u4,kblk:u4,[pi0:u1,... pi32],n0-n23:u4,lk:u116]:u256 // SBLK

// Number of skip list levels
#define SLEVELS 24

#define AANUM (2 * SLEVELS + 2 /* levels + (new block created) + (db block may be updated) */)

// Lower key length in SBLK
#define SBLK_LKLEN 116

// Lower key padding
#define LKPAD 0

// Size of database start block in bytes
#define DB_SZ (2 * (1 << IWKV_FSM_BPOW))

// Size of `SBLK` in bytes
#define SBLK_SZ (2 * (1 << IWKV_FSM_BPOW))

// Number of `KV` blocks in KVBLK
#define KVBLK_IDXNUM 32

// Initial `KVBLK` size power of 2
#define KVBLK_INISZPOW 9

// KVBLK header size: blen:u1,idxsz:u2
#define KVBLK_HDRSZ 3

// Max kvp offset bytes
#define KVP_MAX_OFF_VLEN 8

// Max kvp len 0xfffffffULL bytes
#define KVP_MAX_LEN_VLEN 5

#define KVBLK_MAX_IDX_SZ ((KVP_MAX_OFF_VLEN + KVP_MAX_LEN_VLEN) * KVBLK_IDXNUM)

// Max non KV size [blen:u1,idxsz:u2,[ps1:vn,pl1:vn,...,ps63,pl63]
#define KVBLK_MAX_NKV_SZ (KVBLK_HDRSZ + KVBLK_MAX_IDX_SZ)

#define ADDR2BLK(addr_) ((addr_) >> IWKV_FSM_BPOW)

#define BLK2ADDR(blk_) (((off_t) (blk_)) << IWKV_FSM_BPOW)

struct IWKV;
struct IWDB;

typedef uint32_t blkn_t;
typedef uint32_t dbid_t;

/* Key/Value pair stored in `KVBLK` */
typedef struct KV {
  size_t keysz;
  size_t valsz;
  uint8_t *key;
  uint8_t *val;
} KV;

/* Ket/Value (KV) index: Offset and length. */
typedef struct KVP {
  off_t off;      /**< KV block offset relative to `end` of KVBLK */
  uint32_t len;   /**< Length of kv pair block */
  uint8_t ridx;   /**< Position of the auctually persisted slot in `KVBLK` */
} KVP;

typedef enum {
  KVBLK_DURTY = 1 /**< KVBLK data is durty and should be flushed to mm */
} kvblk_flags_t;

typedef enum {
  RMKV_SYNC = 1,
  RMKV_NO_RESIZE = 1 << 1
} kvblk_rmkv_opts_t;

/* KVBLK: [szpow:u1,idxsz:u2,[ps0:vn,pl0:vn,..., ps32,pl32]____[[KV],...]] */
typedef struct KVBLK {
  IWDB db;
  off_t addr;                 /**< Block address */
  off_t maxoff;               /**< Max pair offset */
  uint16_t idxsz;             /**< Size of KV pairs index in bytes */
  int8_t zidx;                /**< Index of first empty pair slot (zero index), or -1 */
  uint8_t szpow;              /**< Block size as power of 2 */
  kvblk_flags_t flags;        /**< Flags */
  KVP pidx[KVBLK_IDXNUM];     /**< KV pairs index */
} KVBLK;

typedef enum {
  SBLK_FULL_LKEY    = 1,       /**< The lowest `SBLK` key is fully contained in `SBLK`. Persistent flag. */
  SBLK_DB           = 1 << 3,  /**< This block is the start database block. */
  SBLK_DURTY        = 1 << 4,  /**< Block data changed, block marked as durty and needs to be persisted */
  SBLK_CACHE_PUT    = 1 << 5,  /**< Put this `SBLK` into dbcache */
  SBLK_CACHE_UPDATE = 1 << 6,
  SBLK_CACHE_REMOVE = 1 << 7
} sblk_flags_t;

#define SBLK_PERSISTENT_FLAGS (SBLK_FULL_LKEY)
#define SBLK_CACHE_FLAGS (SBLK_CACHE_UPDATE | SBLK_CACHE_PUT | SBLK_CACHE_REMOVE)

#define IWDB_DUP_FLAGS (IWDB_DUP_UINT32_VALS | IWDB_DUP_UINT64_VALS)

#define IWDB_UINT_KEYS_FLAGS (IWDB_UINT32_KEYS | IWDB_UINT64_KEYS)

// Number of top levels to cache (~ (1<<DBCACHE_LEVELS) cached elements)
#define DBCACHE_LEVELS 10

// Minimal cached level
#define DBCACHE_MIN_LEVEL 5

// Single allocation step - number of DBCNODEs
#define DBCACHE_ALLOC_STEP 32

/** Cached SBLK node */
typedef struct DBCNODE {
  blkn_t sblkn;               /**< SBLK block number */
  blkn_t kblkn;               /**< KVBLK block number */
  uint8_t lkl;                /**< Lower key length */
  uint8_t fullkey;            /**< SBLK full key */
  uint8_t k0idx;              /**< KVBLK Zero KVP index */
  uint8_t pad;                /**< 1 byte pad */
  uint8_t lk[1];              /**< Lower key buffer */
} DBCNODE;

#define DBCNODE_NUM_SZ 20
#define DBCNODE_STR_SZ 128
static_assert(DBCNODE_NUM_SZ >= offsetof(DBCNODE, lk) + sizeof(uint64_t),
              "DBCNODE_NUM_SZ >= offsetof(DBCNODE, lk) + sizeof(uint64_t)");
static_assert(DBCNODE_STR_SZ >= offsetof(DBCNODE, lk) + SBLK_LKLEN,
              "DBCNODE_STR_SZ >= offsetof(DBCNODE, lk) + SBLK_LKLEN");

/** Tallest SBLK nodes cache */
typedef struct DBCACHE {
  atomic_uint_least64_t atime;  /**< Cache access MONOTONIC time (ms) */
  size_t asize;                 /**< Size of allocated cache buffer */
  size_t num;                   /**< Actual number of nodes */
  size_t nsize;                 /**< Cached node size */
  uint8_t lvl;                  /**< Lowes cached level */
  bool open;                    /**< Is cache open */
  DBCNODE *nodes;               /**< Sorted nodes array */
} DBCACHE;

/* Database: [magic:u4,dbflg:u1,dbid:u4,next_db_blk:u4,p0:u4,n[24]:u4,c[24]:u4]:209 */
struct IWDB {
  // SBH
  IWDB db;                    /**< Database ref */
  off_t addr;                 /**< Database block address */
  sblk_flags_t flags;         /**< Flags */
  // !SBH
  IWKV iwkv;
  DBCACHE cache;              /**< SBLK nodes cache */
  pthread_rwlock_t rwl;       /**< Database API RW lock */
  uint64_t next_db_addr;      /**< Next IWDB addr */
  struct IWDB *next;          /**< Next IWDB meta */
  struct IWDB *prev;          /**< Prev IWDB meta */
  dbid_t id;                  /**< Database ID */
  volatile int32_t wk_count;  /**< Number of active database workers */
  iwdb_flags_t dbflg;         /**< Database specific flags */
  atomic_bool open;           /**< True if DB is in OPEN state */
  uint32_t lcnt[SLEVELS];     /**< SBLK count per level */
};

/* Skiplist block: [u1:flags,lvl:u1,lkl:u1,pnum:u1,p0:u4,kblk:u4,[pi0:u1,... pi32],n0-n23:u4,lk:u116]:u256 // SBLK */
typedef struct SBLK {
  // SBH
  IWDB db;                    /**< Database ref */
  off_t addr;                 /**< Block address */
  sblk_flags_t flags;         /**< Flags */
  uint8_t lvl;                /**< Skip list node level */
  blkn_t p0;                  /**< Prev node, if IWDB it is the last node */
  blkn_t n[SLEVELS];          /**< Next nodes */
  // !SBH
  KVBLK *kvblk;               /**< Associated KVBLK */
  blkn_t kvblkn;              /**< Associated KVBLK block number */
  int8_t lkl;                 /**< Lower key length within a buffer */
  int8_t pnum;                /**< Number of active kv indexes in `SBLK::pi` */
  int8_t pi[KVBLK_IDXNUM];    /**< Sorted KV slots, value is an index of kv slot in `KVBLK` */
  uint8_t lk[SBLK_LKLEN];     /**< Lower key buffer */
} SBLK;

KHASH_MAP_INIT_INT(DBS, IWDB)

/** IWKV instance */
struct IWKV {
  IWFS_FSM fsm;               /**< FSM pool */
  pthread_rwlock_t rwl;       /**< API RW lock */
  iwrc fatalrc;               /**< Fatal error occuried, no farther operations can be performed */
  IWDB first_db;              /**< First database in chain */
  IWDB last_db;               /**< Last database in chain */
  IWDLSNR *dlsnr;             /**< WAL data events listener */
  khash_t(DBS) *dbs;          /**< Database id -> IWDB mapping */
  iwkv_openflags oflags;      /**< Open flags */
  pthread_cond_t wk_cond;     /**< Workers cond variable */
  pthread_mutex_t wk_mtx;     /**< Workers cond mutext */
  int32_t fmt_version;        /**< Database format version */
  volatile int32_t wk_count;  /**< Number of active workers */
  atomic_bool open;           /**< True if kvstore is in OPEN state */
};

typedef enum {
  IWLCTX_PUT = 1,             /**< Put key value operation */
  IWLCTX_DEL = 1 << 1,        /**< Delete key operation */
} iwlctx_op_t;

/** Database lookup context */
typedef struct IWLCTX {
  IWDB db;
  uint64_t ts;                /**< Context creation timestamp ms */
  const IWKV_val *key;        /**< Search key */
  IWKV_val *val;              /**< Update value */
  SBLK *lower;                /**< Next to upper bound block */
  SBLK *upper;                /**< Upper bound block */
  SBLK *nb;                   /**< New block */
  off_t upper_addr;           /**< Upper block address used in `_lx_del_lr()` */
#ifndef NDEBUG
  uint32_t num_cmps;
#endif
  iwkv_opflags opflags;       /**< Operation flags */
  sblk_flags_t sblk_flags;    /**< `SBLK` flags applied to all new/looked blocks in this context */
  iwlctx_op_t op;             /**< Context operation */
  uint8_t saan;               /**< Position of next free `SBLK` element in the `saa` area */
  uint8_t kaan;               /**< Position of next free `KVBLK` element in the `kaa` area */
  int8_t nlvl;                /**< Level of new inserted/deleted `SBLK` node. -1 if no new node inserted/deleted */
  int8_t cache_reload;        /**< If true dbcache should be refreshed after operation */
  SBLK *plower[SLEVELS];      /**< Pinned lower nodes per level */
  SBLK *pupper[SLEVELS];      /**< Pinned upper nodes per level */
  SBLK dblk;                  /**< First database block */
  SBLK saa[AANUM];            /**< `SBLK` allocation area */
  KVBLK kaa[AANUM];           /**< `KVBLK` allocation area */
} IWLCTX;

/** Cursor context */
struct IWKV_cursor {
  SBLK *cn;                   /**< Current `SBLK` node */
  off_t dbaddr;               /**< Database address used as `cn` */
  uint8_t cnpos;              /**< Position in the current `SBLK` node */
  bool closed;                /**< Cursor closed */
  IWLCTX lx;                  /**< Lookup context */
};

#define ENSURE_OPEN(iwkv_) \
  if (!iwkv_ || !(iwkv_->open)) return IW_ERROR_INVALID_STATE; \
  if (iwkv_->fatalrc) return iwkv_->fatalrc

#define ENSURE_OPEN_DB(db_) \
  if (!(db_) || !(db_)->iwkv || !(db_)->open || !((db_)->iwkv->open)) return IW_ERROR_INVALID_STATE

#define API_RLOCK(iwkv_, rci_) \
  ENSURE_OPEN(iwkv_);  \
  rci_ = pthread_rwlock_rdlock(&(iwkv_)->rwl); \
  if (rci_) return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci_)

IW_INLINE iwrc _api_rlock(IWKV iwkv)  {
  int rci;
  API_RLOCK(iwkv, rci);
  return 0;
}

#define API_WLOCK(iwkv_, rci_) \
  ENSURE_OPEN(iwkv_);  \
  rci_ = pthread_rwlock_wrlock(&(iwkv_)->rwl); \
  if (rci_) return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci_)

IW_INLINE iwrc _api_wlock(IWKV iwkv)  {
  int rci;
  API_WLOCK(iwkv, rci);
  return 0;
}

#define API_UNLOCK(iwkv_, rci_, rc_)  \
  rci_ = pthread_rwlock_unlock(&(iwkv_)->rwl); \
  if (rci_) IWRC(iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci_), rc_)

#define API_DB_RLOCK(db_, rci_)                               \
  do {                                                        \
    API_RLOCK((db_)->iwkv, rci_);                             \
    rci_ = pthread_rwlock_rdlock(&(db_)->rwl);                \
    if (rci_) {                                               \
      pthread_rwlock_unlock(&(db_)->iwkv->rwl);               \
      return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci_);  \
    }                                                         \
  } while(0)

IW_INLINE iwrc _api_db_rlock(IWDB db)  {
  int rci;
  API_DB_RLOCK(db, rci);
  return 0;
}

#define API_DB_WLOCK(db_, rci_)                               \
  do {                                                        \
    API_RLOCK((db_)->iwkv, rci_);                             \
    rci_ = pthread_rwlock_wrlock(&(db_)->rwl);                \
    if (rci_) {                                               \
      pthread_rwlock_unlock(&(db_)->iwkv->rwl);               \
      return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci_);  \
    }                                                         \
  } while(0)

IW_INLINE iwrc _api_db_wlock(IWDB db)  {
  int rci;
  API_DB_WLOCK(db, rci);
  return 0;
}

#define API_DB_UNLOCK(db_, rci_, rc_)                                     \
  do {                                                                    \
    rci_ = pthread_rwlock_unlock(&(db_)->rwl);                            \
    if (rci_) IWRC(iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci_), rc_);  \
    API_UNLOCK((db_)->iwkv, rci_, rc_);                                   \
  } while(0)

#define AAPOS_INC(aan_)         \
  do {                          \
    if ((aan_) < AANUM - 1) {   \
      (aan_) = (aan_) + 1;      \
    } else {                    \
      (aan_) = 0;               \
    }                           \
  } while(0)


// SBLK
// [u1:flags,lvl:u1,lkl:u1,pnum:u1,p0:u4,kblk:u4,[pi0:u1,... pi32],n0-n23:u4,lk:u116]:u256

#define SOFF_FLAGS_U1     0
#define SOFF_LVL_U1       (SOFF_FLAGS_U1 + 1)
#define SOFF_LKL_U1       (SOFF_LVL_U1 + 1)
#define SOFF_PNUM_U1      (SOFF_LKL_U1 + 1)
#define SOFF_P0_U4        (SOFF_PNUM_U1 + 1)
#define SOFF_KBLK_U4      (SOFF_P0_U4 + 4)
#define SOFF_PI0_U1       (SOFF_KBLK_U4 + 4)
#define SOFF_N0_U4        (SOFF_PI0_U1 + 1 * KVBLK_IDXNUM)
#define SOFF_LK           (SOFF_N0_U4 + 4 * SLEVELS + LKPAD)
#define SOFF_END          (SOFF_LK + SBLK_LKLEN)
static_assert(SOFF_END == 256, "SOFF_END == 256");
static_assert(SBLK_SZ >= SOFF_END, "SBLK_SZ >= SOFF_END");

// DB
// [magic:u4,dbflg:u1,dbid:u4,next_db_blk:u4,p0:u4,n[24]:u4,c[24]:u4]:209
#define DOFF_MAGIC_U4     0
#define DOFF_DBFLG_U1     (DOFF_MAGIC_U4 + 4)
#define DOFF_DBID_U4      (DOFF_DBFLG_U1 + 1)
#define DOFF_NEXTDB_U4    (DOFF_DBID_U4 + 4)
#define DOFF_P0_U4        (DOFF_NEXTDB_U4 + 4)
#define DOFF_N0_U4        (DOFF_P0_U4 + 4)
#define DOFF_C0_U4        (DOFF_N0_U4 + 4 * SLEVELS)
#define DOFF_END          (DOFF_C0_U4 + 4 * SLEVELS)
static_assert(DOFF_END == 209, "DOFF_END == 209");
static_assert(DB_SZ >= DOFF_END, "DB_SZ >= DOFF_END");

// KVBLK
// [szpow:u1,idxsz:u2,[ps1:vn,pl1:vn,...,ps32,pl32]____[[_KV],...]] // KVBLK
#define KBLK_SZPOW_OFF   0


iwrc iwkv_exclusive_lock(IWKV iwkv);
iwrc iwkv_exclusive_unlock(IWKV iwkv);
void iwkvd_trigger_xor(uint64_t val);
void iwkvd_kvblk(FILE *f, KVBLK *kb, int maxvlen);
iwrc iwkvd_sblk(FILE *f, IWLCTX *lx, SBLK *sb, int flags);
void iwkvd_db(FILE *f, IWDB db, int flags, int plvl);

// IWKVD Trigger commands 
#ifdef IW_TESTS
#define IWKVD_WAL_NO_CHECKPOINT_ON_CLOSE 1UL
#endif
