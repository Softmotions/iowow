#pragma once
#ifndef IWKV_INTERNAL_H
#define IWKV_INTERNAL_H

#include "iwkv.h"
#include "iwlog.h"
#include "iwarr.h"
#include "iwutils.h"
#include "iwfsmfile.h"
#include "iwdlsnr.h"
#include "iwal.h"
#include "iwhmap.h"
#include "ksort.h"

#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>

#include "iwcfg.h"

#if defined(__APPLE__) || defined(__ANDROID__)
#include "pthread_spin_lock_shim.h"
#endif

// IWKV magic number
#define IWKV_MAGIC 0x69776b76U

// IWKV backup magic number
#define IWKV_BACKUP_MAGIC 0xBACBAC69U

// IWKV file format version
#define IWKV_FORMAT 2U

// IWDB magic number
#define IWDB_MAGIC 0x69776462U

#ifdef IW_32
// Max database file size on 32 bit systems: 2Gb
#define IWKV_MAX_DBSZ 0x7fffffff
#else
// Max database file size: ~512Gb
#define IWKV_MAX_DBSZ 0x7fffffff80ULL
#endif

// Size of KV fsm block as power of 2
#define IWKV_FSM_BPOW 7U

#define IWKV_FSM_ALLOC_FLAGS (IWFSM_ALLOC_NO_OVERALLOCATE | IWFSM_SOLID_ALLOCATED_SPACE | IWFSM_ALLOC_NO_STATS)

// Length of KV fsm header in bytes
#define KVHDRSZ 255U

// [u1:flags,lvl:u1,lkl:u1,pnum:u1,p0:u4,kblk:u4,[pi0:u1,... pi32],n0-n23:u4,lk:u116]:u256 // SBLK

// Maximum length of prefix key to compare for v2 formst
#define PREFIX_KEY_LEN_V2 115U

// Number of skip list levels
#define SLEVELS 24U

#define AANUM (2U * SLEVELS + 2 /* levels + (new block created) + (db block may be updated) */)

// Lower key length in SBLK
#define SBLK_LKLEN PREFIX_KEY_LEN_V2

// Size of database start block in bytes
#define DB_SZ (2UL * (1U << IWKV_FSM_BPOW))

// Size of `SBLK` in bytes
#define SBLK_SZ (2UL * (1U << IWKV_FSM_BPOW))

// Number of SBLK blocks in one page
#define SBLK_PAGE_SBLK_NUM_V2 16U

// Size of page with adjacent SBLK blocks. 4096
// Data format version: v2
#define SBLK_PAGE_SZ_V2 (SBLK_PAGE_SBLK_NUM_V2 * SBLK_SZ)

// Number of `KV` blocks in KVBLK
#define KVBLK_IDXNUM 32U

// Initial `KVBLK` size power of 2
#define KVBLK_INISZPOW 9U

// KVBLK header size: blen:u1,idxsz:u2
#define KVBLK_HDRSZ 3U

// Max kvp offset bytes
#define KVP_MAX_OFF_VLEN 8U

// Max kvp len 0xfffffffULL bytes
#define KVP_MAX_LEN_VLEN 5U

#define KVBLK_MAX_IDX_SZ ((KVP_MAX_OFF_VLEN + KVP_MAX_LEN_VLEN) * KVBLK_IDXNUM)

// Max non KV size [blen:u1,idxsz:u2,[ps1:vn,pl1:vn,...,ps63,pl63]
#define KVBLK_MAX_NKV_SZ (KVBLK_HDRSZ + KVBLK_MAX_IDX_SZ)

#define ADDR2BLK(addr_) ((blkn_t) (((uint64_t) (addr_)) >> IWKV_FSM_BPOW))

#define BLK2ADDR(blk_) (((uint64_t) (blk_)) << IWKV_FSM_BPOW)

struct _IWKV;
struct _IWDB;

typedef uint32_t blkn_t;
typedef uint32_t dbid_t;

/* Key/Value pair stored in `KVBLK` */
typedef struct KV {
  size_t   keysz;
  size_t   valsz;
  uint8_t *key;
  uint8_t *val;
} KV;

/* Ket/Value (KV) index: Offset and length. */
typedef struct KVP {
  off_t    off;   /**< KV block offset relative to `end` of KVBLK */
  uint32_t len;   /**< Length of kv pair block */
  uint8_t  ridx;  /**< Position of the actually persisted slot in `KVBLK` */
} KVP;

typedef uint8_t kvblk_flags_t;
#define KVBLK_DEFAULT ((kvblk_flags_t) 0x00U)
/** KVBLK data is durty and should be flushed to mm */
#define KVBLK_DURTY ((kvblk_flags_t) 0x01U)

typedef uint8_t kvblk_rmkv_opts_t;
#define RMKV_SYNC      ((kvblk_rmkv_opts_t) 0x01U)
#define RMKV_NO_RESIZE ((kvblk_rmkv_opts_t) 0x02U)

typedef uint8_t sblk_flags_t;
/** The lowest `SBLK` key is fully contained in `SBLK`. Persistent flag. */
#define SBLK_FULL_LKEY ((sblk_flags_t) 0x01U)
/** This block is the start database block. */
#define SBLK_DB ((sblk_flags_t) 0x08U)
/** Block data changed, block marked as durty and needs to be persisted */
#define SBLK_DURTY ((sblk_flags_t) 0x10U)

typedef uint8_t iwlctx_op_t;
/** Put key value operation */
#define IWLCTX_PUT ((iwlctx_op_t) 0x01U)
/** Delete key operation */
#define IWLCTX_DEL ((iwlctx_op_t) 0x01U)

/* KVBLK: [szpow:u1,idxsz:u2,[ps0:vn,pl0:vn,..., ps32,pl32]____[[KV],...]] */
typedef struct KVBLK {
  IWDB     db;
  off_t    addr;              /**< Block address */
  off_t    maxoff;            /**< Max pair offset */
  uint16_t idxsz;             /**< Size of KV pairs index in bytes */
  int8_t   zidx;              /**< Index of first empty pair slot (zero index), or -1 */
  uint8_t  szpow;             /**< Block size as power of 2 */
  kvblk_flags_t flags;        /**< Flags */
  KVP pidx[KVBLK_IDXNUM];     /**< KV pairs index */
} KVBLK;

#define SBLK_PERSISTENT_FLAGS (SBLK_FULL_LKEY)
#define SBLK_CACHE_FLAGS      (SBLK_CACHE_UPDATE | SBLK_CACHE_PUT | SBLK_CACHE_REMOVE)

struct _IWKV_cursor;

/* Database: [magic:u4,dbflg:u1,dbid:u4,next_db_blk:u4,p0:u4,n[24]:u4,c[24]:u4]:209 */
struct _IWDB {
  // SBH
  IWDB  db;                       /**< Database ref */
  off_t addr;                     /**< Database block address */
  sblk_flags_t flags;             /**< Flags */
  // !SBH
  IWKV iwkv;
  pthread_rwlock_t   rwl;             /**< Database API RW lock */
  pthread_spinlock_t cursors_slk;     /**< Cursors set guard lock */
  off_t next_db_addr;                 /**< Next IWDB addr */
  struct _IWKV_cursor *cursors;       /**< Active (currently in-use) database cursors */
  struct _IWDB *next;                 /**< Next IWDB meta */
  struct _IWDB *prev;                 /**< Prev IWDB meta */
  dbid_t id;                          /**< Database ID */
  volatile int32_t wk_count;          /**< Number of active database workers */
  blkn_t       meta_blk;              /**< Database meta block number */
  blkn_t       meta_blkn;             /**< Database meta length (number of blocks) */
  iwdb_flags_t dbflg;                 /**< Database specific flags */
  atomic_bool  open;                  /**< True if DB is in OPEN state */
  volatile bool wk_pending_exclusive; /**< If true someone wants to acquire exclusive lock on IWDB */
  uint32_t      lcnt[SLEVELS];        /**< SBLK count per level */
};

/* Skiplist block: [u1:flags,lvl:u1,lkl:u1,pnum:u1,p0:u4,kblk:u4,[pi0:u1,... pi32],n0-n23:u4,lk:u116]:u256 // SBLK */
typedef struct SBLK {
  // SBH
  IWDB  db;                   /**< Database ref */
  off_t addr;                 /**< Block address */
  sblk_flags_t flags;         /**< Flags */
  uint8_t      lvl;           /**< Skip list node level */
  uint8_t      bpos;          /**< Position of SBLK in a page block starting with 1 (zero means SBLK deleted) */
  blkn_t       p0;            /**< Prev node, if IWDB it is the last node */
  blkn_t       n[SLEVELS];    /**< Next nodes */
  // !SBH
  KVBLK  *kvblk;                 /**< Associated KVBLK */
  blkn_t  kvblkn;                /**< Associated KVBLK block number */
  int8_t  pnum;                  /**< Number of active kv indexes in `SBLK::pi` */
  uint8_t lkl;                   /**< Lower key length within a buffer */
  uint8_t pi[KVBLK_IDXNUM];      /**< Sorted KV slots, value is an index of kv slot in `KVBLK` */
  uint8_t lk[PREFIX_KEY_LEN_V2 + 1]; /**< Lower key buffer */
} SBLK;

/** IWKV instance */
struct _IWKV {
  IWFS_FSM fsm;                          /**< FSM pool */
  pthread_rwlock_t rwl;                  /**< API RW lock */
  iwrc     fatalrc;                      /**< Fatal error occuried, no farther operations can be performed */
  IWDB     first_db;                     /**< First database in chain */
  IWDB     last_db;                      /**< Last database in chain */
  IWDLSNR *dlsnr;                        /**< WAL data events listener */
  IWHMAP  *dbs;                          /**< Database id -> IWDB mapping */
  iwkv_openflags  oflags;                /**< Open flags */
  pthread_cond_t  wk_cond;               /**< Workers cond variable */
  pthread_mutex_t wk_mtx;                /**< Workers cond mutext */
  int32_t fmt_version;                   /**< Database format version */
  volatile int32_t wk_count;             /**< Number of active workers */
  volatile bool    wk_pending_exclusive; /**< If true someone wants to acquire exclusive lock on IWKV */
  volatile bool    open;                 /**< True if kvstore is in the operable state */
};

/** Database lookup context */
typedef struct IWLCTX {
  IWDB db;
  const IWKV_val *key;        /**< Search key */
  IWKV_val       *val;        /**< Update value */
  SBLK *lower;                /**< Next to upper bound block */
  SBLK *upper;                /**< Upper bound block */
  SBLK *nb;                   /**< New block */
  off_t destroy_addr;         /**< Block to destroy address */
  off_t upper_addr;           /**< Upper block address used in `_lx_del_lr()` */
#ifndef NDEBUG
  uint32_t num_cmps;
#endif
  iwkv_opflags opflags;       /**< Operation flags */
  sblk_flags_t sbflags;       /**< `SBLK` flags applied to all new/looked blocks in this context */
  iwlctx_op_t  op;            /**< Context operation */
  uint8_t      saan;          /**< Position of next free `SBLK` element in the `saa` area */
  uint8_t      kaan;          /**< Position of next free `KVBLK` element in the `kaa` area */
  int8_t       nlvl;          /**< Level of new inserted/deleted `SBLK` node. -1 if no new node inserted/deleted */
  IWKV_PUT_HANDLER ph;        /**< Optional put handler */
  void    *phop;              /**< Put handler opaque data */
  SBLK    *plower[SLEVELS];   /**< Pinned lower nodes per level */
  SBLK    *pupper[SLEVELS];   /**< Pinned upper nodes per level */
  IWKV_val ekey;
  SBLK     dblk;              /**< First database block */
  SBLK     saa[AANUM];        /**< `SBLK` allocation area */
  KVBLK    kaa[AANUM];        /**< `KVBLK` allocation area */
  uint8_t  nbuf[IW_VNUMBUFSZ];
  uint8_t  incbuf[8];         /**< Buffer used to store incremented/decremented values `IWKV_VAL_INCREMENT` opflag */
} IWLCTX;

/** Cursor context */
struct _IWKV_cursor {
  uint8_t cnpos;              /**< Position in the current `SBLK` node */
  bool    closed;             /**< Cursor closed */
  int8_t  skip_next;          /**< When to skip next IWKV_CURSOR_NEXT|IWKV_CURSOR_PREV cursor move
                                   due to the side effect of `iwkv_cursor_del()` call.
                                   If `skip_next > 0` `IWKV_CURSOR_NEXT` will be skipped
                                   If `skip_next < 0` `IWKV_CURSOR_PREV` will be skipped */
  SBLK *cn;                   /**< Current `SBLK` node */
  struct _IWKV_cursor *next;  /**< Next cursor in active db cursors chain */
  off_t  dbaddr;              /**< Database address used as `cn` */
  IWLCTX lx;                  /**< Lookup context */
};

#define ENSURE_OPEN(iwkv_) \
  if (!(iwkv_) || !((iwkv_)->open)) return IW_ERROR_INVALID_STATE; \
  if ((iwkv_)->fatalrc) return (iwkv_)->fatalrc

#define ENSURE_OPEN_DB(db_) \
  if (!(db_) || !(db_)->iwkv || !(db_)->open || !((db_)->iwkv->open)) return IW_ERROR_INVALID_STATE

#define API_RLOCK(iwkv_, rci_) \
  ENSURE_OPEN(iwkv_);  \
  (rci_) = pthread_rwlock_rdlock(&(iwkv_)->rwl); \
  if (rci_) return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci_)

IW_INLINE iwrc _api_rlock(IWKV iwkv) {
  int rci;
  API_RLOCK(iwkv, rci);
  return 0;
}

#define API_WLOCK(iwkv_, rci_) \
  ENSURE_OPEN(iwkv_);  \
  (rci_) = pthread_rwlock_wrlock(&(iwkv_)->rwl); \
  if (rci_) return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci_)

IW_INLINE iwrc _api_wlock(IWKV iwkv) {
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
    (rci_) = pthread_rwlock_rdlock(&(db_)->rwl);                \
    if (rci_) {                                               \
      pthread_rwlock_unlock(&(db_)->iwkv->rwl);               \
      return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci_);  \
    }                                                         \
  } while (0)

IW_INLINE iwrc _api_db_rlock(IWDB db) {
  int rci;
  API_DB_RLOCK(db, rci);
  return 0;
}

#define API_DB_WLOCK(db_, rci_)                               \
  do {                                                        \
    API_RLOCK((db_)->iwkv, rci_);                             \
    (rci_) = pthread_rwlock_wrlock(&(db_)->rwl);                \
    if (rci_) {                                               \
      pthread_rwlock_unlock(&(db_)->iwkv->rwl);               \
      return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci_);  \
    }                                                         \
  } while (0)

IW_INLINE iwrc _api_db_wlock(IWDB db) {
  int rci;
  API_DB_WLOCK(db, rci);
  return 0;
}

#define API_DB_UNLOCK(db_, rci_, rc_)                                     \
  do {                                                                    \
    (rci_) = pthread_rwlock_unlock(&(db_)->rwl);                            \
    if (rci_) IWRC(iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci_), rc_);  \
    API_UNLOCK((db_)->iwkv, rci_, rc_);                                   \
  } while (0)

#define AAPOS_INC(aan_)         \
  do {                          \
    if ((aan_) < AANUM - 1) {   \
      (aan_) = (aan_) + 1;      \
    } else {                    \
      (aan_) = 0;               \
    }                           \
  } while (0)


// SBLK
// [flags:u1,lvl:u1,lkl:u1,pnum:u1,p0:u4,kblk:u4,pi:u1[32],n:u4[24],bpos:u1,lk:u115]:u256

#define SOFF_FLAGS_U1   0
#define SOFF_LVL_U1     (SOFF_FLAGS_U1 + 1)
#define SOFF_LKL_U1     (SOFF_LVL_U1 + 1)
#define SOFF_PNUM_U1    (SOFF_LKL_U1 + 1)
#define SOFF_P0_U4      (SOFF_PNUM_U1 + 1)
#define SOFF_KBLK_U4    (SOFF_P0_U4 + 4)
#define SOFF_PI0_U1     (SOFF_KBLK_U4 + 4)
#define SOFF_N0_U4      (SOFF_PI0_U1 + 1 * KVBLK_IDXNUM)
#define SOFF_BPOS_U1_V2 (SOFF_N0_U4 + 4 * SLEVELS)
#define SOFF_LK_V2      (SOFF_BPOS_U1_V2 + 1)
#define SOFF_LK_V1      (SOFF_N0_U4 + 4 * SLEVELS)
#define SOFF_END        (SOFF_LK_V2 + SBLK_LKLEN)
static_assert(SOFF_END == 256, "SOFF_END == 256");
static_assert(SBLK_SZ >= SOFF_END, "SBLK_SZ >= SOFF_END");

// DB
// [magic:u4,dbflg:u1,dbid:u4,next_db_blk:u4,p0:u4,n[24]:u4,c[24]:u4,meta_blk:u4,meta_blkn:u4]:217
#define DOFF_MAGIC_U4    0
#define DOFF_DBFLG_U1    (DOFF_MAGIC_U4 + 4)
#define DOFF_DBID_U4     (DOFF_DBFLG_U1 + 1)
#define DOFF_NEXTDB_U4   (DOFF_DBID_U4 + 4)
#define DOFF_P0_U4       (DOFF_NEXTDB_U4 + 4)
#define DOFF_N0_U4       (DOFF_P0_U4 + 4)
#define DOFF_C0_U4       (DOFF_N0_U4 + 4 * SLEVELS)
#define DOFF_METABLK_U4  (DOFF_C0_U4 + 4 * SLEVELS)
#define DOFF_METABLKN_U4 (DOFF_METABLK_U4 + 4)
#define DOFF_END         (DOFF_METABLKN_U4 + 4)
static_assert(DOFF_END == 217, "DOFF_END == 217");
static_assert(DB_SZ >= DOFF_END, "DB_SZ >= DOFF_END");

// KVBLK
// [szpow:u1,idxsz:u2,[ps1:vn,pl1:vn,...,ps32,pl32]____[[_KV],...]] // KVBLK
#define KBLK_SZPOW_OFF 0


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

#endif
