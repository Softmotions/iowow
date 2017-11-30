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
  KVBLK_DURTY = 0x1 /**< KVBLK data is dury and should be flushed to mm */
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
  kvblk_flags_t flags;        /**< Flags */
} KVBLK;

typedef enum {
  SBH_FULL_LKEY = 1,          /**< The lowest `SBLK` key is fully contained in `SBLK`. Persistent flag. */
  SBH_DB = 1 << 1,            /**< This block is the database block. */
  SBH_PINNED = 1 << 2,        /**< `SBH` pinned and should not be released. */
  SBH_WLOCKED = 1 << 3        /**< `SBH` write locked */
} sbh_flags_t;

#define SBH_PERSISTENT_FLAGS (SBH_FULL_LKEY)

#define SBH_FIELDS                                                    \
  sbh_flags_t flags;          /**< Flags */                            \
  uint8_t lvl;                /**< Skip list level */                  \
  off_t addr;                 /**< Block address */                    \
  IWDB db;                    /**< Database ref */

// Common header for IWDB and SBLK
typedef struct SBH {
  SBH_FIELDS
} SBH;

// SBLK: [u1:flags,kblk:u4,lvl:u1,p0:u4,n0-n29:u4,lkl:u1,lk:u61,pnum:u1,[pi1:u1,...pi63]]:u256
typedef struct SBLK {
  SBH_FIELDS
  KVBLK *kvblk;               /**< Associated KVBLK */
  uint8_t lkl;                /**< Lower key length */
  uint8_t lk[SBLK_LKLEN];     /**< Lower key value */
  uint8_t pnum;               /**< Number of active pairs in `piN` array */
  uint8_t pi[KVBLK_IDXNUM];   /**< Key/value pairs indexes in `KVBLK` */
} SBLK;

// Address lock node
typedef struct ALN {
  pthread_rwlock_t rwl;       /**< RW lock */
  int64_t refs;               /**< Locked address refs count */
  bool write_pending;         /**< Pending write lock */
} ALN;

KHASH_MAP_INIT_INT(ALN, ALN *)

/** Database instance */
struct IWDB {
  SBH_FIELDS
  IWKV iwkv;
  iwdb_flags_t dbflg;         /**< Database flags */
  pthread_mutex_t mtx_ctl;    /**< Main control mutex */
  dbid_t id;                  /**< Database ID */
  uint64_t next_addr;         /**< Next IWDB addr */
  struct IWDB *next;          /**< Next IWDB meta */
  struct IWDB *prev;          /**< Prev IWDB meta */
  khash_t(ALN) *aln;          /**< Block id -> ALN node mapping */
};

KHASH_MAP_INIT_INT(DBS, IWDB)

typedef enum {
  IWLCTX_PUT = 0x1,           /**< Put key value operation */
  IWLCTX_DEL = 0x2,           /**< Delete key operation */
} iwlctx_op_t;

/** Database lookup context */
typedef struct IWLCTX {
  IWDB db;
  const IWKV_val *key;        /**< Search key */
  IWKV_val *val;              /**< Update value */
  SBH *lower;                 /**< Next to upper bound block */
  SBH *upper;                 /**< Upper bound block */
  SBLK *nb;                   /**< New block */
  SBH *plower[SLEVELS];       /**< Pinned lower nodes per level */
  SBH *pupper[SLEVELS];       /**< Pinned upper nodes per level */
  int8_t lvl;                 /**< Current level */
  int8_t nlvl;                /**< Level of new inserted `SBLK` node. -1 if no new node inserted */
  iwlctx_op_t op;             /**< Context operation flags */
  iwkv_opflags opf;           /**< Operation flags */
  sbh_flags_t sbflags;
} IWLCTX;

void iwkvd_kvblk(FILE *f, KVBLK *kb);
void iwkvd_sblk(FILE *f, SBLK *sb, int flags);
void iwkvd_db(FILE *f, IWDB db, int flags);

#define ENSURE_OPEN(iwkv_) \
  if (!iwkv_ || !(iwkv_->isopen)) return IW_ERROR_INVALID_STATE;

#define API_RLOCK(iwkv_, rci_) \
  rci_ = pthread_rwlock_rdlock(&(iwkv_)->rwl_api); \
  if (rci_) return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci_)

#define API_WLOCK(iwkv_, rci_) \
  rci_ = pthread_rwlock_wrlock(&(iwkv_)->rwl_api); \
  if (rci_) return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci_)

#define API_UNLOCK(iwkv_, rci_, rc_)  \
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

//-------------------------- TREVERSE

IW_INLINE blkn_t _sh_n(void *s, int n, uint8_t *mm) {
  assert(s && mm && n >= 0 && n < SLEVELS);
  SBH *sh = (SBH *) s;
  uint8_t *vp = IW_UNLIKELY(sh->flags & SBH_DB)
                // [magic:u4,flags:u1,next_blk:u4,last_sblk:u4,dbid:u4,n0-n29:u4]
                ? (mm + sh->addr + (4 + 1 + 4 + 4 + 4) + n * 4)
                // [u1:flags,kblk:u4,lvl:u1,p0:u4,n0-n29:u4,..
                : (mm + sh->addr + (1 + 4 + 1 + 4) + n * 4);
  uint32_t lv;
  memcpy(&lv, vp, 4);
  return IW_ITOHL(lv);
}

IW_INLINE void _sh_set_n(void *s, int n, blkn_t v, uint8_t *mm) {
  assert(s && mm && n >= 0 && n < SLEVELS);
  SBH *sh = (SBH *) s;
  uint8_t *vp = IW_UNLIKELY(sh->flags & SBH_DB)
                // [magic:u4,flags:u1,next_blk:u4,last_sblk:u4,dbid:u4,n0-n29:u4]
                ? (mm + sh->addr + (4 + 1 + 4 + 4 + 4) + n * 4)
                // [u1:flags,kblk:u4,lvl:u1,p0:u4,n0-n29:u4,..
                : (mm + sh->addr + (1 + 4 + 1 + 4) + n * 4);
  uint32_t lv = v;
  lv = IW_HTOIL(lv);
  memcpy(vp, &lv, 4);
}

IW_INLINE blkn_t _sh_p0(void *s, uint8_t *mm) {
  assert(s && mm);
  SBH *sh = (SBH *) s;
  if (sh->flags & SBH_DB) {
    // [magic:u4,flags:u1,next_blk:u4,last_sblk:u4,dbid:u4,n0-n29:u4]
    uint8_t *vp = (mm + sh->addr + (4 + 1 + 4));
    uint32_t lv;
    memcpy(&lv, vp, 4);
    return IW_ITOHL(lv);
  } else {
    // [u1:flags,kblk:u4,lvl:u1,p0:u4,n0-n29:u4,..
    uint8_t *vp = (mm + sh->addr + (1 + 4 + 1));
    uint32_t lv;
    memcpy(&lv, vp, 4);
    return IW_ITOHL(lv);
  }
}

IW_INLINE void _sh_set_p0(void *s, blkn_t v, uint8_t *mm) {
  assert(s && mm);
  SBH *sh = (SBH *) s;
  if (sh->flags & SBH_DB) {
    // [magic:u4,flags:u1,next_blk:u4,last_sblk:u4,dbid:u4,n0-n29:u4]
    // [magic:u4,flags:u1,next_blk:u4,last_sblk:u4,dbid:u4,n0-n29:u4]
    uint8_t *vp = (mm + sh->addr + (4 + 1 + 4));
    uint32_t lv = v;
    lv = IW_HTOIL(lv);
    memcpy(vp, &lv, 4);
  } else {
    // [u1:flags,kblk:u4,lvl:u1,p0:u4,n0-n29:u4,..
    uint8_t *vp = (mm + sh->addr + (1 + 4 + 1));
    uint32_t lv = v;
    lv = IW_HTOIL(lv);
    memcpy(vp, &lv, 4);
  }
}

//--------------------------  PUBLIC API

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
