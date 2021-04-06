// -V::512

#include "iwkv_internal.h"
#include "iwconv.h"
#include <stdalign.h>

static iwrc _dbcache_fill_lw(IWLCTX *lx);
static iwrc _dbcache_get(IWLCTX *lx);
static iwrc _dbcache_put_lw(IWLCTX *lx, SBLK *sblk);
static void _dbcache_remove_lw(IWLCTX *lx, SBLK *sblk);
static void _dbcache_update_lw(IWLCTX *lx, SBLK *sblk);
static void _dbcache_destroy_lw(IWDB db);

#define _wnw_db_wl(db_) _api_db_wlock(db_)

//-------------------------- GLOBALS

#ifdef IW_TESTS
volatile int8_t iwkv_next_level = -1;
#endif
atomic_uint_fast64_t g_trigger;

#define IWKV_IS_INTERNAL_RC(rc_) ((rc_) > _IWKV_ERROR_END && (rc_) < _IWKV_RC_END)

//-------------------------- UTILS

IW_SOFT_INLINE iwrc _to_effective_key(
  struct _IWDB *db, const IWKV_val *key, IWKV_val *okey,
  uint8_t nbuf[static IW_VNUMBUFSZ]) {
  static_assert(IW_VNUMBUFSZ >= sizeof(uint64_t), "IW_VNUMBUFSZ >= sizeof(uint64_t)");
  iwdb_flags_t dbflg = db->dbflg;
  // Keys compound will be processed at lower levels at `addkv` routines
  okey->compound = key->compound;
  if (dbflg & IWDB_VNUM64_KEYS) {
    unsigned len;
    if (key->size == 8) {
      uint64_t llv;
      memcpy(&llv, key->data, sizeof(llv));
      IW_SETVNUMBUF64(len, nbuf, llv);
      if (!len) {
        return IW_ERROR_OVERFLOW;
      }
      okey->size = len;
      okey->data = nbuf;
    } else if (key->size == 4) {
      uint32_t lv;
      memcpy(&lv, key->data, sizeof(lv));
      IW_SETVNUMBUF(len, nbuf, lv);
      if (!len) {
        return IW_ERROR_OVERFLOW;
      }
      okey->size = len;
      okey->data = nbuf;
    } else {
      return IWKV_ERROR_KEY_NUM_VALUE_SIZE;
    }
  } else {
    okey->data = key->data;
    okey->size = key->size;
  }
  return 0;
}

// NOTE: at least `2*IW_VNUMBUFSZ` must be allocated for key->data
static iwrc _unpack_effective_key(struct _IWDB *db, IWKV_val *key, bool no_move_key_data) {
  iwdb_flags_t dbflg = db->dbflg;
  uint8_t *data = key->data;
  if (dbflg & IWDB_COMPOUND_KEYS) {
    int step;
    IW_READVNUMBUF64(key->data, key->compound, step);
    if (step >= key->size) {
      return IWKV_ERROR_KEY_NUM_VALUE_SIZE;
    }
    data += step;
    key->size -= step;
    if (!no_move_key_data && !(dbflg & IWDB_VNUM64_KEYS)) {
      memmove(key->data, data, key->size);
    }
  } else {
    key->compound = 0;
  }
  if (dbflg & IWDB_VNUM64_KEYS) {
    int64_t llv;
    char nbuf[IW_VNUMBUFSZ];
    if (key->size > IW_VNUMBUFSZ) {
      return IWKV_ERROR_KEY_NUM_VALUE_SIZE;
    }
    memcpy(nbuf, data, key->size);
    IW_READVNUMBUF64_2(nbuf, llv);
    memcpy(key->data, &llv, sizeof(llv));
    key->size = sizeof(llv);
  }
  return 0;
}

static int _cmp_keys_prefix(iwdb_flags_t dbflg, const void *v1, int v1len, const IWKV_val *key) {
  int ret;
  if (dbflg & IWDB_COMPOUND_KEYS) {
    // Compound keys mode
    const char *u1 = v1;
    const char *u2 = key->data;
    int step, v2len = (int) key->size;
    int64_t c1, c2 = key->compound;
    IW_READVNUMBUF64(v1, c1, step);
    v1len -= step;
    u1 += step;
    if (v1len < 1) {
      // Inconsistent data?
      return v2len - v1len;
    }
    if (dbflg & IWDB_VNUM64_KEYS) {
      if ((v2len != v1len) || (v2len > IW_VNUMBUFSZ) || (v1len > IW_VNUMBUFSZ)) {
        return v2len - v1len;
      }
      int64_t n1, n2;
      char vbuf[IW_VNUMBUFSZ];
      memcpy(vbuf, u1, v1len);
      IW_READVNUMBUF64_2(vbuf, n1);
      memcpy(vbuf, u2, v2len);
      IW_READVNUMBUF64_2(vbuf, n2);
      ret = n1 > n2 ? -1 : n1 < n2 ? 1 : 0;
      if (ret == 0) {
        ret = c1 > c2 ? -1 : c1 < c2 ? 1 : 0;
      }
    } else if (dbflg & IWDB_REALNUM_KEYS) {
      ret = iwafcmp(u2, v2len, u1, v1len);
      if (ret == 0) {
        ret = c1 > c2 ? -1 : c1 < c2 ? 1 : 0;
      }
    } else {
      IW_CMP2(ret, u2, v2len, u1, v1len);
    }
    return ret;
  } else {
    int v2len = (int) key->size;
    const void *v2 = key->data;
    if (dbflg & IWDB_VNUM64_KEYS) {
      if ((v2len != v1len) || (v2len > IW_VNUMBUFSZ) || (v1len > IW_VNUMBUFSZ)) {
        return v2len - v1len;
      }
      int64_t n1, n2;
      char vbuf[IW_VNUMBUFSZ];
      memcpy(vbuf, v1, v1len);
      IW_READVNUMBUF64_2(vbuf, n1);
      memcpy(vbuf, v2, v2len);
      IW_READVNUMBUF64_2(vbuf, n2);
      return n1 > n2 ? -1 : n1 < n2 ? 1 : 0;
    } else if (dbflg & IWDB_REALNUM_KEYS) {
      return iwafcmp(v2, v2len, v1, v1len);
    } else {
      IW_CMP2(ret, v2, v2len, v1, v1len);
      return ret;
    }
  }
}

IW_INLINE int _cmp_keys(iwdb_flags_t dbflg, const void *v1, int v1len, const IWKV_val *key) {
  int rv = _cmp_keys_prefix(dbflg, v1, v1len, key);
  if ((rv == 0) && !(dbflg & (IWDB_VNUM64_KEYS | IWDB_REALNUM_KEYS))) {
    if (dbflg & IWDB_COMPOUND_KEYS) {
      int step;
      int64_t c1, c2 = key->compound;
      IW_READVNUMBUF64(v1, c1, step);
      v1len -= step;
      if ((int) key->size == v1len) {
        return c1 > c2 ? -1 : c1 < c2 ? 1 : 0;
      }
    }
    return (int) key->size - v1len;
  } else {
    return rv;
  }
}

IW_INLINE void _kv_val_dispose(IWKV_val *v) {
  if (v) {
    free(v->data);
    v->size = 0;
    v->data = 0;
  }
}

IW_INLINE void _kv_dispose(IWKV_val *key, IWKV_val *val) {
  _kv_val_dispose(key);
  _kv_val_dispose(val);
}

void iwkv_val_dispose(IWKV_val *v) {
  _kv_val_dispose(v);
}

void iwkv_kv_dispose(IWKV_val *key, IWKV_val *val) {
  _kv_dispose(key, val);
}

IW_INLINE void _num2lebuf(uint8_t buf[static 8], void *numdata, size_t sz) {
  assert(sz == 4 || sz == 8);
  if (sz > 4) {
    uint64_t llv;
    memcpy(&llv, numdata, sizeof(llv));
    llv = IW_HTOILL(llv);
    memcpy(buf, &llv, sizeof(llv));
  } else {
    uint32_t lv;
    memcpy(&lv, numdata, sizeof(lv));
    lv = IW_HTOIL(lv);
    memcpy(buf, &lv, sizeof(lv));
  }
}

//-------------------------- IWKV/IWDB WORKERS

static WUR iwrc _iwkv_worker_inc_nolk(IWKV iwkv) {
  if (!iwkv || !iwkv->open) {
    return IW_ERROR_INVALID_STATE;
  }
  int rci = pthread_mutex_lock(&iwkv->wk_mtx);
  if (rci) {
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  if (!iwkv->open) { // -V547
    pthread_mutex_unlock(&iwkv->wk_mtx);
    return IW_ERROR_INVALID_STATE;
  }
  while (iwkv->wk_pending_exclusive) {
    pthread_cond_wait(&iwkv->wk_cond, &iwkv->wk_mtx);
  }
  ++iwkv->wk_count;
  pthread_cond_broadcast(&iwkv->wk_cond);
  pthread_mutex_unlock(&iwkv->wk_mtx);
  return 0;
}

static WUR iwrc _db_worker_inc_nolk(IWDB db) {
  if (!db || !db->iwkv || !db->iwkv->open || !db->open) {
    return IW_ERROR_INVALID_STATE;
  }
  IWKV iwkv = db->iwkv;
  int rci = pthread_mutex_lock(&iwkv->wk_mtx);
  if (rci) {
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  if (!iwkv->open || !db->open) { // -V560
    pthread_mutex_unlock(&iwkv->wk_mtx);
    return IW_ERROR_INVALID_STATE;
  }
  while (db->wk_pending_exclusive) {
    pthread_cond_wait(&iwkv->wk_cond, &iwkv->wk_mtx);
  }
  ++iwkv->wk_count;
  ++db->wk_count;
  pthread_cond_broadcast(&iwkv->wk_cond);
  pthread_mutex_unlock(&iwkv->wk_mtx);
  return 0;
}

static iwrc _iwkv_worker_dec_nolk(IWKV iwkv) {
  if (!iwkv) {
    return IW_ERROR_INVALID_STATE;
  }
  int rci = pthread_mutex_lock(&iwkv->wk_mtx);
  if (rci) {
    // Last chanсe to be consistent
    --iwkv->wk_count;
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  --iwkv->wk_count;
  pthread_cond_broadcast(&iwkv->wk_cond);
  pthread_mutex_unlock(&iwkv->wk_mtx);
  return 0;
}

static iwrc _db_worker_dec_nolk(IWDB db) {
  if (!db || !db->iwkv) { // do not use ENSURE_OPEN_DB here
    return IW_ERROR_INVALID_STATE;
  }
  IWKV iwkv = db->iwkv;
  int rci = pthread_mutex_lock(&iwkv->wk_mtx);
  if (rci) {
    // Last chanсe to be consistent
    --iwkv->wk_count;
    --db->wk_count;
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  --iwkv->wk_count;
  --db->wk_count;
  pthread_cond_broadcast(&iwkv->wk_cond);
  pthread_mutex_unlock(&iwkv->wk_mtx);
  return 0;
}

static WUR iwrc _wnw_iwkw_wl(IWKV iwkv) {
  int rci = pthread_rwlock_wrlock(&iwkv->rwl);
  if (rci) {
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  return 0;
}

static WUR iwrc _wnw(IWKV iwkv, iwrc (*after)(IWKV iwkv)) {
  iwrc rc = 0;
  int rci = pthread_mutex_lock(&iwkv->wk_mtx);
  if (rci) {
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  iwkv->wk_pending_exclusive = true;
  while (iwkv->wk_count > 0) {
    pthread_cond_wait(&iwkv->wk_cond, &iwkv->wk_mtx);
  }
  if (after) {
    rc = after(iwkv);
  }
  iwkv->wk_pending_exclusive = false;
  pthread_cond_broadcast(&iwkv->wk_cond);
  rci = pthread_mutex_unlock(&iwkv->wk_mtx);
  if (rci) {
    IWRC(iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci), rc);
  }
  return rc;
}

static WUR iwrc _wnw_db(IWDB db, iwrc (*after)(IWDB db)) {
  iwrc rc = 0;
  IWKV iwkv = db->iwkv;
  int rci = pthread_mutex_lock(&iwkv->wk_mtx);
  if (rci) {
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  db->wk_pending_exclusive = true;
  while (db->wk_count > 0) {
    pthread_cond_wait(&iwkv->wk_cond, &iwkv->wk_mtx);
  }
  if (after) {
    rc = after(db);
  }
  db->wk_pending_exclusive = false;
  pthread_cond_broadcast(&iwkv->wk_cond);
  rci = pthread_mutex_unlock(&iwkv->wk_mtx);
  if (rci) {
    IWRC(iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci), rc);
  }
  return rc;
}

//--------------------------  DB

static WUR iwrc _db_at(IWKV iwkv, IWDB *dbp, off_t addr, uint8_t *mm) {
  iwrc rc = 0;
  uint8_t *rp, bv;
  uint32_t lv;
  int rci;
  IWDB db = calloc(1, sizeof(struct _IWDB));
  *dbp = 0;
  if (!db) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  pthread_rwlockattr_t attr;
  pthread_rwlockattr_init(&attr);
#if defined __linux__ && (defined __USE_UNIX98 || defined __USE_XOPEN2K)
  pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif
  rci = pthread_rwlock_init(&db->rwl, &attr);
  if (rci) {
    free(db);
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  rci = pthread_spin_init(&db->cursors_slk, 0);
  if (rci) {
    pthread_rwlock_destroy(&db->rwl);
    free(db);
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  // [magic:u4,dbflg:u1,dbid:u4,next_db_blk:u4,p0:u4,n[24]:u4,c[24]:u4,meta_blk:u4,meta_blkn:u4]:217
  db->flags = SBLK_DB;
  db->addr = addr;
  db->db = db;
  db->iwkv = iwkv;
  rp = mm + addr;
  IW_READLV(rp, lv, lv);
  if (lv != IWDB_MAGIC) {
    rc = IWKV_ERROR_CORRUPTED;
    iwlog_ecode_error3(rc);
    goto finish;
  }
  IW_READBV(rp, bv, db->dbflg);
  IW_READLV(rp, lv, db->id);
  IW_READLV(rp, lv, db->next_db_addr);
  db->next_db_addr = BLK2ADDR(db->next_db_addr); // blknum -> addr
  rp = mm + addr + DOFF_C0_U4;
  for (int i = 0; i < SLEVELS; ++i) {
    IW_READLV(rp, lv, db->lcnt[i]);
  }
  if (iwkv->fmt_version >= 1) {
    IW_READLV(rp, lv, db->meta_blk);
    IW_READLV(rp, lv, db->meta_blkn);
  }
  db->open = true;
  *dbp = db;

finish:
  if (rc) {
    pthread_rwlock_destroy(&db->rwl);
    free(db);
  }
  return rc;
}

static WUR iwrc _db_save(IWDB db, bool newdb, uint8_t *mm) {
  iwrc rc = 0;
  uint32_t lv;
  uint8_t *wp = mm + db->addr, bv;
  uint8_t *sp = wp;
  IWDLSNR *dlsnr = db->iwkv->dlsnr;
  db->next_db_addr = db->next ? db->next->addr : 0;
  // [magic:u4,dbflg:u1,dbid:u4,next_db_blk:u4,p0:u4,n[24]:u4,c[24]:u4,meta_blk:u4,meta_blkn:u4]:217
  IW_WRITELV(wp, lv, IWDB_MAGIC);
  IW_WRITEBV(wp, bv, db->dbflg);
  IW_WRITELV(wp, lv, db->id);
  IW_WRITELV(wp, lv, ADDR2BLK(db->next_db_addr));
  if (dlsnr) {
    rc = dlsnr->onwrite(dlsnr, db->addr, sp, wp - sp, 0);
    RCRET(rc);
  }
  if (db->iwkv->fmt_version >= 1) {
    if (newdb) {
      memset(wp, 0, 4 + SLEVELS * 4 * 2); // p0 + n[24] + c[24]
      sp = wp;
      wp += 4 + SLEVELS * 4 * 2; // set to zero
    } else {
      wp += 4 + SLEVELS * 4 * 2; // skip
      sp = wp;
    }
    IW_WRITELV(wp, lv, db->meta_blk);
    IW_WRITELV(wp, lv, db->meta_blkn);
    if (dlsnr) {
      rc = dlsnr->onwrite(dlsnr, sp - mm, sp, wp - sp, 0);
    }
  }
  return rc;
}

static WUR iwrc _db_load_chain(IWKV iwkv, off_t addr, uint8_t *mm) {
  iwrc rc;
  int rci;
  IWDB db = 0, ndb;
  if (!addr) {
    return 0;
  }
  do {
    rc = _db_at(iwkv, &ndb, addr, mm);
    RCRET(rc);
    if (db) {
      db->next = ndb;
      ndb->prev = db;
    } else {
      iwkv->first_db = ndb;
    }
    db = ndb;
    addr = db->next_db_addr;
    iwkv->last_db = db;
    khiter_t k = kh_put(DBS, iwkv->dbs, db->id, &rci);
    if (rci != -1) {
      kh_value(iwkv->dbs, k) = db;
    } else {
      return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
  } while (db->next_db_addr);
  return rc;
}

static void _db_release_lw(IWDB *dbp) {
  assert(dbp && *dbp);
  IWDB db = *dbp;
  _dbcache_destroy_lw(db);
  pthread_rwlock_destroy(&db->rwl);
  pthread_spin_destroy(&db->cursors_slk);
  free(db);
  *dbp = 0;
}

typedef struct DISPOSE_DB_CTX {
  IWKV   iwkv;
  IWDB   db;
  blkn_t sbn; // First `SBLK` block in DB
} DISPOSE_DB_CTX;

static iwrc _db_dispose_chain(DISPOSE_DB_CTX *dctx) {
  iwrc rc = 0;
  uint8_t *mm, kvszpow;
  IWFS_FSM *fsm = &dctx->iwkv->fsm;
  blkn_t sbn = dctx->sbn, kvblkn;
  off_t page = 0;

  while (sbn) {
    off_t sba = BLK2ADDR(sbn);
    rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
    RCBREAK(rc);
    memcpy(&kvblkn, mm + sba + SOFF_KBLK_U4, 4);
    kvblkn = IW_ITOHL(kvblkn);
    memcpy(&sbn, mm + sba + SOFF_N0_U4, 4);
    sbn = IW_ITOHL(sbn);
    if (kvblkn) {
      memcpy(&kvszpow, mm + BLK2ADDR(kvblkn) + KBLK_SZPOW_OFF, 1);
    }
    if (dctx->iwkv->fmt_version > 1) {
      uint8_t bpos;
      memcpy(&bpos, mm + sba + SOFF_BPOS_U1_V2, 1);
      rc = fsm->release_mmap(fsm);
      RCBREAK(rc);
      if ((bpos > 0) && (bpos <= SBLK_PAGE_SBLK_NUM_V2)) {
        off_t npage = sba - (bpos - 1) * SBLK_SZ;
        if (npage != page) {
          if (page) {
            if (!fsm->check_allocation_status(fsm, page, SBLK_PAGE_SZ_V2, true)) {
              rc = fsm->deallocate(fsm, page, SBLK_PAGE_SZ_V2);
            }
            RCBREAK(rc);
          }
          page = npage;
        }
      }
    } else {
      rc = fsm->release_mmap(fsm);
      RCBREAK(rc);
      // Deallocate `SBLK`
      rc = fsm->deallocate(fsm, sba, SBLK_SZ);
      RCBREAK(rc);
    }
    // Deallocate `KVBLK`
    if (kvblkn) {
      rc = fsm->deallocate(fsm, BLK2ADDR(kvblkn), 1ULL << kvszpow);
      RCBREAK(rc);
    }
  }
  if (page) {
    if (!fsm->check_allocation_status(fsm, page, SBLK_PAGE_SZ_V2, true)) {
      IWRC(fsm->deallocate(fsm, page, SBLK_PAGE_SZ_V2), rc);
    }
  }
  _db_release_lw(&dctx->db);
  return rc;
}

static WUR iwrc _db_destroy_lw(IWDB *dbp) {
  iwrc rc;
  uint8_t *mm;
  IWDB db = *dbp;
  IWKV iwkv = db->iwkv;
  IWDB prev = db->prev;
  IWDB next = db->next;
  IWFS_FSM *fsm = &iwkv->fsm;
  uint32_t first_sblkn;

  khiter_t k = kh_get(DBS, iwkv->dbs, db->id);
  if (k == kh_end(iwkv->dbs)) {
    iwlog_ecode_error3(IW_ERROR_INVALID_STATE);
    return IW_ERROR_INVALID_STATE;
  }
  kh_del(DBS, iwkv->dbs, k);

  rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCRET(rc);
  if (prev) {
    prev->next = next;
    rc = _db_save(prev, false, mm);
    if (rc) {
      fsm->release_mmap(fsm);
      return rc;
    }
  }
  if (next) {
    next->prev = prev;
    rc = _db_save(next, false, mm);
    if (rc) {
      fsm->release_mmap(fsm);
      return rc;
    }
  }
  // [magic:u4,dbflg:u1,dbid:u4,next_db_blk:u4,p0:u4,n[24]:u4,c[24]:u4,meta_blk:u4,meta_blkn:u4]:217
  memcpy(&first_sblkn, mm + db->addr + DOFF_N0_U4, 4);
  first_sblkn = IW_ITOHL(first_sblkn);
  fsm->release_mmap(fsm);

  if (iwkv->first_db && (iwkv->first_db->addr == db->addr)) {
    uint64_t llv;
    db->iwkv->first_db = next;
    llv = next ? (uint64_t) next->addr : 0;
    llv = IW_HTOILL(llv);
    rc = fsm->writehdr(fsm, sizeof(uint32_t) /*skip magic*/, &llv, sizeof(llv));
  }
  if (iwkv->last_db && (iwkv->last_db->addr == db->addr)) {
    iwkv->last_db = prev;
  }
  // Cleanup DB
  off_t db_addr = db->addr;
  blkn_t meta_blk = db->meta_blk;
  blkn_t meta_blkn = db->meta_blkn;
  db->open = false;

  DISPOSE_DB_CTX dctx = {
    .sbn  = first_sblkn,
    .iwkv = iwkv,
    .db   = db
  };
  IWRC(_db_dispose_chain(&dctx), rc);
  if (meta_blk && meta_blkn) {
    IWRC(fsm->deallocate(fsm, BLK2ADDR(db->meta_blk), BLK2ADDR(db->meta_blkn)), rc);
  }
  IWRC(fsm->deallocate(fsm, db_addr, DB_SZ), rc);
  return rc;
}

static WUR iwrc _db_create_lw(IWKV iwkv, dbid_t dbid, iwdb_flags_t dbflg, IWDB *odb) {
  iwrc rc;
  int rci;
  uint8_t *mm = 0;
  off_t baddr = 0, blen;
  IWFS_FSM *fsm = &iwkv->fsm;
  *odb = 0;
  IWDB db = calloc(1, sizeof(struct _IWDB));
  if (!db) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  pthread_rwlockattr_t attr;
  pthread_rwlockattr_init(&attr);
#if defined __linux__ && (defined __USE_UNIX98 || defined __USE_XOPEN2K)
  pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif
  rci = pthread_rwlock_init(&db->rwl, &attr);
  if (rci) {
    free(db);
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  rci = pthread_spin_init(&db->cursors_slk, 0);
  if (rci) {
    pthread_rwlock_destroy(&db->rwl);
    free(db);
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  rc = fsm->allocate(fsm, DB_SZ, &baddr, &blen, IWKV_FSM_ALLOC_FLAGS);
  if (rc) {
    _db_release_lw(&db);
    return rc;
  }
  db->iwkv = iwkv;
  db->dbflg = dbflg;
  db->addr = baddr;
  db->id = dbid;
  db->prev = iwkv->last_db;
  if (!iwkv->first_db) {
    uint64_t llv;
    iwkv->first_db = db;
    llv = (uint64_t) db->addr;
    llv = IW_HTOILL(llv);
    rc = fsm->writehdr(fsm, sizeof(uint32_t) /*skip magic*/, &llv, sizeof(llv));
  } else if (iwkv->last_db) {
    iwkv->last_db->next = db;
  }
  iwkv->last_db = db;
  khiter_t k = kh_put(DBS, iwkv->dbs, db->id, &rci);
  if (rci != -1) {
    kh_value(iwkv->dbs, k) = db;
  } else {
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    goto finish;
  }
  rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCGO(rc, finish);
  rc = _db_save(db, true, mm);
  RCGO(rc, finish);
  if (db->prev) {
    rc = _db_save(db->prev, false, mm);
    RCGO(rc, finish);
  }
  db->open = true;
  *odb = db;

finish:
  if (mm) {
    fsm->release_mmap(fsm);
  }
  if (rc) {
    fsm->deallocate(fsm, baddr, blen);
    _db_release_lw(&db);
  }
  return rc;
}

//--------------------------  KVBLK

IW_INLINE void _kvblk_create(IWLCTX *lx, off_t baddr, uint8_t kvbpow, KVBLK **oblk) {
  KVBLK *kblk = &lx->kaa[lx->kaan];
  kblk->db = lx->db;
  kblk->addr = baddr;
  kblk->maxoff = 0;
  kblk->idxsz = 2 * IW_VNUMSIZE(0) * KVBLK_IDXNUM;
  kblk->zidx = 0;
  kblk->szpow = kvbpow;
  kblk->flags = KVBLK_DURTY;
  memset(kblk->pidx, 0, sizeof(kblk->pidx));
  *oblk = kblk;
  AAPOS_INC(lx->kaan);
}

IW_INLINE WUR iwrc _kvblk_key_peek(
  const KVBLK *kb,
  uint8_t idx, const uint8_t *mm, uint8_t **obuf,
  uint32_t *olen) {
  if (kb->pidx[idx].len) {
    uint32_t klen, step;
    const uint8_t *rp = mm + kb->addr + (1ULL << kb->szpow) - kb->pidx[idx].off;
    IW_READVNUMBUF(rp, klen, step);
    if (!klen) {
      *obuf = 0;
      *olen = 0;
      iwlog_ecode_error3(IWKV_ERROR_CORRUPTED);
      return IWKV_ERROR_CORRUPTED;
    }
    rp += step;
    *obuf = (uint8_t*) rp;
    *olen = klen;
  } else {
    *obuf = 0;
    *olen = 0;
  }
  return 0;
}

IW_INLINE void _kvblk_value_peek(const KVBLK *kb, uint8_t idx, const uint8_t *mm, uint8_t **obuf, uint32_t *olen) {
  assert(idx < KVBLK_IDXNUM);
  if (kb->pidx[idx].len) {
    uint32_t klen, step;
    const uint8_t *rp = mm + kb->addr + (1ULL << kb->szpow) - kb->pidx[idx].off;
    IW_READVNUMBUF(rp, klen, step);
    rp += step;
    rp += klen;
    *obuf = (uint8_t*) rp;
    *olen = kb->pidx[idx].len - klen - step;
  } else {
    *obuf = 0;
    *olen = 0;
  }
}

static WUR iwrc _kvblk_key_get(KVBLK *kb, uint8_t *mm, uint8_t idx, IWKV_val *key) {
  assert(mm && idx < KVBLK_IDXNUM);
  int32_t klen;
  int step;
  KVP *kvp = &kb->pidx[idx];
  key->compound = 0;
  if (!kvp->len) {
    key->data = 0;
    key->size = 0;
    return 0;
  }
  // [klen:vn,key,value]
  uint8_t *rp = mm + kb->addr + (1ULL << kb->szpow) - kvp->off;
  IW_READVNUMBUF(rp, klen, step);
  rp += step;
  if ((klen < 1) || (klen > kvp->len) || (klen > kvp->off)) {
    iwlog_ecode_error3(IWKV_ERROR_CORRUPTED);
    return IWKV_ERROR_CORRUPTED;
  }
  key->size = (size_t) klen;
  if (kb->db->dbflg & IWDB_VNUM64_KEYS) {
    // Needed to provide enough buffer in _unpack_effective_key()
    key->data = malloc(MAX(key->size, sizeof(int64_t)));
  } else {
    key->data = malloc(key->size);
  }
  if (!key->data) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  memcpy(key->data, rp, key->size);
  return 0;
}

static WUR iwrc _kvblk_value_get(KVBLK *kb, uint8_t *mm, uint8_t idx, IWKV_val *val) {
  assert(mm && idx < KVBLK_IDXNUM);
  int32_t klen;
  int step;
  KVP *kvp = &kb->pidx[idx];
  val->compound = 0;
  if (!kvp->len) {
    val->data = 0;
    val->size = 0;
    return 0;
  }
  // [klen:vn,key,value]
  uint8_t *rp = mm + kb->addr + (1ULL << kb->szpow) - kvp->off;
  IW_READVNUMBUF(rp, klen, step);
  rp += step;
  if ((klen < 1) || (klen > kvp->len) || (klen > kvp->off)) {
    iwlog_ecode_error3(IWKV_ERROR_CORRUPTED);
    return IWKV_ERROR_CORRUPTED;
  }
  rp += klen;
  if (kvp->len > klen + step) {
    val->size = kvp->len - klen - step;
    val->data = malloc(val->size);
    if (!val->data) {
      iwrc rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
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

static WUR iwrc _kvblk_kv_get(KVBLK *kb, uint8_t *mm, uint8_t idx, IWKV_val *key, IWKV_val *val) {
  assert(mm && idx < KVBLK_IDXNUM);
  int32_t klen;
  int step;
  KVP *kvp = &kb->pidx[idx];
  key->compound = 0;
  val->compound = 0;
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
  if ((klen < 1) || (klen > kvp->len) || (klen > kvp->off)) {
    iwlog_ecode_error3(IWKV_ERROR_CORRUPTED);
    return IWKV_ERROR_CORRUPTED;
  }
  key->size = (size_t) klen;
  if (kb->db->dbflg & IWDB_VNUM64_KEYS) {
    // Needed to provide enough buffer in _unpack_effective_key()
    key->data = malloc(MAX(key->size, sizeof(int64_t)));
  } else {
    key->data = malloc(key->size);
  }
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

static WUR iwrc _kvblk_at_mm(IWLCTX *lx, off_t addr, uint8_t *mm, KVBLK *kbp, KVBLK **blkp) {
  uint8_t *rp;
  uint16_t sv;
  int step;
  iwrc rc = 0;
  KVBLK *kb = kbp ? kbp : &lx->kaa[lx->kaan];
  kb->db = lx->db;
  kb->addr = addr;
  kb->maxoff = 0;
  kb->idxsz = 0;
  kb->zidx = -1;
  kb->szpow = 0;
  kb->flags = KVBLK_DEFAULT;
  memset(kb->pidx, 0, sizeof(kb->pidx));

  *blkp = 0;
  rp = mm + addr;
  memcpy(&kb->szpow, rp, 1);
  rp += 1;
  IW_READSV(rp, sv, kb->idxsz);
  if (IW_UNLIKELY(kb->idxsz > KVBLK_MAX_IDX_SZ)) {
    rc = IWKV_ERROR_CORRUPTED;
    iwlog_ecode_error3(rc);
    goto finish;
  }
  for (uint8_t i = 0; i < KVBLK_IDXNUM; ++i) {
    IW_READVNUMBUF64(rp, kb->pidx[i].off, step);
    rp += step;
    IW_READVNUMBUF(rp, kb->pidx[i].len, step);
    rp += step;
    if (kb->pidx[i].len) {
      if (IW_UNLIKELY(!kb->pidx[i].off)) {
        rc = IWKV_ERROR_CORRUPTED;
        iwlog_ecode_error3(rc);
        goto finish;
      }
      if (kb->pidx[i].off > kb->maxoff) {
        kb->maxoff = kb->pidx[i].off;
      }
    } else if (kb->zidx < 0) {
      kb->zidx = i;
    }
    kb->pidx[i].ridx = i;
  }
  *blkp = kb;
  assert(rp - (mm + addr) <= (1ULL << kb->szpow));
  if (!kbp) {
    AAPOS_INC(lx->kaan);
  }

finish:
  return rc;
}

IW_INLINE off_t _kvblk_compacted_offset(KVBLK *kb) {
  off_t coff = 0;
  for (int i = 0; i < KVBLK_IDXNUM; ++i) {
    coff += kb->pidx[i].len;
  }
  return coff;
}

IW_INLINE off_t _kvblk_compacted_dsize(KVBLK *kb) {
  off_t coff = KVBLK_HDRSZ;
  for (int i = 0; i < KVBLK_IDXNUM; ++i) {
    coff += kb->pidx[i].len;
    coff += IW_VNUMSIZE32(kb->pidx[i].len);
    coff += IW_VNUMSIZE(kb->pidx[i].off);
  }
  return coff;
}

static WUR iwrc _kvblk_sync_mm(KVBLK *kb, uint8_t *mm) {
  iwrc rc = 0;
  if (!(kb->flags & KVBLK_DURTY)) {
    return rc;
  }
  uint16_t sp;
  uint8_t *szp;
  uint8_t *wp = mm + kb->addr;
  uint8_t *sptr = wp;
  IWDLSNR *dlsnr = kb->db->iwkv->dlsnr;
  memcpy(wp, &kb->szpow, 1);
  wp += 1;
  szp = wp;
  wp += sizeof(uint16_t);
  for (int i = 0; i < KVBLK_IDXNUM; ++i) {
    KVP *kvp = &kb->pidx[i];
    IW_SETVNUMBUF64(sp, wp, kvp->off);
    wp += sp;
    IW_SETVNUMBUF(sp, wp, kvp->len);
    wp += sp;
  }
  sp = wp - szp - sizeof(uint16_t);
  kb->idxsz = sp;
  assert(kb->idxsz <= KVBLK_MAX_IDX_SZ);
  sp = IW_HTOIS(sp);
  memcpy(szp, &sp, sizeof(uint16_t));
  assert(wp - (mm + kb->addr) <= (1ULL << kb->szpow));
  if (dlsnr) {
    rc = dlsnr->onwrite(dlsnr, kb->addr, sptr, wp - sptr, 0);
  }
  kb->flags &= ~KVBLK_DURTY;
  return rc;
}

#define _kvblk_sort_kv_lt(v1, v2, o) \
  (((v1).off > 0 ? (v1).off : -1UL) < ((v2).off > 0 ? (v2).off : -1UL))

// -V:KSORT_INIT:522, 756, 769
KSORT_INIT(kvblk, KVP, _kvblk_sort_kv_lt)

static WUR iwrc _kvblk_compact_mm(KVBLK *kb, uint8_t *mm) {
  uint8_t i;
  off_t coff = _kvblk_compacted_offset(kb);
  if (coff == kb->maxoff) { // compacted
    return 0;
  }
  KVP tidx[KVBLK_IDXNUM];
  KVP tidx_tmp[KVBLK_IDXNUM];
  iwrc rc = 0;
  uint16_t idxsiz = 0;
  IWDLSNR *dlsnr = kb->db->iwkv->dlsnr;
  off_t blkend = kb->addr + (1ULL << kb->szpow);
  uint8_t *wp = mm + blkend;
  memcpy(tidx, kb->pidx, sizeof(tidx));
  ks_mergesort_kvblk(KVBLK_IDXNUM, tidx, tidx_tmp, 0);

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
      assert(noff <= (1ULL << kb->szpow) && kvp->len <= noff);
      if (dlsnr) {
        rc = dlsnr->onwrite(dlsnr, blkend - noff, wp - kvp->off, kvp->len, 0);
      }
      memmove(wp - noff, wp - kvp->off, kvp->len);
      kvp->off = noff;
    }
    coff += kvp->len;
    idxsiz += IW_VNUMSIZE(kvp->off);
    idxsiz += IW_VNUMSIZE32(kvp->len);
  }
  idxsiz += (KVBLK_IDXNUM - i) * 2;
  for (i = 0; i < KVBLK_IDXNUM; ++i) {
    if (!kb->pidx[i].len) {
      kb->zidx = i;
      break;
    }
  }
  assert(idxsiz <= kb->idxsz);
  kb->idxsz = idxsiz;
  kb->maxoff = coff;
  if (i == KVBLK_IDXNUM) {
    kb->zidx = -1;
  }
  kb->flags |= KVBLK_DURTY;
  assert(_kvblk_compacted_offset(kb) == kb->maxoff);
  return rc;
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

static WUR iwrc _kvblk_rmkv(KVBLK *kb, uint8_t idx, kvblk_rmkv_opts_t opts) {
  iwrc rc = 0;
  uint8_t *mm = 0;
  IWDLSNR *dlsnr = kb->db->iwkv->dlsnr;
  IWFS_FSM *fsm = &kb->db->iwkv->fsm;
  if (kb->pidx[idx].off >= kb->maxoff) {
    kb->maxoff = 0;
    for (int i = 0; i < KVBLK_IDXNUM; ++i) {
      if ((i != idx) && (kb->pidx[i].off > kb->maxoff)) {
        kb->maxoff = kb->pidx[i].off;
      }
    }
  }
  kb->pidx[idx].len = 0;
  kb->pidx[idx].off = 0;
  kb->flags |= KVBLK_DURTY;
  if ((kb->zidx < 0) || (idx < kb->zidx)) {
    kb->zidx = idx;
  }
  if (!(RMKV_NO_RESIZE & opts) && (kb->szpow > KVBLK_INISZPOW)) {
    off_t nlen = 1ULL << kb->szpow;
    off_t dsz = _kvblk_compacted_dsize(kb);
    if (nlen >= 2 * dsz) {
      uint8_t npow = kb->szpow - 1;
      while (npow > KVBLK_INISZPOW && (1ULL << (npow - 1)) >= dsz) {
        --npow;
      }
      rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
      RCGO(rc, finish);

      rc = _kvblk_compact_mm(kb, mm);
      RCGO(rc, finish);

      off_t maxoff = _kvblk_maxkvoff(kb);
      if (dlsnr) {
        rc = dlsnr->onwrite(dlsnr, kb->addr + (1ULL << npow) - maxoff, mm + kb->addr + nlen - maxoff, maxoff, 0);
        RCGO(rc, finish);
      }
      memmove(mm + kb->addr + (1ULL << npow) - maxoff,
              mm + kb->addr + nlen - maxoff,
              (size_t) maxoff);

      fsm->release_mmap(fsm);
      mm = 0;
      rc = fsm->reallocate(fsm, (1ULL << npow), &kb->addr, &nlen, IWKV_FSM_ALLOC_FLAGS);
      RCGO(rc, finish);
      kb->szpow = npow;
      assert(nlen == (1ULL << kb->szpow));
      opts |= RMKV_SYNC;
    }
  }
  if (RMKV_SYNC & opts) {
    rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
    RCGO(rc, finish);
    IWRC(_kvblk_sync_mm(kb, mm), rc);
  }

finish:
  if (mm) {
    fsm->release_mmap(fsm);
  }
  return rc;
}

static WUR iwrc _kvblk_addkv(
  KVBLK          *kb,
  const IWKV_val *key,
  const IWKV_val *val,
  uint8_t        *oidx,
  bool            raw_key) {
  *oidx = 0;

  iwrc rc = 0;
  off_t msz;    // max available free space
  off_t rsz;    // required size to add new key/value pair
  off_t noff;   // offset of new kvpair from end of block
  uint8_t *mm, *wp, *sptr;
  size_t i, sp;
  KVP *kvp;
  IWDB db = kb->db;
  bool compound = !raw_key && (db->dbflg & IWDB_COMPOUND_KEYS);
  IWFS_FSM *fsm = &db->iwkv->fsm;
  bool compacted = false;
  IWDLSNR *dlsnr = kb->db->iwkv->dlsnr;
  IWKV_val *uval = (IWKV_val*) val;

  size_t ksize = key->size;
  if (compound) {
    ksize += IW_VNUMSIZE(key->compound);
  }
  off_t psz = IW_VNUMSIZE(ksize) + ksize;

  if (kb->zidx < 0) {
    return _IWKV_RC_KVBLOCK_FULL;
  }
  psz += uval->size;
  if (psz > IWKV_MAX_KVSZ) {
    return IWKV_ERROR_MAXKVSZ;
  }

start:
  // [szpow:u1,idxsz:u2,[ps0:vn,pl0:vn,..., ps32,pl32]____[[KV],...]] // KVBLK
  msz = (1ULL << kb->szpow) - (KVBLK_HDRSZ + kb->idxsz + kb->maxoff);
  assert(msz >= 0);
  noff = kb->maxoff + psz;
  rsz = psz + IW_VNUMSIZE(noff) + IW_VNUMSIZE(psz);

  if (msz < rsz) { // not enough space
    if (!compacted) {
      compacted = true;
      if (_kvblk_compacted_offset(kb) != kb->maxoff) {
        rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
        RCGO(rc, finish);
        rc = _kvblk_compact_mm(kb, mm);
        RCGO(rc, finish);
        fsm->release_mmap(fsm);
        goto start;
      }
    }
    // resize the whole block
    off_t nlen = 1ULL << kb->szpow;
    off_t nsz = rsz - msz + nlen;
    off_t naddr = kb->addr;
    off_t olen = nlen;

    uint8_t npow = kb->szpow;
    while ((1ULL << ++npow) < nsz) ;

    rc = fsm->allocate(fsm, (1ULL << npow), &naddr, &nlen, IWKV_FSM_ALLOC_FLAGS);
    RCGO(rc, finish);
    assert(nlen == (1ULL << npow));
    rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
    RCGO(rc, finish);
    if (dlsnr) {
      rc = dlsnr->onwrite(dlsnr, naddr, mm + kb->addr, KVBLK_HDRSZ, 0);
      RCGO(rc, finish);
      memcpy(mm + naddr, mm + kb->addr, KVBLK_HDRSZ);
      rc = dlsnr->onwrite(dlsnr, naddr + nlen - kb->maxoff, mm + kb->addr + olen - kb->maxoff, kb->maxoff, 0);
      RCGO(rc, finish);
      memcpy(mm + naddr + nlen - kb->maxoff, mm + kb->addr + olen - kb->maxoff, (size_t) kb->maxoff);
    } else {
      memcpy(mm + naddr, mm + kb->addr, KVBLK_HDRSZ);
      memcpy(mm + naddr + nlen - kb->maxoff, mm + kb->addr + olen - kb->maxoff, (size_t) kb->maxoff);
    }
    fsm->release_mmap(fsm);
    rc = fsm->deallocate(fsm, kb->addr, olen);
    RCGO(rc, finish);

    kb->addr = naddr;
    kb->szpow = npow;
  }
  *oidx = (uint8_t) kb->zidx;
  kvp = &kb->pidx[kb->zidx];
  kvp->len = (uint32_t) psz;
  kvp->off = noff;
  kvp->ridx = (uint8_t) kb->zidx;
  kb->maxoff = noff;
  kb->flags |= KVBLK_DURTY;
  for (i = 0; i < KVBLK_IDXNUM; ++i) {
    if (!kb->pidx[i].len && (i != kb->zidx)) {
      kb->zidx = i;
      break;
    }
  }
  if (i >= KVBLK_IDXNUM) {
    kb->zidx = -1;
  }
  rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCGO(rc, finish);
  assert((1ULL << kb->szpow) >= KVBLK_HDRSZ + kb->idxsz + kb->maxoff);
  assert(kvp->off < (1ULL << kb->szpow) && kvp->len <= kvp->off);
  wp = mm + kb->addr + (1ULL << kb->szpow) - kvp->off;
  sptr = wp;
  // [klen:vn,key,value]
  IW_SETVNUMBUF(sp, wp, ksize);
  wp += sp;
  if (compound) {
    IW_SETVNUMBUF64(sp, wp, key->compound);
    wp += sp;
  }
  memcpy(wp, key->data, key->size);
  wp += key->size;
  memcpy(wp, uval->data, uval->size);
  wp += uval->size;
#ifndef NDEBUG
  assert(wp - sptr == kvp->len);
#endif
  if (dlsnr) {
    rc = dlsnr->onwrite(dlsnr, kb->addr + (1ULL << kb->szpow) - kvp->off, sptr, wp - sptr, 0);
  }
  fsm->release_mmap(fsm);

finish:
  return rc;
}

static WUR iwrc _kvblk_updatev(
  KVBLK          *kb,
  uint8_t        *idxp,
  const IWKV_val *key,                              /* Nullable */
  const IWKV_val *val) {
  assert(*idxp < KVBLK_IDXNUM);
  int32_t i;
  uint32_t len, nlen, sz;
  uint8_t pidx = *idxp, *mm = 0, *wp, *sp;
  IWDB db = kb->db;
  IWDLSNR *dlsnr = kb->db->iwkv->dlsnr;
  IWKV_val *uval = (IWKV_val*) val;
  IWKV_val *ukey = (IWKV_val*) key;
  IWKV_val skey; // stack allocated key/val
  KVP *kvp = &kb->pidx[pidx];
  size_t kbsz = 1ULL << kb->szpow;                            // kvblk size
  off_t freesz = kbsz - KVBLK_HDRSZ - kb->idxsz - kb->maxoff; // free space available
  IWFS_FSM *fsm = &db->iwkv->fsm;

  iwrc rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCRET(rc);
  assert(freesz >= 0);

  wp = mm + kb->addr + kbsz - kvp->off;
  sp = wp;
  IW_READVNUMBUF(wp, len, sz);
  wp += sz;
  if (ukey && (len != ukey->size)) {
    rc = IWKV_ERROR_CORRUPTED;
    iwlog_ecode_error3(rc);
    goto finish;
  }
  wp += len;
  off_t rsize = sz + len + uval->size; // required size
  if (rsize <= kvp->len) {
    memcpy(wp, uval->data, uval->size);
    if (dlsnr) {
      rc = dlsnr->onwrite(dlsnr, wp - mm, uval->data, uval->size, 0);
      RCGO(rc, finish);
    }
    wp += uval->size;
    if ((wp - sp) != kvp->len) {
      kvp->len = wp - sp;
      kb->flags |= KVBLK_DURTY;
    }
  } else {
    KVP tidx[KVBLK_IDXNUM];
    KVP tidx_tmp[KVBLK_IDXNUM];
    off_t koff = kb->pidx[pidx].off;
    memcpy(tidx, kb->pidx, KVBLK_IDXNUM * sizeof(kb->pidx[0]));
    ks_mergesort_kvblk(KVBLK_IDXNUM, tidx, tidx_tmp, 0);
    kb->flags |= KVBLK_DURTY;
    if (!ukey) { // we need a key
      ukey = &skey;
      rc = _kvblk_key_get(kb, mm, pidx, ukey);
      RCGO(rc, finish);
    }
    for (i = 0; i < KVBLK_IDXNUM; ++i) {
      if (tidx[i].off == koff) {
        if (koff - ((i > 0) ? tidx[i - 1].off : 0) >= rsize) {
          nlen = wp + uval->size - sp;
          if (!((nlen > kvp->len) && (freesz - IW_VNUMSIZE32(nlen) + IW_VNUMSIZE32(kvp->len) < 0))) { // enough space?
            memcpy(wp, uval->data, uval->size);
            if (dlsnr) {
              rc = dlsnr->onwrite(dlsnr, wp - mm, uval->data, uval->size, 0);
              RCGO(rc, finish);
            }
            wp += uval->size;
            kvp->len = nlen;
            break;
            ;
          }
        }
        mm = 0;
        fsm->release_mmap(fsm);
        rc = _kvblk_rmkv(kb, pidx, RMKV_NO_RESIZE);
        RCGO(rc, finish);
        rc = _kvblk_addkv(kb, ukey, uval, idxp, false);
        break;
      }
    }
  }

finish:
  if (ukey != key) {
    _kv_val_dispose(ukey);
  }
  if (mm) {
    IWRC(fsm->release_mmap(fsm), rc);
  }
  return rc;
}

//--------------------------  SBLK

IW_INLINE void _sblk_release(IWLCTX *lx, SBLK **sblkp) {
  assert(sblkp && *sblkp);
  SBLK *sblk = *sblkp;
  sblk->flags &= ~SBLK_CACHE_FLAGS; // clear cache flags
  sblk->flags &= ~SBLK_DURTY;       // clear dirty flag
  sblk->kvblk = 0;
  *sblkp = 0;
}

IW_INLINE WUR iwrc _sblk_loadkvblk_mm(IWLCTX *lx, SBLK *sblk, uint8_t *mm) {
  if (!sblk->kvblk && sblk->kvblkn) {
    return _kvblk_at_mm(lx, BLK2ADDR(sblk->kvblkn), mm, 0, &sblk->kvblk);
  } else {
    return 0;
  }
}

static bool _sblk_is_only_one_on_page_v2(IWLCTX *lx, uint8_t *mm, SBLK *sblk, off_t *page_addr) {
  *page_addr = 0;
  if ((sblk->bpos > 0) && (sblk->bpos <= SBLK_PAGE_SBLK_NUM_V2)) {
    off_t addr = sblk->addr - (sblk->bpos - 1) * SBLK_SZ;
    *page_addr = addr;
    for (int i = 0; i < SBLK_PAGE_SBLK_NUM_V2; ++i) {
      if (i != sblk->bpos - 1) {
        uint8_t bv;
        memcpy(&bv, mm + addr + i * SBLK_SZ + SOFF_BPOS_U1_V2, 1);
        if (bv) {
          return false;
        }
      }
    }
  } else {
    return false; // be safe
  }
  return true;
}

IW_INLINE WUR iwrc _sblk_destroy(IWLCTX *lx, SBLK **sblkp) {
  assert(sblkp && *sblkp && (*sblkp)->addr);
  iwrc rc = 0;
  SBLK *sblk = *sblkp;
  lx->destroy_addr = sblk->addr;

  if (!(sblk->flags & SBLK_DB)) {
    uint8_t kvb_szpow, *mm;
    IWDLSNR *dlsnr = lx->db->iwkv->dlsnr;
    IWFS_FSM *fsm = &lx->db->iwkv->fsm;
    off_t kvb_addr = BLK2ADDR(sblk->kvblkn);
    rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
    RCRET(rc);

    if (!sblk->kvblk) {
      // Read KVBLK size as power of two
      memcpy(&kvb_szpow, mm + kvb_addr + KBLK_SZPOW_OFF, 1);
    } else {
      kvb_szpow = sblk->kvblk->szpow;
    }
    if (lx->db->lcnt[sblk->lvl]) {
      lx->db->lcnt[sblk->lvl]--;
      lx->db->flags |= SBLK_DURTY;
    }
    _dbcache_remove_lw(lx, sblk);
    if (lx->db->iwkv->fmt_version > 1) {
      off_t paddr;
      if (_sblk_is_only_one_on_page_v2(lx, mm, sblk, &paddr)) {
        fsm->release_mmap(fsm);
        // Deallocate whole page
        rc = fsm->deallocate(fsm, paddr, SBLK_PAGE_SZ_V2);
      } else {
        memset(mm + sblk->addr + SOFF_BPOS_U1_V2, 0, 1);
        fsm->release_mmap(fsm);
        if (dlsnr) {
          dlsnr->onset(dlsnr, sblk->addr + SOFF_BPOS_U1_V2, 0, 1, 0);
        }
      }
    } else {
      fsm->release_mmap(fsm);
      rc = fsm->deallocate(fsm, sblk->addr, SBLK_SZ);
    }
    IWRC(fsm->deallocate(fsm, kvb_addr, 1ULL << kvb_szpow), rc);
  }
  _sblk_release(lx, sblkp);
  return rc;
}

IW_INLINE uint8_t _sblk_genlevel(IWDB db) {
  uint8_t lvl;
#ifdef IW_TESTS
  if (iwkv_next_level >= 0) {
    lvl = (uint8_t) iwkv_next_level;
    iwkv_next_level = -1;
    assert(lvl < SLEVELS);
    return lvl;
  }
#endif
  uint32_t r = iwu_rand_u32();
  for (lvl = 0; lvl < SLEVELS && !(r & 1); ++lvl) r >>= 1;
  uint8_t ret = IW_UNLIKELY(lvl >= SLEVELS) ? SLEVELS - 1 : lvl;
  while (ret > 0 && db->lcnt[ret - 1] == 0) {
    --ret;
  }
  return ret;
}

static WUR iwrc _sblk_create_v1(IWLCTX *lx, uint8_t nlevel, uint8_t kvbpow, off_t baddr, uint8_t bpos, SBLK **oblk) {
  iwrc rc;
  SBLK *sblk;
  KVBLK *kvblk;
  off_t blen;
  IWFS_FSM *fsm = &lx->db->iwkv->fsm;
  if (kvbpow < KVBLK_INISZPOW) {
    kvbpow = KVBLK_INISZPOW;
  }
  *oblk = 0;
  if (!bpos) {
    rc = fsm->allocate(fsm, SBLK_SZ + (1ULL << kvbpow), &baddr, &blen, IWKV_FSM_ALLOC_FLAGS);
    RCRET(rc);
    assert(blen - SBLK_SZ == (1ULL << kvbpow));
    _kvblk_create(lx, baddr + SBLK_SZ, kvbpow, &kvblk);
  } else {
    // Allocate kvblk as separate chunk
    off_t kblkaddr = 0;
    rc = fsm->allocate(fsm, (1ULL << kvbpow), &kblkaddr, &blen, IWKV_FSM_ALLOC_FLAGS);
    assert(blen == (1ULL << kvbpow));
    _kvblk_create(lx, kblkaddr, kvbpow, &kvblk);
  }
  sblk = &lx->saa[lx->saan];
  sblk->db = lx->db;
  sblk->db->lcnt[nlevel]++;
  sblk->db->flags |= SBLK_DURTY;
  sblk->addr = baddr;
  sblk->flags = (SBLK_DURTY | SBLK_CACHE_PUT);
  sblk->lvl = nlevel;
  sblk->p0 = 0;
  memset(sblk->n, 0, sizeof(sblk->n));
  sblk->kvblk = kvblk;
  sblk->kvblkn = ADDR2BLK(kvblk->addr);
  sblk->lkl = 0;
  sblk->pnum = 0;
  sblk->bpos = bpos;
  memset(sblk->pi, 0, sizeof(sblk->pi));
  *oblk = sblk;
  AAPOS_INC(lx->saan);
  return 0;
}

static void _sblk_find_free_page_slot_v2(IWLCTX *lx, uint8_t *mm, SBLK *sblk, off_t *obaddr, uint8_t *oslot) {
  if ((sblk->bpos < 1) || (sblk->bpos > SBLK_PAGE_SBLK_NUM_V2)) {
    *obaddr = 0;
    *oslot = 0;
    return;
  }
  off_t paddr = sblk->addr - (sblk->bpos - 1) * SBLK_SZ;
  for (int i = sblk->bpos + 1; i <= SBLK_PAGE_SBLK_NUM_V2; ++i) {
    uint8_t slot;
    memcpy(&slot, mm + paddr + (i - 1) * SBLK_SZ + SOFF_BPOS_U1_V2, 1);
    if (!slot) {
      *obaddr = paddr + (i - 1) * SBLK_SZ;
      *oslot = i;
      return;
    }
  }
  for (int i = sblk->bpos - 1; i > 0; --i) {
    uint8_t slot;
    memcpy(&slot, mm + paddr + (i - 1) * SBLK_SZ + SOFF_BPOS_U1_V2, 1);
    if (!slot) {
      *obaddr = paddr + (i - 1) * SBLK_SZ;
      *oslot = i;
      return;
    }
  }
  *obaddr = 0;
  *oslot = 0;
}

/// Create
static WUR iwrc _sblk_create_v2(IWLCTX *lx, uint8_t nlevel, uint8_t kvbpow, SBLK *lower, SBLK *upper, SBLK **oblk) {
  off_t baddr = 0;
  uint8_t bpos = 0, *mm;
  IWFS_FSM *fsm = &lx->db->iwkv->fsm;
  SBLK *_lower = lower;
  SBLK *_upper = upper;

  for (int i = SLEVELS - 1; i >= 0; --i) {
    if (lx->pupper[i] && (lx->pupper[i]->lvl >= nlevel)) {
      _upper = lx->pupper[i];
    }
    if (lx->plower[i] && (lx->plower[i]->lvl >= nlevel)) {
      _lower = lx->plower[i];
    }
  }

  iwrc rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCRET(rc);
  _sblk_find_free_page_slot_v2(lx, mm, _lower, &baddr, &bpos);
  if (!baddr && _upper && (_upper->addr != _lower->addr)) {
    _sblk_find_free_page_slot_v2(lx, mm, _upper, &baddr, &bpos);
  }
  if (!baddr) {
    if (_lower->addr != lower->addr) {
      _sblk_find_free_page_slot_v2(lx, mm, lower, &baddr, &bpos);
    }
    if (!baddr && upper && _upper && (_upper->addr != upper->addr)) {
      _sblk_find_free_page_slot_v2(lx, mm, upper, &baddr, &bpos);
    }
  }
  fsm->release_mmap(fsm);

  if (!baddr) {
    // No free slots - allocate new SBLK page
    off_t blen;
    bpos = 1;
    IWDLSNR *dlsnr = lx->db->iwkv->dlsnr;
    rc = fsm->allocate(fsm, SBLK_PAGE_SZ_V2, &baddr, &blen, IWKV_FSM_ALLOC_FLAGS);
    RCRET(rc);
    rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
    RCRET(rc);
    // Fill page to zero
    memset(mm + baddr, 0, blen);
    if (dlsnr) {
      rc = dlsnr->onset(dlsnr, baddr, 0, blen, 0);
    }
    fsm->release_mmap(fsm);
    RCRET(rc);
  }
  return _sblk_create_v1(lx, nlevel, kvbpow, baddr, bpos, oblk);
}

IW_INLINE WUR iwrc _sblk_create(IWLCTX *lx, uint8_t nlevel, uint8_t kvbpow, SBLK *lower, SBLK *upper, SBLK **oblk) {
  if (lx->db->iwkv->fmt_version > 1) {
    return _sblk_create_v2(lx, nlevel, kvbpow, lower, upper, oblk);
  } else {
    return _sblk_create_v1(lx, nlevel, kvbpow, lower->addr, 0, oblk);
  }
}

static WUR iwrc _sblk_at2(IWLCTX *lx, off_t addr, sblk_flags_t flgs, SBLK *sblk) {
  iwrc rc;
  uint8_t *mm;
  uint32_t lv;
  sblk_flags_t flags = lx->sbflags | flgs;
  IWDB db = lx->db;
  IWFS_FSM *fsm = &db->iwkv->fsm;
  sblk->kvblk = 0;
  sblk->bpos = 0;
  sblk->db = db;

  rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCRET(rc);

  if (IW_UNLIKELY(addr == db->addr)) {
    uint8_t *rp = mm + addr + DOFF_N0_U4;
    // [magic:u4,dbflg:u1,dbid:u4,next_db_blk:u4,p0:u4,n[24]:u4,c[24]:u4,meta_blk:u4,meta_blkn:u4]:217
    sblk->addr = addr;
    sblk->flags = SBLK_DB | flags;
    sblk->lvl = 0;
    sblk->p0 = 0;
    sblk->kvblkn = 0;
    sblk->lkl = 0;
    sblk->pnum = KVBLK_IDXNUM;
    memset(sblk->pi, 0, sizeof(sblk->pi));
    for (int i = 0; i < SLEVELS; ++i) {
      IW_READLV(rp, lv, sblk->n[i]);
      if (sblk->n[i]) {
        ++sblk->lvl;
      } else {
        break;
      }
    }
    if (sblk->lvl) {
      --sblk->lvl;
    }
  } else if (addr) {
    uint8_t uflags;
    uint8_t *rp = mm + addr;
    sblk->addr = addr;
    // [flags:u1,lvl:u1,lkl:u1,pnum:u1,p0:u4,kblk:u4,pi:u1[32],n:u4[24],bpos:u1,lk:u115]:u256
    memcpy(&uflags, rp++, 1);
    sblk->flags = uflags;
    if (sblk->flags & ~SBLK_PERSISTENT_FLAGS) {
      rc = IWKV_ERROR_CORRUPTED;
      iwlog_ecode_error3(rc);
      goto finish;
    }
    sblk->flags |= flags;
    memcpy(&sblk->lvl, rp++, 1);
    if (sblk->lvl >= SLEVELS) {
      rc = IWKV_ERROR_CORRUPTED;
      iwlog_ecode_error3(rc);
      goto finish;
    }
    memcpy(&sblk->lkl, rp++, 1);
    if (sblk->lkl > db->iwkv->pklen) {
      rc = IWKV_ERROR_CORRUPTED;
      iwlog_ecode_error3(rc);
      goto finish;
    }
    memcpy(&sblk->pnum, rp++, 1);
    if (sblk->pnum < 0) {
      rc = IWKV_ERROR_CORRUPTED;
      iwlog_ecode_error3(rc);
      goto finish;
    }
    memcpy(&sblk->p0, rp, 4);
    sblk->p0 = IW_ITOHL(sblk->p0);
    rp += 4;
    memcpy(&sblk->kvblkn, rp, 4);
    sblk->kvblkn = IW_ITOHL(sblk->kvblkn);
    rp += 4;
    memcpy(sblk->pi, rp, KVBLK_IDXNUM);
    rp += KVBLK_IDXNUM;
    for (int i = 0; i <= sblk->lvl; ++i) {
      memcpy(&sblk->n[i], rp, 4);
      sblk->n[i] = IW_ITOHL(sblk->n[i]);
      rp += 4;
    }
    if (db->iwkv->fmt_version > 1) {
      rp = mm + addr + SOFF_BPOS_U1_V2;
      memcpy(&sblk->bpos, rp++, 1);
    } else {
      rp = mm + addr + SOFF_LK_V1;
    }
    // Lower key
    memcpy(sblk->lk, rp, (size_t) sblk->lkl);
  } else { // Database tail
    uint8_t *rp = mm + db->addr + DOFF_P0_U4;
    sblk->addr = 0;
    sblk->flags = SBLK_DB | flags;
    sblk->lvl = 0;
    sblk->kvblkn = 0;
    sblk->lkl = 0;
    sblk->pnum = KVBLK_IDXNUM;
    memset(sblk->pi, 0, sizeof(sblk->pi));
    IW_READLV(rp, lv, sblk->p0);
    if (!sblk->p0) {
      sblk->p0 = ADDR2BLK(db->addr);
    }
  }

finish:
  fsm->release_mmap(fsm);
  return rc;
}

IW_INLINE WUR iwrc _sblk_at(IWLCTX *lx, off_t addr, sblk_flags_t flgs, SBLK **sblkp) {
  *sblkp = 0;
  SBLK *sblk = &lx->saa[lx->saan];
  iwrc rc = _sblk_at2(lx, addr, flgs, sblk);
  AAPOS_INC(lx->saan);
  *sblkp = sblk;
  return rc;
}

static WUR iwrc _sblk_sync_mm(IWLCTX *lx, SBLK *sblk, uint8_t *mm) {
  iwrc rc = 0;
  if (sblk->flags & SBLK_DURTY) {
    uint32_t lv;
    IWDLSNR *dlsnr = lx->db->iwkv->dlsnr;
    sblk->flags &= ~SBLK_DURTY;
    if (IW_UNLIKELY(sblk->flags & SBLK_DB)) {
      uint8_t *sp;
      uint8_t *wp = mm + sblk->db->addr;
      if (sblk->addr) {
        assert(sblk->addr == sblk->db->addr);
        wp += DOFF_N0_U4;
        sp = wp;
        // [magic:u4,dbflg:u1,dbid:u4,next_db_blk:u4,p0:u4,n[24]:u4,c[24]:u4,meta_blk:u4,meta_blkn:u4]:217
        for (int i = 0; i < SLEVELS; ++i) {
          IW_WRITELV(wp, lv, sblk->n[i]);
        }
        assert(wp - (mm + sblk->db->addr) <= SBLK_SZ);
        for (int i = 0; i < SLEVELS; ++i) {
          IW_WRITELV(wp, lv, lx->db->lcnt[i]);
        }
      } else { // Database tail
        wp += DOFF_P0_U4;
        sp = wp;
        IW_WRITELV(wp, lv, sblk->p0);
        assert(wp - (mm + sblk->db->addr) <= SBLK_SZ);
      }
      if (dlsnr) {
        rc = dlsnr->onwrite(dlsnr, sp - mm, sp, wp - sp, 0);
      }
      return rc;
    } else {
      uint8_t *wp = mm + sblk->addr;
      sblk_flags_t flags = (sblk->flags & SBLK_PERSISTENT_FLAGS);
      uint8_t uflags = flags;
      assert(sblk->lkl <= lx->db->iwkv->pklen);
      // [u1:flags,lvl:u1,lkl:u1,pnum:u1,p0:u4,kblk:u4,[pi0:u1,... pi32],n0-n23:u4,lk:u116]:u256
      wp += SOFF_FLAGS_U1;
      memcpy(wp++, &uflags, 1);
      memcpy(wp++, &sblk->lvl, 1);
      memcpy(wp++, &sblk->lkl, 1);
      memcpy(wp++, &sblk->pnum, 1);
      IW_WRITELV(wp, lv, sblk->p0);
      IW_WRITELV(wp, lv, sblk->kvblkn);
      memcpy(wp, sblk->pi, KVBLK_IDXNUM);
      wp = mm + sblk->addr + SOFF_N0_U4;
      for (int i = 0; i <= sblk->lvl; ++i) {
        IW_WRITELV(wp, lv, sblk->n[i]);
      }
      if (lx->db->iwkv->fmt_version > 1) {
        wp = mm + sblk->addr + SOFF_BPOS_U1_V2;
        memcpy(wp++, &sblk->bpos, 1);
      } else {
        wp = mm + sblk->addr + SOFF_LK_V1;
      }
      memcpy(wp, sblk->lk, (size_t) sblk->lkl);
      if (dlsnr) {
        rc = dlsnr->onwrite(dlsnr, sblk->addr, mm + sblk->addr, SOFF_END, 0);
        RCRET(rc);
      }
    }
  }
  if (sblk->kvblk && (sblk->kvblk->flags & KVBLK_DURTY)) {
    IWRC(_kvblk_sync_mm(sblk->kvblk, mm), rc);
  }
  if (sblk->flags & SBLK_CACHE_UPDATE) {
    _dbcache_update_lw(lx, sblk);
  }
  return rc;
}

IW_INLINE WUR iwrc _sblk_sync(IWLCTX *lx, SBLK *sblk) {
  if ((sblk->flags & SBLK_DURTY) || (sblk->kvblk && (sblk->kvblk->flags & KVBLK_DURTY))) {
    uint8_t *mm;
    IWFS_FSM *fsm = &lx->db->iwkv->fsm;
    iwrc rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
    RCRET(rc);
    rc = _sblk_sync_mm(lx, sblk, mm);
    fsm->release_mmap(fsm);
    return rc;
  }
  return 0;
}

IW_INLINE WUR iwrc _sblk_sync_and_release_mm(IWLCTX *lx, SBLK **sblkp, uint8_t *mm) {
  SBLK *sblk = *sblkp;
  if (lx->destroy_addr && (lx->destroy_addr == sblk->addr)) {
    return 0;
  }
  iwrc rc = 0;
  if (mm) {
    rc = _sblk_sync_mm(lx, *sblkp, mm);
  }
  _sblk_release(lx, sblkp);
  return rc;
}

static WUR iwrc _sblk_find_pi_mm(SBLK *sblk, IWLCTX *lx, const uint8_t *mm, bool *found, uint8_t *idxp) {
  *found = false;
  if (sblk->flags & SBLK_DB) {
    *idxp = KVBLK_IDXNUM;
    return 0;
  }
  uint8_t *k;
  uint32_t kl;
  int idx = 0, lb = 0, ub = sblk->pnum - 1;
  iwdb_flags_t dbflg = lx->db->dbflg;

  if (sblk->pnum < 1) {
    *idxp = 0;
    return 0;
  }
  while (1) {
    idx = (ub + lb) / 2;
    iwrc rc = _kvblk_key_peek(sblk->kvblk, sblk->pi[idx], mm, &k, &kl);
    RCRET(rc);
    int cr = _cmp_keys(dbflg, k, kl, lx->key);
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
  *idxp = idx;
  return 0;
}

static WUR iwrc _sblk_insert_pi_mm(
  SBLK *sblk, uint8_t nidx, IWLCTX *lx,
  const uint8_t *mm, uint8_t *idxp) {
  assert(sblk->kvblk);

  uint8_t *k;
  uint32_t kl;
  int idx = 0, lb = 0, ub = sblk->pnum - 1, nels = sblk->pnum; // NOLINT

  if (nels < 1) {
    sblk->pi[0] = nidx;
    ++sblk->pnum;
    *idxp = 0;
    return 0;
  }
  iwdb_flags_t dbflg = sblk->db->dbflg;
  while (1) {
    idx = (ub + lb) / 2;
    iwrc rc = _kvblk_key_peek(sblk->kvblk, sblk->pi[idx], mm, &k, &kl);
    RCRET(rc);
    int cr = _cmp_keys(dbflg, k, kl, lx->key);
    if (!cr) {
      break;
    } else if (cr < 0) {
      lb = idx + 1;
      if (lb > ub) {
        idx = lb;
        ++sblk->pnum;
        break;
      }
    } else {
      ub = idx - 1;
      if (lb > ub) {
        ++sblk->pnum;
        break;
      }
    }
  }
  if (nels - idx > 0) {
    memmove(sblk->pi + idx + 1, sblk->pi + idx, nels - idx);
  }
  sblk->pi[idx] = nidx;
  *idxp = idx;
  return 0;
}

static WUR iwrc _sblk_addkv2(
  SBLK           *sblk,
  int8_t          idx,
  const IWKV_val *key,
  const IWKV_val *val,
  bool            raw_key) {
  assert(sblk && key && key->size && key->data && val && idx >= 0 && sblk->kvblk);

  uint8_t kvidx;
  IWDB db = sblk->db;
  KVBLK *kvblk = sblk->kvblk;
  if (sblk->pnum >= KVBLK_IDXNUM) {
    return _IWKV_RC_KVBLOCK_FULL;
  }

  iwrc rc = _kvblk_addkv(kvblk, key, val, &kvidx, raw_key);
  RCRET(rc);
  if (sblk->pnum - idx > 0) {
    memmove(sblk->pi + idx + 1, sblk->pi + idx, sblk->pnum - idx);
  }
  sblk->pi[idx] = kvidx;
  if (sblk->kvblkn != ADDR2BLK(kvblk->addr)) {
    sblk->kvblkn = ADDR2BLK(kvblk->addr);
    if (!(sblk->flags & SBLK_CACHE_FLAGS)) {
      sblk->flags |= SBLK_CACHE_UPDATE;
    }
  }
  ++sblk->pnum;
  sblk->flags |= SBLK_DURTY;
  if (idx == 0) { // the lowest key inserted
    size_t ksize = key->size;
    bool compound = !raw_key && (db->dbflg & IWDB_COMPOUND_KEYS);
    if (compound) {
      ksize += IW_VNUMSIZE(key->compound);
    }
    sblk->lkl = MIN(db->iwkv->pklen, ksize);
    uint8_t *wp = sblk->lk;
    if (compound) {
      int len;
      IW_SETVNUMBUF64(len, wp, key->compound);
      wp += len;
    }
    memcpy(wp, key->data, sblk->lkl - (ksize - key->size));
    if (ksize <= db->iwkv->pklen) {
      sblk->flags |= SBLK_FULL_LKEY;
    } else {
      sblk->flags &= ~SBLK_FULL_LKEY;
    }
    if (!(sblk->flags & SBLK_CACHE_FLAGS)) {
      sblk->flags |= SBLK_CACHE_UPDATE;
    }
  }
  if (!raw_key) {
    // Update active cursors inside this block
    pthread_spin_lock(&db->cursors_slk);
    for (IWKV_cursor cur = db->cursors; cur; cur = cur->next) {
      if (cur->cn && (cur->cn->addr == sblk->addr)) {
        if (cur->cn != sblk) {
          memcpy(cur->cn, sblk, sizeof(*cur->cn));
          cur->cn->kvblk = 0;
          cur->cn->flags &= SBLK_PERSISTENT_FLAGS;
        }
        if (cur->cnpos >= idx) {
          cur->cnpos++;
        }
      }
    }
    pthread_spin_unlock(&db->cursors_slk);
  }
  return 0;
}

static WUR iwrc _sblk_addkv(SBLK *sblk, IWLCTX *lx) {
  const IWKV_val *key = lx->key;
  const IWKV_val *val = lx->val;
  assert(key && key->size && key->data && val && sblk->kvblk);
  if (!sblk) {
    iwlog_error2("sblk != 0");
    return IW_ERROR_ASSERTION;
  }
  uint8_t *mm, idx, kvidx;
  IWDB db = sblk->db;
  KVBLK *kvblk = sblk->kvblk;
  IWFS_FSM *fsm = &sblk->db->iwkv->fsm;
  if (sblk->pnum >= KVBLK_IDXNUM) {
    return _IWKV_RC_KVBLOCK_FULL;
  }
  iwrc rc = _kvblk_addkv(kvblk, key, val, &kvidx, false);
  RCRET(rc);
  rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCRET(rc);
  rc = _sblk_insert_pi_mm(sblk, kvidx, lx, mm, &idx);
  RCRET(rc);
  fsm->release_mmap(fsm);
  if (idx == 0) { // the lowest key inserted
    size_t ksize = key->size;
    bool compound = (db->dbflg & IWDB_COMPOUND_KEYS);
    if (compound) {
      ksize += IW_VNUMSIZE(key->compound);
    }
    sblk->lkl = MIN(db->iwkv->pklen, ksize);
    uint8_t *wp = sblk->lk;
    if (compound) {
      int len;
      IW_SETVNUMBUF64(len, wp, key->compound);
      wp += len;
    }
    memcpy(wp, key->data, sblk->lkl - (ksize - key->size));
    if (ksize <= db->iwkv->pklen) {
      sblk->flags |= SBLK_FULL_LKEY;
    } else {
      sblk->flags &= ~SBLK_FULL_LKEY;
    }
    if (!(sblk->flags & SBLK_CACHE_FLAGS)) {
      sblk->flags |= SBLK_CACHE_UPDATE;
    }
  }
  if (sblk->kvblkn != ADDR2BLK(kvblk->addr)) {
    sblk->kvblkn = ADDR2BLK(kvblk->addr);
    if (!(sblk->flags & SBLK_CACHE_FLAGS)) {
      sblk->flags |= SBLK_CACHE_UPDATE;
    }
  }
  sblk->flags |= SBLK_DURTY;

  // Update active cursors inside this block
  pthread_spin_lock(&db->cursors_slk);
  for (IWKV_cursor cur = db->cursors; cur; cur = cur->next) {
    if (cur->cn && (cur->cn->addr == sblk->addr)) {
      if (cur->cn != sblk) {
        memcpy(cur->cn, sblk, sizeof(*cur->cn));
        cur->cn->kvblk = 0;
        cur->cn->flags &= SBLK_PERSISTENT_FLAGS;
      }
      if (cur->cnpos >= idx) {
        cur->cnpos++;
      }
    }
  }
  pthread_spin_unlock(&db->cursors_slk);

  return 0;
}

static WUR iwrc _sblk_updatekv(
  SBLK *sblk, int8_t idx,
  const IWKV_val *key, const IWKV_val *val) {
  assert(sblk && sblk->kvblk && idx >= 0 && idx < sblk->pnum);
  IWDB db = sblk->db;
  KVBLK *kvblk = sblk->kvblk;
  uint8_t kvidx = sblk->pi[idx];
  iwrc intrc = 0;
  iwrc rc = _kvblk_updatev(kvblk, &kvidx, key, val);
  if (IWKV_IS_INTERNAL_RC(rc)) {
    intrc = rc;
    rc = 0;
  }
  RCRET(rc);
  if (sblk->kvblkn != ADDR2BLK(kvblk->addr)) {
    sblk->kvblkn = ADDR2BLK(kvblk->addr);
    if (!(sblk->flags & SBLK_CACHE_FLAGS)) {
      sblk->flags |= SBLK_CACHE_UPDATE;
    }
  }
  sblk->pi[idx] = kvidx;
  sblk->flags |= SBLK_DURTY;
  // Update active cursors inside this block
  pthread_spin_lock(&db->cursors_slk);
  for (IWKV_cursor cur = db->cursors; cur; cur = cur->next) {
    if (cur->cn && (cur->cn != sblk) && (cur->cn->addr == sblk->addr)) {
      memcpy(cur->cn, sblk, sizeof(*cur->cn));
      cur->cn->kvblk = 0;
      cur->cn->flags &= SBLK_PERSISTENT_FLAGS;
    }
  }
  pthread_spin_unlock(&db->cursors_slk);
  return intrc;
}

static WUR iwrc _sblk_rmkv(SBLK *sblk, uint8_t idx) {
  assert(sblk && sblk->kvblk);
  IWDB db = sblk->db;
  KVBLK *kvblk = sblk->kvblk;
  IWFS_FSM *fsm = &sblk->db->iwkv->fsm;
  assert(kvblk && idx < sblk->pnum && sblk->pi[idx] < KVBLK_IDXNUM);

  iwrc rc = _kvblk_rmkv(kvblk, sblk->pi[idx], 0);
  RCRET(rc);

  if (sblk->kvblkn != ADDR2BLK(kvblk->addr)) {
    sblk->kvblkn = ADDR2BLK(kvblk->addr);
    if (!(sblk->flags & SBLK_CACHE_FLAGS)) {
      sblk->flags |= SBLK_CACHE_UPDATE;
    }
  }
  --sblk->pnum;
  sblk->flags |= SBLK_DURTY;

  if ((idx < sblk->pnum) && (sblk->pnum > 0)) {
    memmove(sblk->pi + idx, sblk->pi + idx + 1, sblk->pnum - idx);
  }

  if (idx == 0) { // Lowest key removed
    // Replace the lowest key with the next one or reset
    if (sblk->pnum > 0) {
      uint8_t *mm, *kbuf;
      uint32_t klen;
      rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
      RCRET(rc);
      rc = _kvblk_key_peek(sblk->kvblk, sblk->pi[idx], mm, &kbuf, &klen);
      if (rc) {
        fsm->release_mmap(fsm);
        return rc;
      }
      sblk->lkl = MIN(db->iwkv->pklen, klen);
      memcpy(sblk->lk, kbuf, sblk->lkl);
      fsm->release_mmap(fsm);
      if (klen <= db->iwkv->pklen) {
        sblk->flags |= SBLK_FULL_LKEY;
      } else {
        sblk->flags &= ~SBLK_FULL_LKEY;
      }
      if (!(sblk->flags & SBLK_CACHE_FLAGS)) {
        sblk->flags |= SBLK_CACHE_UPDATE;
      }
    } else {
      sblk->lkl = 0;
      sblk->flags |= SBLK_CACHE_REMOVE;
    }
  }

  // Update active cursors
  pthread_spin_lock(&db->cursors_slk);
  for (IWKV_cursor cur = db->cursors; cur; cur = cur->next) {
    if (cur->cn && (cur->cn->addr == sblk->addr)) {
      cur->skip_next = 0;
      if (cur->cn != sblk) {
        memcpy(cur->cn, sblk, sizeof(*cur->cn));
        cur->cn->kvblk = 0;
        cur->cn->flags &= SBLK_PERSISTENT_FLAGS;
      }
      if (cur->cnpos == idx) {
        if (idx && (idx == sblk->pnum)) {
          cur->cnpos--;
          cur->skip_next = -1;
        } else {
          cur->skip_next = 1;
        }
      } else if (cur->cnpos > idx) {
        cur->cnpos--;
      }
    }
  }
  pthread_spin_unlock(&db->cursors_slk);
  return 0;
}

//--------------------------  IWLCTX

WUR iwrc _lx_sblk_cmp_key(IWLCTX *lx, SBLK *sblk, int *resp) {
  int res = 0;
  iwrc rc = 0;
  iwdb_flags_t dbflg = sblk->db->dbflg;
  const IWKV_val *key = lx->key;
  uint8_t lkl = sblk->lkl;
  size_t ksize = key->size;

  if (IW_UNLIKELY((sblk->pnum < 1) || (sblk->flags & SBLK_DB))) {
    *resp = 0;
    iwlog_ecode_error3(IWKV_ERROR_CORRUPTED);
    return IWKV_ERROR_CORRUPTED;
  }
  if (dbflg & IWDB_COMPOUND_KEYS) {
    ksize += IW_VNUMSIZE(key->compound);
  }
  if (  (sblk->flags & SBLK_FULL_LKEY)
     || (ksize < lkl)
     || (dbflg & (IWDB_VNUM64_KEYS | IWDB_REALNUM_KEYS))) {
    res = _cmp_keys(dbflg, sblk->lk, lkl, key);
  } else {
    res = _cmp_keys_prefix(dbflg, sblk->lk, lkl, key);
    if (res == 0) {
      uint32_t kl;
      uint8_t *mm, *k;
      IWFS_FSM *fsm = &lx->db->iwkv->fsm;
      rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
      if (rc) {
        *resp = 0;
        return rc;
      }
      if (!sblk->kvblk) {
        rc = _sblk_loadkvblk_mm(lx, sblk, mm);
        if (rc) {
          *resp = 0;
          fsm->release_mmap(fsm);
          return rc;
        }
      }
      rc = _kvblk_key_peek(sblk->kvblk, sblk->pi[0], mm, &k, &kl);
      RCRET(rc);
      res = _cmp_keys(dbflg, k, kl, key);
      fsm->release_mmap(fsm);
    }
  }
  *resp = res;
  return rc;
}

static WUR iwrc _lx_roll_forward(IWLCTX *lx, uint8_t lvl) {
  iwrc rc = 0;
  int cret;
  SBLK *sblk;
  blkn_t blkn;
  assert(lx->lower);

  while ((blkn = lx->lower->n[lvl])) {
    off_t blkaddr = BLK2ADDR(blkn);
    if ((lx->nlvl > -1) && (lvl < lx->nlvl)) {
      uint8_t ulvl = lvl + 1;
      if (lx->pupper[ulvl] && (lx->pupper[ulvl]->addr == blkaddr)) {
        sblk = lx->pupper[ulvl];
      } else if (lx->plower[ulvl] && (lx->plower[ulvl]->addr == blkaddr)) {
        sblk = lx->plower[ulvl];
      } else {
        rc = _sblk_at(lx, blkaddr, 0, &sblk);
      }
    } else {
      rc = _sblk_at(lx, blkaddr, 0, &sblk);
    }
    RCRET(rc);
#ifndef NDEBUG
    ++lx->num_cmps;
#endif
    rc = _lx_sblk_cmp_key(lx, sblk, &cret);
    RCRET(rc);
    if ((cret > 0) || (lx->upper_addr == sblk->addr)) { // upper > key
      lx->upper = sblk;
      break;
    } else {
      lx->lower = sblk;
    }
  }
  return 0;
}

static WUR iwrc _lx_find_bounds(IWLCTX *lx) {
  iwrc rc = 0;
  int lvl;
  blkn_t blkn;
  SBLK *dblk = &lx->dblk;
  if (!dblk->addr) {
    SBLK *s;
    rc = _sblk_at(lx, lx->db->addr, 0, &s);
    RCRET(rc);
    memcpy(dblk, s, sizeof(*dblk));
  }
  if (!lx->lower) {
    rc = _dbcache_get(lx);
    RCRET(rc);
  }
  if (lx->nlvl > dblk->lvl) {
    // New level in DB
    dblk->lvl = (uint8_t) lx->nlvl;
    dblk->flags |= SBLK_DURTY;
  }
  lvl = lx->lower->lvl;
  while (lvl > -1) {
    rc = _lx_roll_forward(lx, (uint8_t) lvl);
    RCRET(rc);
    if (lx->upper) {
      blkn = ADDR2BLK(lx->upper->addr);
    } else {
      blkn = 0;
    }
    do {
      if (lx->nlvl >= lvl) {
        lx->plower[lvl] = lx->lower;
        lx->pupper[lvl] = lx->upper;
      }
    } while (lvl-- && lx->lower->n[lvl] == blkn);
  }
  return 0;
}

static iwrc _lx_release_mm(IWLCTX *lx, uint8_t *mm) {
  iwrc rc = 0;
  if (lx->nlvl > -1) {
    SBLK *lsb = 0, *usb = 0;
    if (lx->nb) {
      rc = _sblk_sync_mm(lx, lx->nb, mm);
      RCGO(rc, finish);
    }
    if (lx->pupper[0] == lx->upper) {
      lx->upper = 0;
    }
    if (lx->plower[0] == lx->lower) {
      lx->lower = 0;
    }
    for (int i = 0; i <= lx->nlvl; ++i) {
      if (lx->pupper[i]) {
        if (lx->pupper[i] != usb) {
          usb = lx->pupper[i];
          rc = _sblk_sync_and_release_mm(lx, &lx->pupper[i], mm);
          RCGO(rc, finish);
        }
        lx->pupper[i] = 0;
      }
      if (lx->plower[i]) {
        if (lx->plower[i] != lsb) {
          lsb = lx->plower[i];
          rc = _sblk_sync_and_release_mm(lx, &lx->plower[i], mm);
          RCGO(rc, finish);
        }
        lx->plower[i] = 0;
      }
    }
  }
  if (lx->upper) {
    rc = _sblk_sync_and_release_mm(lx, &lx->upper, mm);
    RCGO(rc, finish);
  }
  if (lx->lower) {
    rc = _sblk_sync_and_release_mm(lx, &lx->lower, mm);
    RCGO(rc, finish);
  }
  if (lx->dblk.flags & SBLK_DURTY) {
    rc = _sblk_sync_mm(lx, &lx->dblk, mm);
    RCGO(rc, finish);
  }
  if (lx->nb) {
    if (lx->nb->flags & SBLK_CACHE_PUT) {
      rc = _dbcache_put_lw(lx, lx->nb);
    }
    _sblk_release(lx, &lx->nb);
    RCGO(rc, finish);
  }
  if (lx->cache_reload) {
    rc = _dbcache_fill_lw(lx);
  }

finish:
  lx->destroy_addr = 0;
  return rc;
}

iwrc _lx_release(IWLCTX *lx) {
  uint8_t *mm;
  IWFS_FSM *fsm = &lx->db->iwkv->fsm;
  iwrc rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCRET(rc);
  rc = _lx_release_mm(lx, mm);
  IWRC(fsm->release_mmap(fsm), rc);
  return rc;
}

static iwrc _lx_split_addkv(IWLCTX *lx, int idx, SBLK *sblk) {
  iwrc rc;
  SBLK *nb;
  blkn_t nblk;
  IWDB db = sblk->db;
  bool uside = (idx == sblk->pnum);
  register const int8_t pivot = (KVBLK_IDXNUM / 2) + 1; // 32

  if (uside) { // Upper side
    rc = _sblk_create(lx, (uint8_t) lx->nlvl, 0, sblk, lx->upper, &nb);
    RCRET(rc);
    rc = _sblk_addkv(nb, lx);
    RCGO(rc, finish);
  } else { // New key is somewhere in a middle of sblk->kvblk
    assert(sblk->kvblk);
    // We are in the middle
    // Do the partial split
    // Move kv pairs into new `nb`
    // Compute space required for the new sblk which stores kv pairs after pivot `idx`
    size_t sz = 0;
    for (int8_t i = pivot; i < sblk->pnum; ++i) {
      sz += sblk->kvblk->pidx[sblk->pi[i]].len;
    }
    if (idx > pivot) {
      sz += IW_VNUMSIZE(lx->key->size) + lx->key->size + lx->val->size;
    }
    sz += KVBLK_MAX_NKV_SZ;
    uint8_t kvbpow = (uint8_t) iwlog2_64(sz);
    while ((1ULL << kvbpow) < sz) kvbpow++;

    rc = _sblk_create(lx, (uint8_t) lx->nlvl, kvbpow, sblk, lx->upper, &nb);
    RCRET(rc);

    IWKV_val key, val;
    IWFS_FSM *fsm = &lx->db->iwkv->fsm;
    for (int8_t i = pivot, end = sblk->pnum; i < end; ++i) {
      uint8_t *mm;
      rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
      RCBREAK(rc);

      rc = _kvblk_kv_get(sblk->kvblk, mm, sblk->pi[i], &key, &val);
      assert(key.size);
      fsm->release_mmap(fsm);
      RCBREAK(rc);

      rc = _sblk_addkv2(nb, i - pivot, &key, &val, true);
      _kv_dispose(&key, &val);

      RCBREAK(rc);
      sblk->kvblk->pidx[sblk->pi[i]].len = 0;
      sblk->kvblk->pidx[sblk->pi[i]].off = 0;
      --sblk->pnum;
    }
    sblk->kvblk->flags |= KVBLK_DURTY;
    sblk->kvblk->zidx = sblk->pi[pivot];
    sblk->kvblk->maxoff = 0;
    for (int i = 0; i < KVBLK_IDXNUM; ++i) {
      if (sblk->kvblk->pidx[i].off > sblk->kvblk->maxoff) {
        sblk->kvblk->maxoff = sblk->kvblk->pidx[i].off;
      }
    }
  }

  // Fix levels:
  //  [ lb -> sblk -> ub ]
  //  [ lb -> sblk -> nb -> ub ]
  nblk = ADDR2BLK(nb->addr);
  lx->pupper[0]->p0 = nblk;
  lx->pupper[0]->flags |= SBLK_DURTY;
  nb->p0 = ADDR2BLK(lx->plower[0]->addr);
  for (int i = 0; i <= nb->lvl; ++i) {
    lx->plower[i]->n[i] = nblk;
    lx->plower[i]->flags |= SBLK_DURTY;
    nb->n[i] = ADDR2BLK(lx->pupper[i]->addr);
  }

  pthread_spin_lock(&db->cursors_slk);
  for (IWKV_cursor cur = db->cursors; cur; cur = cur->next) {
    if (cur->cn && (cur->cn->addr == sblk->addr)) {
      if (cur->cnpos >= pivot) {
        memcpy(cur->cn, nb, sizeof(*cur->cn));
        cur->cn->kvblk = 0;
        cur->cn->flags &= SBLK_PERSISTENT_FLAGS;
        cur->cnpos -= pivot;
      }
    }
  }
  pthread_spin_unlock(&db->cursors_slk);

  if (!uside) {
    if (idx > pivot) {
      rc = _sblk_addkv(nb, lx);
    } else {
      rc = _sblk_addkv(sblk, lx);
    }
    RCGO(rc, finish);
  }

finish:
  if (rc) {
    lx->nb = 0;
    IWRC(_sblk_destroy(lx, &nb), rc);
  } else {
    lx->nb = nb;
  }
  return rc;
}

IW_INLINE iwrc _lx_init_chute(IWLCTX *lx) {
  assert(lx->nlvl >= 0);
  iwrc rc = 0;
  if (!lx->pupper[lx->nlvl]) { // fix zero upper by dbtail
    SBLK *dbtail;
    rc = _sblk_at(lx, 0, 0, &dbtail);
    RCRET(rc);
    for (int8_t i = lx->nlvl; i >= 0 && !lx->pupper[i]; --i) {
      lx->pupper[i] = dbtail;
    }
  }
  return 0;
}

static WUR iwrc _lx_addkv(IWLCTX *lx) {
  iwrc rc;
  bool found, uadd;
  uint8_t *mm = 0, idx;
  SBLK *sblk = lx->lower;
  IWFS_FSM *fsm = &lx->db->iwkv->fsm;
  if (lx->nlvl > -1) {
    rc = _lx_init_chute(lx);
    RCRET(rc);
  }
  rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCRET(rc);
  rc = _sblk_loadkvblk_mm(lx, sblk, mm);
  if (rc) {
    fsm->release_mmap(fsm);
    return rc;
  }
  rc = _sblk_find_pi_mm(sblk, lx, mm, &found, &idx);
  RCRET(rc);
  if (found && (lx->opflags & IWKV_NO_OVERWRITE)) {
    fsm->release_mmap(fsm);
    return IWKV_ERROR_KEY_EXISTS;
  }
  uadd = (  !found
         && sblk->pnum > KVBLK_IDXNUM - 1 && idx > KVBLK_IDXNUM - 1
         && lx->upper && lx->upper->pnum < KVBLK_IDXNUM);
  if (uadd) {
    rc = _sblk_loadkvblk_mm(lx, lx->upper, mm);
    if (rc) {
      fsm->release_mmap(fsm);
      return rc;
    }
  }
  if (found) {
    IWKV_val sval, *val = lx->val;
    if (lx->opflags & IWKV_VAL_INCREMENT) {
      int64_t ival;
      uint8_t *rp;
      uint32_t len;
      if (val->size == 4) {
        int32_t lv;
        memcpy(&lv, val->data, val->size);
        lv = IW_ITOHL(lv);
        ival = lv;
      } else if (val->size == 8) {
        memcpy(&ival, val->data, val->size);
        ival = IW_ITOHLL(ival);
      } else {
        rc = IWKV_ERROR_VALUE_CANNOT_BE_INCREMENTED;
        fsm->release_mmap(fsm);
        return rc;
      }
      _kvblk_value_peek(sblk->kvblk, sblk->pi[idx], mm, &rp, &len);
      sval.data = rp;
      sval.size = len;
      if (sval.size == 4) {
        uint32_t lv;
        memcpy(&lv, sval.data, 4);
        lv = IW_ITOHL(lv);
        lv += ival;
        _num2lebuf(lx->incbuf, &lv, 4);
      } else if (sval.size == 8) {
        uint64_t llv;
        memcpy(&llv, sval.data, 8);
        llv = IW_ITOHLL(llv);
        llv += ival;
        _num2lebuf(lx->incbuf, &llv, 8);
      } else {
        rc = IWKV_ERROR_VALUE_CANNOT_BE_INCREMENTED;
        fsm->release_mmap(fsm);
        return rc;
      }
      sval.data = lx->incbuf;
      val = &sval;
    }
    if (lx->ph) {
      IWKV_val oldval;
      rc = _kvblk_value_get(sblk->kvblk, mm, sblk->pi[idx], &oldval);
      fsm->release_mmap(fsm);
      if (!rc) {
        // note: oldval should be disposed by ph
        rc = lx->ph(lx->key, lx->val, &oldval, lx->phop);
      }
      RCRET(rc);
    } else {
      fsm->release_mmap(fsm);
    }
    return _sblk_updatekv(sblk, idx, lx->key, val);
  } else {
    fsm->release_mmap(fsm);
    if (sblk->pnum > KVBLK_IDXNUM - 1) {
      if (uadd) {
        if (lx->ph) {
          rc = lx->ph(lx->key, lx->val, 0, lx->phop);
          RCRET(rc);
        }
        return _sblk_addkv(lx->upper, lx);
      }
      if (lx->nlvl < 0) {
        return _IWKV_RC_REQUIRE_NLEVEL;
      }
      if (lx->ph) {
        rc = lx->ph(lx->key, lx->val, 0, lx->phop);
        RCRET(rc);
      }
      return _lx_split_addkv(lx, idx, sblk);
    } else {
      if (lx->ph) {
        rc = lx->ph(lx->key, lx->val, 0, lx->phop);
        RCRET(rc);
      }
      return _sblk_addkv2(sblk, idx, lx->key, lx->val, false);
    }
  }
}

IW_INLINE WUR iwrc _lx_put_lw(IWLCTX *lx) {
  iwrc rc;
start:
  rc = _lx_find_bounds(lx);
  if (rc) {
    _lx_release_mm(lx, 0);
    return rc;
  }
  rc = _lx_addkv(lx);
  if (rc == _IWKV_RC_REQUIRE_NLEVEL) {
    SBLK *lower = lx->lower;
    lx->lower = 0;
    _lx_release_mm(lx, 0);
    lx->nlvl = _sblk_genlevel(lx->db);
    if (lower->lvl >= lx->nlvl) {
      lx->lower = lower;
    }
    goto start;
  }
  if (rc == _IWKV_RC_KVBLOCK_FULL) {
    rc = IWKV_ERROR_CORRUPTED;
    iwlog_ecode_error3(rc);
  }
  IWRC(_lx_release(lx), rc);
  return rc;
}

IW_INLINE WUR iwrc _lx_get_lr(IWLCTX *lx) {
  iwrc rc = _lx_find_bounds(lx);
  RCRET(rc);
  bool found;
  uint8_t *mm, idx;
  IWFS_FSM *fsm = &lx->db->iwkv->fsm;
  lx->val->size = 0;
  rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCRET(rc);
  rc = _sblk_loadkvblk_mm(lx, lx->lower, mm);
  RCGO(rc, finish);
  rc = _sblk_find_pi_mm(lx->lower, lx, mm, &found, &idx);
  RCGO(rc, finish);
  if (found) {
    rc = _kvblk_value_get(lx->lower->kvblk, mm, lx->lower->pi[idx], lx->val);
  } else {
    rc = IWKV_ERROR_NOTFOUND;
  }

finish:
  IWRC(fsm->release_mmap(fsm), rc);
  _lx_release_mm(lx, 0);
  return rc;
}

static WUR iwrc _lx_del_sblk_lw(IWLCTX *lx, SBLK *sblk, uint8_t idx) {
  assert(sblk->pnum == 1 && sblk->kvblk);

  iwrc rc;
  IWDB db = lx->db;
  KVBLK *kvblk = sblk->kvblk;
  blkn_t sblk_blkn = ADDR2BLK(sblk->addr);

  _lx_release_mm(lx, 0);
  lx->nlvl = sblk->lvl;
  lx->upper_addr = sblk->addr;

  rc = _lx_find_bounds(lx);
  RCRET(rc);
  assert(lx->upper->pnum == 1 && lx->upper->addr == lx->upper_addr);

  lx->upper->kvblk = kvblk;
  rc = _sblk_rmkv(lx->upper, idx);
  RCGO(rc, finish);

  for (int i = 0; i <= lx->nlvl; ++i) {
    lx->plower[i]->n[i] = lx->upper->n[i];
    lx->plower[i]->flags |= SBLK_DURTY;
    if (lx->plower[i]->flags & SBLK_DB) {
      if (!lx->plower[i]->n[i]) {
        --lx->plower[i]->lvl;
      }
    }
    if (lx->pupper[i] == lx->upper) {
      // Do not touch `lx->upper` in next `_lx_release_mm()` call
      lx->pupper[i] = 0;
    }
  }

  SBLK rb;  // Block to remove
  memcpy(&rb, lx->upper, sizeof(rb));

  SBLK *nb, // Block after lx->upper
       *rbp = &rb;

  assert(!lx->nb);
  rc = _sblk_at(lx, BLK2ADDR(rb.n[0]), 0, &nb);
  RCGO(rc, finish);
  lx->nb = nb;
  lx->nb->p0 = rb.p0;
  lx->nb->flags |= SBLK_DURTY;

  // Update cursors within sblk removed
  pthread_spin_lock(&db->cursors_slk);
  for (IWKV_cursor cur = db->cursors; cur; cur = cur->next) {
    if (cur->cn) {
      if (cur->cn->addr == sblk->addr) {
        if (nb->flags & SBLK_DB) {
          if (!(lx->plower[0]->flags & SBLK_DB)) {
            memcpy(cur->cn, lx->plower[0], sizeof(*cur->cn));
            cur->cn->flags &= SBLK_PERSISTENT_FLAGS;
            cur->cn->kvblk = 0;
            cur->skip_next = -1;
            cur->cnpos = lx->plower[0]->pnum;
            if (cur->cnpos) {
              cur->cnpos--;
            }
          } else {
            cur->cn = 0;
            cur->cnpos = 0;
            cur->skip_next = 0;
          }
        } else {
          memcpy(cur->cn, nb, sizeof(*nb));
          cur->cn->flags &= SBLK_PERSISTENT_FLAGS;
          cur->cn->kvblk = 0;
          cur->cnpos = 0;
          cur->skip_next = 1;
        }
      } else if (cur->cn->n[0] == sblk_blkn) {
        memcpy(cur->cn, lx->plower[0], sizeof(*cur->cn));
        cur->cn->kvblk = 0;
        cur->cn->flags &= SBLK_PERSISTENT_FLAGS;
      } else if (cur->cn->p0 == sblk_blkn) {
        memcpy(cur->cn, nb, sizeof(*nb));
        cur->cn->kvblk = 0;
        cur->cn->flags &= SBLK_PERSISTENT_FLAGS;
      }
    }
  }
  pthread_spin_unlock(&db->cursors_slk);

  rc = _sblk_destroy(lx, &rbp);

finish:
  return rc;
}

static WUR iwrc _lx_del_lw(IWLCTX *lx) {
  iwrc rc;
  bool found;
  uint8_t *mm = 0, idx;
  IWDB db = lx->db;
  IWFS_FSM *fsm = &db->iwkv->fsm;
  SBLK *sblk;

  rc = _lx_find_bounds(lx);
  RCRET(rc);

  sblk = lx->lower;
  rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCGO(rc, finish);
  rc = _sblk_loadkvblk_mm(lx, sblk, mm);
  RCGO(rc, finish);
  rc = _sblk_find_pi_mm(sblk, lx, mm, &found, &idx);
  RCGO(rc, finish);
  if (!found) {
    rc = IWKV_ERROR_NOTFOUND;
    goto finish;
  }
  fsm->release_mmap(fsm);
  mm = 0;

  if (sblk->pnum == 1) { // last kv in block
    rc = _lx_del_sblk_lw(lx, sblk, idx);
  } else {
    rc = _sblk_rmkv(sblk, idx);
  }

finish:
  if (mm) {
    fsm->release_mmap(fsm);
  }
  if (rc) {
    _lx_release_mm(lx, 0);
  } else {
    rc = _lx_release(lx);
  }
  return rc;
}

//-------------------------- CACHE

static void _dbcache_destroy_lw(IWDB db) {
  free(db->cache.nodes);
  memset(&db->cache, 0, sizeof(db->cache));
}

IW_INLINE uint8_t _dbcache_lvl(uint8_t lvl) {
  uint8_t clvl = (lvl >= DBCACHE_LEVELS) ? (lvl - DBCACHE_LEVELS + 1) : DBCACHE_MIN_LEVEL;
  if (clvl < DBCACHE_MIN_LEVEL) {
    clvl = DBCACHE_MIN_LEVEL;
  }
  return clvl;
}

static WUR iwrc _dbcache_cmp_nodes(const void *v1, const void *v2, void *op, int *res) {
  iwrc rc = 0;
  uint8_t *mm = 0;
  IWLCTX *lx = op;
  IWDB db = lx->db;
  IWFS_FSM *fsm = &db->iwkv->fsm;
  iwdb_flags_t dbflg = db->dbflg;
  int rv = 0, step;

  const DBCNODE *cn1 = v1, *cn2 = v2;
  uint8_t *k1 = (uint8_t*) cn1->lk, *k2 = (uint8_t*) cn2->lk;
  uint32_t kl1 = cn1->lkl, kl2 = cn2->lkl;
  KVBLK *kb;

  if (!kl1 && cn1->fullkey) {
    kl1 = cn1->sblkn;
  }
  if (!kl2 && cn2->fullkey) {
    kl2 = cn2->sblkn;
  }

  IWKV_val key2 = {
    .size = kl2,
    .data = k2
  };

  if (dbflg & IWDB_COMPOUND_KEYS) {
    IW_READVNUMBUF64(k2, key2.compound, step);
    key2.size -= step;
    key2.data = (char*) key2.data + step;
  }

  rv = _cmp_keys_prefix(dbflg, k1, kl1, &key2);

  if ((rv == 0) && !(dbflg & (IWDB_VNUM64_KEYS | IWDB_REALNUM_KEYS))) {

    if (!cn1->fullkey || !cn2->fullkey) {
      rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
      RCRET(rc);
      if (!cn1->fullkey) {
        rc = _kvblk_at_mm(lx, BLK2ADDR(cn1->kblkn), mm, 0, &kb);
        RCGO(rc, finish);
        rc = _kvblk_key_peek(kb, cn1->k0idx, mm, &k1, &kl1);
        RCGO(rc, finish);
      }
      if (!cn2->fullkey) {
        rc = _kvblk_at_mm(lx, BLK2ADDR(cn2->kblkn), mm, 0, &kb);
        RCGO(rc, finish);
        rc = _kvblk_key_peek(kb, cn2->k0idx, mm, &k2, &kl2);
        RCGO(rc, finish);
        key2.size = kl2;
        key2.data = k2;
        if (dbflg & IWDB_COMPOUND_KEYS) {
          IW_READVNUMBUF64(k2, key2.compound, step);
          key2.size -= step;
          key2.data = (char*) key2.data + step;
        }
      }

      rv = _cmp_keys(dbflg, k1, kl1, &key2);
    } else if (dbflg & IWDB_COMPOUND_KEYS) {

      int64_t c1, c2 = key2.compound;
      IW_READVNUMBUF64(k1, c1, step);
      kl1 -= step;
      if (key2.size == kl1) {
        rv = c1 > c2 ? -1 : c1 < c2 ? 1 : 0;
      } else {
        rv = (int) key2.size - (int) kl1;
      }
    } else {
      rv = (int) kl2 - (int) kl1;
    }
  }

finish:
  *res = rv;
  if (mm) {
    fsm->release_mmap(fsm);
  }
  return rc;
}

static WUR iwrc _dbcache_fill_lw(IWLCTX *lx) {
  iwrc rc = 0;
  IWDB db = lx->db;
  lx->cache_reload = 0;
  if (!lx->dblk.addr) {
    SBLK *s;
    rc = _sblk_at(lx, lx->db->addr, 0, &s);
    RCRET(rc);
    memcpy(&lx->dblk, s, sizeof(lx->dblk));
  }
  SBLK *sdb = &lx->dblk;
  SBLK *sblk = sdb;
  DBCACHE *c = &db->cache;
  assert(lx->db->addr == sdb->addr);
  c->num = 0;
  if (c->nodes) {
    free(c->nodes);
    c->nodes = 0;
  }
  if (sdb->lvl < DBCACHE_MIN_LEVEL) {
    c->open = true;
    return 0;
  }
  c->lvl = _dbcache_lvl(sdb->lvl);
  c->nsize = (lx->db->dbflg & IWDB_VNUM64_KEYS) ? DBCNODE_VNUM_SZ : DBCNODE_STR_SZ;
  c->asize = c->nsize * ((1U << DBCACHE_LEVELS) + DBCACHE_ALLOC_STEP);

  size_t nsize = c->nsize;
  c->nodes = malloc(c->asize);
  if (!c->nodes) {
    c->open = false;
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  blkn_t n;
  uint8_t *wp;
  size_t num = 0;
  while ((n = sblk->n[c->lvl])) {
    rc = _sblk_at(lx, BLK2ADDR(n), 0, &sblk);
    RCRET(rc);
    if (offsetof(DBCNODE, lk) + sblk->lkl > nsize) {
      free(c->nodes);
      c->nodes = 0;
      rc = IWKV_ERROR_CORRUPTED;
      iwlog_ecode_error3(rc);
      return rc;
    }
    DBCNODE cn = {
      .lkl     = sblk->lkl,
      .fullkey = (sblk->flags & SBLK_FULL_LKEY),
      .k0idx   = sblk->pi[0],
      .sblkn   = ADDR2BLK(sblk->addr),
      .kblkn   = sblk->kvblkn
    };
    if (c->asize < nsize * (num + 1)) {
      c->asize += (nsize * DBCACHE_ALLOC_STEP);
      wp = (uint8_t*) c->nodes;
      DBCNODE *nn = realloc(c->nodes, c->asize);
      if (!nn) {
        rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
        free(wp);
        return rc;
      }
      c->nodes = nn;
    }
    wp = (uint8_t*) c->nodes + nsize * num;
    memcpy(wp, &cn, offsetof(DBCNODE, lk));
    wp += offsetof(DBCNODE, lk);
    memcpy(wp, sblk->lk, sblk->lkl);
    ++num;
  }
  c->num = num;
  c->open = true;
  return 0;
}

static WUR iwrc _dbcache_get(IWLCTX *lx) {
  iwrc rc = 0;
  off_t idx;
  bool found;
  DBCNODE *n;
  alignas(DBCNODE) uint8_t dbcbuf[255];
  IWDB db = lx->db;
  DBCACHE *cache = &db->cache;
  const IWKV_val *key = lx->key;
  if ((lx->nlvl > -1) || (cache->num < 1)) {
    lx->lower = &lx->dblk;
    return 0;
  }
  assert(cache->nodes);
  size_t lxksiz = key->size;
  if (db->dbflg & IWDB_COMPOUND_KEYS) {
    lxksiz += IW_VNUMSIZE(key->compound);
  }

  if (sizeof(DBCNODE) + lxksiz <= sizeof(dbcbuf)) {
    n = (DBCNODE*) dbcbuf;
  } else {
    n = malloc(sizeof(DBCNODE) + lxksiz);
    if (!n) {
      return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
  }
  n->sblkn = (uint32_t) lxksiz; // `sblkn` used to store key size (to keep DBCNODE compact)
  n->kblkn = 0;
  n->fullkey = 1;
  n->lkl = 0;
  n->k0idx = 0;

  uint8_t *wp = (uint8_t*) n + offsetof(DBCNODE, lk);
  if (db->dbflg & IWDB_COMPOUND_KEYS) {
    size_t step;
    char vbuf[IW_VNUMBUFSZ];
    IW_SETVNUMBUF(step, vbuf, key->compound);
    memcpy(wp, vbuf, step);
    wp += step;
  }
  memcpy(wp, key->data, key->size);

  idx = iwarr_sorted_find2(cache->nodes, cache->num, cache->nsize, n, lx, &found, _dbcache_cmp_nodes);
  if (idx > 0) {
    DBCNODE *fn = (DBCNODE*) ((uint8_t*) cache->nodes + (idx - 1) * cache->nsize);
    assert(fn && idx - 1 < cache->num);
    rc = _sblk_at(lx, BLK2ADDR(fn->sblkn), 0, &lx->lower);
  } else {
    lx->lower = &lx->dblk;
  }
  if ((uint8_t*) n != dbcbuf) {
    free(n);
  }
  return rc;
}

static WUR iwrc _dbcache_put_lw(IWLCTX *lx, SBLK *sblk) {
  off_t idx;
  bool found;
  IWDB db = lx->db;
  alignas(DBCNODE) uint8_t dbcbuf[255];
  DBCNODE *n = (DBCNODE*) dbcbuf;
  DBCACHE *cache = &db->cache;
  size_t nsize = cache->nsize;

  sblk->flags &= ~SBLK_CACHE_PUT;
  assert(sizeof(*cache) + sblk->lkl <= sizeof(dbcbuf));
  if ((sblk->pnum < 1) || (sblk->lvl < cache->lvl)) {
    return 0;
  }
  if ((sblk->lvl >= cache->lvl + DBCACHE_LEVELS) || !cache->nodes) { // need to reload full cache
    lx->cache_reload = 1;
    return 0;
  }
  if (!sblk->kvblk) {
    assert(sblk->kvblk);
    return IW_ERROR_INVALID_STATE;
  }
  n->lkl = sblk->lkl;
  n->fullkey = (sblk->flags & SBLK_FULL_LKEY);
  n->k0idx = sblk->pi[0];
  n->sblkn = ADDR2BLK(sblk->addr);
  n->kblkn = sblk->kvblkn;
  memcpy((uint8_t*) n + offsetof(DBCNODE, lk), sblk->lk, sblk->lkl);

  idx = iwarr_sorted_find2(cache->nodes, cache->num, nsize, n, lx, &found, _dbcache_cmp_nodes);
  assert(!found);

  if (cache->asize <= cache->num * nsize) {
    size_t nsz = cache->asize + (nsize * DBCACHE_ALLOC_STEP);
    DBCNODE *nodes = realloc(cache->nodes, nsz);
    if (!nodes) {
      iwrc rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
      free(cache->nodes);
      cache->nodes = 0;
      return rc;
    }
    cache->asize = nsz;
    cache->nodes = nodes;
  }

  uint8_t *cptr = (uint8_t*) cache->nodes;
  if (cache->num != idx) {
    memmove(cptr + (idx + 1) * nsize, cptr + idx * nsize, (cache->num - idx) * nsize);
  }
  memcpy(cptr + idx * nsize, n, nsize);
  ++cache->num;
  return 0;
}

static void _dbcache_remove_lw(IWLCTX *lx, SBLK *sblk) {
  IWDB db = lx->db;
  DBCACHE *cache = &db->cache;
  sblk->flags &= ~SBLK_CACHE_REMOVE;
  if ((sblk->lvl < cache->lvl) || (cache->num < 1)) {
    return;
  }
  if ((cache->lvl > DBCACHE_MIN_LEVEL) && (lx->dblk.lvl < sblk->lvl)) {
    // Database level reduced so we need to shift cache down
    lx->cache_reload = 1;
    return;
  }
  blkn_t sblkn = ADDR2BLK(sblk->addr);
  size_t num = cache->num;
  size_t nsize = cache->nsize;
  uint8_t *rp = (uint8_t*) cache->nodes;
  for (size_t i = 0; i < num; ++i) {
    DBCNODE *n = (DBCNODE*) (rp + i * nsize);
    if (sblkn == n->sblkn) {
      if (i < num - 1) {
        memmove(rp + i * nsize, rp + (i + 1) * nsize, (num - i - 1) * nsize);
      }
      --cache->num;
      break;
    }
  }
}

static void _dbcache_update_lw(IWLCTX *lx, SBLK *sblk) {
  IWDB db = lx->db;
  DBCACHE *cache = &db->cache;
  assert(sblk->pnum > 0);
  sblk->flags &= ~SBLK_CACHE_UPDATE;
  if ((sblk->lvl < cache->lvl) || (cache->num < 1)) {
    return;
  }
  blkn_t sblkn = ADDR2BLK(sblk->addr);
  size_t num = cache->num;
  size_t nsize = cache->nsize;
  uint8_t *rp = (uint8_t*) cache->nodes;
  for (size_t i = 0; i < num; ++i) {
    DBCNODE *n = (DBCNODE*) (rp + i * nsize);
    if (sblkn == n->sblkn) {
      n->kblkn = sblk->kvblkn;
      n->lkl = sblk->lkl;
      n->fullkey = (sblk->flags & SBLK_FULL_LKEY);
      n->k0idx = sblk->pi[0];
      memcpy((uint8_t*) n + offsetof(DBCNODE, lk), sblk->lk, sblk->lkl);
      break;
    }
  }
}

//--------------------------  CURSOR

IW_INLINE WUR iwrc _cursor_get_ge_idx(IWLCTX *lx, IWKV_cursor_op op, uint8_t *oidx) {
  iwrc rc = _lx_find_bounds(lx);
  RCRET(rc);
  bool found;
  uint8_t *mm, idx;
  IWFS_FSM *fsm = &lx->db->iwkv->fsm;
  rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCRET(rc);
  rc = _sblk_loadkvblk_mm(lx, lx->lower, mm);
  RCGO(rc, finish);
  rc = _sblk_find_pi_mm(lx->lower, lx, mm, &found, &idx);
  RCGO(rc, finish);
  if (found) {
    *oidx = idx;
  } else {
    if ((op == IWKV_CURSOR_EQ) || (lx->lower->flags & SBLK_DB) || (lx->lower->pnum < 1)) {
      rc = IWKV_ERROR_NOTFOUND;
    } else {
      *oidx = idx ? idx - 1 : idx;
    }
  }

finish:
  IWRC(fsm->release_mmap(fsm), rc);
  return rc;
}

static WUR iwrc _cursor_to_lr(IWKV_cursor cur, IWKV_cursor_op op) {
  iwrc rc = 0;
  IWDB db = cur->lx.db;
  IWLCTX *lx = &cur->lx;
  blkn_t dblk = ADDR2BLK(db->addr);
  if (op < IWKV_CURSOR_NEXT) { // IWKV_CURSOR_BEFORE_FIRST | IWKV_CURSOR_AFTER_LAST
    if (cur->cn) {
      _sblk_release(lx, &cur->cn);
    }
    if (op == IWKV_CURSOR_BEFORE_FIRST) {
      cur->dbaddr = db->addr;
      cur->cnpos = KVBLK_IDXNUM - 1;
    } else {
      cur->dbaddr = -1; // Negative as sign of dbtail
      cur->cnpos = 0;
    }
    return 0;
  }

start:
  if (op < IWKV_CURSOR_EQ) { // IWKV_CURSOR_NEXT | IWKV_CURSOR_PREV
    blkn_t n = 0;
    if (!cur->cn) {
      if (cur->dbaddr) {
        rc = _sblk_at(lx, (cur->dbaddr < 0 ? 0 : cur->dbaddr), 0, &cur->cn);
        cur->dbaddr = 0;
        RCGO(rc, finish);
      } else {
        rc = IWKV_ERROR_NOTFOUND;
        goto finish;
      }
    }
    if (op == IWKV_CURSOR_NEXT) {
      if (cur->skip_next > 0) {
        goto finish;
      }
      if (cur->cnpos + 1 >= cur->cn->pnum) {
        n = cur->cn->n[0];
        if (!n) {
          rc = IWKV_ERROR_NOTFOUND;
          goto finish;
        }
        _sblk_release(lx, &cur->cn);
        rc = _sblk_at(lx, BLK2ADDR(n), 0, &cur->cn);
        RCGO(rc, finish);
        cur->cnpos = 0;
        if (IW_UNLIKELY(!cur->cn->pnum)) {
          goto start;
        }
      } else {
        if (cur->cn->flags & SBLK_DB) {
          rc = IWKV_ERROR_NOTFOUND;
          goto finish;
        }
        ++cur->cnpos;
      }
    } else { // IWKV_CURSOR_PREV
      if (cur->skip_next < 0) {
        goto finish;
      }
      if (cur->cnpos == 0) {
        n = cur->cn->p0;
        if (!n || (n == dblk)) {
          rc = IWKV_ERROR_NOTFOUND;
          goto finish;
        }
        _sblk_release(lx, &cur->cn);
        RCGO(rc, finish);
        rc = _sblk_at(lx, BLK2ADDR(n), 0, &cur->cn);
        RCGO(rc, finish);
        if (IW_LIKELY(cur->cn->pnum)) {
          cur->cnpos = cur->cn->pnum - 1;
        } else {
          goto start;
        }
      } else {
        if (cur->cn->flags & SBLK_DB) {
          rc = IWKV_ERROR_NOTFOUND;
          goto finish;
        }
        --cur->cnpos;
      }
    }
  } else { // IWKV_CURSOR_EQ | IWKV_CURSOR_GE
    if (!lx->key) {
      rc = IW_ERROR_INVALID_STATE;
      goto finish;
    }
    rc = _cursor_get_ge_idx(lx, op, &cur->cnpos);
    if (lx->upper) {
      _sblk_release(lx, &lx->upper);
    }
    if (!rc) {
      cur->cn = lx->lower;
      lx->lower = 0;
    }
  }

finish:
  cur->skip_next = 0;
  if (rc && (rc != IWKV_ERROR_NOTFOUND)) {
    if (cur->cn) {
      _sblk_release(lx, &cur->cn);
    }
  }
  return rc;
}

//--------------------------  PUBLIC API

static const char *_kv_ecodefn(locale_t locale, uint32_t ecode) {
  if (!((ecode > _IWKV_ERROR_START) && (ecode < _IWKV_ERROR_END))) {
    return 0;
  }
  switch (ecode) {
    case IWKV_ERROR_NOTFOUND:
      return "Key not found. (IWKV_ERROR_NOTFOUND)";
    case IWKV_ERROR_KEY_EXISTS:
      return "Key exists. (IWKV_ERROR_KEY_EXISTS)";
    case IWKV_ERROR_MAXKVSZ:
      return "Size of Key+value must be not greater than 0xfffffff bytes (IWKV_ERROR_MAXKVSZ)";
    case IWKV_ERROR_CORRUPTED:
      return "Database file invalid or corrupted (IWKV_ERROR_CORRUPTED)";
    case IWKV_ERROR_DUP_VALUE_SIZE:
      return "Value size is not compatible for insertion into sorted values array (IWKV_ERROR_DUP_VALUE_SIZE)";
    case IWKV_ERROR_KEY_NUM_VALUE_SIZE:
      return "Given key is not compatible to store as number (IWKV_ERROR_KEY_NUM_VALUE_SIZE)";
    case IWKV_ERROR_INCOMPATIBLE_DB_MODE:
      return "Incompatible database open mode (IWKV_ERROR_INCOMPATIBLE_DB_MODE)";
    case IWKV_ERROR_INCOMPATIBLE_DB_FORMAT:
      return "Incompatible database format version, please migrate database data (IWKV_ERROR_INCOMPATIBLE_DB_FORMAT)";
    case IWKV_ERROR_CORRUPTED_WAL_FILE:
      return "Corrupted WAL file (IWKV_ERROR_CORRUPTED_WAL_FILE)";
    case IWKV_ERROR_VALUE_CANNOT_BE_INCREMENTED:
      return "Stored value cannot be incremented/descremented (IWKV_ERROR_VALUE_CANNOT_BE_INCREMENTED)";
    case IWKV_ERROR_WAL_MODE_REQUIRED:
      return "Operation requires WAL enabled database. (IWKV_ERROR_WAL_MODE_REQUIRED)";
    case IWKV_ERROR_BACKUP_IN_PROGRESS:
      return "ackup operation in progress. (IWKV_ERROR_BACKUP_IN_PROGRESS)";
    default:
      break;
  }
  return 0;
}

iwrc iwkv_init(void) {
  static int _kv_initialized = 0;
  if (!__sync_bool_compare_and_swap(&_kv_initialized, 0, 1)) {
    return 0;
  }
  return iwlog_register_ecodefn(_kv_ecodefn);
}

static off_t _szpolicy(off_t nsize, off_t csize, struct IWFS_EXT *f, void **_ctx) {
  off_t res;
  size_t aunit = iwp_alloc_unit();
  if (csize < 0x4000000) { // Doubled alloc up to 64M
    res = csize ? csize : aunit;
    while (res < nsize) {
      res <<= 1;
    }
  } else {
    res = nsize + 10 * 1024 * 1024; // + 10M extra space
  }
  res = IW_ROUNDUP(res, aunit);
  return res;
}

iwrc iwkv_state(IWKV iwkv, IWFS_FSM_STATE *out) {
  if (!iwkv || !out) {
    return IW_ERROR_INVALID_ARGS;
  }
  int rci;
  API_RLOCK(iwkv, rci);
  IWFS_FSM fsm = iwkv->fsm;
  iwrc rc = fsm.state(&fsm, out);
  API_UNLOCK(iwkv, rci, rc);
  return rc;
}

iwrc iwkv_online_backup(IWKV iwkv, uint64_t *ts, const char *target_file) {
  return iwal_online_backup(iwkv, ts, target_file);
}

static iwrc _iwkv_check_online_backup(const char *path, iwp_lockmode extra_lock_flags, bool *out_has_online_bkp) {
  size_t sp;
  uint32_t lv;
  off_t fsz, pos;
  uint64_t waloff; // WAL offset
  char buf[16384];

  *out_has_online_bkp = false;
  const size_t aunit = iwp_alloc_unit();
  char *wpath = 0;

  IWFS_FILE f = { 0 }, w = { 0 };
  IWFS_FILE_STATE fs, fw;
  iwrc rc = iwfs_file_open(&f, &(IWFS_FILE_OPTS) {
    .path = path,
    .omode = IWFS_OREAD | IWFS_OWRITE,
    .lock_mode = IWP_WLOCK | extra_lock_flags
  });
  if (rc == IW_ERROR_NOT_EXISTS) {
    return 0;
  }
  RCRET(rc);

  rc = f.state(&f, &fs);
  RCGO(rc, finish);

  rc = iwp_lseek(fs.fh, 0, IWP_SEEK_END, &fsz);
  RCGO(rc, finish);
  if (fsz < iwp_alloc_unit()) {
    goto finish;
  }

  rc = iwp_pread(fs.fh, 0, &lv, sizeof(lv), &sp);
  RCGO(rc, finish);
  lv = IW_ITOHL(lv);
  if ((sp != sizeof(lv)) || (lv != IWFSM_MAGICK)) {
    goto finish;
  }

  rc = iwp_pread(fs.fh, IWFSM_CUSTOM_HDR_DATA_OFFSET, &lv, sizeof(lv), &sp);
  RCGO(rc, finish);
  lv = IW_ITOHL(lv);
  if ((sp != sizeof(lv)) || (lv != IWKV_MAGIC)) {
    goto finish;
  }

  rc = iwp_lseek(fs.fh, (off_t) -1 * sizeof(lv), IWP_SEEK_END, 0);
  RCGO(rc, finish);

  rc = iwp_read(fs.fh, &lv, sizeof(lv), &sp);
  RCGO(rc, finish);
  lv = IW_ITOHL(lv);
  if ((sp != sizeof(lv)) || (lv != IWKV_BACKUP_MAGIC)) {
    goto finish;
  }

  // Get WAL data offset
  rc = iwp_lseek(fs.fh, (off_t) -1 * (sizeof(waloff) + sizeof(lv)), IWP_SEEK_END, &pos);
  RCGO(rc, finish);

  rc = iwp_read(fs.fh, &waloff, sizeof(waloff), &sp);
  RCGO(rc, finish);

  waloff = IW_ITOHLL(waloff);
  if (((waloff != pos) && (waloff > pos - sizeof(WBSEP))) || (waloff & (aunit - 1))) {
    goto finish;
  }

  // Read the first WAL instruction: WBSEP
  if (waloff != pos) { // Not an empty WAL?
    WBSEP wbsep = { 0 };
    rc = iwp_pread(fs.fh, waloff, &wbsep, sizeof(wbsep), &sp);
    RCGO(rc, finish);
    if (wbsep.id != WOP_SEP) {
      goto finish;
    }
  }

  // Now we have an online backup image, unpack WAL file

  sp = strlen(path);
  wpath = malloc(sp + 4 /*-wal*/ + 1 /*\0*/);
  if (!wpath) {
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    goto finish;
  }
  memcpy(wpath, path, sp);
  memcpy(wpath + sp, "-wal", 4);
  wpath[sp + 4] = '\0';

  iwlog_warn("Unpacking WAL from online backup into: %s", wpath);
  *out_has_online_bkp = true;

  // WAL file
  rc = iwfs_file_open(&w, &(IWFS_FILE_OPTS) {
    .path = wpath,
    .omode = IWFS_OREAD | IWFS_OWRITE | IWFS_OTRUNC
  });
  RCGO(rc, finish);

  rc = w.state(&w, &fw);
  RCGO(rc, finish);

  // WAL content copy
  rc = iwp_lseek(fs.fh, waloff, IWP_SEEK_SET, 0);
  RCGO(rc, finish);
  fsz = fsz - waloff - sizeof(lv) /* magic */ - sizeof(waloff) /* wal offset */;
  if (fsz > 0) {
    sp = 0;
    do {
      rc = iwp_read(fs.fh, buf, sizeof(buf), &sp);
      RCGO(rc, finish);
      if (sp > fsz) {
        sp = fsz;
      }
      fsz -= sp;
      rc = iwp_write(fw.fh, buf, sp);
      RCGO(rc, finish);
    } while (fsz > 0 && sp > 0);
  }
  rc = iwp_fsync(fw.fh);
  RCGO(rc, finish);

  rc = iwp_ftruncate(fs.fh, waloff);
  RCGO(rc, finish);

  rc = iwp_fsync(fs.fh);
  RCGO(rc, finish);

finish:
  if (f.impl) {
    IWRC(f.close(&f), rc);
  }
  if (w.impl) {
    IWRC(w.close(&w), rc);
  }
  free(wpath);
  return rc;
}

iwrc iwkv_open(const IWKV_OPTS *opts, IWKV *iwkvp) {
  if (!opts || !iwkvp || !opts->path) {
    return IW_ERROR_INVALID_ARGS;
  }
  *iwkvp = 0;
  int rci;
  iwrc rc = 0;
  uint32_t lv;
  uint64_t llv;
  uint8_t *rp, *mm;
  bool has_online_bkp = false;

  rc = iw_init();
  RCRET(rc);

  if (opts->random_seed) {
    iwu_rand_seed(opts->random_seed);
  }
  iwkv_openflags oflags = opts->oflags;
  iwfs_omode omode = IWFS_OREAD;
  if (oflags & IWKV_TRUNC) {
    oflags &= ~IWKV_RDONLY;
    omode |= IWFS_OTRUNC;
  }
  if (!(oflags & IWKV_RDONLY)) {
    omode |= IWFS_OWRITE;
    omode |= IWFS_OCREATE;
  }
  if ((omode & IWFS_OWRITE) && !(omode & IWFS_OTRUNC)) {
    iwp_lockmode extra_lock_flags = 0;
    if (opts->file_lock_fail_fast) {
      extra_lock_flags |= IWP_NBLOCK;
    }
    rc = _iwkv_check_online_backup(opts->path, extra_lock_flags, &has_online_bkp);
    RCRET(rc);
  }

  *iwkvp = calloc(1, sizeof(struct _IWKV));
  if (!*iwkvp) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  IWKV iwkv = *iwkvp;
  iwkv->fmt_version = opts->fmt_version > 0 ? opts->fmt_version : IWKV_FORMAT;
  if (iwkv->fmt_version > IWKV_FORMAT) {
    rc = IWKV_ERROR_INCOMPATIBLE_DB_FORMAT;
    iwlog_ecode_error3(rc);
    return rc;
  }
  // Adjust lower key len accourding to database format version
  if (iwkv->fmt_version < 2) {
    iwkv->pklen = PREFIX_KEY_LEN_V1;
  } else {
    iwkv->pklen = PREFIX_KEY_LEN_V2;
  }

  pthread_rwlockattr_t attr;
  pthread_rwlockattr_init(&attr);
#if defined __linux__ && (defined __USE_UNIX98 || defined __USE_XOPEN2K)
  pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif
  rci = pthread_rwlock_init(&iwkv->rwl, &attr);
  if (rci) {
    free(*iwkvp);
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  rci = pthread_mutex_init(&iwkv->wk_mtx, 0);
  if (rci) {
    pthread_rwlock_destroy(&iwkv->rwl);
    free(*iwkvp);
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  rci = pthread_cond_init(&iwkv->wk_cond, 0);
  if (rci) {
    pthread_rwlock_destroy(&iwkv->rwl);
    pthread_mutex_destroy(&iwkv->wk_mtx);
    free(*iwkvp);
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }

  iwkv->oflags = oflags;
  IWFS_FSM_STATE fsmstate;
  IWFS_FSM_OPTS fsmopts = {
    .exfile        = {
      .file        = {
        .path      = opts->path,
        .omode     = omode,
        .lock_mode = (oflags & IWKV_RDONLY) ? IWP_RLOCK : IWP_WLOCK
      },
      .rspolicy    = _szpolicy,
      .maxoff      = IWKV_MAX_DBSZ,
      .use_locks   = true
    },
    .bpow          = IWKV_FSM_BPOW, // 64 bytes block size
    .hdrlen        = KVHDRSZ,       // Size of custom file header
    .oflags        = ((oflags & IWKV_RDONLY) ? IWFSM_NOLOCKS : 0),
    .mmap_all      = true
  };
#ifndef NDEBUG
  fsmopts.oflags |= IWFSM_STRICT;
#endif
  if (oflags & IWKV_NO_TRIM_ON_CLOSE) {
    fsmopts.oflags |= IWFSM_NO_TRIM_ON_CLOSE;
  }
  if (opts->file_lock_fail_fast) {
    fsmopts.exfile.file.lock_mode |= IWP_NBLOCK;
  }
  // Init WAL
  rc = iwal_create(iwkv, opts, &fsmopts, has_online_bkp);
  RCGO(rc, finish);

  // Now open database file
  rc = iwfs_fsmfile_open(&iwkv->fsm, &fsmopts);
  RCGO(rc, finish);

  IWFS_FSM *fsm = &iwkv->fsm;
  iwkv->dbs = kh_init(DBS);
  rc = fsm->state(fsm, &fsmstate);
  RCGO(rc, finish);

  // Database header: [magic:u4, first_addr:u8, db_format_version:u4]
  if (fsmstate.exfile.file.ostatus & IWFS_OPEN_NEW) {
    uint8_t hdr[KVHDRSZ] = { 0 };
    uint8_t *wp = hdr;
    IW_WRITELV(wp, lv, IWKV_MAGIC);
    wp += sizeof(llv); // skip first db addr
    IW_WRITELV(wp, lv, iwkv->fmt_version);
    rc = fsm->writehdr(fsm, 0, hdr, sizeof(hdr));
    RCGO(rc, finish);
    rc = fsm->sync(fsm, 0);
    RCGO(rc, finish);
  } else {
    off_t dbaddr; // first database address
    uint8_t hdr[KVHDRSZ];
    rc = fsm->readhdr(fsm, 0, hdr, KVHDRSZ);
    RCGO(rc, finish);
    rp = hdr; // -V507
    IW_READLV(rp, lv, lv);
    IW_READLLV(rp, llv, dbaddr);
    if ((lv != IWKV_MAGIC) || (dbaddr < 0)) {
      rc = IWKV_ERROR_CORRUPTED;
      iwlog_ecode_error3(rc);
      goto finish;
    }
    IW_READLV(rp, lv, iwkv->fmt_version);
    if ((iwkv->fmt_version > IWKV_FORMAT)) {
      rc = IWKV_ERROR_INCOMPATIBLE_DB_FORMAT;
      iwlog_ecode_error3(rc);
      goto finish;
    }
    if (iwkv->fmt_version < 2) {
      iwkv->pklen = PREFIX_KEY_LEN_V1;
    } else {
      iwkv->pklen = PREFIX_KEY_LEN_V2;
    }
    rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
    RCGO(rc, finish);
    rc = _db_load_chain(iwkv, dbaddr, mm);
    fsm->release_mmap(fsm);
  }
  (*iwkvp)->open = true;

finish:
  if (rc) {
    (*iwkvp)->open = true; // will be closed in iwkv_close
    IWRC(iwkv_close(iwkvp), rc);
  }
  return rc;
}

iwrc iwkv_exclusive_lock(IWKV iwkv) {
  return _wnw(iwkv, _wnw_iwkw_wl);
}

iwrc iwkv_exclusive_unlock(IWKV iwkv) {
  int rci;
  iwrc rc = 0;
  API_UNLOCK(iwkv, rci, rc);
  return rc;
}

iwrc iwkv_close(IWKV *iwkvp) {
  ENSURE_OPEN((*iwkvp));
  IWKV iwkv = *iwkvp;
  iwkv->open = false;
  iwal_shutdown(iwkv);
  iwrc rc = iwkv_exclusive_lock(iwkv);
  RCRET(rc);
  IWDB db = iwkv->first_db;
  while (db) {
    IWDB ndb = db->next;
    _db_release_lw(&db);
    db = ndb;
  }
  IWRC(iwkv->fsm.close(&iwkv->fsm), rc);
  // Below the memory cleanup only
  if (iwkv->dbs) {
    kh_destroy(DBS, iwkv->dbs);
    iwkv->dbs = 0;
  }
  iwkv_exclusive_unlock(iwkv);
  pthread_rwlock_destroy(&iwkv->rwl);
  pthread_mutex_destroy(&iwkv->wk_mtx);
  pthread_cond_destroy(&iwkv->wk_cond);
  free(iwkv);
  *iwkvp = 0;
  return rc;
}

static iwrc _iwkv_sync(IWKV iwkv, iwfs_sync_flags _flags) {
  ENSURE_OPEN(iwkv);
  if (iwkv->oflags & IWKV_RDONLY) {
    return IW_ERROR_READONLY;
  }
  iwrc rc;
  if (iwkv->dlsnr) {
    rc = iwal_poke_savepoint(iwkv);
  } else {
    IWFS_FSM *fsm = &iwkv->fsm;
    pthread_rwlock_wrlock(&iwkv->rwl);
    iwfs_sync_flags flags = IWFS_FDATASYNC | _flags;
    rc = fsm->sync(fsm, flags);
    pthread_rwlock_unlock(&iwkv->rwl);
  }
  return rc;
}

iwrc iwkv_sync(IWKV iwkv, iwfs_sync_flags _flags) {
  ENSURE_OPEN(iwkv);
  if (iwkv->oflags & IWKV_RDONLY) {
    return IW_ERROR_READONLY;
  }
  iwrc rc;
  if (iwkv->dlsnr) {
    rc = iwkv_exclusive_lock(iwkv);
    RCRET(rc);
    rc = iwal_savepoint_exl(iwkv, true);
    iwkv_exclusive_unlock(iwkv);
  } else {
    IWFS_FSM *fsm = &iwkv->fsm;
    pthread_rwlock_wrlock(&iwkv->rwl);
    iwfs_sync_flags flags = IWFS_FDATASYNC | _flags;
    rc = fsm->sync(fsm, flags);
    pthread_rwlock_unlock(&iwkv->rwl);
  }
  return rc;
}

iwrc iwkv_db(IWKV iwkv, uint32_t dbid, iwdb_flags_t dbflg, IWDB *dbp) {
  int rci;
  iwrc rc = 0;
  IWDB db = 0;
  *dbp = 0;
  API_RLOCK(iwkv, rci);
  khiter_t ki = kh_get(DBS, iwkv->dbs, dbid);
  if (ki != kh_end(iwkv->dbs)) {
    db = kh_value(iwkv->dbs, ki);
  }
  API_UNLOCK(iwkv, rci, rc);
  RCRET(rc);
  if (db) {
    if (db->dbflg != dbflg) {
      return IWKV_ERROR_INCOMPATIBLE_DB_MODE;
    }
    *dbp = db;
    return 0;
  }
  if (iwkv->oflags & IWKV_RDONLY) {
    return IW_ERROR_READONLY;
  }
  rc = iwkv_exclusive_lock(iwkv);
  RCRET(rc);
  ki = kh_get(DBS, iwkv->dbs, dbid);
  if (ki != kh_end(iwkv->dbs)) {
    db = kh_value(iwkv->dbs, ki);
  }
  if (db) {
    if (db->dbflg != dbflg) {
      return IWKV_ERROR_INCOMPATIBLE_DB_MODE;
    }
    *dbp = db;
  } else {
    rc = _db_create_lw(iwkv, dbid, dbflg, dbp);
  }
  if (!rc) {
    rc = iwal_savepoint_exl(iwkv, true);
  }
  iwkv_exclusive_unlock(iwkv);
  return rc;
}

iwrc iwkv_new_db(IWKV iwkv, iwdb_flags_t dbflg, uint32_t *dbidp, IWDB *dbp) {
  *dbp = 0;
  *dbidp = 0;
  if (iwkv->oflags & IWKV_RDONLY) {
    return IW_ERROR_READONLY;
  }
  uint32_t dbid = 0;
  iwrc rc = iwkv_exclusive_lock(iwkv);
  RCRET(rc);
  for (khiter_t k = kh_begin(iwkv->dbs); k != kh_end(iwkv->dbs); ++k) {
    if (!kh_exist(iwkv->dbs, k)) {
      continue;
    }
    uint32_t id = kh_key(iwkv->dbs, k);
    if (id > dbid) {
      dbid = id;
    }
  }
  dbid++;
  rc = _db_create_lw(iwkv, dbid, dbflg, dbp);
  if (!rc) {
    *dbidp = dbid;
    rc = iwal_savepoint_exl(iwkv, true);
  }
  iwkv_exclusive_unlock(iwkv);
  return rc;
}

iwrc iwkv_db_cache_release(IWDB db) {
  if (!db || !db->iwkv) {
    return IW_ERROR_INVALID_ARGS;
  }
  int rci;
  iwrc rc = 0;
  API_DB_WLOCK(db, rci);
  _dbcache_destroy_lw(db);
  API_DB_UNLOCK(db, rci, rc);
  return rc;
}

iwrc iwkv_db_destroy(IWDB *dbp) {
  if (!dbp || !*dbp) {
    return IW_ERROR_INVALID_ARGS;
  }
  IWDB db = *dbp;
  IWKV iwkv = db->iwkv;
  *dbp = 0;
  if (iwkv->oflags & IWKV_RDONLY) {
    return IW_ERROR_READONLY;
  }
  iwrc rc = iwkv_exclusive_lock(iwkv);
  RCRET(rc);
  rc = _db_destroy_lw(&db);
  iwkv_exclusive_unlock(iwkv);
  return rc;
}

iwrc iwkv_puth(
  IWDB db, const IWKV_val *key, const IWKV_val *val,
  iwkv_opflags opflags, IWKV_PUT_HANDLER ph, void *phop) {
  if (!db || !db->iwkv || !key || !key->size || !val) {
    return IW_ERROR_INVALID_ARGS;
  }
  IWKV iwkv = db->iwkv;
  if (iwkv->oflags & IWKV_RDONLY) {
    return IW_ERROR_READONLY;
  }
  if (opflags & IWKV_VAL_INCREMENT) {
    // No overwrite for increment
    opflags &= ~IWKV_NO_OVERWRITE;
  }

  int rci;
  IWKV_val ekey;
  uint8_t nbuf[IW_VNUMBUFSZ];
  iwrc rc = _to_effective_key(db, key, &ekey, nbuf);
  RCRET(rc);

  IWLCTX lx = {
    .db      = db,
    .key     = &ekey,
    .val     = (IWKV_val*) val,
    .nlvl    = -1,
    .op      = IWLCTX_PUT,
    .opflags = opflags,
    .ph      = ph,
    .phop    = phop
  };
  API_DB_WLOCK(db, rci);
  if (!db->cache.open) {
    rc = _dbcache_fill_lw(&lx);
    RCGO(rc, finish);
  }
  rc = _lx_put_lw(&lx);

finish:
  API_DB_UNLOCK(db, rci, rc);
  if (!rc) {
    if (lx.opflags & IWKV_SYNC) {
      rc = _iwkv_sync(iwkv, 0);
    } else {
      rc = iwal_poke_checkpoint(iwkv, false);
    }
  }
  return rc;
}

iwrc iwkv_put(IWDB db, const IWKV_val *key, const IWKV_val *val, iwkv_opflags opflags) {
  return iwkv_puth(db, key, val, opflags, 0, 0);
}

iwrc iwkv_get(IWDB db, const IWKV_val *key, IWKV_val *oval) {
  if (!db || !db->iwkv || !key || !oval) {
    return IW_ERROR_INVALID_ARGS;
  }

  int rci;
  IWKV_val ekey;
  uint8_t nbuf[IW_VNUMBUFSZ];
  iwrc rc = _to_effective_key(db, key, &ekey, nbuf);
  RCRET(rc);

  IWLCTX lx = {
    .db   = db,
    .key  = &ekey,
    .val  = oval,
    .nlvl = -1
  };
  oval->size = 0;
  if (IW_LIKELY(db->cache.open)) {
    API_DB_RLOCK(db, rci);
  } else {
    API_DB_WLOCK(db, rci);
    if (!db->cache.open) { // -V547
      rc = _dbcache_fill_lw(&lx);
      RCGO(rc, finish);
    }
  }
  rc = _lx_get_lr(&lx);

finish:
  API_DB_UNLOCK(db, rci, rc);
  return rc;
}

iwrc iwkv_get_copy(IWDB db, const IWKV_val *key, void *vbuf, size_t vbufsz, size_t *vsz) {
  if (!db || !db->iwkv || !key || !vbuf) {
    return IW_ERROR_INVALID_ARGS;
  }
  *vsz = 0;

  int rci;
  bool found;
  IWKV_val ekey;
  uint32_t ovalsz;
  uint8_t *mm = 0, *oval, idx;
  IWFS_FSM *fsm = &db->iwkv->fsm;
  uint8_t nbuf[IW_VNUMBUFSZ];
  iwrc rc = _to_effective_key(db, key, &ekey, nbuf);
  RCRET(rc);

  IWLCTX lx = {
    .db   = db,
    .key  = &ekey,
    .nlvl = -1
  };
  if (IW_LIKELY(db->cache.open)) {
    API_DB_RLOCK(db, rci);
  } else {
    API_DB_WLOCK(db, rci);
    if (!db->cache.open) { // -V547
      rc = _dbcache_fill_lw(&lx);
      RCGO(rc, finish);
    }
  }
  rc = _lx_find_bounds(&lx);
  RCGO(rc, finish);
  rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCGO(rc, finish);
  rc = _sblk_loadkvblk_mm(&lx, lx.lower, mm);
  RCGO(rc, finish);
  rc = _sblk_find_pi_mm(lx.lower, &lx, mm, &found, &idx);
  RCGO(rc, finish);
  if (found) {
    _kvblk_value_peek(lx.lower->kvblk, lx.lower->pi[idx], mm, &oval, &ovalsz);
    *vsz = ovalsz;
    memcpy(vbuf, oval, MIN(vbufsz, ovalsz));
  } else {
    rc = IWKV_ERROR_NOTFOUND;
  }

finish:
  if (mm) {
    IWRC(fsm->release_mmap(fsm), rc);
  }
  _lx_release_mm(&lx, 0);
  API_DB_UNLOCK(db, rci, rc);
  return rc;
}

iwrc iwkv_db_set_meta(IWDB db, void *buf, size_t sz) {
  if (!db || !db->iwkv || !buf) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (!sz) {
    return 0;
  }

  int rci;
  iwrc rc = 0;
  bool resized = false;
  uint8_t *mm = 0, *wp, *sp;
  IWFS_FSM *fsm = &db->iwkv->fsm;
  size_t asz = IW_ROUNDUP(sz, 1U << IWKV_FSM_BPOW);

  API_DB_WLOCK(db, rci);
  if ((asz > db->meta_blkn) || (asz * 2 <= db->meta_blkn)) {
    off_t oaddr = 0;
    off_t olen = 0;
    if (db->meta_blk) {
      rc = fsm->deallocate(fsm, BLK2ADDR(db->meta_blk), BLK2ADDR(db->meta_blkn));
      RCGO(rc, finish);
    }
    rc = fsm->allocate(fsm, asz, &oaddr, &olen, IWKV_FSM_ALLOC_FLAGS);
    RCGO(rc, finish);
    db->meta_blk = ADDR2BLK(oaddr);
    db->meta_blkn = ADDR2BLK(olen);
    resized = true;
  }
  rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCGO(rc, finish);
  wp = mm + BLK2ADDR(db->meta_blk);
  memcpy(wp, buf, sz);
  if (db->iwkv->dlsnr) {
    rc = db->iwkv->dlsnr->onwrite(db->iwkv->dlsnr, wp - mm, wp, sz, 0);
    RCGO(rc, finish);
  }
  if (resized) {
    uint32_t lv;
    wp = mm + db->addr + DOFF_METABLK_U4;
    sp = wp;
    IW_WRITELV(wp, lv, db->meta_blk);
    IW_WRITELV(wp, lv, db->meta_blkn);
    if (db->iwkv->dlsnr) {
      rc = db->iwkv->dlsnr->onwrite(db->iwkv->dlsnr, sp - mm, sp, wp - sp, 0);
      RCGO(rc, finish);
    }
  }
  fsm->release_mmap(fsm);
  mm = 0;

finish:
  if (mm) {
    fsm->release_mmap(fsm);
  }
  API_DB_UNLOCK(db, rci, rc);
  return rc;
}

iwrc iwkv_db_get_meta(IWDB db, void *buf, size_t sz, size_t *rsz) {
  if (!db || !db->iwkv || !buf) {
    return IW_ERROR_INVALID_ARGS;
  }
  *rsz = 0;
  if (!sz || !db->meta_blkn) {
    return 0;
  }
  int rci;
  iwrc rc = 0;
  uint8_t *mm = 0;
  IWFS_FSM *fsm = &db->iwkv->fsm;
  size_t rmax = BLK2ADDR(db->meta_blkn);
  if (sz > rmax) {
    sz = rmax;
  }
  API_DB_RLOCK(db, rci);
  rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCGO(rc, finish);
  memcpy(buf, mm + BLK2ADDR(db->meta_blk), sz);
  *rsz = sz;

finish:
  if (mm) {
    fsm->release_mmap(fsm);
  }
  API_DB_UNLOCK(db, rci, rc);
  return rc;
}

iwrc iwkv_del(IWDB db, const IWKV_val *key, iwkv_opflags opflags) {
  if (!db || !db->iwkv || !key) {
    return IW_ERROR_INVALID_ARGS;
  }
  int rci;
  IWKV_val ekey;
  IWKV iwkv = db->iwkv;

  uint8_t nbuf[IW_VNUMBUFSZ];
  iwrc rc = _to_effective_key(db, key, &ekey, nbuf);
  RCRET(rc);
  IWLCTX lx = {
    .db      = db,
    .key     = &ekey,
    .nlvl    = -1,
    .op      = IWLCTX_DEL,
    .opflags = opflags
  };
  API_DB_WLOCK(db, rci);
  if (!db->cache.open) {
    rc = _dbcache_fill_lw(&lx);
    RCGO(rc, finish);
  }
  rc = _lx_del_lw(&lx);

finish:
  API_DB_UNLOCK(db, rci, rc);
  if (!rc) {
    if (lx.opflags & IWKV_SYNC) {
      rc = _iwkv_sync(iwkv, 0);
    } else {
      rc = iwal_poke_checkpoint(iwkv, false);
    }
  }
  return rc;
}

IW_INLINE iwrc _cursor_close_lw(IWKV_cursor cur) {
  iwrc rc = 0;
  cur->closed = true;
  IWDB db = cur->lx.db;
  pthread_spin_lock(&db->cursors_slk);
  for (IWKV_cursor c = db->cursors, pc = 0; c; pc = c, c = c->next) {
    if (c == cur) {
      if (pc) {
        pc->next = c->next;
      } else {
        db->cursors = c->next;
      }
      break;
    }
  }
  pthread_spin_unlock(&db->cursors_slk);
  return rc;
}

iwrc iwkv_cursor_open(
  IWDB            db,
  IWKV_cursor    *curptr,
  IWKV_cursor_op  op,
  const IWKV_val *key) {
  if (  !db || !db->iwkv || !curptr
     || (key && (op < IWKV_CURSOR_EQ) ) || (op < IWKV_CURSOR_BEFORE_FIRST) ) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc;
  int rci;
  rc = _db_worker_inc_nolk(db);
  RCRET(rc);
  if (IW_LIKELY(db->cache.open)) {
    rc = _api_db_rlock(db);
  } else {
    rc = _api_db_wlock(db);
  }
  if (rc) {
    _db_worker_dec_nolk(db);
    return rc;
  }
  IWKV_cursor cur = 0;
  *curptr = calloc(1, sizeof(**curptr));
  if (!(*curptr)) {
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    goto finish;
  }
  cur = *curptr;
  IWLCTX *lx = &cur->lx;
  if (key) {
    rc = _to_effective_key(db, key, &lx->ekey, lx->nbuf);
    RCGO(rc, finish);
    lx->key = &lx->ekey;
  }
  lx->db = db;
  lx->nlvl = -1;
  if (!db->cache.open) {
    rc = _dbcache_fill_lw(lx);
    RCGO(rc, finish);
  }
  rc = _cursor_to_lr(cur, op);

finish:
  if (cur) {
    if (rc) {
      *curptr = 0;
      IWRC(_cursor_close_lw(cur), rc);
      free(cur);
    } else {
      pthread_spin_lock(&db->cursors_slk);
      cur->next = db->cursors;
      db->cursors = cur;
      pthread_spin_unlock(&db->cursors_slk);
    }
  }
  API_DB_UNLOCK(db, rci, rc);
  if (rc) {
    _db_worker_dec_nolk(db);
  }
  return rc;
}

iwrc iwkv_cursor_close(IWKV_cursor *curp) {
  iwrc rc = 0;
  int rci;
  if (!curp || !*curp) {
    return 0;
  }
  IWKV_cursor cur = *curp;
  *curp = 0;
  IWKV iwkv = cur->lx.db->iwkv;
  if (cur->closed) {
    free(cur);
    return 0;
  }
  if (!cur->lx.db) {
    return IW_ERROR_INVALID_ARGS;
  }
  API_DB_WLOCK(cur->lx.db, rci);
  rc = _cursor_close_lw(cur);
  API_DB_UNLOCK(cur->lx.db, rci, rc);
  IWRC(_db_worker_dec_nolk(cur->lx.db), rc);
  free(cur);
  if (!rc) {
    rc = iwal_poke_checkpoint(iwkv, false);
  }
  return rc;
}

iwrc iwkv_cursor_to(IWKV_cursor cur, IWKV_cursor_op op) {
  int rci;
  if (!cur) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (!cur->lx.db) {
    return IW_ERROR_INVALID_ARGS;
  }
  API_DB_RLOCK(cur->lx.db, rci);
  iwrc rc = _cursor_to_lr(cur, op);
  API_DB_UNLOCK(cur->lx.db, rci, rc);
  return rc;
}

iwrc iwkv_cursor_to_key(IWKV_cursor cur, IWKV_cursor_op op, const IWKV_val *key) {
  int rci;
  if (!cur || ((op != IWKV_CURSOR_EQ) && (op != IWKV_CURSOR_GE))) {
    return IW_ERROR_INVALID_ARGS;
  }
  IWLCTX *lx = &cur->lx;
  if (!lx->db) {
    return IW_ERROR_INVALID_STATE;
  }
  iwrc rc = _to_effective_key(lx->db, key, &lx->ekey, lx->nbuf);
  RCRET(rc);

  API_DB_RLOCK(lx->db, rci);
  lx->key = &lx->ekey;
  rc = _cursor_to_lr(cur, op);
  API_DB_UNLOCK(lx->db, rci, rc);
  return rc;
}

iwrc iwkv_cursor_get(
  IWKV_cursor cur,
  IWKV_val   *okey,                    /* Nullable */
  IWKV_val   *oval) {                  /* Nullable */
  int rci;
  iwrc rc = 0;
  if (!cur || !cur->lx.db) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (!cur->cn || (cur->cn->flags & SBLK_DB) || (cur->cnpos >= cur->cn->pnum)) {
    return IWKV_ERROR_NOTFOUND;
  }
  IWLCTX *lx = &cur->lx;
  API_DB_RLOCK(lx->db, rci);
  uint8_t *mm = 0;
  IWFS_FSM *fsm = &lx->db->iwkv->fsm;
  rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCGO(rc, finish);
  if (!cur->cn->kvblk) {
    rc = _sblk_loadkvblk_mm(lx, cur->cn, mm);
    RCGO(rc, finish);
  }
  uint8_t idx = cur->cn->pi[cur->cnpos];
  if (okey && oval) {
    rc = _kvblk_kv_get(cur->cn->kvblk, mm, idx, okey, oval);
  } else if (oval) {
    rc = _kvblk_value_get(cur->cn->kvblk, mm, idx, oval);
  } else if (okey) {
    rc = _kvblk_key_get(cur->cn->kvblk, mm, idx, okey);
  } else {
    rc = IW_ERROR_INVALID_ARGS;
  }
  if (!rc && okey) {
    _unpack_effective_key(lx->db, okey, false);
  }
finish:
  if (mm) {
    fsm->release_mmap(fsm);
  }
  API_DB_UNLOCK(lx->db, rci, rc);
  return rc;
}

iwrc iwkv_cursor_copy_val(IWKV_cursor cur, void *vbuf, size_t vbufsz, size_t *vsz) {
  int rci;
  iwrc rc = 0;
  if (!cur || !vbuf || !cur->lx.db) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (!cur->cn || (cur->cn->flags & SBLK_DB) || (cur->cnpos >= cur->cn->pnum)) {
    return IWKV_ERROR_NOTFOUND;
  }

  *vsz = 0;
  IWLCTX *lx = &cur->lx;
  API_DB_RLOCK(lx->db, rci);
  uint8_t *mm = 0, *oval;
  uint32_t ovalsz;
  IWFS_FSM *fsm = &lx->db->iwkv->fsm;
  rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCGO(rc, finish);
  if (!cur->cn->kvblk) {
    rc = _sblk_loadkvblk_mm(lx, cur->cn, mm);
    RCGO(rc, finish);
  }
  uint8_t idx = cur->cn->pi[cur->cnpos];
  _kvblk_value_peek(cur->cn->kvblk, idx, mm, &oval, &ovalsz);
  *vsz = ovalsz;
  memcpy(vbuf, oval, MIN(vbufsz, ovalsz));

finish:
  if (mm) {
    fsm->release_mmap(fsm);
  }
  API_DB_UNLOCK(lx->db, rci, rc);
  return rc;
}

iwrc iwkv_cursor_is_matched_key(IWKV_cursor cur, const IWKV_val *key, bool *ores, int64_t *ocompound) {
  int rci;
  iwrc rc = 0;
  if (!cur || !ores || !key || !cur->lx.db) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (!cur->cn || (cur->cn->flags & SBLK_DB) || (cur->cnpos >= cur->cn->pnum)) {
    return IWKV_ERROR_NOTFOUND;
  }

  *ores = 0;
  if (ocompound) {
    *ocompound = 0;
  }

  IWLCTX *lx = &cur->lx;
  API_DB_RLOCK(lx->db, rci);
  uint8_t *mm = 0, *okey;
  uint32_t okeysz;
  iwdb_flags_t dbflg = lx->db->dbflg;
  IWFS_FSM *fsm = &lx->db->iwkv->fsm;
  rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCGO(rc, finish);
  if (!cur->cn->kvblk) {
    rc = _sblk_loadkvblk_mm(lx, cur->cn, mm);
    RCGO(rc, finish);
  }

  uint8_t idx = cur->cn->pi[cur->cnpos];
  rc = _kvblk_key_peek(cur->cn->kvblk, idx, mm, &okey, &okeysz);
  RCGO(rc, finish);

  if (dbflg & (IWDB_COMPOUND_KEYS | IWDB_VNUM64_KEYS)) {
    char nbuf[2 * IW_VNUMBUFSZ];
    IWKV_val rkey = { .data = nbuf, .size = okeysz };
    memcpy(rkey.data, okey, MIN(rkey.size, sizeof(nbuf)));
    rc = _unpack_effective_key(lx->db, &rkey, true);
    RCGO(rc, finish);
    if (ocompound) {
      *ocompound = rkey.compound;
    }
    if (rkey.size != key->size) {
      *ores = false;
      goto finish;
    }
    if (dbflg & IWDB_VNUM64_KEYS) {
      *ores = !memcmp(rkey.data, key->data, key->size);
    } else {
      *ores = !memcmp(okey + (okeysz - rkey.size), key->data, key->size);
    }
  } else {
    *ores = (okeysz == key->size) && !memcmp(okey, key->data, key->size);
  }

finish:
  if (mm) {
    fsm->release_mmap(fsm);
  }
  API_DB_UNLOCK(cur->lx.db, rci, rc);
  return rc;
}

iwrc iwkv_cursor_copy_key(IWKV_cursor cur, void *kbuf, size_t kbufsz, size_t *ksz, int64_t *compound) {
  int rci;
  iwrc rc = 0;
  if (!cur || !cur->lx.db) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (!cur->cn || (cur->cn->flags & SBLK_DB) || (cur->cnpos >= cur->cn->pnum)) {
    return IWKV_ERROR_NOTFOUND;
  }

  *ksz = 0;
  IWLCTX *lx = &cur->lx;
  API_DB_RLOCK(lx->db, rci);
  uint8_t *mm = 0, *okey;
  uint32_t okeysz;
  iwdb_flags_t dbflg = lx->db->dbflg;
  IWFS_FSM *fsm = &lx->db->iwkv->fsm;
  rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
  RCGO(rc, finish);
  if (!cur->cn->kvblk) {
    rc = _sblk_loadkvblk_mm(lx, cur->cn, mm);
    RCGO(rc, finish);
  }

  uint8_t idx = cur->cn->pi[cur->cnpos];
  rc = _kvblk_key_peek(cur->cn->kvblk, idx, mm, &okey, &okeysz);
  RCGO(rc, finish);

  if (dbflg & (IWDB_COMPOUND_KEYS | IWDB_VNUM64_KEYS)) {
    char nbuf[2 * IW_VNUMBUFSZ];
    IWKV_val rkey = { .data = nbuf, .size = okeysz };
    memcpy(rkey.data, okey, MIN(rkey.size, sizeof(nbuf)));
    rc = _unpack_effective_key(lx->db, &rkey, true);
    RCGO(rc, finish);
    if (compound) {
      *compound = rkey.compound;
    }
    *ksz = rkey.size;
    if (dbflg & IWDB_VNUM64_KEYS) {
      memcpy(kbuf, rkey.data, MIN(kbufsz, rkey.size));
    } else {
      memcpy(kbuf, okey + (okeysz - rkey.size), MIN(kbufsz, rkey.size));
    }
  } else {
    *ksz = okeysz;
    if (compound) {
      *compound = 0;
    }
    memcpy(kbuf, okey, MIN(kbufsz, okeysz));
  }

finish:
  if (mm) {
    fsm->release_mmap(fsm);
  }
  API_DB_UNLOCK(cur->lx.db, rci, rc);
  return rc;
}

IW_EXPORT iwrc iwkv_cursor_seth(
  IWKV_cursor cur, IWKV_val *val, iwkv_opflags opflags,
  IWKV_PUT_HANDLER ph, void *phop) {
  int rci;
  iwrc rc = 0, irc = 0;
  if (!cur || !cur->lx.db) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (!cur->cn || (cur->cn->flags & SBLK_DB) || (cur->cnpos >= cur->cn->pnum)) {
    return IWKV_ERROR_NOTFOUND;
  }

  IWLCTX *lx = &cur->lx;
  IWDB db = lx->db;
  IWKV iwkv = db->iwkv;
  SBLK *sblk = cur->cn;

  API_DB_WLOCK(db, rci);
  if (ph) {
    uint8_t *mm;
    IWKV_val key, oldval;
    IWFS_FSM *fsm = &db->iwkv->fsm;
    rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
    RCGO(rc, finish);
    rc = _kvblk_kv_get(sblk->kvblk, mm, sblk->pi[cur->cnpos], &key, &oldval);
    fsm->release_mmap(fsm);
    if (!rc) {
      // note: oldval should be disposed by ph
      rc = ph(&key, val, &oldval, phop);
      _kv_val_dispose(&key);
    }
    RCGO(rc, finish);
  }

  rc = _sblk_updatekv(sblk, cur->cnpos, 0, val);
  if (IWKV_IS_INTERNAL_RC(rc)) {
    irc = rc;
    rc = 0;
  }
  RCGO(rc, finish);

  rc = _sblk_sync(lx, sblk);
  RCGO(rc, finish);

  // Update active cursors inside this block
  pthread_spin_lock(&db->cursors_slk);
  for (IWKV_cursor c = db->cursors; c; c = c->next) {
    if (c->cn && (c->cn->addr == sblk->addr)) {
      if (c->cn != sblk) {
        memcpy(c->cn, sblk, sizeof(*c->cn));
        c->cn->kvblk = 0;
        c->cn->flags &= SBLK_PERSISTENT_FLAGS;
      }
    }
  }
  pthread_spin_unlock(&db->cursors_slk);

finish:
  API_DB_UNLOCK(db, rci, rc);
  if (!rc) {
    if (opflags & IWKV_SYNC) {
      rc = _iwkv_sync(iwkv, 0);
    } else {
      rc = iwal_poke_checkpoint(iwkv, false);
    }
  }
  return rc ? rc : irc;
}

iwrc iwkv_cursor_set(IWKV_cursor cur, IWKV_val *val, iwkv_opflags opflags) {
  return iwkv_cursor_seth(cur, val, opflags, 0, 0);
}

iwrc iwkv_cursor_val(IWKV_cursor cur, IWKV_val *oval) {
  return iwkv_cursor_get(cur, 0, oval);
}

iwrc iwkv_cursor_key(IWKV_cursor cur, IWKV_val *okey) {
  return iwkv_cursor_get(cur, okey, 0);
}

iwrc iwkv_cursor_del(IWKV_cursor cur, iwkv_opflags opflags) {
  int rci;
  iwrc rc = 0;
  if (!cur || !cur->lx.db) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (!cur->cn || (cur->cn->flags & SBLK_DB) || (cur->cnpos >= cur->cn->pnum)) {
    return IWKV_ERROR_NOTFOUND;
  }

  uint8_t *mm;
  SBLK *sblk = cur->cn;
  IWLCTX *lx = &cur->lx;
  IWDB db = lx->db;
  IWKV iwkv = db->iwkv;
  IWFS_FSM *fsm = &iwkv->fsm;

  API_DB_WLOCK(db, rci);
  if (!db->cache.open) {
    rc = _dbcache_fill_lw(lx);
    RCGO(rc, finish);
  }
  if (sblk->pnum == 1) { // sblk will be removed
    IWKV_val key = { 0 };
    // Key a key
    rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
    RCGO(rc, finish2);
    if (!sblk->kvblk) {
      rc = _sblk_loadkvblk_mm(lx, sblk, mm);
      fsm->release_mmap(fsm);
      RCGO(rc, finish2);
    }
    rc = _kvblk_key_get(sblk->kvblk, mm, sblk->pi[cur->cnpos], &key);
    fsm->release_mmap(fsm);
    RCGO(rc, finish2);

    lx->key = &key;
    rc = _lx_del_sblk_lw(lx, sblk, cur->cnpos);
    lx->key = 0;

finish2:
    if (rc) {
      _lx_release_mm(lx, 0);
    } else {
      rc = _lx_release(lx);
    }
    if (key.data) {
      _kv_val_dispose(&key);
    }
  } else { // Simple case
    if (!sblk->kvblk) {
      rc = fsm->acquire_mmap(fsm, 0, &mm, 0);
      RCGO(rc, finish);
      rc = _sblk_loadkvblk_mm(lx, sblk, mm);
      fsm->release_mmap(fsm);
      RCGO(rc, finish);
    }
    rc = _sblk_rmkv(sblk, cur->cnpos);
    RCGO(rc, finish);
    rc = _sblk_sync(lx, sblk);
  }

finish:
  API_DB_UNLOCK(db, rci, rc);
  if (!rc) {
    if (opflags & IWKV_SYNC) {
      rc = _iwkv_sync(iwkv, 0);
    } else {
      rc = iwal_poke_checkpoint(iwkv, false);
    }
  }
  return rc;
}

#include "./dbg/iwkvdbg.c"
