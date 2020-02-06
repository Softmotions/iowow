#include "iwkv_internal.h"
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>

#ifdef _WIN32
#include "win32/mman/mman.h"
#else

#include <sys/mman.h>

#endif

extern atomic_uint_fast64_t g_trigger;

#define BKP_STARTED           0x1 /**< Backup started */
#define BKP_WAL_CLEANUP       0x2 /**< Do checkpoint and truncate WAL file */
#define BKP_MAIN_COPY         0x3 /**< Copy main database file */
#define BKP_WAL_COPY1         0x4 /**< Copy most of WAL file content */
#define BKP_WAL_COPY2         0x5 /**< Copy rest of WAL file in exclusive locked mode */

typedef struct IWAL {
  IWDLSNR lsnr;
  atomic_bool applying;             /**< WAL applying */
  atomic_bool open;                 /**< Is WAL in use */
  atomic_bool force_cp;             /**< Next checkpoint scheduled */
  atomic_bool synched;              /**< WAL is synched or WBFIXPOINT is the last write operation */
  bool force_sp;                    /**< Next savepoint scheduled */
  bool check_cp_crc;                /**< Check CRC32 sum of data blocks during checkpoint. Default: false  */
  iwkv_openflags oflags;            /**< File open flags */
  atomic_int bkp_stage;             /**< Online backup stage */
  size_t wal_buffer_sz;             /**< WAL file intermediate buffer size. */
  size_t checkpoint_buffer_sz;      /**< Checkpoint buffer size in bytes. */
  uint32_t bufpos;                  /**< Current position in buffer */
  uint32_t bufsz;                   /**< Size of buffer */
  HANDLE fh;                        /**< File handle */
  uint8_t *buf;                     /**< File buffer */
  char *path;                       /**< WAL file path */
  pthread_mutex_t *mtxp;            /**< Global WAL mutex */
  pthread_cond_t *cpt_condp;        /**< Checkpoint thread cond variable */
  pthread_t *cptp;                  /**< Checkpoint thread */
  iwrc(*wal_lock_interceptor)(bool, void *);
  /**< Optional function called
       - before acquiring
       - after releasing
       exclusive database lock by WAL checkpoint thread.
       In the case of `before lock` first argument will be set to true */
  void *wal_lock_interceptor_opaque;/**< Opaque data for `wal_lock_interceptor` */
  uint32_t savepoint_timeout_sec;   /**< Savepoint timeout seconds */
  uint32_t checkpoint_timeout_sec;  /**< Checkpoint timeout seconds */
  atomic_size_t mbytes;             /**< Estimated size of modifed private mmaped memory bytes */
  off_t rollforward_offset;         /**< Rollforward offset during online backup */
  uint64_t checkpoint_ts;           /**< Last checkpoint timestamp milliseconds */
  pthread_mutex_t mtx;              /**< Global WAL mutex */
  pthread_cond_t cpt_cond;          /**< Checkpoint thread cond variable */
  pthread_t cpt;                    /**< Checkpoint thread */
  IWKV iwkv;
} IWAL;

static iwrc _checkpoint_exl(IWAL *wal, uint64_t *tsp, bool no_fixpoint);

IW_INLINE iwrc _lock(IWAL *wal) {
  int rci = pthread_mutex_lock(wal->mtxp);
  return (rci ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci) : 0);
}

IW_INLINE iwrc _unlock(IWAL *wal) {
  int rci = pthread_mutex_unlock(wal->mtxp);
  return (rci ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci) : 0);
}

static iwrc _excl_lock(IWAL *wal) {
  iwrc rc = 0;
  if (wal->wal_lock_interceptor) {
    rc = wal->wal_lock_interceptor(true, wal->wal_lock_interceptor_opaque);
    RCRET(rc);
  }
  rc = iwkv_exclusive_lock(wal->iwkv);
  if (rc) {
    if (wal->wal_lock_interceptor) {
      IWRC(wal->wal_lock_interceptor(false, wal->wal_lock_interceptor_opaque), rc);
    }
    return rc;
  }
  rc = _lock(wal);
  if (rc) {
    IWRC(iwkv_exclusive_unlock(wal->iwkv), rc);
    if (wal->wal_lock_interceptor) {
      IWRC(wal->wal_lock_interceptor(false, wal->wal_lock_interceptor_opaque), rc);
    }
  }
  return rc;
}

static iwrc _excl_unlock(IWAL *wal) {
  iwrc rc = _unlock(wal);
  IWRC(iwkv_exclusive_unlock(wal->iwkv), rc);
  if (wal->wal_lock_interceptor) {
    IWRC(wal->wal_lock_interceptor(false, wal->wal_lock_interceptor_opaque), rc);
  }
  return rc;
}

static iwrc _init_locks(IWAL *wal) {
  int rci = pthread_mutex_init(&wal->mtx, 0);
  if (rci) {
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  wal->mtxp = &wal->mtx;
  return 0;
}

static void _destroy(IWAL *wal) {
  if (wal) {
    wal->open = false;
    if (!INVALIDHANDLE(wal->fh)) {
      iwp_unlock(wal->fh);
      iwp_closefh(wal->fh);
    }
    if (wal->cpt_condp) {
      pthread_cond_destroy(wal->cpt_condp);
      wal->cpt_condp = 0;
    }
    if (wal->mtxp) {
      pthread_mutex_destroy(wal->mtxp);
      wal->mtxp = 0;
    }
    if (wal->path) {
      free(wal->path);
    }
    if (wal->buf) {
      wal->buf -= sizeof(WBSEP);
      free(wal->buf);
    }
    free(wal);
  }
}

static iwrc _flush_wl(IWAL *wal, bool sync) {
  iwrc rc = 0;
  if (wal->bufpos) {
    uint32_t crc = wal->check_cp_crc ? iwu_crc32(wal->buf, wal->bufpos, 0) : 0;
    WBSEP sep = {
      .id = WOP_SEP,
      .crc = crc,
      .len = wal->bufpos
    };
    size_t wz = wal->bufpos + sizeof(WBSEP);
    uint8_t *wp = wal->buf - sizeof(WBSEP);
    memcpy(wp, &sep, sizeof(WBSEP));
    rc = iwp_write(wal->fh, wp, wz);
    RCRET(rc);
    wal->bufpos = 0;
  }
  if (sync) {
    rc = iwp_fsync(wal->fh);
  }
  return rc;
}

IW_INLINE iwrc _truncate_wl(IWAL *wal) {
  iwrc rc = iwp_ftruncate(wal->fh, 0);
  RCRET(rc);
  wal->rollforward_offset = 0;
  rc = iwp_lseek(wal->fh, 0, IWP_SEEK_SET, 0);
  RCRET(rc);
  rc = iwp_fsync(wal->fh);
  return rc;
}

static iwrc _write_wl(IWAL *wal, const void *op, off_t oplen, const uint8_t *data, off_t len) {
  iwrc rc = 0;
  const off_t bufsz = wal->bufsz;
  wal->synched = false;
  if (bufsz - wal->bufpos < oplen) {
    rc = _flush_wl(wal, false);
    RCRET(rc);
  }
  assert(bufsz - wal->bufpos >= oplen);
  memcpy(wal->buf + wal->bufpos, op, (size_t) oplen);
  wal->bufpos += oplen;
  if (bufsz - wal->bufpos < len) {
    rc = _flush_wl(wal, false);
    RCRET(rc);
    rc = iwp_write(wal->fh, data, (size_t) len);
    RCRET(rc);
  } else {
    assert(bufsz - wal->bufpos >= len);
    memcpy(wal->buf + wal->bufpos, data, (size_t) len);
    wal->bufpos += len;
  }
  return rc;
}

IW_INLINE iwrc _write_op(IWAL *wal, const void *op, off_t oplen, const uint8_t *data, off_t len) {
  iwrc rc = _lock(wal);
  RCRET(rc);
  rc = _write_wl(wal, op, oplen, data, len);
  IWRC(_unlock(wal), rc);
  return rc;
}

iwrc iwal_sync(IWKV iwkv) {
  IWAL *wal = (IWAL *) iwkv->dlsnr;
  iwrc rc = _lock(wal);
  RCRET(rc);
  rc = _flush_wl(wal, true);
  IWRC(_unlock(wal), rc);
  return rc;
}

static iwrc _onopen(struct IWDLSNR *self, const char *path, int mode) {
  return 0;
}

static iwrc _onclosing(struct IWDLSNR *self) {
  IWAL *wal = (IWAL *) self;
#ifdef IW_TESTS
  uint64_t tv = g_trigger;
  if (tv & IWKVD_WAL_NO_CHECKPOINT_ON_CLOSE) {
    _destroy(wal);
    return 0;
  }
#endif
  iwrc rc = _checkpoint_exl(wal, 0, false);
  _destroy(wal);
  return rc;
}

static iwrc _onset(struct IWDLSNR *self, off_t off, uint8_t val, off_t len, int flags) {
  IWAL *wal = (IWAL *) self;
  if (wal->applying) {
    return 0;
  }
  WBSET wb = {
    .id = WOP_SET,
    .val = val,
    .off = off,
    .len = len
  };
  wal->mbytes += len;
  return _write_op((IWAL *) self, &wb, sizeof(wb), 0, 0);
}

static iwrc _oncopy(struct IWDLSNR *self, off_t off, off_t len, off_t noff, int flags) {
  IWAL *wal = (IWAL *) self;
  if (wal->applying) {
    return 0;
  }
  WBCOPY wb = {
    .id = WOP_COPY,
    .off = off,
    .len = len,
    .noff = noff
  };
  wal->mbytes += len;
  return _write_op(wal, &wb, sizeof(wb), 0, 0);
}

static iwrc _onwrite(struct IWDLSNR *self, off_t off, const void *buf, off_t len, int flags) {
  assert(len <= (size_t)(-1));
  IWAL *wal = (IWAL *) self;
  if (wal->applying) {
    return 0;
  }
  WBWRITE wb = {
    .id = WOP_WRITE,
    .crc = wal->check_cp_crc ? iwu_crc32(buf, len, 0) : 0,
    .len = len,
    .off = off
  };
  wal->mbytes += len;
  return _write_op(wal, &wb, sizeof(wb), buf, len);
}

static iwrc _onresize(struct IWDLSNR *self, off_t osize, off_t nsize, int flags, bool *handled) {
  IWAL *wal = (IWAL *) self;
  if (wal->applying) {
    *handled = false;
    return 0;
  }
  *handled = true;
  WBRESIZE wb = {
    .id = WOP_RESIZE,
    .osize = osize,
    .nsize = nsize
  };
  iwrc rc = _lock(wal);
  RCRET(rc);
  rc = _write_wl(wal, &wb, sizeof(wb), 0, 0);
  RCGO(rc, finish);
  rc = _checkpoint_exl(wal, 0, true);
finish:
  IWRC(_unlock(wal), rc);
  return rc;
}

static iwrc _onsynced(struct IWDLSNR *self, int flags) {
  IWAL *wal = (IWAL *) self;
  if (wal->applying) {
    return 0;
  }
  iwrc rc = _lock(wal);
  RCRET(rc);
  rc = _flush_wl(wal, true);
  IWRC(_unlock(wal), rc);
  return rc;
}

static void _last_fix_and_reset_points(IWAL *wal, uint8_t *wmm, off_t fsz, off_t *fpos, off_t *rpos) {
  uint8_t *rp = wmm;
  *fpos = 0;
  *rpos = 0;

  for (uint32_t i = 0; rp - wmm < fsz; ++i) {
    uint8_t opid;
    off_t avail = fsz - (rp - wmm);
    memcpy(&opid, rp, 1);
    if (i == 0 && opid != WOP_SEP) {
      return;
    }
    switch (opid) {
      case WOP_SEP: {
        WBSEP wb;
        if (avail < sizeof(wb)) {
          return;
        }
        memcpy(&wb, rp, sizeof(wb));
        rp += sizeof(wb);
        if (wb.len > avail) {
          return;
        }
        break;
      }
      case WOP_SET: {
        if (avail < sizeof(WBSET)) {
          return;
        }
        rp += sizeof(WBSET);
        break;
      }
      case WOP_COPY: {
        if (avail < sizeof(WBCOPY)) {
          return;
        }
        rp += sizeof(WBCOPY);
        break;
      }
      case WOP_WRITE: {
        WBWRITE wb;
        if (avail < sizeof(wb)) {
          return;
        }
        memcpy(&wb, rp, sizeof(wb));
        rp += sizeof(wb);
        if (avail < wb.len) {
          return;
        }
        rp += wb.len;
        break;
      }
      case WOP_RESIZE: {
        if (avail < sizeof(WBRESIZE)) {
          return;
        }
        rp += sizeof(WBRESIZE);
        break;
      }
      case WOP_FIXPOINT: {
        *fpos = (rp - wmm);
        rp += sizeof(WBFIXPOINT);
        break;
      }
      case WOP_RESET: {
        *rpos = (rp - wmm);
        rp += sizeof(WBRESET);
        break;
      }
      default: {
        return;
        break;
      }
    }
  }
}

static iwrc _rollforward_exl(IWAL *wal, IWFS_EXT *extf, int recover_mode) {
  assert(wal->bufpos == 0);
  off_t fsz = 0;
  iwrc rc = iwp_lseek(wal->fh, 0, IWP_SEEK_END, &fsz);
  RCRET(rc);
  if (!fsz) { // empty wal log
    return 0;
  }
  size_t sp;
  uint8_t *mm;
  const bool ccrc = wal->check_cp_crc;
  off_t fpos = 0; // checkpoint
#ifndef _WIN32
  off_t pfsz = IW_ROUNDUP(fsz, iwp_page_size());
  uint8_t *wmm = mmap(0, (size_t) pfsz, PROT_READ, MAP_PRIVATE, wal->fh, 0);
  madvise(wmm, (size_t) fsz, MADV_SEQUENTIAL);
#else
  off_t pfsz = fsz;
  uint8_t *wmm = mmap(0, 0, PROT_READ, MAP_PRIVATE, wal->fh, 0);
#endif
  if (wmm == MAP_FAILED) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
  // Temporary turn off extf locking
  wal->applying = true;

  // Remap fsm in MAP_SHARED mode
  extf->remove_mmap_unsafe(extf, 0);
  rc = extf->add_mmap_unsafe(extf, 0, SIZE_T_MAX, IWFS_MMAP_SHARED);
  if (rc) {
    munmap(wmm, (size_t) pfsz);
    wal->iwkv->fatalrc = rc;
    wal->applying = false;
    return rc;
  }

#define _WAL_CORRUPTED(msg_) do { \
    rc = IWKV_ERROR_CORRUPTED_WAL_FILE; \
    iwlog_ecode_error2(rc, msg_); \
    goto finish; \
  } while(0);

  if (recover_mode) {
    off_t rpos; // reset point
    _last_fix_and_reset_points(wal, wmm, fsz, &fpos, &rpos);
    if (!fpos) {
      goto finish;
    }
    if (rpos > 0 && recover_mode == 1) {
      // Recover from last known reset point
      if (fpos < rpos) {
        goto finish;
      }
      // WBSEP__WBRESET
      //        \_rpos
      rpos -= sizeof(WBSEP);
      // WBSEP__WBRESET
      // \_rpos
      wmm += rpos;
      fsz -= rpos;
    }
  } else if (wal->rollforward_offset > 0) {
    if (wal->rollforward_offset >= fsz) {
      _WAL_CORRUPTED("Invalid rollforward offset");
    }
    wmm += wal->rollforward_offset;
    fsz -= wal->rollforward_offset;
  }

  uint8_t *rp = wmm;
  for (uint32_t i = 0; rp - wmm < fsz; ++i) {
    uint8_t opid;
    off_t avail = fsz - (rp - wmm);
    memcpy(&opid, rp, 1);
    if (i == 0 && opid != WOP_SEP) {
      rc = IWKV_ERROR_CORRUPTED_WAL_FILE;
      goto finish;
    }
    switch (opid) {
      case WOP_SEP: {
        WBSEP wb;
        if (avail < sizeof(wb)) _WAL_CORRUPTED("Premature end of WAL (WBSEP)");
        memcpy(&wb, rp, sizeof(wb));
        rp += sizeof(wb);
        if (wb.len > avail) _WAL_CORRUPTED("Premature end of WAL (WBSEP)");
        if (ccrc && wb.crc) {
          uint32_t crc = iwu_crc32(rp, wb.len, 0);
          if (crc != wb.crc) {
            _WAL_CORRUPTED("Invalid CRC32 checksum of WAL segment (WBSEP)");
          }
        }
        break;
      }
      case WOP_SET: {
        WBSET wb;
        if (avail < sizeof(wb)) _WAL_CORRUPTED("Premature end of WAL (WBSET)");
        memcpy(&wb, rp, sizeof(wb));
        rp += sizeof(wb);
        rc = extf->probe_mmap_unsafe(extf, 0, &mm, &sp);
        RCGO(rc, finish);
        memset(mm + wb.off, wb.val, (size_t) wb.len);
        break;
      }
      case WOP_COPY: {
        WBCOPY wb;
        if (avail < sizeof(wb)) _WAL_CORRUPTED("Premature end of WAL (WBCOPY)");
        memcpy(&wb, rp, sizeof(wb));
        rp += sizeof(wb);
        rc = extf->probe_mmap_unsafe(extf, 0, &mm, &sp);
        RCGO(rc, finish);
        memmove(mm + wb.noff, mm + wb.off, (size_t) wb.len);
        break;
      }
      case WOP_WRITE: {
        WBWRITE wb;
        if (avail < sizeof(wb)) _WAL_CORRUPTED("Premature end of WAL (WBWRITE)");
        memcpy(&wb, rp, sizeof(wb));
        rp += sizeof(wb);
        if (avail < wb.len) _WAL_CORRUPTED("Premature end of WAL (WBWRITE)");
        if (ccrc && wb.crc) {
          uint32_t crc = iwu_crc32(rp, wb.len, 0);
          if (crc != wb.crc) {
            _WAL_CORRUPTED("Invalid CRC32 checksum of WAL segment (WBWRITE)");
          }
        }
        rc = extf->probe_mmap_unsafe(extf, 0, &mm, &sp);
        RCGO(rc, finish);
        memmove(mm + wb.off, rp, wb.len);
        rp += wb.len;
        break;
      }
      case WOP_RESIZE: {
        WBRESIZE wb;
        if (avail < sizeof(wb)) _WAL_CORRUPTED("Premature end of WAL (WBRESIZE)");
        memcpy(&wb, rp, sizeof(wb));
        rp += sizeof(wb);
        rc = extf->truncate_unsafe(extf, wb.nsize);
        RCGO(rc, finish);
        break;
      }
      case WOP_FIXPOINT:
        if (fpos == rp - wmm) { // last fixpoint to
          WBFIXPOINT wb;
          memcpy(&wb, rp, sizeof(wb));
          iwlog_warn("Database recovered at point of time: %"
                     PRIu64
                     " ms since epoch\n", wb.ts);
          goto finish;
        }
        rp += sizeof(WBFIXPOINT);
        break;
      case WOP_RESET: {
        rp += sizeof(WBRESET);
        break;
      }
      default: {
        _WAL_CORRUPTED("Invalid WAL command");
        break;
      }
    }
  }
#undef _WAL_CORRUPTED

finish:
  if (!rc) {
    rc = extf->sync_mmap_unsafe(extf, 0, IWFS_SYNCDEFAULT);
  }
  munmap(wmm, (size_t) pfsz);
  IWRC(extf->remove_mmap_unsafe(extf, 0), rc);
  IWRC(extf->add_mmap_unsafe(extf, 0, SIZE_T_MAX, IWFS_MMAP_PRIVATE), rc);
  if (!rc) {
    int stage = wal->bkp_stage;
    if (stage == 0 || stage == BKP_WAL_CLEANUP) {
      rc = _truncate_wl(wal);
    } else {
      // Don't truncate WAL during online backup.
      // Just append the WBRESET mark
      WBRESET wb = {
        .id = WOP_RESET
      };
      IWRC(_flush_wl(wal, false), rc);
      // Write: WBSEP + WBRESET
      IWRC(_write_wl(wal, &wb, sizeof(wb), 0, 0), rc);
      IWRC(_flush_wl(wal, true), rc);
      IWRC(iwp_lseek(wal->fh, 0, IWP_SEEK_END, &fsz), rc);
      if (!rc) {
        // rollforward_offset points here --> WBSEP __ WBRESET __ EOF
        wal->rollforward_offset = fsz - (sizeof(WBSEP) + sizeof(WBRESET));
      }
    }
  }
  if (rc && !wal->iwkv->fatalrc) {
    wal->iwkv->fatalrc = rc;
  }
  wal->synched = true;
  wal->applying = false;
  return rc;
}

static iwrc _recover_wl(IWKV iwkv, IWAL *wal, IWFS_FSM_OPTS *fsmopts, bool recover_backup) {
  off_t fsz = 0;
  iwrc rc = iwp_lseek(wal->fh, 0, IWP_SEEK_END, &fsz);
  RCRET(rc);
  if (!fsz) { // empty wal log
    return 0;
  }
  IWFS_EXT extf;
  IWFS_EXT_OPTS extopts;
  memcpy(&extopts, &fsmopts->exfile, sizeof(extopts));
  extopts.use_locks = false;
  extopts.file.omode = IWFS_OCREATE | IWFS_OWRITE;
  extopts.file.dlsnr = 0;
  rc = iwfs_exfile_open(&extf, &extopts);
  RCRET(rc);
  rc = _rollforward_exl(wal, &extf, recover_backup ? 2 : 1);
  IWRC(extf.close(&extf), rc);
  return rc;
}

IW_INLINE bool _need_checkpoint(IWAL *wal) {
  uint64_t mbytes = wal->mbytes;
  bool force = wal->force_cp;
  return (force || mbytes >= wal->checkpoint_buffer_sz);
}

static iwrc _checkpoint_exl(IWAL *wal, uint64_t *tsp, bool no_fixpoint) {
  if (tsp) {
    *tsp = 0;
  }
  int stage = wal->bkp_stage;
  if (stage == BKP_MAIN_COPY) {
    // No checkpoints during main file copying
    return 0;
  }
  iwrc rc = 0;
  IWFS_EXT *extf;
  IWKV iwkv = wal->iwkv;
  if (!no_fixpoint) {
    wal->force_cp = false;
    wal->force_sp = false;
    WBFIXPOINT wb = {
      .id = WOP_FIXPOINT
    };
    rc = iwp_current_time_ms(&wb.ts, false);
    RCGO(rc, finish);
    rc = _write_wl(wal, &wb, sizeof(wb), 0, 0);
    RCGO(rc, finish);
  }
  rc = _flush_wl(wal, true);
  RCGO(rc, finish);
  rc = iwkv->fsm.extfile(&iwkv->fsm, &extf);
  RCGO(rc, finish);

  rc = _rollforward_exl(wal, extf, 0);
  wal->mbytes = 0;
  wal->synched = true;
  iwp_current_time_ms(&wal->checkpoint_ts, true);
  if (tsp) {
    *tsp = wal->checkpoint_ts;
  }

finish:
  if (rc) {
    if (iwkv->fatalrc) {
      iwlog_ecode_error3(rc);
    } else {
      iwkv->fatalrc = rc;
    }
  }
  return rc;
}

#ifdef IW_TESTS

iwrc iwal_test_checkpoint(IWKV iwkv) {
  if (!iwkv->dlsnr) {
    return IWKV_ERROR_WAL_MODE_REQUIRED;
  }
  IWAL *wal = (IWAL *) iwkv->dlsnr;
  iwrc rc = _excl_lock(wal);
  RCRET(rc);
  rc = _checkpoint_exl(wal, 0, false);
  IWRC(_excl_unlock(wal), rc);
  return rc;
}

#endif

//--------------------------------------- Public API

WUR iwrc iwal_poke_checkpoint(IWKV iwkv, bool force) {
  IWAL *wal = (IWAL *) iwkv->dlsnr;
  if (!wal || !(force || _need_checkpoint(wal))) {
    return 0;
  }
  iwrc rc = _lock(wal);
  RCRET(rc);
  bool cforce = wal->force_cp;
  if (cforce) { // Forced already
    _unlock(wal);
    return 0;
  } else if (force) {
    wal->force_cp = true;
  } else if (!_need_checkpoint(wal)) {
    _unlock(wal);
    return 0;
  }
  int rci = pthread_cond_broadcast(wal->cpt_condp);
  if (rci) {
    rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  _unlock(wal);
  return rc;
}

iwrc iwal_poke_savepoint(IWKV iwkv) {
  IWAL *wal = (IWAL *) iwkv->dlsnr;
  if (!wal) {
    return 0;
  }
  iwrc rc = _lock(wal);
  RCRET(rc);
  bool fsp = wal->force_sp;
  if (!fsp) {
    wal->force_sp = true;
    int rci = pthread_cond_broadcast(wal->cpt_condp);
    if (rci) {
      rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
    }
  }
  _unlock(wal);
  return rc;
}

iwrc _savepoint_exl(IWAL *wal, uint64_t *tsp, bool sync) {
  if (tsp) {
    *tsp = 0;
  }
  wal->force_sp = false;
  WBFIXPOINT wbfp = {
    .id = WOP_FIXPOINT
  };
  iwrc rc = iwp_current_time_ms(&wbfp.ts, false);
  RCRET(rc);
  rc = _write_wl(wal, &wbfp, sizeof(wbfp), 0, 0);
  RCRET(rc);
  rc = _flush_wl(wal, sync);
  RCRET(rc);
  if (sync) {
    wal->synched = true;
  }
  if (tsp) {
    *tsp = wbfp.ts;
  }
  return 0;
}

bool iwal_synched(IWKV iwkv) {
  IWAL *wal = (IWAL *) iwkv->dlsnr;
  if (!wal) {
    return false;
  }
  return wal->synched;
}

iwrc iwal_savepoint_exl(IWKV iwkv, bool sync) {
  IWAL *wal = (IWAL *) iwkv->dlsnr;
  if (!wal) {
    return 0;
  }
  return _savepoint_exl(wal, 0, sync);
}

void iwal_shutdown(IWKV iwkv) {
  IWAL *wal = (IWAL *) iwkv->dlsnr;
  if (!wal) {
    return;
  }
  while (wal->bkp_stage) { // todo: review
    iwp_sleep(50);
  }
  wal->open = false;
  if (wal->mtxp && wal->cpt_condp) {
    pthread_mutex_lock(wal->mtxp);
    pthread_cond_broadcast(wal->cpt_condp);
    pthread_mutex_unlock(wal->mtxp);
  }
  if (wal->cptp) {
    pthread_join(wal->cpt, 0);
    wal->cpt = 0;
  }
}

static void *_cpt_worker_fn(void *op) {
  int rci;
  iwrc rc = 0;
  IWAL *wal = op;
  IWKV iwkv = wal->iwkv;
  uint64_t savepoint_ts = 0;

  while (wal->open) {
    struct timespec tp;
    uint64_t tick_ts;
    bool sp = false, cp = false;
    rc = _lock(wal);
    RCBREAK(rc);

    if (_need_checkpoint(wal)) {
      cp = true;
      _unlock(wal);
      goto cprun;
    } else if (wal->force_sp) {
      sp = true;
      _unlock(wal);
      goto cprun;
    }

#if defined(IW_HAVE_CLOCK_MONOTONIC) && defined(IW_HAVE_PTHREAD_CONDATTR_SETCLOCK)
    rc = iwp_clock_get_time(CLOCK_MONOTONIC, &tp);
#else
    rc = iwp_clock_get_time(CLOCK_REALTIME, &tp);
#endif
    if (rc) {
      _unlock(wal);
      break;
    }
    tp.tv_sec += 1; // one sec tick
    tick_ts = tp.tv_sec * 1000 + (uint64_t) round(tp.tv_nsec / 1.0e6);
    rci = pthread_cond_timedwait(wal->cpt_condp, wal->mtxp, &tp);
    if (rci && rci != ETIMEDOUT) {
      rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
      _unlock(wal);
      break;
    }
    if (!wal->open || iwkv->fatalrc) {
      _unlock(wal);
      break;
    }
    bool synched = wal->synched;
    size_t mbytes = wal->mbytes;
    cp = _need_checkpoint(wal) || ((mbytes && (tick_ts - wal->checkpoint_ts) >= 1000LL * wal->checkpoint_timeout_sec));
    if (!cp) {
      sp = !synched && (wal->force_sp || ((tick_ts - savepoint_ts) >= 1000LL * wal->savepoint_timeout_sec));
    }
    _unlock(wal);

cprun:
    if (cp || sp) {
      rc = _excl_lock(wal);
      RCBREAK(rc);
      if (iwkv->open) {
        if (cp) {
          rc = _checkpoint_exl(wal, &savepoint_ts, false);
        } else {
          rc = _savepoint_exl(wal, &savepoint_ts, true);
        }
      }
      _excl_unlock(wal);
      if (rc) {
        iwlog_ecode_error2(rc, "WAL worker savepoint/checkpoint error\n");
        rc = 0;
      }
    }
  }
  if (rc) {
    iwkv->fatalrc = iwkv->fatalrc ? iwkv->fatalrc : rc;
    iwlog_ecode_error2(rc, "WAL worker exited with error\n");
  }
  return 0;
}

iwrc iwal_online_backup(IWKV iwkv, uint64_t *ts, const char *target_file) {
  iwrc rc;
  size_t sp;
  uint32_t lv;
  uint64_t llv;
  char buf[16384];
  off_t off = 0, fsize = 0;
  *ts = 0;

  if (!target_file) {
    return IW_ERROR_INVALID_ARGS;
  }
  IWAL *wal = (IWAL *) iwkv->dlsnr;
  if (!wal) {
    return IWKV_ERROR_WAL_MODE_REQUIRED;
  }
  rc = _lock(wal);
  RCRET(rc);
  if (wal->bkp_stage) {
    rc = IWKV_ERROR_BACKUP_IN_PROGRESS;
  } else {
    wal->bkp_stage = BKP_STARTED;
  }
  _unlock(wal);

#ifndef _WIN32
  HANDLE fh = open(target_file, O_CREAT | O_WRONLY | O_TRUNC, 00600);
  if (INVALIDHANDLE(fh)) {
    rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    goto finish;
  }
#else
  HANDLE fh = CreateFile(target_file, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (INVALIDHANDLE(fh)) {
    rc = iwrc_set_werror(IW_ERROR_IO_ERRNO, GetLastError());
    goto finish;
  }
#endif

  // Flush all pending WAL changes
  rc = _excl_lock(wal);
  RCGO(rc, finish);
  wal->bkp_stage = BKP_WAL_CLEANUP;
  rc = _checkpoint_exl(wal, 0, false);
  wal->bkp_stage = BKP_MAIN_COPY;
  _excl_unlock(wal);
  RCGO(rc, finish);

  // Copy main database file
  IWFS_FSM_STATE fstate = {0};
  rc = iwkv->fsm.state(&iwkv->fsm, &fstate);
  RCGO(rc, finish);
  do {
    rc = iwp_pread(fstate.exfile.file.fh, off, buf, sizeof(buf), &sp);
    RCGO(rc, finish);
    if (sp > 0) {
      rc = iwp_write(fh, buf, sp);
      RCGO(rc, finish);
      off += sp;
    }
  } while (sp > 0);

  // Copy most of WAL file content
  rc = _lock(wal);
  RCGO(rc, finish);
  wal->bkp_stage = BKP_WAL_COPY1;
  rc = _flush_wl(wal, false);
  _unlock(wal);
  RCGO(rc, finish);

  fsize = off;
  off = 0;
  do {
    rc = iwp_pread(wal->fh, off, buf, sizeof(buf), &sp);
    RCGO(rc, finish);
    if (sp > 0) {
      rc = iwp_write(fh, buf, sp);
      RCGO(rc, finish);
      off += sp;
    }
  } while (sp > 0);


  // Copy rest of WAL file in exclusive locked mode
  rc = _excl_lock(wal);
  RCGO(rc, finish);
  wal->bkp_stage = BKP_WAL_COPY2;
  rc = _savepoint_exl(wal, ts, true);
  RCGO(rc, unlock);
  do {
    rc = iwp_pread(wal->fh, off, buf, sizeof(buf), &sp);
    RCGO(rc, unlock);
    if (sp > 0) {
      rc = iwp_write(fh, buf, sp);
      RCGO(rc, unlock);
      off += sp;
    }
  } while (sp > 0);

  llv = IW_HTOILL(fsize);
  rc = iwp_write(fh, &llv, sizeof(llv));
  RCGO(rc, unlock);

  lv = IW_HTOIL(IWKV_BACKUP_MAGIC);
  rc = iwp_write(fh, &lv, sizeof(lv));
  RCGO(rc, unlock);

unlock:
  wal->bkp_stage = 0;
  IWRC(_excl_unlock(wal), rc);

finish:
  if (rc) {
    _lock(wal);
    wal->bkp_stage = 0;
    _unlock(wal);
  } else {
    rc = iwal_poke_checkpoint(iwkv, true);
  }
  if (!INVALIDHANDLE(fh)) {
    IWRC(iwp_fdatasync(fh), rc);
    IWRC(iwp_closefh(fh), rc);
  }
  return rc;
}

iwrc _init_cpt(IWAL *wal) {
  if (wal->savepoint_timeout_sec == UINT32_MAX
      && wal->checkpoint_timeout_sec == UINT32_MAX) {
    // do not start checkpoint thread
    return 0;
  }
  pthread_attr_t pattr;
  pthread_condattr_t cattr;
  int rci = pthread_condattr_init(&cattr);
  if (rci) {
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
#if defined(IW_HAVE_CLOCK_MONOTONIC) && defined(IW_HAVE_PTHREAD_CONDATTR_SETCLOCK)
  rci = pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
  if (rci) {
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
#endif
  rci = pthread_cond_init(&wal->cpt_cond, &cattr);
  if (rci) {
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  wal->cpt_condp = &wal->cpt_cond;
  rci = pthread_attr_init(&pattr);
  if (rci) {
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  pthread_attr_setdetachstate(&pattr, PTHREAD_CREATE_JOINABLE);
  rci = pthread_create(&wal->cpt, &pattr, _cpt_worker_fn, wal);
  if (rci) {
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  wal->cptp = &wal->cpt;
  return 0;
}

iwrc iwal_create(IWKV iwkv, const IWKV_OPTS *opts, IWFS_FSM_OPTS *fsmopts, bool recover_backup) {
  assert(!iwkv->dlsnr && opts && fsmopts);
  if (!opts) {
    return IW_ERROR_INVALID_ARGS;
  }
  if ((opts->oflags & IWKV_RDONLY) || !opts->wal.enabled) {
    return 0;
  }
  iwrc rc = 0;
  IWAL *wal = calloc(1, sizeof(*wal));
  if (!wal) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  wal->wal_lock_interceptor = opts->wal.wal_lock_interceptor;
  wal->wal_lock_interceptor_opaque = opts->wal.wal_lock_interceptor_opaque;

  size_t sz = strlen(opts->path);
  char *wpath = malloc(sz + 4 /*-wal*/ + 1 /*\0*/);
  if (!wpath) {
    free(wal);
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  memcpy(wpath, opts->path, sz);
  memcpy(wpath + sz, "-wal", 4);
  wpath[sz + 4] = '\0';

  wal->fh = INVALID_HANDLE_VALUE;
  wal->path = wpath;
  wal->oflags = opts->oflags;
  wal->iwkv = iwkv;
  iwp_current_time_ms(&wal->checkpoint_ts, true);

  rc = _init_locks(wal);
  RCGO(rc, finish);

  IWDLSNR *dlsnr = &wal->lsnr;
  dlsnr->onopen = _onopen;
  dlsnr->onclosing = _onclosing;
  dlsnr->onset = _onset;
  dlsnr->oncopy = _oncopy;
  dlsnr->onwrite = _onwrite;
  dlsnr->onresize = _onresize;
  dlsnr->onsynced = _onsynced;
  iwkv->dlsnr = (IWDLSNR *) wal;

  wal->wal_buffer_sz =
    opts->wal.wal_buffer_sz > 0 ?
    opts->wal.wal_buffer_sz :
#if defined __ANDROID__ || defined TARGET_OS_IPHONE
    2 * 1024 * 1024; // 2M
#else
    8 * 1024 * 1024; // 8M
#endif
  if (wal->wal_buffer_sz < 4096) {
    wal->wal_buffer_sz = 4096;
  }

  wal->checkpoint_buffer_sz
    = opts->wal.checkpoint_buffer_sz > 0 ?
      opts->wal.checkpoint_buffer_sz :
#if defined __ANDROID__ || defined TARGET_OS_IPHONE
      64ULL * 1024 * 1024; // 64M
#else
      1024ULL * 1024 * 1024; // 1G
#endif
  if (wal->checkpoint_buffer_sz < 1024 * 1024) { // 1M minimal
    wal->checkpoint_buffer_sz = 1024 * 1024;
  }

  wal->savepoint_timeout_sec
    = opts->wal.savepoint_timeout_sec > 0 ?
      opts->wal.savepoint_timeout_sec : 10; // 10 sec

  wal->checkpoint_timeout_sec
    = opts->wal.checkpoint_timeout_sec > 0 ?
#if defined __ANDROID__ || defined TARGET_OS_IPHONE
      opts->wal.checkpoint_timeout_sec : 60; // 1 min
#else
      opts->wal.checkpoint_timeout_sec : 300; // 5 min
#endif

  if (wal->checkpoint_timeout_sec < 10) { // 10 sec minimal
    wal->checkpoint_timeout_sec = 10;
  }
  if (wal->savepoint_timeout_sec >= wal->checkpoint_timeout_sec) {
    wal->savepoint_timeout_sec = wal->checkpoint_timeout_sec / 2;
  }

  wal->check_cp_crc = opts->wal.check_crc_on_checkpoint;

  wal->buf = malloc(wal->wal_buffer_sz);
  if (!wal->buf) {
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    goto finish;
  }
  wal->buf += sizeof(WBSEP);
  wal->bufsz = wal->wal_buffer_sz - sizeof(WBSEP);

  // Now open WAL file

#ifndef _WIN32
  HANDLE fh = open(wal->path, O_CREAT | O_RDWR, IWFS_DEFAULT_FILEMODE);
  if (INVALIDHANDLE(fh)) {
    rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    goto finish;
  }
#else
  HANDLE fh = CreateFile(wal->path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                         NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (INVALIDHANDLE(fh)) {
    rc = iwrc_set_werror(IW_ERROR_IO_ERRNO, GetLastError());
    goto finish;
  }
#endif

  wal->fh = fh;
  rc = iwp_flock(wal->fh, IWP_WLOCK);
  RCGO(rc, finish);

  // Now force all fsm data to be privately mmaped.
  // We will apply wal log to main database file
  // then re-read our private mmaps
  fsmopts->mmap_opts = IWFS_MMAP_PRIVATE;
  fsmopts->exfile.file.dlsnr = iwkv->dlsnr;

  if (wal->oflags & IWKV_TRUNC) {
    rc = _truncate_wl(wal);
    RCGO(rc, finish);
  } else {
    rc = _recover_wl(iwkv, wal, fsmopts, recover_backup);
    RCGO(rc, finish);
  }

  wal->open = true;
  // Start checkpoint thread
  rc = _init_cpt(wal);

finish:
  if (rc) {
    iwkv->dlsnr = 0;
    iwkv->fatalrc = iwkv->fatalrc ? iwkv->fatalrc : rc;
    iwal_shutdown(iwkv);
    _destroy(wal);
  }
  return rc;
}
