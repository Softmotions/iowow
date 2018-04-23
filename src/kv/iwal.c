#include "iwkv_internal.h"
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <time.h>

extern atomic_uint_fast64_t g_trigger;

typedef enum {
  WOP_SET = 1,
  WOP_COPY,
  WOP_WRITE,
  WOP_RESIZE,
  WOP_FIXPOINT,
  WOP_SEP = 127, /**< WAL file separator */
} wop_t;

typedef struct WBSEP {
  uint8_t id;
  uint32_t crc;
  uint32_t len;
} WBSEP;

typedef struct WBSET {
  uint8_t id;
  uint8_t val;
  off_t off;
  off_t len;
} WBSET;

typedef struct WBCOPY {
  uint8_t id;
  off_t off;
  off_t len;
  off_t noff;
} WBCOPY;

typedef struct WBWRITE {
  uint8_t id;
  uint32_t crc;
  uint32_t len;
  off_t off;
} WBWRITE;

typedef struct WBRESIZE {
  uint8_t id;
  off_t osize;
  off_t nsize;
} WBRESIZE;

typedef struct WBFIXPOINT {
  uint8_t id;
  uint64_t ts;
} WBFIXPOINT;

typedef struct IWAL {
  IWDLSNR lsnr;
  atomic_bool applying;             /**< WAL log applying */
  atomic_bool open;                 /**< WAL log applying */
  bool check_cp_crc;                /**< Check CRC32 sum of data blocks during checkpoint. Default: false  */
  iwkv_openflags oflags;            /**< File open flags */
  size_t wal_buffer_sz;             /**< WAL file intermediate buffer size. */
  size_t checkpoint_buffer_sz;      /**< Checkpoint buffer size in bytes. */
  size_t page_size;                 /**< System page size */
  uint32_t bufpos;                  /**< Current position in buffer */
  uint32_t bufsz;                   /**< Size of buffer */
  HANDLE fh;                        /**< File handle */
  uint8_t *buf;                     /**< File buffer */
  char *path;                       /**< WAL file path */
  pthread_mutex_t *mtxp;            /**< Global WAL mutex */
  pthread_cond_t *cpt_condp;        /**< Checkpoint thread cond variable */
  pthread_t *cptp;                  /**< Checkpoint thread */
  uint32_t checkpoint_timeout_sec;  /**< Checkpoint timeout seconds */
  atomic_uint_fast64_t mbytes;      /**< Estimated size of modifed private mmaped memory bytes */
  uint64_t checkpoint_ts;           /**< Last checkpoint timestamp milliseconds */
  pthread_mutex_t mtx;              /**< Global WAL mutex */
  pthread_cond_t cpt_cond;          /**< Checkpoint thread cond variable */
  pthread_t cpt;                    /**< Checkpoint thread */
  IWKV iwkv;
} IWAL;

bool extfile_use_locks(IWFS_EXT *f, bool use_locks);
static iwrc _checkpoint(IWAL *wal);
static iwrc _checkpoint_wl(IWAL *wal);

IW_INLINE iwrc _lock(IWAL *wal) {
  int rci = wal->mtxp ? pthread_mutex_lock(wal->mtxp) : 0;
  return (rci ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci) : 0);
}

IW_INLINE iwrc _unlock(IWAL *wal) {
  int rci = wal->mtxp ? pthread_mutex_unlock(wal->mtxp) : 0;
  return (rci ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci) : 0);
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
  if (wal->bufpos) {
    uint32_t crc = iwu_crc32(wal->buf, wal->bufpos, 0);
    WBSEP sep = {0}; // Avoid uninitialized padding bytes
    sep.id = WOP_SEP;
    sep.crc = crc;
    sep.len = wal->bufpos;
    ssize_t wz = wal->bufpos + sizeof(WBSEP);
    uint8_t *wp = wal->buf - sizeof(WBSEP);
    wal->bufpos = 0;
    memcpy(wp, &sep, sizeof(WBSEP));
    ssize_t sz = write(wal->fh, wp, wz);
    if (wz != sz) {
      return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    }
  }
  if (sync && fsync(wal->fh)) {
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
  return 0;
}

IW_INLINE iwrc _truncate(IWAL *wal) {
  iwrc rc = iwp_ftruncate(wal->fh, 0);
  RCRET(rc);
  if (lseek(wal->fh, 0, SEEK_SET) < 0) {
    rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    RCRET(rc);
  }
  if (fsync(wal->fh)) {
    rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
  return rc;
}

static iwrc _write_wl(IWAL *wal, const void *op, off_t oplen, const uint8_t *data, off_t len, bool checkpoint) {
  ssize_t sz;
  iwrc rc = 0;
  const off_t bufsz = wal->bufsz;
  if (bufsz - wal->bufpos < oplen) {
    rc = _flush_wl(wal, false);
    RCRET(rc);
  }
  assert(bufsz - wal->bufpos >= oplen);
  memcpy(wal->buf + wal->bufpos, op, oplen);
  wal->bufpos += oplen;
  if (bufsz - wal->bufpos < len) {
    rc = _flush_wl(wal, false);
    RCRET(rc);
    sz = write(wal->fh, data, len);
    if (sz != len) {
      return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    }
  } else {
    assert(bufsz - wal->bufpos >= len);
    memcpy(wal->buf + wal->bufpos, data, len);
    wal->bufpos += len;
  }
  if (checkpoint) {
    rc = _checkpoint_wl(wal);
  }
  return rc;
}


IW_INLINE iwrc _write(IWAL *wal, const void *op, off_t oplen, const uint8_t *data, off_t len, bool checkpoint) {
  iwrc rc = _lock(wal);
  RCRET(rc);
  rc = _write_wl(wal, op, oplen, data, len, checkpoint);
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
    fprintf(stderr, "Skip _onclosing checkpoint\n")  ;
    return 0;
  }
#endif
  iwrc rc = _checkpoint(wal);
  _destroy(wal);
  return rc;
}

static iwrc _onset(struct IWDLSNR *self, off_t off, uint8_t val, off_t len, int flags) {
  IWAL *wal = (IWAL *) self;
  if (wal->applying) {
    return 0;
  }
  WBSET wb = {0}; // Avoid uninitialized padding bytes
  wb.id = WOP_SET;
  wb.val = val;
  wb.off = off;
  wb.len = len;
  wal->mbytes += len;
  return _write((IWAL *) self, &wb, sizeof(wb), 0, 0, false);
}

static iwrc _oncopy(struct IWDLSNR *self, off_t off, off_t len, off_t noff, int flags) {
  IWAL *wal = (IWAL *) self;
  if (wal->applying) {
    return 0;
  }
  WBCOPY wb = {0}; // Avoid uninitialized padding bytes
  wb.id = WOP_COPY;
  wb.off = off;
  wb.len = len;
  wb.noff = noff;
  wal->mbytes += len;
  return _write(wal, &wb, sizeof(wb), 0, 0, false);
}

static iwrc _onwrite(struct IWDLSNR *self, off_t off, const void *buf, off_t len, int flags) {
  assert(len <= (size_t)(-1));
  IWAL *wal = (IWAL *) self;
  if (wal->applying) {
    return 0;
  }
  WBWRITE wb = {0}; // Avoid uninitialized padding bytes
  wb.id = WOP_WRITE;
  wb.crc = iwu_crc32(buf, len, 0);
  wb.len = len;
  wb.off = off;
  wal->mbytes += len;
  return _write(wal, &wb, sizeof(wb), buf, len, false);
}

static iwrc _onresize(struct IWDLSNR *self, off_t osize, off_t nsize, int flags, bool *handled) {
  IWAL *wal = (IWAL *) self;
  if (wal->applying) {
    *handled = false;
    return 0;
  }
  *handled = true;
  WBRESIZE wb = {0}; // Avoid uninitialized padding bytes
  wb.id = WOP_RESIZE;
  wb.osize = osize;
  wb.nsize = nsize;
  return _write(wal, &wb, sizeof(wb), 0, 0, true);
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

static iwrc _find_last_fixpoint(IWAL *wal, uint8_t *wmm, off_t fsz, off_t *pfpos) {
  uint8_t *rp = wmm;
  *pfpos = 0;
  
#define _WAL_CORRUPTED(msg_) do { \
    iwrc rc = IWKV_ERROR_CORRUPTED_WAL_FILE; \
    iwlog_ecode_error2(rc, msg_); \
    return rc; \
  } while(0);
  
  for (uint32_t i = 0; rp - wmm < fsz; ++i) {
    uint8_t opid;
    off_t avail = fsz - (rp - wmm);
    memcpy(&opid, rp, 1);
    if (i == 0 && opid != WOP_SEP) {
      return IWKV_ERROR_CORRUPTED_WAL_FILE;
    }
    switch (opid) {
      case WOP_SEP: {
        WBSEP wb;
        if (avail < sizeof(wb)) _WAL_CORRUPTED("Premature end of WAL (WBSEP)");
        memcpy(&wb, rp, sizeof(wb));
        rp += sizeof(wb);
        if (wb.len > avail) _WAL_CORRUPTED("Premature end of WAL (WBSEP)");
        uint32_t crc = iwu_crc32(rp, wb.len, 0);
        if (crc != wb.crc) {
          _WAL_CORRUPTED("Invalid CRC32 checksum of WAL segment (WBSEP)");
        }
        break;
      }
      case WOP_SET: {
        if (avail < sizeof(WBSET)) _WAL_CORRUPTED("Premature end of WAL (WBSET)");
        rp += sizeof(WBSET);
        break;
      }
      case WOP_COPY: {
        if (avail < sizeof(WBCOPY)) _WAL_CORRUPTED("Premature end of WAL (WBCOPY)");
        rp += sizeof(WBCOPY);
        break;
      }
      case WOP_WRITE: {
        WBWRITE wb;
        if (avail < sizeof(wb)) _WAL_CORRUPTED("Premature end of WAL (WBWRITE)");
        memcpy(&wb, rp, sizeof(wb));
        rp += sizeof(wb);
        if (avail < wb.len) _WAL_CORRUPTED("Premature end of WAL (WBWRITE)");
        uint32_t crc = iwu_crc32(rp, wb.len, 0);
        if (crc != wb.crc) {
          _WAL_CORRUPTED("Invalid CRC32 checksum of WAL segment (WBWRITE)");
        }
        rp += wb.len;
        break;
      }
      case WOP_RESIZE: {
        if (avail < sizeof(WBRESIZE)) _WAL_CORRUPTED("Premature end of WAL (WBRESIZE)");
        rp += sizeof(WBRESIZE);
        break;
      }
      case WOP_FIXPOINT:
        *pfpos = (rp - wmm);
        rp += sizeof(WBFIXPOINT);
        break;
      default: {
        _WAL_CORRUPTED("Invalid WAL command");
        break;
      }
    }
  }
#undef _WAL_CORRUPTED
  return 0;
}

static iwrc _rollforward_wl(IWAL *wal, IWFS_EXT *extf, bool recover) {
  assert(wal->bufpos == 0);
  iwrc rc = 0;
  const off_t fsz = lseek(wal->fh, 0, SEEK_END);
  if (fsz < 0) {
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  } else if (!fsz) {
    return 0; // empty wal log
  }
  size_t sp;
  uint8_t *mm;
  const bool ccrc = wal->check_cp_crc;
  off_t fpos = 0; // checkpoint
  off_t pfsz = IW_ROUNDUP(fsz, wal->page_size);
  uint8_t *wmm = mmap(0, pfsz, PROT_READ, MAP_PRIVATE, wal->fh, 0);
  if (wmm == MAP_FAILED) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
  madvise(wmm, fsz, MADV_SEQUENTIAL);
  
  // Temporary turn off extf locking
  wal->applying = true;
  bool eul = extfile_use_locks(extf, false);
  
  // Remap fsm in MAP_SHARED mode
  extf->remove_mmap(extf, 0);
  rc = extf->add_mmap(extf, 0, SIZE_T_MAX, 0);
  if (rc) {
    munmap(wmm, pfsz);
    extfile_use_locks(extf, eul);
    wal->applying = false;
    return rc;
  }
  if (recover) {
    rc = _find_last_fixpoint(wal, wmm, fsz, &fpos);
    if (rc || !fpos) {
      goto finish;
    }
  }
#define _WAL_CORRUPTED(msg_) do { \
    rc = IWKV_ERROR_CORRUPTED_WAL_FILE; \
    iwlog_ecode_error2(rc, msg_); \
    goto finish; \
  } while(0);
  
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
        if (ccrc) {
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
        rc = extf->probe_mmap(extf, 0, &mm, &sp);
        RCGO(rc, finish);
        memset(mm + wb.off, wb.val, wb.len);
        break;
      }
      case WOP_COPY: {
        WBCOPY wb;
        if (avail < sizeof(wb)) _WAL_CORRUPTED("Premature end of WAL (WBCOPY)");
        memcpy(&wb, rp, sizeof(wb));
        rp += sizeof(wb);
        rc = extf->probe_mmap(extf, 0, &mm, &sp);
        RCGO(rc, finish);
        memmove(mm + wb.noff, mm + wb.off, wb.len);
        break;
      }
      case WOP_WRITE: {
        WBWRITE wb;
        if (avail < sizeof(wb)) _WAL_CORRUPTED("Premature end of WAL (WBWRITE)");
        memcpy(&wb, rp, sizeof(wb));
        rp += sizeof(wb);
        if (avail < wb.len) _WAL_CORRUPTED("Premature end of WAL (WBWRITE)");
        if (ccrc) {
          uint32_t crc = iwu_crc32(rp, wb.len, 0);
          if (crc != wb.crc) {
            _WAL_CORRUPTED("Invalid CRC32 checksum of WAL segment (WBWRITE)");
          }
        }
        rc = extf->probe_mmap(extf, 0, &mm, &sp);
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
        rc = extf->truncate(extf, wb.nsize);
        RCGO(rc, finish);
        break;
      }
      case WOP_FIXPOINT:
        if (fpos == rp - wmm) { // last fixpoint to recover
          WBFIXPOINT wb;
          memcpy(&wb, rp, sizeof(wb));
          iwlog_warn("Database recovered at point of time: %" PRIu64 " ms since epoch\n", wb.ts);
          goto finish;
        }
        rp += sizeof(WBFIXPOINT);
        break;
      default: {
        _WAL_CORRUPTED("Invalid WAL command");
        break;
      }
    }
  }
#undef _WAL_CORRUPTED
  
finish:
  if (!rc) {
    rc = extf->sync_mmap(extf, 0, 0);
  }
  munmap(wmm, pfsz);
  extf->remove_mmap(extf, 0);
  IWRC(extf->add_mmap(extf, 0, SIZE_T_MAX, IWFS_MMAP_PRIVATE), rc);
  if (!rc) {
    rc = _truncate(wal);
  }
  wal->applying = false;
  extfile_use_locks(extf, eul);
  return rc;
}

static iwrc _recover_wl(IWKV iwkv, IWAL *wal, IWFS_FSM_OPTS *fsmopts) {
  const off_t fsz = lseek(wal->fh, 0, SEEK_END);
  if (fsz < 0) {
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  } else if (!fsz) {
    return 0; // empty wal log
  }
  iwrc rc;
  IWFS_EXT extf;
  IWFS_EXT_OPTS extopts;
  memcpy(&extopts, &fsmopts->exfile, sizeof(extopts));
  extopts.use_locks = false;
  extopts.file.omode = IWFS_OCREATE | IWFS_OWRITE;
  extopts.file.dlsnr = 0;
  rc = iwfs_exfile_open(&extf, &extopts);
  RCRET(rc);
  rc = _rollforward_wl(wal, &extf, true);
  IWRC(extf.close(&extf), rc);
  return rc;
}

IW_INLINE bool _need_checkpoint(IWAL *wal) {
  uint64_t mbytes = wal->mbytes;
  if (mbytes >= wal->checkpoint_buffer_sz) {
    return true;
  }
  return false;
}

static iwrc _checkpoint_wl(IWAL *wal) {
  //fprintf(stderr, "_checkpoint_wl\n");
  IWFS_EXT *extf;
  IWKV iwkv = wal->iwkv;
  WBFIXPOINT wbfp = {0};
  wbfp.id = WOP_FIXPOINT;
  iwrc rc = iwp_current_time_ms(&wbfp.ts, false);
  RCRET(rc);
  rc = _write_wl(wal, &wbfp, sizeof(wbfp), 0, 0, false);
  RCRET(rc);
  rc = _flush_wl(wal, true);
  RCGO(rc, finish);
  rc = iwkv->fsm.extfile(&iwkv->fsm, &extf);
  RCGO(rc, finish);
  rc = _rollforward_wl(wal, extf, false);
  wal->mbytes = 0;
  iwp_current_time_ms(&wal->checkpoint_ts, true);
  
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

IW_INLINE iwrc _checkpoint(IWAL *wal) {
  iwrc rc = _lock(wal);
  RCRET(rc);
  rc = _checkpoint_wl(wal);
  _unlock(wal);
  return rc;
}

//--------------------------------------- Public API

WUR iwrc iwal_checkpoint(IWKV iwkv, bool force) {
  IWAL *wal = (IWAL *) iwkv->dlsnr;
  if (!wal) {
    return 0;
  }
  bool ncp = _need_checkpoint(wal);
  if (!ncp && !force) {
    return 0;
  }
  iwrc rc = iwkv_exclusive_lock(iwkv);
  RCRET(rc);
  rc = _checkpoint(wal);
  iwkv_exclusive_unlock(iwkv);
  return rc;
}


WUR iwrc iwal_savepoint(IWKV iwkv, bool sync) {
  IWAL *wal = (IWAL *) iwkv->dlsnr;
  if (!wal) {
    return 0;
  }
  iwrc rc = iwkv_exclusive_lock(iwkv);
  RCRET(rc);
  rc = _lock(wal);
  if (rc) {
    iwkv_exclusive_unlock(iwkv);
    return rc;
  }
  WBFIXPOINT wbfp = {0};
  wbfp.id = WOP_FIXPOINT;
  rc = iwp_current_time_ms(&wbfp.ts, false);
  RCGO(rc, finish);
  rc = _write_wl(wal, &wbfp, sizeof(wbfp), 0, 0, false);
  RCRET(rc);
  rc = _flush_wl(wal, sync);
  RCGO(rc, finish);
  
finish:
  _unlock(wal);
  iwkv_exclusive_unlock(iwkv);
  return rc;
}

void iwal_shutdown(IWKV iwkv) {
  IWAL *wal = (IWAL *) iwkv->dlsnr;
  if (!wal) {
    return;
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
  IWP_FILE_STAT fs;
  uint64_t sec = wal->checkpoint_timeout_sec;
  
  while (wal->open) {
    struct timespec tp;
    bool iscp = false;
    rc = _lock(wal);
    RCBREAK(rc);
    if (clock_gettime(CLOCK_MONOTONIC, &tp)) {
      rc = iwrc_set_errno(IW_ERROR_ERRNO, errno);
      _unlock(wal);
      break;
    }
    tp.tv_sec += (sec / 2 + 1);
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
    rc = iwp_fstath(wal->fh, &fs);
    iscp = !rc && iwkv->open && (wal->bufpos || fs.size);
    rc = 0;
    _unlock(wal);
    if (iscp) {
      uint64_t ts;
      uint64_t cpts = wal->checkpoint_ts;
      iwp_current_time_ms(&ts, true);
      if (ts - cpts >= sec * 1000) {
        rc = iwkv_exclusive_lock(iwkv);
        RCBREAK(rc);
        rc = iwp_fstath(wal->fh, &fs);
        iscp = !rc && iwkv->open && (wal->bufpos || fs.size);
        rc = 0;
        if (iscp) {
          rc = _checkpoint(wal);
        }
        iwkv_exclusive_unlock(iwkv);
      }
    }
  }
  if (rc) {
    iwkv->fatalrc = iwkv->fatalrc ? iwkv->fatalrc : rc;
    iwlog_ecode_error2(rc, "WAL checkpoint worker exited with error\n");
  } else {
    fprintf(stderr, "WAL checkpoint worker exited\n");
  }
  return 0;
}

iwrc _init_cpt(IWAL *wal) {
  if (!wal->checkpoint_timeout_sec || wal->checkpoint_timeout_sec == UINT32_MAX) {
    // do not start checkpoint thread
    return 0;
  }
  pthread_attr_t pattr;
  pthread_condattr_t cattr;
  int rci = pthread_condattr_init(&cattr);
  if (rci) {
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  rci = pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
  if (rci) {
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
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

iwrc iwal_create(IWKV iwkv, const IWKV_OPTS *opts, IWFS_FSM_OPTS *fsmopts) {
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
  size_t sz = strlen(opts->path);
  char *wpath = malloc(sz + 4 /*-wal*/ + 1 /*\0*/);
  if (!wpath) {
    free(wal);
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  memcpy(wpath, opts->path, sz);
  memcpy(wpath + sz, "-wal", 4);
  wpath[sz + 4] = '\0';
  
  wal->page_size = iwp_page_size();
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
    opts->wal.wal_buffer_sz  : 8 * 1024 * 1024; // 8M
  if (wal->wal_buffer_sz < 4096) {
    wal->wal_buffer_sz = 4096;
  }
  
  wal->checkpoint_buffer_sz
    = opts->wal.checkpoint_buffer_sz > 0 ?
      opts->wal.checkpoint_buffer_sz : 1ULL * 1024 * 1024 * 1024; // 1G
      
  wal->checkpoint_timeout_sec
    = opts->wal.checkpoint_timeout_sec > 0 ?
      opts->wal.checkpoint_timeout_sec : 30; // 30 sec
      
  wal->check_cp_crc = opts->wal.check_crc_on_checkpoint;
  
  wal->buf = malloc(wal->wal_buffer_sz);
  if (!wal->buf) {
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    goto finish;
  }
  wal->buf += sizeof(WBSEP);
  wal->bufsz = wal->wal_buffer_sz - sizeof(WBSEP);
  
  // Now open WAL file
  HANDLE fh = open(wal->path, O_CREAT | O_RDWR, IWFS_DEFAULT_FILEMODE);
  if (INVALIDHANDLE(fh)) {
    rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    goto finish;
  }
  wal->fh = fh;
  rc = iwp_flock(wal->fh, IWP_WLOCK);
  RCGO(rc, finish);
  
  // Now force all fsm data to be privately mmaped.
  // We will apply wal log to main database file
  // then re-read our private mmaps
  fsmopts->mmap_opts = IWFS_MMAP_PRIVATE;
  fsmopts->exfile.file.dlsnr = iwkv->dlsnr;
  
  if (wal->oflags & IWKV_TRUNC) {
    rc = _truncate(wal);
    RCGO(rc, finish);
  } else {
    rc = _recover_wl(iwkv, wal, fsmopts);
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
