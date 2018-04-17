#include "iwkv_internal.h"
#include "iwp.h"

#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>

typedef enum {
  WOP_SET = 1,
  WOP_COPY,
  WOP_WRITE,
  WOP_RESIZE,
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

union WBOP {
  WBSEP sep;
  WBSET set;
  WBCOPY copy;
  WBWRITE write;
  WBRESIZE resize;
};

typedef struct IWAL {
  IWDLSNR lsnr;
  iwkv_openflags oflags;            /**< File open flags */
  size_t wal_buffer_sz;             /**< WAL file intermediate buffer size */
  size_t checkpoint_buffer_sz;      /**< Checkpoint buffer size in bytes. */
  uint64_t checkpoint_timeout_ms;   /**< Checkpoint timeout millesconds */
  char *path;                       /**< WAL file path */
  uint8_t *buf;                     /**< File buffer */
  uint32_t bufsz;                   /**< Size of buffer */
  uint32_t bufpos;                  /**< Current position in buffer */
  atomic_uint mbytes;               /**< Estimated size of modifed private mmaped memory bytes */
  HANDLE fh;                        /**< File handle */
  pthread_mutex_t *mtx;             /**< Global thread mutex */
  IWKV iwkv;
} IWAL;

IW_INLINE iwrc _lock(IWAL *wal) {
  int rci = wal->mtx ? pthread_mutex_lock(wal->mtx) : 0;
  return (rci ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci) : 0);
}

IW_INLINE iwrc _unlock(IWAL *wal) {
  int rci = wal->mtx ? pthread_mutex_unlock(wal->mtx) : 0;
  return (rci ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci) : 0);
}

static iwrc _init_locks(IWAL *wal) {
  assert(!wal->mtx);
  if (wal->oflags & IWKV_NOLOCKS) {
    return 0;
  }
  wal->mtx = malloc(sizeof(*wal->mtx));
  if (!wal->mtx) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  int rci = pthread_mutex_init(wal->mtx, 0);
  if (rci) {
    free(wal->mtx);
    wal->mtx = 0;
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  return 0;
}

static iwrc _destroy_locks(IWAL *wal) {
  if (!wal->mtx) {
    return 0;
  }
  iwrc rc = 0;
  int rci = pthread_mutex_destroy(wal->mtx);
  if (rci) {
    IWRC(iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci), rc);
  }
  free(wal->mtx);
  wal->mtx = 0;
  return rc;
}

static void _iwal_destroy(IWAL *wal) {
  if (wal) {
    if (!INVALIDHANDLE(wal->fh)) {
      iwp_unlock(wal->fh);
      iwp_closefh(wal->fh);
    }
    _destroy_locks(wal);
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

static iwrc _flush_lk(IWAL *wal, bool sync) {
  if (wal->bufpos) {
    uint32_t crc = iwu_crc32(wal->buf, wal->bufpos, 0);
    WBSEP sep = {
      .id = WOP_SEP,
      .crc = crc,
      .len = wal->bufpos
    };
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
  if (fsync(wal->fh)) {
    rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
  return rc;
}

static iwrc _write(IWAL *wal, const void *op, off_t oplen, const uint8_t *data, off_t len) {
  iwrc rc = _lock(wal);
  RCRET(rc);
  ssize_t sz;
  const off_t bufsz = wal->bufsz;
  if (bufsz - wal->bufpos < oplen) {
    rc = _flush_lk(wal, false);
    RCGO(rc, finish);
  }
  assert(bufsz - wal->bufpos >= oplen);
  memcpy(wal->buf + wal->bufpos, op, oplen);
  wal->bufpos += oplen;
  if (bufsz < len) {
    rc = _flush_lk(wal, false);
    RCGO(rc, finish);
    sz = write(wal->fh, data, len);
    if (sz != len) {
      rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
      goto finish;
    }
  } else {
    if (bufsz - wal->bufpos < len) {
      rc = _flush_lk(wal, false);
      RCGO(rc, finish);
    }
    assert(bufsz - wal->bufpos >= len);
    memcpy(wal->buf + wal->bufpos, data, len);
    wal->bufpos += len;
  }

finish:
  IWRC(_unlock(wal), rc);
  return rc;
}

iwrc iwal_sync(IWKV iwkv) {
  IWAL *wal = (IWAL *) iwkv->dlsnr;
  iwrc rc = _lock(wal);
  RCRET(rc);
  rc = _flush_lk(wal, true);
  IWRC(_unlock(wal), rc);
  return rc;
}

static iwrc _onopen(struct IWDLSNR *self, const char *path, int mode) {
  return 0;
}

static iwrc _onclosed(struct IWDLSNR *self, const char *path) {
  return 0;
}

static iwrc _onset(struct IWDLSNR *self, off_t off, uint8_t val, off_t len, int flags) {
  WBSET wb = {
    .id = WOP_SET,
    .val = val,
    .off = off,
    .len = len
  };
  return _write((IWAL *) self, &wb, sizeof(wb), 0, 0);
}

static iwrc _oncopy(struct IWDLSNR *self, off_t off, off_t len, off_t noff, int flags) {
  WBCOPY wb = {
    .id = WOP_COPY,
    .off = off,
    .len = len,
    .noff = noff
  };
  return _write((IWAL *) self, &wb, sizeof(wb), 0, 0);
}

static iwrc _onwrite(struct IWDLSNR *self, off_t off, const void *buf, off_t len, int flags) {
  IWAL *wal = (IWAL *) self;
  assert(len <= (size_t)(-1));
  WBWRITE wb = {
    .id = WOP_WRITE,
    .crc = iwu_crc32(buf, len, 0),
    .len = len,
    .off = off
  };
  wal->mbytes += len;
  return _write((IWAL *) self, &wb, sizeof(wb), buf, len);
}

static iwrc _onresize(struct IWDLSNR *self, off_t osize, off_t nsize, int flags) {
  WBRESIZE wb = {
    .id = WOP_RESIZE,
    .osize = osize,
    .nsize = nsize
  };
  return _write((IWAL *) self, &wb, sizeof(wb), 0, 0);
}

static iwrc _onsynced(struct IWDLSNR *self, int flags) {
  IWAL *wal = (IWAL *) self;
  iwrc rc = _lock(wal);
  RCRET(rc);
  rc = _flush_lk(wal, true);
  IWRC(_unlock(wal), rc);
  return rc;
}

static bool _need_checkpoint(IWAL *wal) {
  // TODO:
  return true;
}

iwrc iwal_checkpoint(IWKV iwkv, bool force) {
  IWAL *wal = (IWAL *) iwkv->dlsnr;
  if (!wal) {
    return 0;
  }
  assert(iwkv == wal->iwkv);
  bool ncp = _need_checkpoint(wal);
  if (!ncp && force) {
    return 0;
  }
  iwrc rc = _flush_lk(wal, true);
  RCRET(rc);

  IWFS_FSM_STATE fst;
  rc = iwkv->fsm.state(&iwkv->fsm, &fst);
  RCRET(rc);

  int rci = 0;
  size_t psize = iwp_page_size();
  off_t fsize = fst.exfile.fsize;
  HANDLE fh = fst.exfile.file.fh;
  assert(!(fsize & (psize - 1)));
  uint8_t *mm = mmap(0, fsize, PROT_WRITE, MAP_SHARED, fh, 0);
  if (mm == MAP_FAILED) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
  // apply changes to main file
  // TODO:


  // sync
  rci = msync(mm, fsize, MS_SYNC);
  if (rci) {
    rc = iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
  munmap(mm, fsize);
  wal->mbytes = 0;
  IWRC(iwkv->fsm.remap_all(&iwkv->fsm), rc);
  if (!rc) {
    rc = _truncate(wal);
  }
  return rc;
}

iwrc _recover_lk(IWKV iwkv, IWAL *wal) {
  return 0;
}

iwrc iwal_close(IWKV iwkv) {
  IWAL *iwal = (IWAL *) iwkv->dlsnr;
  if (iwal) {
    _iwal_destroy(iwal);
  }
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

  wal->fh = INVALID_HANDLE_VALUE;
  wal->path = wpath;
  wal->oflags = opts->oflags;
  wal->iwkv = iwkv;

  rc = _init_locks(wal);
  RCGO(rc, finish);

  IWDLSNR *dlsnr = &wal->lsnr;
  dlsnr->onopen = _onopen;
  dlsnr->onclosed = _onclosed;
  dlsnr->onset = _onset;
  dlsnr->oncopy = _oncopy;
  dlsnr->onwrite = _onwrite;
  dlsnr->onresize = _onresize;
  dlsnr->onsynced = _onsynced;
  iwkv->dlsnr = (IWDLSNR *) wal;

  wal->wal_buffer_sz =
    opts->wal.wal_buffer_sz > 0 ?
    opts->wal.wal_buffer_sz  : 16 * 4096; // 64Kb
  if (wal->wal_buffer_sz < 4096) {
    wal->wal_buffer_sz = 4096;
  }

  wal->checkpoint_buffer_sz
    = opts->wal.checkpoint_buffer_sz > 0 ?
      opts->wal.checkpoint_buffer_sz : 1024 * 1024 * 32; // 32Mb

  wal->checkpoint_timeout_ms
    = opts->wal.checkpoint_timeout_ms > 0 ?
      opts->wal.checkpoint_timeout_ms : 60 * 1000; // 1 min

  wal->buf = malloc(wal->wal_buffer_sz);
  if (!wal->buf) {
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    goto finish;
  }
  wal->buf += sizeof(WBSEP);
  wal->bufsz -= sizeof(WBSEP);

  // Now force all fsm data to be privately mmaped.
  // We will apply wal log to main database file
  // then re-read our private mmaps
  fsmopts->mmap_all = true;
  fsmopts->mmap_opts = IWFS_MMAP_PRIVATE;
  fsmopts->exfile.file.dlsnr = iwkv->dlsnr;

  // Now open WAL file
  HANDLE fh = open(wal->path, O_CREAT | O_RDWR, IWFS_DEFAULT_FILEMODE);
  if (INVALIDHANDLE(fh)) {
    rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    goto finish;
  }
  wal->fh = fh;
  rc = iwp_flock(wal->fh, IWP_WLOCK);
  RCGO(rc, finish);

  if (wal->oflags & IWKV_TRUNC) {
    rc = iwp_ftruncate(wal->fh, 0);
    RCGO(rc, finish);
  }

  // Start recovery
  rc = _recover_lk(iwkv, wal);

finish:
  if (rc) {
    iwkv->dlsnr = 0;
    fsmopts->exfile.file.dlsnr = 0;
    fsmopts->mmap_opts = 0;
    _iwal_destroy(wal);
  }
  return rc;
}
