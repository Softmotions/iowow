#include "iwkv_internal.h"
#include "iwp.h"

#include <sys/types.h>
#include <fcntl.h>

typedef enum {
  WOP_SEP = 1, /**< WAL file separator */
  WOP_SET,
  WOP_COPY,
  WOP_WRITE,
  WOP_RESIZE
} wop_t;

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
} IWAL;

IW_INLINE iwrc _lock(IWAL *wal) {
  int rci = wal->mtx ? pthread_mutex_lock(wal->mtx) : 0;
  return (rci ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci) : 0);
}

IW_INLINE iwrc _unlock(IWAL *wal) {
  int rci = wal->mtx ? pthread_mutex_unlock(wal->mtx) : 0;
  return (rci ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci) : 0);
}

iwrc _init_locks(IWAL *wal) {
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

iwrc _destroy_locks(IWAL *wal) {
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

void _iwal_destroy(IWAL *wal) {
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
      free(wal->buf);
    }
    free(wal);
  }
}

iwrc _flush_lk(IWAL *wal, bool sync) {
  if (wal->bufpos) {
    uint8_t sep[1 + sizeof(wal->bufpos) + sizeof(uint32_t)];
    uint32_t crc = iwu_crc32(wal->buf, wal->bufpos, 0);
    uint8_t *wp = sep;
    *wp = WOP_SEP;
    ++wp;
    memcpy(wp, &wal->bufpos, sizeof(wal->bufpos));
    wp += sizeof(wal->bufpos);
    memcpy(wp, &crc, sizeof(crc));

    ssize_t sz = write(wal->fh, sep, sizeof(sep));
    if (sz != sizeof(sep)) {
      return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    }
    sz = write(wal->fh, wal->buf, wal->bufpos);
    if (sz != wal->bufpos) {
      return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    }
    wal->bufpos = 0;
  }
  if (sync && fsync(wal->fh)) {
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
  return 0;
}

iwrc _write(IWAL *wal, const uint8_t *op, off_t oplen, const uint8_t *data, off_t len) {
  iwrc rc = _lock(wal);
  RCRET(rc);
  const off_t bufsz = wal->bufsz;
  const uint8_t *wp = data;
  uint8_t *buf = wal->buf;
  if (bufsz - wal->bufpos < oplen) {
    rc = _flush_lk(wal, false);
    RCGO(rc, finish);
  }
  assert(bufsz - wal->bufpos >= oplen);
  memcpy(buf + wal->bufpos, op, oplen);
  wal->bufpos += oplen;
  while (len > 0) {
    off_t wlen = MIN(bufsz - wal->bufpos, len);
    if (!wlen) {
      rc = _flush_lk(wal, false);
      RCGO(rc, finish);
      wlen = MIN(bufsz - wal->bufpos, len);
    }
    memcpy(buf, wp, wlen);
    wal->bufpos += wlen;
    wp += wlen;
    len -= wlen;
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

iwrc _onopen(struct IWDLSNR *self, const char *path, int mode) {
  return 0;
}

iwrc _onclosed(struct IWDLSNR *self, const char *path) {
  return 0;
}

iwrc _onset(struct IWDLSNR *self, off_t off, uint8_t val, off_t len, int flags) {
  uint8_t obuf[1 + sizeof(off) + sizeof(val) + sizeof(len)];
  uint8_t *wp = obuf;
  *wp = WOP_SET;
  ++wp;
  memcpy(wp, &off, sizeof(off));
  wp += sizeof(off);
  memcpy(wp, &val, sizeof(val));
  wp += sizeof(val);
  memcpy(wp, &len, sizeof(len));
  return _write((IWAL*) self, obuf, sizeof(obuf), 0, 0);
}

iwrc _oncopy(struct IWDLSNR *self, off_t off, off_t len, off_t noff, int flags) {
  uint8_t obuf[1 + sizeof(off) + sizeof(len) + sizeof(noff)];
  uint8_t *wp = obuf;
  *wp = WOP_COPY;
  ++wp;
  memcpy(wp, &off, sizeof(off));
  wp += sizeof(off);
  memcpy(wp, &len, sizeof(len));
  wp += sizeof(len);
  memcpy(wp, &noff, sizeof(noff));
  return _write((IWAL*) self, obuf, sizeof(obuf), 0, 0);
}

iwrc _onwrite(struct IWDLSNR *self, off_t off, const void *buf, off_t len, int flags) {
  uint8_t obuf[1 + sizeof(len)];
  uint8_t *wp = obuf;
  *wp = WOP_WRITE;
  ++wp;
  memcpy(wp, &len, sizeof(len));
  return _write((IWAL*) self, obuf, sizeof(obuf), buf, len);
}

iwrc _onresize(struct IWDLSNR *self, off_t osize, off_t nsize, int flags) {
  uint8_t obuf[1 + sizeof(osize) + sizeof(nsize)];
  uint8_t *wp = obuf;
  *wp = WOP_RESIZE;
  ++wp;
  memcpy(wp, &osize, sizeof(osize));
  wp += sizeof(osize);
  memcpy(wp, &nsize, sizeof(nsize));
  return _write((IWAL*) self, obuf, sizeof(obuf), 0, 0);
}

iwrc _onsynced(struct IWDLSNR *self, int flags) {
  return 0;
}

iwrc iwal_checkpoint(IWKV iwkv, bool force) {
  return 0;
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
  if (opts->oflags & IWKV_RDONLY) {
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
