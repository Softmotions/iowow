#include "iwkv_internal.h"
#include "iwp.h"

#include <sys/types.h>
#include <fcntl.h>

typedef struct IWAL {
  IWDLSNR lsnr;
  iwkv_openflags oflags;            /**< File open flags */
  size_t wal_buffer_sz;             /**< WAL file intermediate buffer size */
  size_t checkpoint_buffer_sz;      /**< Checkpoint buffer size in bytes. */
  uint64_t checkpoint_timeout_ms;   /**< Checkpoint timeout millesconds */
  char *path;                       /**< WAL file path */
  uint8_t *buf;                     /**< File buffer */
  size_t bufsz;                     /**< Size of buffer */
  off_t bufpos;                     /**< Current position in buffer */
  off_t end;                        /**< WAL file end position */
  off_t mbytes;                     /**< Estimated size of modifed private mmaped memory bytes */
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

iwrc iwal_close(IWKV iwkv) {
  IWAL *iwal = (IWAL *) iwkv->dlsnr;
  if (iwal) {
    _iwal_destroy(iwal);
  }
  return 0;
}

iwrc iwal_sync(IWKV iwkv) {
  return 0;
}

iwrc iwal_checkpoint(IWKV iwkv, bool force) {
  return 0;
}

iwrc _recover_lk(IWKV iwkv, IWAL *wal) {
  return 0;
}

iwrc _onopen(struct IWDLSNR *self, const char *path, int mode) {
  return 0;
}

iwrc _onclosed(struct IWDLSNR *self, const char *path) {
  return 0;
}

iwrc _onset(struct IWDLSNR *self, off_t off, uint8_t val, uint64_t len, int flags) {
  return 0;
}

iwrc _oncopy(struct IWDLSNR *self, off_t off, uint64_t len, off_t noff, int flags) {
  return 0;
}

iwrc _onwrite(struct IWDLSNR *self, off_t off, const void *buf, uint64_t len, int flags) {
  return 0;
}

iwrc _onresize(struct IWDLSNR *self, uint64_t osize, uint64_t nsize, int flags) {
  return 0;
}

iwrc _onsynced(struct IWDLSNR *self, int flags) {
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
  char *wpath = malloc(sz + 4 /*-wal*/ + 1);
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

  // Start recovery procedure
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
