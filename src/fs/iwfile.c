/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2018 Softmotions Ltd <info@softmotions.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *************************************************************************************************/

#include "iwcfg.h"
#include "log/iwlog.h"
#include "platform/iwp.h"
#include "iwfile.h"
#include "iwutils.h"

#include <fcntl.h>
#include <limits.h>
#include <unistd.h>

typedef struct IWFS_FILE_IMPL {
  HANDLE fh;               /**< File handle. */
  iwfs_openstatus ostatus; /**< File open status. */
  IWFS_FILE_OPTS opts;     /**< File open options. */
} IWF;

static iwrc _iwfs_write(struct IWFS_FILE *f, off_t off, const void *buf, size_t siz, size_t *sp) {
  assert(f);
  IWF *impl = f->impl;
  if (!impl) {
    return IW_ERROR_INVALID_STATE;
  }
  if (!(impl->opts.omode & IWFS_OWRITE)) {
    return IW_ERROR_READONLY;
  }
  iwrc rc = iwp_write(impl->fh, off, buf, siz, sp);
  if (!rc && impl->opts.dlsnr) {
    rc = impl->opts.dlsnr->onwrite(impl->opts.dlsnr, off, buf, siz, 0);
  }
  return rc;
}

static iwrc _iwfs_read(struct IWFS_FILE *f, off_t off, void *buf, size_t siz, size_t *sp) {
  assert(f);
  IWF *impl = f->impl;
  if (!impl) {
    return IW_ERROR_INVALID_STATE;
  }
  return iwp_read(impl->fh, off, buf, siz, sp);
}

static iwrc _iwfs_close(struct IWFS_FILE *f) {
  if (!f || !f->impl) {
    return 0;
  }
  iwrc rc = 0;
  IWF *impl = f->impl;
  IWFS_FILE_OPTS *opts = &impl->opts;
  if (opts->lock_mode != IWP_NOLOCK) {
    IWRC(iwp_unlock(impl->fh), rc);
  }
  IWRC(iwp_closefh(impl->fh), rc);
  if (opts->path) {
    free((char *) opts->path);
    opts->path = 0;
  }
  free(f->impl);
  f->impl = 0;
  return rc;
}

static iwrc _iwfs_sync(struct IWFS_FILE *f, iwfs_sync_flags flags) {
  assert(f);
  iwrc rc = 0;
  if (!f->impl) {
    return IW_ERROR_INVALID_STATE;
  }
  IWF *impl = f->impl;
  if (flags & IWFS_FDATASYNC) {
#ifdef __APPLE__
    if (fcntl(wf->fh, F_FULLFSYNC) == -1) {
      return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    }
#else
    if (fdatasync(impl->fh) == -1) {
      return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    }
#endif
  } else if (fsync(impl->fh) == -1) {
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
  if (impl->opts.dlsnr) {
    rc = impl->opts.dlsnr->onsynced(impl->opts.dlsnr, 0);
  }
  return rc;
}

static iwrc _iwfs_state(struct IWFS_FILE *f, IWFS_FILE_STATE *state) {
  assert(f);
  assert(state);
  memset(state, 0, sizeof(*state));
  IWF *impl = f->impl;
  state->is_open = !!impl;
  if (!state->is_open) {
    return 0;
  }
  state->ostatus = impl->ostatus;
  state->opts = impl->opts;
  state->fh = impl->fh;
  return 0;
}

static iwrc _iwfs_copy(struct IWFS_FILE *f, off_t off, size_t siz, off_t noff) {
  assert(f);
  IWF *impl = f->impl;
  if (!impl) {
    return IW_ERROR_INVALID_STATE;
  }
  if (!(impl->opts.omode & IWFS_OWRITE)) {
    return IW_ERROR_READONLY;
  }
  iwrc rc = iwp_copy_bytes(impl->fh, off, siz, noff);
  if (!rc && impl->opts.dlsnr) {
    rc = impl->opts.dlsnr->oncopy(impl->opts.dlsnr, off, siz, noff, 0);
  }
  return rc;
}

iwrc iwfs_file_open(IWFS_FILE *f, const IWFS_FILE_OPTS *_opts) {
  assert(f);
  assert(_opts && _opts->path);

  IWFS_FILE_OPTS *opts;
  IWF *impl;
  IWP_FILE_STAT fstat;
  iwfs_omode omode;
  iwrc rc;
  int mode;

  memset(f, 0, sizeof(*f));
  rc = iwfs_file_init();
  RCRET(rc);

  f->write = _iwfs_write;
  f->read = _iwfs_read;
  f->close = _iwfs_close;
  f->sync = _iwfs_sync;
  f->state = _iwfs_state;
  f->copy = _iwfs_copy;

  impl = f->impl = calloc(sizeof(IWF), 1);
  if (!impl) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  impl->opts = *_opts;
  opts = &impl->opts;

  if (opts->dlsnr) {
    IWDLSNR *l = opts->dlsnr;
    if (!l->onopen || !l->onclosed || !l->oncopy || !l->onresize ||
        !l->onset || !l->onsynced || !l->onwrite) {
      iwlog_ecode_error2(IW_ERROR_INVALID_ARGS, "Invalid 'opts->dlsnr' specified");
      return IW_ERROR_INVALID_ARGS;
    }
  }

  opts->path = strndup(_opts->path, PATH_MAX);
  if (!opts->path) {
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    goto finish;
  }

  if (!opts->lock_mode) {
    opts->lock_mode = IWFS_DEFAULT_LOCKMODE;
  }
  if (!opts->omode) {
    opts->omode = IWFS_DEFAULT_OMODE;
  }
  if (!opts->filemode) {
    opts->filemode = IWFS_DEFAULT_FILEMODE;
  }
  opts->omode |= IWFS_OREAD;
  if (opts->omode & IWFS_OTRUNC) {
    opts->omode |= IWFS_OWRITE;
    opts->omode |= IWFS_OCREATE;
  }
  if ((opts->omode & IWFS_OCREATE) || (opts->omode & IWFS_OTRUNC)) {
    opts->omode |= IWFS_OWRITE;
  }
  omode = opts->omode;

  if (!(opts->omode & IWFS_OWRITE) && (opts->lock_mode & IWP_WLOCK)) {
    opts->lock_mode &= ~IWP_WLOCK;
  }

  rc = iwp_fstat(opts->path, &fstat);
  if (!rc && !(opts->omode & IWFS_OTRUNC)) {
    impl->ostatus = IWFS_OPEN_EXISTING;
  } else {
    impl->ostatus = IWFS_OPEN_NEW;
  }
  rc = 0;
  mode = O_RDONLY;
  if (omode & IWFS_OWRITE) {
    mode = O_RDWR;
    if (omode & IWFS_OCREATE)
      mode |= O_CREAT;
    if (omode & IWFS_OTRUNC)
      mode |= O_TRUNC;
  }
  impl->fh = open(opts->path, mode, opts->filemode);
  if (INVALIDHANDLE(impl->fh)) {
    rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    goto finish;
  }
  if (opts->lock_mode != IWP_NOLOCK) {
    rc = iwp_flock(impl->fh, opts->lock_mode);
    RCGO(rc, finish);
  }
finish:
  if (rc) {
    impl->ostatus = IWFS_OPEN_FAIL;
    if (opts->path) {
      free((char *) opts->path);
    }
    f->impl = 0;
    free(impl);
  }
  return rc;
}

iwrc iwfs_file_init(void) {
  return iw_init();
}
