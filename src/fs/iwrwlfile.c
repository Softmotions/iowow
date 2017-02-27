// clang-format off
/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2017 Softmotions Ltd <info@softmotions.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
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
// clang-format on

#include "iwrwlfile.h"
#include "utils/iwrlock.h"
#include "iwcfg.h"

typedef struct IWFS_RWL_IMPL {
  IWFS_EXT exfile; /**< Underlying exfile */
  IWRLOCK *lk;     /**< Address range lock */
} _RWL;

#define _RWL_ENSURE_OPEN(f)                                                                                  \
  if (!f || !f->impl || !f->impl->lk)                                                                        \
    return IW_ERROR_INVALID_STATE;

static iwrc _rwl_write(struct IWFS_RWL *f, off_t off, const void *buf, size_t siz, size_t *sp) {
  assert(f);
  _RWL_ENSURE_OPEN(f);
  return f->impl->exfile.write(&f->impl->exfile, off, buf, siz, sp);
}

static iwrc _rwl_read(struct IWFS_RWL *f, off_t off, void *buf, size_t siz, size_t *sp) {
  assert(f);
  _RWL_ENSURE_OPEN(f);
  return f->impl->exfile.read(&f->impl->exfile, off, buf, siz, sp);
}

static iwrc _rwl_sync(struct IWFS_RWL *f, iwfs_sync_flags flags) {
  assert(f);
  _RWL_ENSURE_OPEN(f);
  return f->impl->exfile.sync(&f->impl->exfile, flags);
}

static iwrc _rwl_state(struct IWFS_RWL *f, IWFS_RWL_STATE *state) {
  assert(f);
  _RWL_ENSURE_OPEN(f);
  iwrc rc = 0;
  IWRC(f->impl->exfile.state(&f->impl->exfile, &state->exfile), rc);
  IWRC(iwrl_num_ranges(f->impl->lk, &state->num_ranges), rc);
  IWRC(iwrl_write_ranges(f->impl->lk, &state->num_write_ranges), rc);
  return rc;
}

static iwrc _rwl_ensure_size(struct IWFS_RWL *f, off_t size) {
  _RWL_ENSURE_OPEN(f);
  return f->impl->exfile.ensure_size(&f->impl->exfile, size);
}

static iwrc _rwl_truncate(struct IWFS_RWL *f, off_t size) {
  _RWL_ENSURE_OPEN(f);
  return f->impl->exfile.truncate(&f->impl->exfile, size);
}

static iwrc _rwl_add_mmap(struct IWFS_RWL *f, off_t off, size_t maxlen) {
  _RWL_ENSURE_OPEN(f);
  return f->impl->exfile.add_mmap(&f->impl->exfile, off, maxlen);
}

static iwrc _rwl_get_mmap(struct IWFS_RWL *f, off_t off, uint8_t **mm, size_t *sp) {
  _RWL_ENSURE_OPEN(f);
  return f->impl->exfile.get_mmap(&f->impl->exfile, off, mm, sp);
}

static iwrc _rwl_remove_mmap(struct IWFS_RWL *f, off_t off) {
  _RWL_ENSURE_OPEN(f);
  return f->impl->exfile.remove_mmap(&f->impl->exfile, off);
}

static iwrc _rwl_sync_mmap(struct IWFS_RWL *f, off_t off, int flags) {
  _RWL_ENSURE_OPEN(f);
  return f->impl->exfile.sync_mmap(&f->impl->exfile, off, flags);
}

static iwrc _rwl_lock(struct IWFS_RWL *f, off_t off, off_t len, iwrl_lockflags lflags) {
  _RWL_ENSURE_OPEN(f);
  return iwrl_lock(f->impl->lk, off, len, lflags);
}

static iwrc _rwl_try_lock(struct IWFS_RWL *f, off_t off, off_t len, iwrl_lockflags lflags) {
  _RWL_ENSURE_OPEN(f);
  return iwrl_trylock(f->impl->lk, off, len, lflags);
}

static iwrc _rwl_unlock(struct IWFS_RWL *f, off_t off, off_t len) {
  _RWL_ENSURE_OPEN(f);
  return iwrl_unlock(f->impl->lk, off, len);
}

static iwrc _rwl_lwrite(struct IWFS_RWL *f, off_t off, const void *buf, size_t siz, size_t *sp) {
  _RWL_ENSURE_OPEN(f);
  iwrc rc = iwrl_lock(f->impl->lk, off, siz, IWRL_WRITE);
  if (rc) {
    return rc;
  }
  IWRC(f->impl->exfile.write(&f->impl->exfile, off, buf, siz, sp), rc);
  IWRC(iwrl_unlock(f->impl->lk, off, siz), rc);
  return rc;
}

static iwrc _rwl_lread(struct IWFS_RWL *f, off_t off, void *buf, size_t siz, size_t *sp) {
  _RWL_ENSURE_OPEN(f);
  iwrc rc = iwrl_lock(f->impl->lk, off, siz, IWRL_READ);
  if (rc) {
    return rc;
  }
  IWRC(f->impl->exfile.read(&f->impl->exfile, off, buf, siz, sp), rc);
  IWRC(iwrl_unlock(f->impl->lk, off, siz), rc);
  return rc;
}

static iwrc _rwl_close(struct IWFS_RWL *f) {
  iwrc rc = 0;
  _RWL_ENSURE_OPEN(f);
  _RWL *impl = f->impl;
  IWRC(impl->exfile.close(&impl->exfile), rc);
  IWRC(iwrl_destroy(impl->lk), rc);
  f->impl->lk = 0;
  f->impl = 0;
  free(impl);
  return rc;
}

iwrc iwfs_rwlfile_open(IWFS_RWL *f, const IWFS_RWL_OPTS *opts) {
  assert(f);
  assert(opts);
  iwrc rc = 0;
  const char *path = opts->exfile.file.path;
  
  memset(f, 0, sizeof(*f));
  
  f->write = _rwl_write;
  f->read = _rwl_read;
  f->close = _rwl_close;
  f->sync = _rwl_sync;
  f->state = _rwl_state;
  
  f->ensure_size = _rwl_ensure_size;
  f->truncate = _rwl_truncate;
  f->add_mmap = _rwl_add_mmap;
  f->get_mmap = _rwl_get_mmap;
  f->remove_mmap = _rwl_remove_mmap;
  f->sync_mmap = _rwl_sync_mmap;
  
  f->lock = _rwl_lock;
  f->try_lock = _rwl_try_lock;
  f->unlock = _rwl_unlock;
  f->lwrite = _rwl_lwrite;
  f->lread = _rwl_lread;
  
  if (!path) {
    return IW_ERROR_INVALID_ARGS;
  }
  
  _RWL *impl = f->impl = calloc(1, sizeof(*f->impl));
  if (!impl) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  
  rc = iwfs_exfile_open(&impl->exfile, &opts->exfile);
  if (rc) {
    goto finish;
  }
  rc = iwrl_new(&impl->lk);
  if (rc) {
    goto finish;
  }
  
finish:
  if (rc) {
    if (f->impl) {
      if (f->impl->lk) {
        iwrl_destroy(f->impl->lk);
        f->impl->lk = 0;
      }
      free(f->impl);
      f->impl = 0;
    }
  }
  return rc;
}

iwrc iwfs_rwlfile_init(void) {
  return 0;
}
