/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2019 Softmotions Ltd <info@softmotions.com>
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
#include "iwutils.h"
#include "iwlog.h"
#include "iwexfile.h"

#include <pthread.h>
#ifdef _WIN32
#include "win32/mman/mman.h"
#else
#include <sys/mman.h>
#endif

struct MMAPSLOT;
typedef struct IWFS_EXT_IMPL {
  IWFS_FILE file;            /**< Underlying file */
  uint64_t fsize;            /**< Current file size */
  uint64_t maxoff;           /**< Maximum allowed file offset. Unlimited if zero.
                                  If maximum offset is reached `IWFS_ERROR_MAXOFF` will be reported. */
  pthread_rwlock_t *rwlock;  /**< Thread RW lock */
  IW_EXT_RSPOLICY rspolicy;  /**< File resize policy function ptr */
  void *rspolicy_ctx;        /**< Custom opaque data for policy functions */
  struct MMAPSLOT *mmslots;  /**< Memory mapping slots */
  IWDLSNR *dlsnr;            /**< Data events listener */
  HANDLE fh;                 /**< File handle */
  size_t psize;              /**< System page size */
  bool use_locks;            /**< Use rwlocks to guard method access */
  iwfs_omode omode;          /**< File open mode */
} EXF;

typedef struct MMAPSLOT {
  off_t off;     /**< Offset to a memory mapped region */
  size_t len;    /**< Actual size of memory mapped region. */
  size_t maxlen; /**< Maximum length of memory mapped region */
  iwfs_ext_mmap_opts_t mmopts;
  struct MMAPSLOT *prev; /**< Previous mmap slot. */
  struct MMAPSLOT *next; /**< Next mmap slot. */
  uint8_t *mmap;          /**< Pointer to a mmaped address space
                               in the case if file data is memory mapped. */
} MMAPSLOT;

// For internal usage only
bool extfile_use_locks(IWFS_EXT *f, bool use_locks) {
  bool ret = f->impl->use_locks;
  f->impl->use_locks = use_locks;
  return ret;
}

IW_INLINE iwrc _exfile_wlock(IWFS_EXT *f) {
  struct IWFS_EXT_IMPL *impl = f->impl;
  if (impl) {
    if (!impl->use_locks) return 0;
    if (impl->rwlock) {
      int rv = pthread_rwlock_wrlock(impl->rwlock);
      return rv ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rv) : 0;
    }
  }
  return IW_ERROR_INVALID_STATE;
}

IW_INLINE iwrc _exfile_rlock(IWFS_EXT *f) {
  struct IWFS_EXT_IMPL *impl = f->impl;
  if (impl) {
    if (!impl->use_locks) return 0;
    if (impl->rwlock) {
      int rv = pthread_rwlock_rdlock(impl->rwlock);
      return rv ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rv) : 0;
    }
  }
  return IW_ERROR_INVALID_STATE;
}

IW_INLINE iwrc _exfile_unlock(IWFS_EXT *f) {
  struct IWFS_EXT_IMPL *impl = f->impl;
  if (impl) {
    if (!impl->use_locks) return 0;
    if (impl->rwlock) {
      int rv = pthread_rwlock_unlock(impl->rwlock);
      return rv ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rv) : 0;
    }
  }
  return IW_ERROR_INVALID_STATE;
}

IW_INLINE iwrc _exfile_unlock2(EXF *impl) {
  if (impl) {
    if (!impl->use_locks) return 0;
    if (impl->rwlock) {
      int rv = pthread_rwlock_unlock(impl->rwlock);
      return rv ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rv) : 0;
    }
  }
  return IW_ERROR_INVALID_STATE;
}

static iwrc _exfile_destroylocks(EXF *impl) {
  if (!impl) return IW_ERROR_INVALID_STATE;
  if (!impl->rwlock) return 0;
  int rv = pthread_rwlock_destroy(impl->rwlock);
  free(impl->rwlock);
  impl->rwlock = 0;
  return rv ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rv) : 0;
}

static iwrc _exfile_initmmap_slot_lw(struct IWFS_EXT *f, MMAPSLOT *s) {
  assert(f && s);
  size_t nlen;
  EXF *impl = f->impl;
  if (s->off >= impl->fsize) {
    nlen = 0;
  } else {
    nlen = MIN(s->maxlen, impl->fsize - s->off);
  }
  if (nlen == s->len) {
    return 0;
  }
  if (s->len) {  // unmap me first
    assert(s->mmap);
    if (!(s->mmopts & IWFS_MMAP_PRIVATE) && msync(s->mmap, s->len, 0) == -1) {
      s->len = 0;
      return iwrc_set_errno(IW_ERROR_ERRNO, errno);
    }
    if (munmap(s->mmap, s->len) == -1) {
      s->len = 0;
      return iwrc_set_errno(IW_ERROR_ERRNO, errno);
    }
    s->len = 0;
  }
  if (nlen > 0) {
    int flags = (s->mmopts & IWFS_MMAP_PRIVATE)
#ifdef MAP_NORESERVE
                ? (MAP_PRIVATE + MAP_NORESERVE)
#else
                ? MAP_PRIVATE
#endif
                : MAP_SHARED;
    int prot = (impl->omode & IWFS_OWRITE) ? (PROT_WRITE + PROT_READ) : (PROT_READ);
    s->len = nlen;
    s->mmap = mmap(0, s->len, prot, flags, impl->fh, s->off);
    if (s->mmap == MAP_FAILED) {
      iwrc rc = iwrc_set_errno(IW_ERROR_ERRNO, errno);
      iwlog_ecode_error3(rc);
      return rc;
    }
  }
  return 0;
}

static iwrc _exfile_initmmap_lw(struct IWFS_EXT *f) {
  assert(f);
  iwrc rc = 0;
  EXF *impl = f->impl;
  assert(!(impl->fsize & (impl->psize - 1)));
  MMAPSLOT *s = impl->mmslots;
  while (s) {
    rc = _exfile_initmmap_slot_lw(f, s);
    if (rc) {
      break;
    }
    s = s->next;
  }
  return rc;
}

static iwrc _exfile_truncate_lw(struct IWFS_EXT *f, off_t size) {
  assert(f && f->impl);
  iwrc rc = 0;
  EXF *impl = f->impl;
  iwfs_omode omode = impl->omode;
  uint64_t old_size = impl->fsize;
  bool rsh = false;
  if (impl->fsize == size) {
    return 0;
  }
  size = IW_ROUNDUP(size, impl->psize);
  if (old_size < size) {
    if (!(omode & IWFS_OWRITE)) {
      return IW_ERROR_READONLY;
    }
    if (impl->maxoff && size > impl->maxoff) {
      return IWFS_ERROR_MAXOFF;
    }
    if (impl->dlsnr) {
      rc = impl->dlsnr->onresize(impl->dlsnr, old_size, size, 0, &rsh);
      RCGO(rc, truncfail);
    }
    if (!rsh) {
      impl->fsize = (uint64_t) size;
      rc = iwp_fallocate(impl->fh, size);
      RCGO(rc, truncfail);
      rc = _exfile_initmmap_lw(f);
    }
  } else if (old_size > size) {
    if (!(omode & IWFS_OWRITE)) {
      return IW_ERROR_READONLY;
    }
    if (impl->dlsnr) {
      rc = impl->dlsnr->onresize(impl->dlsnr, old_size, size, 0, &rsh);
      RCGO(rc, truncfail);
    }
    if (!rsh) {
      impl->fsize = (uint64_t) size;
      rc = _exfile_initmmap_lw(f);
      RCGO(rc, truncfail);
      rc = iwp_ftruncate(impl->fh, size);
      RCGO(rc, truncfail);
    }
  }
  return rc;

truncfail:
  impl->fsize = old_size;
  IWRC(_exfile_initmmap_lw(f), rc);
  return rc;
}

IW_INLINE iwrc _exfile_ensure_size_lw(struct IWFS_EXT *f, off_t sz) {
  EXF *impl = f->impl;
  assert(impl && impl->rspolicy);
  if (impl->fsize >= sz) {
    return 0;
  }
  off_t nsz = impl->rspolicy(sz, impl->fsize, f, &impl->rspolicy_ctx);
  if (nsz < sz || ((uint64_t) nsz & (impl->psize - 1))) {
    return IWFS_ERROR_RESIZE_POLICY_FAIL;
  }
  if (impl->maxoff && nsz > impl->maxoff) {
    nsz = impl->maxoff;
    if (nsz < sz) {
      return IWFS_ERROR_MAXOFF;
    }
  }
  return _exfile_truncate_lw(f, nsz);
}

static iwrc _exfile_sync(struct IWFS_EXT *f, iwfs_sync_flags flags) {
  iwrc rc = _exfile_rlock(f);
  RCRET(rc);
  EXF *impl = f->impl;
  int mflags = MS_SYNC;
  MMAPSLOT *s = impl->mmslots;
  while (s) {
    if (s->mmap && s->mmap != MAP_FAILED
        && !(s->mmopts & IWFS_MMAP_PRIVATE)
        && msync(s->mmap, s->len, mflags) == -1) {
      rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    }
    s = s->next;
  }
  IWRC(impl->file.sync(&impl->file, flags), rc);
  IWRC(_exfile_unlock2(impl), rc);
  return rc;
}

static iwrc _exfile_write(struct IWFS_EXT *f, off_t off, const void *buf, size_t siz, size_t *sp) {
  MMAPSLOT *s;
  EXF *impl = f->impl;
  off_t end = off + siz;
  off_t wp = siz, len;

  *sp = 0;
  if (off < 0 || end < 0) {
    return IW_ERROR_OUT_OF_BOUNDS;
  }
  if (impl->maxoff && off + siz > impl->maxoff) {
    return IWFS_ERROR_MAXOFF;
  }
  iwrc rc = _exfile_rlock(f);
  RCRET(rc);
  if (end > impl->fsize) {
    rc = _exfile_unlock2(impl);
    RCGO(rc, end);
    rc = _exfile_wlock(f);
    RCGO(rc, end);
    if (end > impl->fsize) {
      rc = _exfile_ensure_size_lw(f, end);
      RCGO(rc, finish);
    }
  }
  s = impl->mmslots;
  while (s && wp > 0) {
    if (!s->len || wp + off <= s->off) {
      break;
    }
    if (s->off > off) {
      len = MIN(wp, s->off - off);
      rc = impl->file.write(&impl->file, off, (const char *) buf + (siz - wp), (size_t) len, sp);
      RCGO(rc, finish);
      wp = wp - *sp;
      off = off + *sp;
    }
    if (wp > 0 && s->off <= off && s->off + s->len > off) {
      len = MIN(wp, s->off + s->len - off);
      memcpy(s->mmap + (off - s->off), (const char *) buf + (siz - wp), (size_t) len);
      if (impl->dlsnr) {
        rc = impl->dlsnr->onwrite(impl->dlsnr, off - s->off, (const char *) buf + (siz - wp), len, 0);
        RCGO(rc, finish);
      }
      wp -= len;
      off += len;
    }
    s = s->next;
  }
  if (wp > 0) {
    rc = impl->file.write(&impl->file, off, (const char *) buf + (siz - wp), (size_t) wp, sp);
    RCGO(rc, finish);
    wp = wp - *sp;
  }
  *sp = siz - wp;
finish:
  IWRC(_exfile_unlock2(impl), rc);
end:
  if (rc) {
    *sp = 0;
  }
  return rc;
}

static iwrc _exfile_read(struct IWFS_EXT *f, off_t off, void *buf, size_t siz, size_t *sp) {
  MMAPSLOT *s;
  EXF *impl;
  off_t end = off + siz;
  off_t rp = siz, len;
  *sp = 0;
  if (off < 0 || end < 0) {
    return IW_ERROR_OUT_OF_BOUNDS;
  }
  iwrc rc = _exfile_rlock(f);
  RCRET(rc);
  impl = f->impl;
  s = impl->mmslots;
  if (end > impl->fsize) {
    siz = (size_t) (impl->fsize - off);
    rp = siz;
  }
  while (s && rp > 0) {
    if (!s->len || rp + off <= s->off) {
      break;
    }
    if (s->off > off) {
      len = MIN(rp, s->off - off);
      rc = impl->file.read(&impl->file, off, (char *) buf + (siz - rp), (size_t) len, sp);
      RCGO(rc, finish);
      rp = rp - *sp;
      off = off + *sp;
    }
    if (rp > 0 && s->off <= off && s->off + s->len > off) {
      len = MIN(rp, s->off + s->len - off);
      memcpy((char *) buf + (siz - rp), s->mmap + (off - s->off), (size_t) len);
      rp -= len;
      off += len;
    }
    s = s->next;
  }
  if (rp > 0) {
    rc = impl->file.read(&impl->file, off, (char *) buf + (siz - rp), (size_t) rp, sp);
    RCGO(rc, finish);
    rp = rp - *sp;
  }
  *sp = siz - rp;
finish:
  if (rc) {
    *sp = 0;
  }
  IWRC(_exfile_unlock2(impl), rc);
  return rc;
}

static iwrc _exfile_state(struct IWFS_EXT *f, IWFS_EXT_STATE *state) {
  iwrc rc = _exfile_rlock(f);
  RCRET(rc);
  EXF *xf = f->impl;
  IWRC(xf->file.state(&xf->file, &state->file), rc);
  state->fsize = f->impl->fsize;
  IWRC(_exfile_unlock(f), rc);
  return rc;
}

static iwrc _exfile_copy(struct IWFS_EXT *f, off_t off, size_t siz, off_t noff) {
  iwrc rc = _exfile_rlock(f);
  RCRET(rc);
  EXF *impl = f->impl;
  MMAPSLOT *s = impl->mmslots;
  if (s && s->mmap && s->off == 0 && s->len >= noff + siz) { // fully mmaped file
    rc = _exfile_ensure_size_lw(f, noff + siz);
    RCRET(rc);
    memmove(s->mmap + noff, s->mmap + off, siz);
    if (impl->dlsnr) {
      rc = impl->dlsnr->oncopy(impl->dlsnr, off, siz, noff, 0);
      RCRET(rc);
    }
  } else {
    IWRC(impl->file.copy(&impl->file, off, siz, noff), rc);
  }
  IWRC(_exfile_unlock(f), rc);
  return rc;
}

static iwrc _exfile_remove_mmap_wl(struct IWFS_EXT *f, off_t off) {
  iwrc rc = 0;
  EXF *impl = f->impl;
  MMAPSLOT *s = impl->mmslots;
  while (s) {
    if (s->off == off) {
      break;
    }
    s = s->next;
  }
  if (!s) {
    rc = IWFS_ERROR_NOT_MMAPED;
    goto finish;
  }
  if (impl->mmslots == s) {
    if (s->next) {
      s->next->prev = s->prev;
    }
    impl->mmslots = s->next;
  } else if (impl->mmslots->prev == s) {
    s->prev->next = 0;
    impl->mmslots->prev = s->prev;
  } else {
    s->prev->next = s->next;
    s->next->prev = s->prev;
  }
  if (s->len) {
    if (munmap(s->mmap, s->len)) {
      rc = iwrc_set_errno(IW_ERROR_ERRNO, errno);
      goto finish;
    }
  }
finish:
  free(s);
  return rc;
}

static iwrc _exfile_close(struct IWFS_EXT *f) {
  if (!f || !f->impl) {
    return 0;
  }
  iwrc rc = _exfile_wlock(f);
  RCRET(rc);
  EXF *impl = f->impl;
  if (impl->dlsnr) {
    rc = impl->dlsnr->onclosing(impl->dlsnr);
  }
  MMAPSLOT *s = impl->mmslots, *next;
  while (s) {
    next = s->next;
    IWRC(_exfile_remove_mmap_wl(f, s->off), rc);
    s = next;
  }
  IWRC(impl->file.close(&impl->file), rc);
  f->impl = 0;
  if (impl->rspolicy) {  // dispose resize policy function
    impl->rspolicy(-1, impl->fsize, f, &impl->rspolicy_ctx);
  }
  IWRC(_exfile_unlock2(impl), rc);
  IWRC(_exfile_destroylocks(impl), rc);
  free(impl);
  return rc;
}

static iwrc _exfile_ensure_size(struct IWFS_EXT *f, off_t sz) {
  iwrc rc = _exfile_rlock(f);
  RCRET(rc);
  if (f->impl->fsize >= sz) {
    return _exfile_unlock2(f->impl);
  }
  rc = _exfile_unlock2(f->impl);
  RCRET(rc);
  rc = _exfile_wlock(f);
  RCRET(rc);
  rc = _exfile_ensure_size_lw(f, sz);
  IWRC(_exfile_unlock2(f->impl), rc);
  return rc;
}

static iwrc _exfile_truncate(struct IWFS_EXT *f, off_t sz) {
  iwrc rc = _exfile_wlock(f);
  RCRET(rc);
  rc = _exfile_truncate_lw(f, sz);
  IWRC(_exfile_unlock(f), rc);
  return rc;
}

static iwrc _exfile_add_mmap(struct IWFS_EXT *f, off_t off, size_t maxlen, iwfs_ext_mmap_opts_t mmopts) {
  assert(f && off >= 0);
  iwrc rc;
  size_t tmp;
  MMAPSLOT *ns = 0;

  rc = _exfile_wlock(f);
  RCRET(rc);
  EXF *impl = f->impl;
  if ((uint64_t) off & (impl->psize - 1)) {
    rc = IW_ERROR_NOT_ALIGNED;
    goto finish;
  }
  if (OFF_T_MAX - off < maxlen) {
    maxlen = (size_t) (OFF_T_MAX - off);
  }
  tmp = IW_ROUNDUP(maxlen, impl->psize);
  if (tmp < maxlen || OFF_T_MAX - off < tmp) {
    maxlen = IW_ROUNDOWN(maxlen, impl->psize);
  } else {
    maxlen = tmp;
  }
  if (!maxlen) {
    rc = IW_ERROR_OUT_OF_BOUNDS;
    goto finish;
  }
  assert(!(maxlen & (impl->psize - 1)));
  ns = calloc(1, sizeof(*ns));
  if (!ns) {
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    goto finish;
  }
  ns->off = off;
  ns->len = 0;
  ns->maxlen = maxlen;
  ns->mmopts = mmopts;
  rc = _exfile_initmmap_slot_lw(f, ns);
  RCGO(rc, finish);
  if (impl->mmslots == 0) {
    ns->next = 0;
    ns->prev = ns;
    impl->mmslots = ns;
  } else {
    MMAPSLOT *s = impl->mmslots;
    while (s) {
      off_t e1 = s->off + s->maxlen;
      off_t e2 = ns->off + ns->maxlen;
      if (IW_RANGES_OVERLAP(s->off, e1, ns->off, e2)) {
        rc = IWFS_ERROR_MMAP_OVERLAP;
        goto finish;
      }
      if (ns->off < s->off) {
        break;
      }
      s = s->next;
    }
    if (s) {  // insert before
      ns->next = s;
      ns->prev = s->prev;
      s->prev->next = ns;
      s->prev = ns;
      if (s == impl->mmslots) {
        impl->mmslots = ns;
        ns->prev->next = 0;
      }
    } else {  // insert at the end
      s = impl->mmslots;
      ns->next = 0;
      ns->prev = s->prev;
      s->prev->next = ns;
      s->prev = ns;
    }
  }
finish:
  if (rc) {
    if (ns) {
      if (impl->mmslots == ns) {
        impl->mmslots = 0;
      }
      free(ns);
    }
  }
  IWRC(_exfile_unlock(f), rc);
  return rc;
}

iwrc _exfile_acquire_mmap(struct IWFS_EXT *f, off_t off, uint8_t **mm, size_t *sp) {
  assert(f && mm && off >= 0);
  iwrc rc = _exfile_rlock(f);
  if (IW_UNLIKELY(rc)) {
    *mm = 0;
    if (sp) {
      *sp = 0;
    }
    return rc;
  }
  MMAPSLOT *s = f->impl->mmslots;
  while (s) {
    if (s->off == off) {
      if (s->len) {
        *mm = s->mmap;
        if (sp) {
          *sp = s->len;
        }
        return 0;
      }
      break;
    }
    s = s->next;
  }
  *mm = 0;
  if (sp) {
    *sp = 0;
  }
  return IWFS_ERROR_NOT_MMAPED;
}

iwrc _exfile_probe_mmap(struct IWFS_EXT *f, off_t off, uint8_t **mm, size_t *sp) {
  // todo remove code duplication
  assert(f && mm && off >= 0);
  if (sp) {
    *sp = 0;
  }
  *mm = 0;
  iwrc rc = _exfile_rlock(f);
  RCRET(rc);
  EXF *impl = f->impl;
  MMAPSLOT *s = impl->mmslots;
  while (s) {
    if (s->off == off) {
      if (!s->len) {
        rc = IWFS_ERROR_NOT_MMAPED;
        break;
      }
      *mm = s->mmap;
      if (sp) {
        *sp = s->len;
      }
      break;
    }
    s = s->next;
  }
  if (!rc && !*mm) {
    rc = IWFS_ERROR_NOT_MMAPED;
  }
  IWRC(_exfile_unlock2(impl), rc);
  return rc;
}

iwrc _exfile_release_mmap(struct IWFS_EXT *f) {
  assert(f);
  return _exfile_unlock(f);
}

static iwrc _exfile_remove_mmap(struct IWFS_EXT *f, off_t off) {
  assert(f && off >= 0);
  iwrc rc = _exfile_wlock(f);
  RCRET(rc);
  rc = _exfile_remove_mmap_wl(f, off);
  IWRC(_exfile_unlock(f), rc);
  return rc;
}

static iwrc _exfile_sync_mmap(struct IWFS_EXT *f, off_t off, iwfs_sync_flags flags) {
  assert(f && off >= 0);
  iwrc rc = _exfile_rlock(f);
  RCRET(rc);
  EXF *impl = f->impl;
  int mflags = MS_SYNC;
  MMAPSLOT *s = impl->mmslots;
  while (s) {
    if (s->off == off) {
      if (s->len == 0) {
        rc = IWFS_ERROR_NOT_MMAPED;
        break;
      }
      if (s->mmap && s->mmap != MAP_FAILED) {
        if (!(s->mmopts & IWFS_MMAP_PRIVATE)
            && msync(s->mmap, s->len, mflags) == -1) {
          rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
        }
        break;
      }
    }
    s = s->next;
  }
  if (!s) {
    rc = IWFS_ERROR_NOT_MMAPED;
  }
  IWRC(_exfile_unlock(f), rc);
  return rc;
}

static iwrc _exfile_remap_all(struct IWFS_EXT *f) {
  assert(f);
  iwrc rc = _exfile_rlock(f);
  RCRET(rc);
  rc = _exfile_initmmap_lw(f);
  IWRC(_exfile_unlock(f), rc);
  return rc;
}

static off_t _exfile_default_szpolicy(off_t nsize, off_t csize, struct IWFS_EXT *f, void **ctx) {
  if (nsize == -1) {
    return 0;
  }
  return IW_ROUNDUP(nsize, f->impl->psize);
}

off_t iw_exfile_szpolicy_fibo(off_t nsize, off_t csize, struct IWFS_EXT *f, void **_ctx) {
  struct _FIBO_CTX {
    off_t prev_sz;
  } *ctx = *_ctx;
  if (nsize == -1) {
    if (ctx) {
      free(ctx);
      *_ctx = 0;
    }
    return 0;
  }
  if (!ctx) {
    *_ctx = ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
      return _exfile_default_szpolicy(nsize, csize, f, _ctx);
    }
  }
  uint64_t res = (uint64_t) csize + ctx->prev_sz;
  res = MAX(res, nsize);
  res = IW_ROUNDUP(res, f->impl->psize);
  if (res > OFF_T_MAX) {
    res = OFF_T_MAX;
  }
  ctx->prev_sz = csize;
  return res;
}

off_t iw_exfile_szpolicy_mul(off_t nsize, off_t csize, struct IWFS_EXT *f, void **_ctx) {
  IW_RNUM *mul = *_ctx;
  if (nsize == -1) {
    return 0;
  }
  if (!mul || !mul->dn || mul->n < mul->dn) {
    iwlog_error2(
      "Invalid iw_exfile_szpolicy_mul context arguments, fallback to the "
      "default resize policy");
    return _exfile_default_szpolicy(nsize, csize, f, _ctx);
  }
  uint64_t ret = (uint64_t) nsize;
  ret /= mul->dn;
  ret *= mul->n;
  ret = IW_ROUNDUP(ret, f->impl->psize);
  if (ret > OFF_T_MAX) {
    ret = OFF_T_MAX;
  }
  return ret;
}

static iwrc _exfile_initlocks(IWFS_EXT *f) {
  assert(f && f->impl);
  assert(!f->impl->rwlock);
  EXF *impl = f->impl;
  if (!impl->use_locks) {
    return 0;
  }
  impl->rwlock = calloc(1, sizeof(*impl->rwlock));
  if (!impl->rwlock) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  int rv = pthread_rwlock_init(impl->rwlock, (void *) 0);
  if (rv) {
    free(impl->rwlock);
    impl->rwlock = 0;
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rv);
  }
  return 0;
}

iwrc iwfs_exfile_open(IWFS_EXT *f, const IWFS_EXT_OPTS *opts) {
  assert(f);
  assert(opts);
  iwrc rc = 0;
  const char *path = opts->file.path;

  memset(f, 0, sizeof(*f));

  rc = iwfs_exfile_init();
  RCGO(rc, finish);

  f->close = _exfile_close;
  f->read = _exfile_read;
  f->write = _exfile_write;
  f->sync = _exfile_sync;
  f->state = _exfile_state;
  f->copy =  _exfile_copy;

  f->ensure_size = _exfile_ensure_size;
  f->truncate = _exfile_truncate;
  f->add_mmap = _exfile_add_mmap;
  f->acquire_mmap = _exfile_acquire_mmap;
  f->probe_mmap = _exfile_probe_mmap;
  f->release_mmap = _exfile_release_mmap;
  f->remove_mmap = _exfile_remove_mmap;
  f->sync_mmap = _exfile_sync_mmap;
  f->remap_all = _exfile_remap_all;

  if (!path) {
    return IW_ERROR_INVALID_ARGS;
  }

  EXF *impl = f->impl = calloc(1, sizeof(EXF));
  if (!impl) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  impl->dlsnr = opts->file.dlsnr;
  impl->psize = iwp_alloc_unit();
  impl->rspolicy = opts->rspolicy ? opts->rspolicy : _exfile_default_szpolicy;
  impl->rspolicy_ctx = opts->rspolicy_ctx;
  impl->use_locks = opts->use_locks;
  if (opts->maxoff >= impl->psize) {
    impl->maxoff = IW_ROUNDOWN(opts->maxoff, impl->psize);
  }
  rc = _exfile_initlocks(f);
  RCGO(rc, finish);

  rc = iwfs_file_open(&impl->file, &opts->file);
  RCGO(rc, finish);

  IWFS_FILE_STATE state;
  rc = impl->file.state(&impl->file, &state);
  RCGO(rc, finish);

  IWP_FILE_STAT fstat;
  rc = iwp_fstat(state.opts.path, &fstat);
  RCGO(rc, finish);

  impl->fsize = fstat.size;

  IWFS_FILE_STATE fstate;
  rc = impl->file.state(&impl->file, &fstate);
  impl->omode = fstate.opts.omode;
  impl->fh = fstate.fh;

  if (impl->fsize < opts->initial_size) {
    rc = _exfile_truncate_lw(f, opts->initial_size);
  } else if ((uint64_t) impl->fsize & (impl->psize - 1)) {  // not a page aligned
    rc = _exfile_truncate_lw(f, impl->fsize);
  }
finish:
  if (rc) {
    if (f->impl) {
      _exfile_destroylocks(f->impl);
      free(f->impl);
      f->impl = 0;
    }
  }
  return rc;
}

static const char *_exfile_ecodefn(locale_t locale, uint32_t ecode) {
  if (!(ecode > _IWFS_EXT_ERROR_START && ecode < _IWFS_EXT_ERROR_END)) {
    return 0;
  }
  switch (ecode) {
    case IWFS_ERROR_MMAP_OVERLAP:
      return "Region is mmaped already, mmaping overlaps. "
             "(IWFS_ERROR_MMAP_OVERLAP)";
    case IWFS_ERROR_NOT_MMAPED:
      return "Region is not mmaped. (IWFS_ERROR_NOT_MMAPED)";
    case IWFS_ERROR_RESIZE_POLICY_FAIL:
      return "Invalid result of resize policy function. "
             "(IWFS_ERROR_RESIZE_POLICY_FAIL)";
    case IWFS_ERROR_MAXOFF:
      return "Maximum file offset reached. (IWFS_ERROR_MAXOFF)";
    default:
      break;
  }
  return 0;
}

iwrc iwfs_exfile_init(void) {
  static int _exfile_initialized = 0;
  iwrc rc = iw_init();
  RCRET(rc);
  if (!__sync_bool_compare_and_swap(&_exfile_initialized, 0, 1)) {
    return 0;  // initialized already
  }
  return iwlog_register_ecodefn(_exfile_ecodefn);
}
