/**************************************************************************************************
 *  IOWOW library
 *  Copyright (C) 2012-2015 Softmotions Ltd <info@softmotions.com>
 *
 *  This file is part of IOWOW.
 *  IOWOW is free software; you can redistribute it and/or modify it under the terms of
 *  the GNU Lesser General Public License as published by the Free Software Foundation; either
 *  version 2.1 of the License or any later version. IOWOW is distributed in the hope
 *  that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 *  License for more details.
 *  You should have received a copy of the GNU Lesser General Public License along with IOWOW;
 *  if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 *  Boston, MA 02111-1307 USA.
 *************************************************************************************************/

#include "iwexfile.h"
#include "log/iwlog.h"
#include "iwcfg.h"

#include <pthread.h>
#include <sys/mman.h>

struct _MMAPSLOT;
typedef struct IWFS_EXT_IMPL {
    IWFS_FILE           file;           /**< Underlying file */
    off_t               fsize;          /**< Current file size */
    off_t               psize;          /**< System page size */
    pthread_rwlock_t    *rwlock;        /**< Thread RW lock */
    IW_EXT_RSPOLICY     rspolicy;       /**< File resize policy function ptr. */
    void                *rspolicy_ctx;  /**< Custom opaque data for policy functions. */
    struct _MMAPSLOT    *mmslots;       /**< Memory mapping slots. */
    int                 use_locks;      /**< Use rwlocks to guard method access */
    iwfs_omode          omode;          /**< File open mode. */
    HANDLE              fh;             /**< File handle */
} _EXF;

typedef struct _MMAPSLOT {
    off_t   off;                /**< Offset to a memory mapped region */
    size_t  len;                /**< Actual size of memory mapped region. */
    size_t  maxlen;             /**< Maximum length of memory mapped region */
#ifdef _WIN32
    HANDLE mmapfh;              /**< Win32 file mapping handle. */
#endif
    struct _MMAPSLOT *prev;    /**< Previous mmap slot. */
    struct _MMAPSLOT *next;    /**< Next mmap slot. */
    uint8_t          *mmap;    /**< Pointer to a mmaped address space in the case if file data is memory mapped. */
} _MMAPSLOT;

IW_INLINE iwrc _exfile_wlock(IWFS_EXT *f) {
    assert(f);
    if (!f->impl) return IW_ERROR_INVALID_STATE;
    if (!f->impl->use_locks) return 0;
    if (!f->impl->rwlock) return IW_ERROR_INVALID_STATE;
    int rv = pthread_rwlock_wrlock(f->impl->rwlock);
    return rv ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rv) : 0;
}

IW_INLINE iwrc _exfile_rlock(IWFS_EXT *f) {
    assert(f);
    if (!f->impl) return IW_ERROR_INVALID_STATE;
    if (!f->impl->use_locks) return 0;
    if (!f->impl->rwlock) return IW_ERROR_INVALID_STATE;
    int rv = pthread_rwlock_rdlock(f->impl->rwlock);
    return rv ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rv) : 0;
}

IW_INLINE iwrc _exfile_unlock(IWFS_EXT *f) {
    assert(f);
    if (!f->impl) return IW_ERROR_INVALID_STATE;
    if (!f->impl->use_locks) return 0;
    if (!f->impl->rwlock) return IW_ERROR_INVALID_STATE;
    int rv = pthread_rwlock_unlock(f->impl->rwlock);
    return rv ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rv) : 0;
}

IW_INLINE iwrc _exfile_unlock2(_EXF *impl) {
    if (!impl) return IW_ERROR_INVALID_STATE;
    if (!impl->use_locks) return 0;
    if (!impl->rwlock) return IW_ERROR_INVALID_STATE;
    int rv = pthread_rwlock_unlock(impl->rwlock);
    return rv ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rv) : 0;
}

static iwrc _exfile_destroylocks(_EXF *impl) {
    if (!impl) return IW_ERROR_INVALID_STATE;
    if (!impl->rwlock) return 0;
    int rv = pthread_rwlock_destroy(impl->rwlock);
    free(impl->rwlock);
    impl->rwlock = 0;
    return rv ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rv) : 0;
}

static iwrc _exfile_initmmap_slot_lw(struct IWFS_EXT *f, _MMAPSLOT *s) {
    assert(f && s);
    size_t nlen;
    _EXF *impl = f->impl;
    if (s->off >= impl->fsize) {
        nlen = 0;
    } else {
        nlen = MIN(s->maxlen, impl->fsize - s->off);
    }
    if (nlen == s->len) {
        return 0;
    }
    if (s->len) { // unmap me first
        assert(s->mmap);
        if (munmap(s->mmap, s->len) == -1) {
            s->len = 0;
            return iwrc_set_errno(IW_ERROR_ERRNO, errno);
        }
        s->len = 0;
    }
    if (nlen > 0) {
        int flags = MAP_SHARED;
        int prot = (impl->omode & IWFS_OWRITE) ? (PROT_WRITE | PROT_READ) : (PROT_READ);
        s->len = nlen;
        s->mmap = mmap(0, s->len, prot, flags, impl->fh, s->off);
        if (s->mmap == MAP_FAILED) {
            return iwrc_set_errno(IW_ERROR_ERRNO, errno);
        }
    }
    return 0;
}

static iwrc _exfile_initmmap_lw(struct IWFS_EXT *f) {
    assert(f);
    iwrc rc = 0;
    _EXF *impl = f->impl;
    assert(!(impl->fsize & (impl->psize - 1)));
    _MMAPSLOT *s = impl->mmslots;
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
    _EXF *impl = f->impl;
    iwfs_omode omode = impl->omode;
    off_t old_size = impl->fsize;

    if (impl->fsize == size) {
        return 0;
    }
    size = IW_ROUNDUP(size, impl->psize);
    if (old_size < size) {
        if (!(omode & IWFS_OWRITE)) {
            return IW_ERROR_READONLY;
        }
        impl->fsize = size;
        rc = iwp_ftruncate(impl->fh, size);
        if (rc) {
            goto truncfail;
        }
        rc = _exfile_initmmap_lw(f);
    } else if (old_size > size) {
        if (!(omode & IWFS_OWRITE)) {
            return IW_ERROR_READONLY;
        }
        impl->fsize = size;
        rc = _exfile_initmmap_lw(f);
        if (rc) {
            goto truncfail;
        }
        rc = iwp_ftruncate(impl->fh, size);
        if (rc) {
            goto truncfail;
        }
    }
    return rc;

truncfail:
    //restore old size
    impl->fsize = old_size;
    //try to reinit mmap slots
    IWRC(_exfile_initmmap_lw(f), rc);
    return rc;
}

static iwrc _exfile_ensure_size_lw(struct IWFS_EXT *f, off_t sz) {
    _EXF *impl = f->impl;
    assert(impl && impl->rspolicy);
    if (impl->fsize >= sz) {
        return 0;
    }
    off_t nsz = impl->rspolicy(sz, impl->fsize, f, &impl->rspolicy_ctx);
    if (nsz < sz || (nsz & (impl->psize - 1))) {
        return IWFS_ERROR_RESIZE_POLICY_FAIL;
    }
    return _exfile_truncate_lw(f, nsz);
}

static iwrc _exfile_sync(struct IWFS_EXT *f, iwfs_sync_flags flags) {
    iwrc rc = _exfile_rlock(f);
    if (rc) {
        return rc;
    }
    _EXF *impl = f->impl;
    _MMAPSLOT *s = impl->mmslots;
    while (s) {
        if (s->mmap && s->mmap != MAP_FAILED) {
            int mflags = 0;
            if (!(flags & IWFS_NO_MMASYNC)) {
                mflags |= MS_ASYNC;
            }
            if (msync(s->mmap, s->len, mflags)) {
                rc = iwrc_set_errno(rc, errno);
            }
        }
        s = s->next;
    }
    IWRC(impl->file.sync(&impl->file, flags), rc);
    IWRC(_exfile_unlock2(impl), rc);
    return rc;
}

static iwrc _exfile_write(struct IWFS_EXT *f, off_t off,
                          const void *buf, size_t siz, size_t *sp) {
    _MMAPSLOT *s;
    _EXF *impl;
    off_t end = off + siz;
    off_t wp = siz, len;

    *sp = 0;
    if (off < 0 || end < 0) {
        return IW_ERROR_OUT_OF_BOUNDS;
    }
    iwrc rc = _exfile_rlock(f);
    if (rc) {
        return rc;
    }
    impl = f->impl;
    if (end > impl->fsize) {
        if ((rc = _exfile_unlock2(impl)) || (rc = _exfile_wlock(f))) {
            goto end;
        }
        if (end > impl->fsize) {
            rc = _exfile_ensure_size_lw(f, end);
            if (rc) goto finish;
        }
    }
    s = impl->mmslots;
    while (s && wp > 0) {
        if (!s->len || wp + off <= s->off) {
            break;
        }
        if (s->off > off) {
            len = MIN(wp, s->off - off);
            rc = impl->file.write(&impl->file, off, (const char*) buf + (siz - wp), len, sp);
            if (rc) goto finish;
            wp = wp - *sp;
            off = off + *sp;
        }
        if (wp > 0 && s->off <= off && s->off + s->len > off) {
            len = MIN(wp, s->off + s->len - off);
            memcpy(s->mmap + (off - s->off), (const char*) buf + (siz - wp), len);
            wp -= len;
            off += len;
        }
        s = s->next;
    }
    if (wp > 0) {
        rc = impl->file.write(&impl->file, off, (const char*) buf + (siz - wp), wp, sp);
        if (rc) {
            goto finish;
        }
        wp = wp - *sp;
        //off = off + *sp;
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

static iwrc _exfile_read(struct IWFS_EXT *f, off_t off,
                         void *buf, size_t siz, size_t *sp) {
    _MMAPSLOT *s;
    _EXF *impl;
    off_t end = off + siz;
    off_t rp = siz, len;
    *sp = 0;
    if (off < 0 || end < 0) {
        return IW_ERROR_OUT_OF_BOUNDS;
    }
    iwrc rc = _exfile_rlock(f);
    if (rc) {
        return rc;
    }
    impl = f->impl;
    s = impl->mmslots;
    if (end > impl->fsize) {
        rp = siz = impl->fsize - off;
    }
    while (s && rp > 0) {
        if (!s->len || rp + off <= s->off) {
            break;
        }
        if (s->off > off) {
            len = MIN(rp, s->off - off);
            rc = impl->file.read(&impl->file, off, (char*) buf + (siz - rp), len, sp);
            if (rc) {
                goto finish;
            }
            rp = rp - *sp;
            off = off + *sp;
        }
        if (rp > 0 && s->off <= off && s->off + s->len > off) {
            len = MIN(rp, s->off + s->len - off);
            memcpy((char*) buf + (siz - rp), s->mmap + (off - s->off), len);
            rp -= len;
            off += len;
        }
        s = s->next;
    }
    if (rp > 0) {
        rc = impl->file.read(&impl->file, off, (char*) buf + (siz - rp), rp, sp);
        if (rc) {
            goto finish;
        }
        rp = rp - *sp;
        //off = off + *sp;
    }
    *sp = siz - rp;
finish:
    if (rc) {
        *sp = 0;
    }
    IWRC(_exfile_unlock2(impl), rc);
    return rc;
}

static iwrc _exfile_state(struct IWFS_EXT *f, IWFS_EXT_STATE* state) {
    int rc = _exfile_rlock(f);
    if (rc) {
        return rc;
    }
    IWRC(f->impl->file.state(&f->impl->file, &state->file), rc);
    state->fsize = f->impl->fsize;
    IWRC(_exfile_unlock(f), rc);
    return rc;
}

static iwrc _exfile_remove_mmap_wl(struct IWFS_EXT *f, off_t off) {
    iwrc rc = 0;
    _EXF *impl = f->impl;
    _MMAPSLOT *s = impl->mmslots;
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
    assert(f);
    iwrc rc = _exfile_wlock(f);
    if (rc) {
        return rc;
    }
    _EXF *impl = f->impl;
    _MMAPSLOT *s = impl->mmslots, *next;
    while (s) {
        next = s->next;
        IWRC(_exfile_remove_mmap_wl(f, s->off), rc);
        s = next;
    }
    IWRC(impl->file.close(&impl->file), rc);
    f->impl = 0;
    if (impl->rspolicy) { //deactivate resize policy function
        impl->rspolicy(-1, impl->fsize, f, &impl->rspolicy_ctx);
    }
    IWRC(_exfile_unlock2(impl), rc);
    IWRC(_exfile_destroylocks(impl), rc);
    free(impl);
    return rc;
}

static iwrc _exfile_ensure_size(struct IWFS_EXT *f, off_t sz) {
    iwrc rc = _exfile_rlock(f);
    if (rc) {
        return rc;
    }
    rc = _exfile_ensure_size_lw(f, sz);
    IWRC(_exfile_unlock2(f->impl), rc);
    return rc;
}

static iwrc _exfile_truncate(struct IWFS_EXT *f, off_t sz) {
    iwrc rc = _exfile_wlock(f);
    if (rc) {
        return rc;
    }
    rc = _exfile_truncate_lw(f, sz);
    IWRC(_exfile_unlock(f), rc);
    return rc;
}

static iwrc _exfile_add_mmap(struct IWFS_EXT *f, off_t off, size_t maxlen) {
    assert(f);
    assert(off >= 0);

    iwrc rc;
    size_t tmp;
    _MMAPSLOT *ns = 0;

    rc = _exfile_wlock(f);
    if (rc) {
        return rc;
    }
    _EXF *impl = f->impl;
    if (off & (impl->psize - 1)) {
        rc = IW_ERROR_NOT_ALIGNED;
        goto finish;
    }
    if (OFF_T_MAX - off < maxlen) {
        maxlen = OFF_T_MAX - off;
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
#ifdef _WIN32
    ns->mmapfh = INVALIDHANDLE;
#endif
    rc = _exfile_initmmap_slot_lw(f, ns);
    if (rc) {
        goto finish;
    }
    if (impl->mmslots == 0) {
        ns->next = 0;
        ns->prev = ns;
        impl->mmslots = ns;
    } else {
        _MMAPSLOT *s = impl->mmslots;
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
        if (s) { // insert before
            ns->next = s;
            ns->prev = s->prev;
            s->prev->next = ns;
            s->prev = ns;
            if (s == impl->mmslots) {
                impl->mmslots = ns;
                ns->prev->next = 0;
            }
        } else { // insert at the end
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

iwrc _exfile_get_mmap(struct IWFS_EXT *f, off_t off, uint8_t **mm, size_t *sp) {
    assert(f);
    assert(off >= 0);
    assert(mm);

    if (sp) *sp = 0;
    *mm = 0;

    iwrc rc = _exfile_rlock(f);
    if (rc) {
        return rc;
    }
    _EXF *impl = f->impl;
    _MMAPSLOT *s = impl->mmslots;
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
    IWRC(_exfile_unlock(f), rc);
    return rc;
}

static iwrc _exfile_remove_mmap(struct IWFS_EXT *f, off_t off) {
    assert(f);
    assert(off >= 0);

    iwrc rc = _exfile_wlock(f);
    if (rc) {
        return rc;
    }
    rc = _exfile_remove_mmap_wl(f, off);
    IWRC(_exfile_unlock(f), rc);
    return rc;
}

static iwrc _exfile_sync_mmap(struct IWFS_EXT *f, off_t off, int _flags) {
    assert(f);
    assert(off >= 0);

    iwrc rc = _exfile_rlock(f);
    if (rc) {
        return rc;
    }
    _EXF *impl = f->impl;
    _MMAPSLOT *s = impl->mmslots;
    while (s) {
        if (s->off == off) {
            if (s->len == 0) {
                rc = IWFS_ERROR_NOT_MMAPED;
                break;
            }
            if (s->mmap && s->mmap != MAP_FAILED) {
                int flags = _flags;
                if (!flags) flags = MS_ASYNC;
                if (msync(s->mmap, s->len, flags)) {
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

static off_t _exfile_default_szpolicy(off_t nsize, off_t csize,
                                      struct IWFS_EXT *f, void **ctx) {
    if (nsize == -1) {
        return 0;
    }
    return IW_ROUNDUP(nsize, iwp_page_size());
}

off_t iw_exfile_szpolicy_fibo(off_t nsize, off_t csize,
                              struct IWFS_EXT *f,
                              void **_ctx) {
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
    uint64_t res = csize + ctx->prev_sz;
    res = MAX(res, nsize);
    res = IW_ROUNDUP(res, iwp_page_size());
    if (res > OFF_T_MAX) {
        res = OFF_T_MAX;
    }
    ctx->prev_sz = csize;
    return res;
}

off_t iw_exfile_szpolicy_mul(off_t nsize, off_t csize,
                             struct IWFS_EXT *f,
                             void **_ctx) {

    IW_RNUM *mul = *_ctx;
    if (nsize == -1) {
        return 0;
    }
    if (!mul || !mul->dn || mul->n < mul->dn) {
        iwlog_error2("Invalid iw_exfile_szpolicy_mul context arguments, fallback to the default resize policy");
        return _exfile_default_szpolicy(nsize, csize, f, _ctx);
    }
    uint64_t ret = nsize;
    ret /= mul->dn;
    ret *= mul->n;
    ret = IW_ROUNDUP(ret, iwp_page_size());
    if (ret > OFF_T_MAX) {
        ret = OFF_T_MAX;
    }
    return ret;
}

static iwrc _exfile_initlocks(IWFS_EXT *f) {
    assert(f && f->impl);
    assert(!f->impl->rwlock);
    _EXF *impl = f->impl;
    if (!impl->use_locks) {
        return 0;
    }
    impl->rwlock = calloc(1, sizeof(*impl->rwlock));
    if (!impl->rwlock) {
        return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
    int rv = pthread_rwlock_init(impl->rwlock, (void*) 0);
    if (rv) {
        free(impl->rwlock);
        impl->rwlock = 0;
        return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rv);
    }
    return 0;
}

iwrc iwfs_exfile_open(IWFS_EXT *f,
                      const IWFS_EXT_OPTS *opts) {

    assert(f);
    assert(opts);
    iwrc rc = 0;
    const char *path = opts->file.path;
    if (!path) {
        return IW_ERROR_INVALID_ARGS;
    }
    memset(f, 0, sizeof(*f));
    _EXF *impl = f->impl = calloc(1, sizeof(*f->impl));
    if (!impl) {
        return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
    
    f->close = _exfile_close;
    f->read = _exfile_read;
    f->write = _exfile_write;
    f->sync = _exfile_sync;
    f->state = _exfile_state;

    f->ensure_size = _exfile_ensure_size;
    f->truncate = _exfile_truncate;
    f->add_mmap = _exfile_add_mmap;
    f->get_mmap = _exfile_get_mmap;
    f->remove_mmap = _exfile_remove_mmap;
    f->sync_mmap = _exfile_sync_mmap;

    impl->psize = iwp_page_size();
    impl->rspolicy = opts->rspolicy ? opts->rspolicy : _exfile_default_szpolicy;
    impl->rspolicy_ctx = opts->rspolicy_ctx;
    impl->use_locks = opts->use_locks;

    rc = _exfile_initlocks(f);
    if (rc) {
        goto finish;
    }
    rc = iwfs_file_open(&impl->file, &opts->file);
    if (rc) {
        goto finish;
    }
    IWP_FILE_STAT fstat;
    rc = iwp_fstat(path, &fstat);
    if (rc) {
        goto finish;
    }
    impl->fsize = fstat.size;

    IWFS_FILE_STATE fstate;
    rc = impl->file.state(&impl->file, &fstate);
    impl->omode = fstate.opts.omode;
    impl->fh = fstate.fh;

    if (impl->fsize < opts->initial_size) {
        rc = _exfile_truncate_lw(f, opts->initial_size);
    } else if (impl->fsize & (impl->psize - 1)) { //not a page aligned
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

static const char* _exfile_ecodefn(locale_t locale, uint32_t ecode) {
    if (!(ecode > _IWFS_EXT_ERROR_START && ecode < _IWFS_EXT_ERROR_END)) {
        return 0;
    }
    switch (ecode) {
        case IWFS_ERROR_MMAP_OVERLAP:
            return "Region is mmaped already, mmaping overlaps. (IWFS_ERROR_MMAP_OVERLAP)";
        case IWFS_ERROR_NOT_MMAPED:
            return "Region is not mmaped. (IWFS_ERROR_NOT_MMAPED)";
        case IWFS_ERROR_RESIZE_POLICY_FAIL:
            return "Invalid result of resize policy function. (IWFS_ERROR_RESIZE_POLICY_FAIL)";
    }
    return 0;
}

iwrc iwfs_exfile_init(void) {
    static int _exfile_initialized = 0;
    if (!__sync_bool_compare_and_swap(&_exfile_initialized, 0, 1)) {
        return 0; //initialized already
    }
    return iwlog_register_ecodefn(_exfile_ecodefn);
}
