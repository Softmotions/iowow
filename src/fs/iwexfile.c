#include "iwexfile.h"
#include "log/iwlog.h"
#include "iwcfg.h"

#include <pthread.h>

struct IWFS_EXFILE_IMPL {
    IWFS_FILE   *file;          /**< Underlying file pointer */
    off_t       fsize;           /**< Current file size */
    off_t       psize;           /**< System page size */
    int         use_locks;      /**< Use rwlocks to guard method access */
    pthread_rwlock_t *rwlock;   /**< Thread RW lock */
    IW_EXFILE_RSPOLICY  rspolicy;  /**< File resize policy function ptr. */
    void *rspolicy_ctx;  /**< Custom opaque data for policy functions. */
};

typedef struct _EXFILE_MMAPSLOT {
    off_t offset;                    /**< Offset to a memory mapped region */
    size_t length;                   /**< Actual size of memory mapped region. */
    size_t maxlength;                /**< Maximum length of memory mapped region */
#ifdef _WIN32
    HANDLE mmapfh;                      /**< Win32 file mapping handle. */
#endif
    struct _EXFILE_MMAPSLOT *prev;    /**< Previous mmap slot. */
    struct _EXFILE_MMAPSLOT *next;    /**< Next mmap slot. */
    uint8_t *mmap;                    /**< Pointer to a mmaped address space in the case if file data is memory mapped. */
} _EXFILE_MMAPSLOT;

static iwrc _exfile_initlocks(IWFS_EXFILE *f);
static iwrc _exfile_rwlock(IWFS_EXFILE *f, int wl);
static iwrc _exfile_unlock(IWFS_EXFILE *f);
static iwrc _exfile_unlock2(IWFS_EXFILE_IMPL *impl);
static iwrc _exfile_destroylocks(IWFS_EXFILE_IMPL *impl);
static iwrc _exfile_resize(IWFS_EXFILE *f, size_t nsize);
static iwrc _exfile_ensure_size(struct IWFS_EXFILE* f, off_t size);
static iwrc _exfile_truncate(struct IWFS_EXFILE* f, off_t size);
static iwrc _exfile_truncate_impl(struct IWFS_EXFILE* f, off_t size);
static iwrc _exfile_add_mmap(struct IWFS_EXFILE* f, off_t off, size_t maxlen);
static iwrc _exfile_remove_mmap(struct IWFS_EXFILE* f, off_t off);
static iwrc _exfile_sync_mmap(struct IWFS_EXFILE* f, off_t off);
static iwrc _exfile_sync(struct IWFS_EXFILE *f, const IWFS_FILE_SYNC_OPTS *opts);
static iwrc _exfile_write(struct IWFS_EXFILE *f, off_t off, const void *buf, size_t siz, size_t *sp);
static iwrc _exfile_read(struct IWFS_EXFILE *f, off_t off, void *buf, size_t siz, size_t *sp);
static iwrc _exfile_close(struct IWFS_EXFILE *f);
static iwrc _exfile_initmmap(struct IWFS_EXFILE *f);
static iwrc _exfile_initmmap_slot(struct IWFS_EXFILE *f, _EXFILE_MMAPSLOT *slot);
static off_t _exfile_default_spolicy(off_t size, struct IWFS_EXFILE *f, void *ctx);


static iwrc _exfile_sync(struct IWFS_EXFILE *f, const IWFS_FILE_SYNC_OPTS *opts) {

    return 0;
}

static iwrc _exfile_write(struct IWFS_EXFILE *f, off_t off,
                          const void *buf, size_t siz, size_t *sp) {

    return 0;
}

static iwrc _exfile_read(struct IWFS_EXFILE *f, off_t off,
                         void *buf, size_t siz, size_t *sp) {

    return 0;
}


static iwrc _exfile_state(struct IWFS_EXFILE *f, IWFS_EXFILE_STATE* state) {
    int rc = _exfile_rwlock(f, 0);
    if (rc) {
        return rc;
    }
    IWRC(f->impl->file->state(f->impl->file, &state->fstate), rc);
    state->fsize = f->impl->fsize;
    IWRC(_exfile_unlock(f), rc);
    return rc;
}

static iwrc _exfile_close(struct IWFS_EXFILE *f) {
    assert(f);
    iwrc rc = _exfile_rwlock(f, 1);
    if (rc) {
        return rc;
    }
    IWFS_EXFILE_IMPL *impl = f->impl;
    IWRC(impl->file->close(impl->file), rc);
    f->impl = 0;
    IWRC(_exfile_unlock2(impl), rc);
    IWRC(_exfile_destroylocks(impl), rc);
    free(impl);
    return rc;
}

static iwrc _exfile_ensure_size(struct IWFS_EXFILE* f, off_t size) {
    return 0;
}

static iwrc _exfile_truncate(struct IWFS_EXFILE* f, off_t size) {
    iwrc rc = _exfile_rwlock(f, 1);
    if (rc) {
        return rc;
    }
    rc = _exfile_truncate_impl(f, size);
    IWRC(_exfile_unlock(f), rc);
    return rc;
}

static iwrc _exfile_initmmap(struct IWFS_EXFILE *f) {
    return 0;
}

static iwrc _exfile_initmmap_slot(struct IWFS_EXFILE *f, _EXFILE_MMAPSLOT *slot) {
    return 0;
}

static iwrc _exfile_truncate_impl(struct IWFS_EXFILE* f, off_t size) {
    assert(f && f->impl);
    iwrc rc = 0;
    IWFS_EXFILE_IMPL *impl = f->impl;
    IWFS_FILE_STATE fstate;
    iwfs_omode omode;
    rc = impl->file->state(impl->file, &fstate);
    if (rc) {
        return rc;
    }
    off_t old_size = impl->fsize;
    omode = fstate.opts.open_mode;
    size = IW_ROUNDUP(size, impl->psize);
    if (impl->fsize < size) {
        if (!(omode & IWFS_OWRITE)) {
            return IW_ERROR_READONLY;
        }
        rc = iwp_ftruncate(fstate.fh, size);
        if (rc) {
            goto truncfail;
        }
        rc = _exfile_initmmap(f);
    } else if (impl->fsize > size) {
        if (!(omode & IWFS_OWRITE)) {
            return IW_ERROR_READONLY;
        }
        impl->fsize = size;
        rc = _exfile_initmmap(f);
        if (rc) {
            goto truncfail;
        }
        rc = iwp_ftruncate(fstate.fh, size);
        if (rc) {
            goto truncfail;
        }
    }
    return rc;
    
truncfail:
    //restore old size
    impl->fsize = old_size;
    //try to reinit mmap slots
    IWRC(_exfile_initmmap(f), rc); 
    return rc;
}

static iwrc _exfile_add_mmap(struct IWFS_EXFILE* f, off_t off, size_t maxlen) {
    return 0;
}

static iwrc _exfile_remove_mmap(struct IWFS_EXFILE* f, off_t off) {
    return 0;
}

static iwrc _exfile_sync_mmap(struct IWFS_EXFILE* f, off_t off) {
    return 0;
}

iwrc iwfs_exfile_open(IWFS_EXFILE *f,
                      const IWFS_EXFILE_OPTS *opts) {

    assert(f);
    assert(opts);
    assert(opts->fopts.path);
    iwrc rc = 0;
    const char *path = opts->fopts.path;

    memset(f, 0, sizeof(*f));
    IWFS_EXFILE_IMPL *impl = f->impl = calloc(1, sizeof(*f->impl));
    if (!f->impl) {
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
    f->remove_mmap = _exfile_remove_mmap;
    f->sync_mmap = _exfile_sync_mmap;

    impl->psize = iwp_page_size();
    impl->rspolicy = opts->rspolicy ? opts->rspolicy : _exfile_default_spolicy;
    impl->rspolicy_ctx = opts->rspolicy_ctx;
    impl->use_locks = opts->use_locks;

    rc = _exfile_initlocks(f);
    if (rc) {
        goto finish;
    }
    rc = iwfs_file_open(impl->file, &opts->fopts);
    if (rc) {
        goto finish;
    }
    IWP_FILE_STAT fstat;
    rc = iwp_fstat(path, &fstat);
    if (rc) {
        goto finish;
    }
    impl->fsize = fstat.size;
    if (impl->fsize < opts->initial_size) {
        rc = _exfile_resize(f, opts->initial_size);
    } else if (impl->fsize & (impl->psize - 1)) { //not a page aligned
        rc = _exfile_resize(f, impl->fsize);
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

static off_t _exfile_default_spolicy(off_t size, struct IWFS_EXFILE *f, void *ctx) {
    return size;
}

static iwrc _exfile_resize(IWFS_EXFILE *f, size_t nsize) {
    return 0;
}

static iwrc _exfile_initlocks(IWFS_EXFILE *f) {
    assert(f && f->impl);
    assert(!f->impl->rwlock);
    IWFS_EXFILE_IMPL *impl = f->impl;
    if (!impl->use_locks) {
        return 0;
    }
    impl->rwlock = calloc(1, sizeof(*impl->rwlock));
    if (impl->rwlock) {
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

static iwrc _exfile_destroylocks(IWFS_EXFILE_IMPL *impl) {
    if (!impl) return IW_ERROR_INVALID_STATE;
    if (!impl->rwlock) return 0;
    int rv = pthread_rwlock_destroy(impl->rwlock);
    free(impl->rwlock);
    impl->rwlock = 0;
    return rv ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rv) : 0;
}

IW_INLINE iwrc _exfile_rwlock(IWFS_EXFILE *f, int wl) {
    assert(f);
    if (!f->impl) return IW_ERROR_INVALID_STATE;
    if (!f->impl->use_locks) return 0;
    if (!f->impl->rwlock) return IW_ERROR_INVALID_STATE;
    {
        int rv = wl ? pthread_rwlock_wrlock(f->impl->rwlock)
                 : pthread_rwlock_rdlock(f->impl->rwlock);
        return rv ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rv) : 0;
    }
}

IW_INLINE iwrc _exfile_unlock(IWFS_EXFILE *f) {
    assert(f);
    if (!f->impl) return IW_ERROR_INVALID_STATE;
    if (!f->impl->use_locks) return 0;
    if (!f->impl->rwlock) return IW_ERROR_INVALID_STATE;
    {
        int rv = pthread_rwlock_unlock(f->impl->rwlock);
        return rv ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rv) : 0;
    }
}

IW_INLINE iwrc _exfile_unlock2(IWFS_EXFILE_IMPL *impl) {
    if (!impl) return IW_ERROR_INVALID_STATE;
    if (!impl->use_locks) return 0;
    if (!impl->rwlock) return IW_ERROR_INVALID_STATE;
    {
        int rv = pthread_rwlock_unlock(impl->rwlock);
        return rv ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rv) : 0;
    }
}

static const char* _exfile_ecodefn(locale_t locale, uint32_t ecode) {
    return 0;
}

iwrc iwfs_exfile_init(void) {
    static int _exfile_initialized = 0;
    iwrc rc;
    if (!__sync_bool_compare_and_swap(&_exfile_initialized, 0, 1)) {
        return 0; //initialized already
    }
    rc = iwlog_register_ecodefn(_exfile_ecodefn);
    return rc;
    return 0;
}
