#include "iwfile.h"
#include "platform/iwp.h"
#include "iwcfg.h"
#include "log/iwlog.h"

#include <fcntl.h>

struct IWFS_FILE_IMPL {
    HANDLE fh;              /**< File handle. */
    IWFS_FILE_STATE state;
};


static const char* _iwfs_ecode_fn(locale_t locale, uint32_t ecode) {
    return 0;
}

IWLOG_ECODE_FN iwfs_ecode_fn = _iwfs_ecode_fn;


static iwrc _iwfs_write(struct IWFS_FILE *f, uint64_t off,
                        const void *buf, int64_t siz, int64_t *sp) {

    return 0;
}

static iwrc _iwfs_read(struct IWFS_FILE *f, uint64_t off,
                       void *buf, int64_t siz, int64_t *sp) {

    return 0;
}

static iwrc _iwfs_close(struct IWFS_FILE *f) {
    assert(f);
    iwrc rc = 0;
    IWFS_FILE_IMPL *impl = f->impl;
    IWFS_FILE_OPTS *opts = &impl->state.opts;
    if (opts->lock_mode != IWP_NOLOCK) {
        rc = iwp_unlock(impl->fh);
        goto finish;
    }
    
    
finish:    
    return rc;
}

static iwrc _iwfs_sync(struct IWFS_FILE *f, const IWFS_FILE_SYNC_OPTS *opts) {

    return 0;
}


static iwrc _iwfs_state(struct IWFS_FILE *f, IWFS_FILE_STATE* state) {

    return 0;
}

iwrc iwfs_file_open(IWFS_FILE *f, const IWFS_FILE_OPTS *_opts) {
    assert(f);
    assert(_opts);
    assert(_opts->path);

    IWFS_FILE_OPTS *opts;
    IWFS_FILE_IMPL *impl;
    IWP_FILE_STAT fstat;
    iwfs_omode omode;
    iwrc rc = 0;
    int mode;
    
    memset(f, 0, sizeof(*f));
    impl = f->impl = calloc(sizeof(*f->impl), 1);
    impl->state.opts = *_opts;
    opts = &impl->state.opts;
    opts->path = strdup(_opts->path);
    if (!opts->path) {
        rc = iwrc_set_errno(IW_ERROR_ERRNO, errno);
        goto finish;
    }

    if (!opts->lock_mode) {
        opts->lock_mode = IWFS_DEFAULT_LOCKMODE;
    }
    if (!opts->open_mode) {
        opts->open_mode = IWFS_DEFAULT_OMODE;
    }
    opts->open_mode |= IWFS_OREAD;
    if ((opts->open_mode & IWFS_OCREATE) || (opts->open_mode & IWFS_OTRUNC)) {
        opts->open_mode |= IWFS_OWRITE;
    }
    omode = opts->open_mode;

    f->write = _iwfs_write;
    f->read = _iwfs_read;
    f->close = _iwfs_close;
    f->sync = _iwfs_sync;
    f->state = _iwfs_state;

    rc = iwp_fstat(opts->path, &fstat);
    if (!rc && !(opts->open_mode & IWFS_OTRUNC)) {
        impl->state.ostatus = IWFS_OPEN_EXISTING;
    } else {
        impl->state.ostatus = IWFS_OPEN_NEW;
    }
    rc = 0;
    mode = O_RDONLY;
    if (omode & IWFS_OWRITE) {
        mode = O_RDWR;
        if (omode & IWFS_OCREATE) mode |= O_CREAT;
        if (omode & IWFS_OTRUNC) mode |= O_TRUNC;
    }
    impl->fh = open(opts->path, mode, opts->filemode);
    if (INVALIDHANDLE(impl->fh)) {
        rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
        goto finish;
    }
    if (opts->lock_mode != IWP_NOLOCK) {
        rc = iwp_flock(impl->fh, opts->lock_mode);
        if (rc) {
            goto finish;
        }
    }

finish:
    if (rc) {
        impl->state.ostatus = IWFS_OPEN_FAIL;
        if (opts->path) {
            free((char*) opts->path);
        }
    }
    return rc;
}

static const char* _iwfile_ecodefn(locale_t locale, uint32_t ecode) {
    switch (ecode) {
        default:
            return 0;
    }
    return 0;
}

iwrc iwfs_file_init(void) {
    static int _iwfs_file_initialized = 0;
    iwrc rc;
    if (!__sync_bool_compare_and_swap(&_iwfs_file_initialized, 0, 1)) {
        return 0; //initialized already
    }
    rc = iwlog_register_ecodefn(_iwfile_ecodefn);
    return rc;
}
