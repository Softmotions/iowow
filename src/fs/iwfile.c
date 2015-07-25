#include "iwfile.h"
#include "iwcfg.h"

struct IWFS_FILE_IMPL {
    HANDLE fh;              /**< File handle. */
    iwfs_lockmode lmode;    /**< File OS locking mode. */
    const char *path;       /**< File path */
    IWFS_FILE_STATE state;
};


static const char* _iwfs_ecode_fn(locale_t locale, int64_t ecode) {
    return 0;
}

IWLOG_ECODE_FN iwfs_ecode_fn = _iwfs_ecode_fn;


static int _iwfs_write(struct IWFS_FILE *f, uint64_t off,
                       const void *buf, int64_t siz, int64_t *sp) {

    return 0;
}

int _iwfs_read(struct IWFS_FILE *f, uint64_t off,
               void *buf, int64_t siz, int64_t *sp) {

    return 0;
}

int _iwfs_close(struct IWFS_FILE *f) {


    return 0;
}

int _iwfs_sync(struct IWFS_FILE *f, const IWFS_FILE_SYNC_OPTS *opts) {

    return 0;
}


int _iwfs_state(struct IWFS_FILE *f, IWFS_FILE_STATE* state) {

    return 0;
}

int iwfs_file_open(IWFS_FILE *f, const IWFS_FILE_OPTS *_opts) {
    assert(f);
    IWFS_FILE_OPTS opts;
    int rs = 0;

    if (_opts) {
        opts = *_opts;

        if (!opts.lock_mode) {
            opts.lock_mode = IWFS_DEFAULT_LOCKMODE;
        }

        if (!opts.open_mode) {
            opts.open_mode = IWFS_DEFAULT_OMODE;
        }
    } else {
        opts = (IWFS_FILE_OPTS) {
            .open_mode = IWFS_DEFAULT_OMODE,
             .lock_mode = IWFS_DEFAULT_LOCKMODE
        };
    }

    memset(f, 0, sizeof(*f));
    IWFS_FILE_IMPL *impl = f->impl = calloc(sizeof(*f->impl), 1);
    
    f->write = _iwfs_write;
    f->read = _iwfs_read;
    f->close = _iwfs_close;
    f->sync = _iwfs_sync;
    
    
    
    

    return rs;
}
