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

#include "iwrwlfile.h"
#include "utils/iwrlock.h"
#include "iwcfg.h"

typedef struct IWFS_RWLFILE_IMPL {
    IWFS_EXFILE exfile;         /**< Underlying exfile */
    IWRLOCK *lk;                /**< Address range lock */
} _RWL;


#define _RWL_ENSURE_OPEN(f) \
    if (!f || !f->impl || !f->impl->lk) \
        return IW_ERROR_INVALID_STATE;


static iwrc _rwl_write(struct IWFS_RWLFILE* f, off_t off, const void *buf, size_t siz, size_t *sp) {
    return 0;
}

static iwrc _rwl_read(struct IWFS_RWLFILE* f, off_t off, void *buf, size_t siz, size_t *sp) {
    return 0;
}

static iwrc _rwl_sync(struct IWFS_RWLFILE* f, iwfs_sync_flags flags) {
    return 0;
}

static iwrc _rwl_state(struct IWFS_RWLFILE* f, IWFS_RWLFILE_STATE* state) {
    return 0;
}

static iwrc _rwl_ensure_size(struct IWFS_RWLFILE* f, off_t size) {
    return 0;
}

static iwrc _rwl_truncate(struct IWFS_RWLFILE* f, off_t size) {
    return 0;
}

static iwrc _rwl_add_mmap(struct IWFS_RWLFILE* f, off_t off, size_t maxlen) {
    return 0;
}

static iwrc _rwl_get_mmap(struct IWFS_RWLFILE* f, off_t off, uint8_t **mm, size_t *sp) {
    return 0;
}

static iwrc _rwl_remove_mmap(struct IWFS_RWLFILE* f, off_t off) {
    return 0;
}

static iwrc _rwl_sync_mmap(struct IWFS_RWLFILE* f, off_t off, int flags) {
    return 0;
}

static iwrc _rwl_lock(struct IWFS_RWLFILE* f, off_t start, off_t len, iwrl_lockflags lflags) {
    return 0;
}

static iwrc _rwl_try_lock(struct IWFS_RWLFILE* f, off_t start, off_t len, iwrl_lockflags lflags) {
    return 0;
}

static iwrc _rwl_unlock(struct IWFS_RWLFILE* f, off_t start, off_t len) {
    return 0;
}

static iwrc _rwl_lwrite(struct IWFS_RWLFILE* f, off_t start, const void *buf, size_t siz, size_t *sp) {
    return 0;
}

static iwrc _rwl_lread(struct IWFS_RWLFILE* f, off_t start, void *buf, size_t siz, size_t *sp) {
    return 0;
}

static iwrc _rwl_close(struct IWFS_RWLFILE* f) {
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

iwrc iwfs_rwlfile_open(IWFS_RWLFILE *f,
                       const IWFS_RWLFILE_OPTS *opts) {

    assert(f);
    assert(opts);
    iwrc rc = 0;
    const char *path = opts->exfile.file.path;

    if (!path) {
        return IW_ERROR_INVALID_ARGS;
    }
    memset(f, 0, sizeof(*f));
    _RWL *impl = f->impl = calloc(1, sizeof(*f->impl));
    if (!impl) {
        return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }

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
