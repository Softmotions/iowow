
#include "iwfsmfile.h"
#include "log/iwlog.h"
#include "platform/iwp.h"
#include "utils/iwutils.h"

#include "iwcfg.h"

#include <pthread.h>

typedef struct IWFS_FSM_IMPL {
    IWFS_RWL                rwl;        /**< Underlying rwl file. */
    iwfs_fsm_openflags      oflags;     /**< Open flags. */
    IWFS_FSM                *f;         /**< Self reference. */
    pthread_rwlock_t        *ctlrwlk;   /**< Methods RW lock */
    pthread_mutex_t         *fsmtx;     /**< Free-space bitmap mutex */
    uint8_t                 bpow;       /**< Block size power of 2 */
    size_t                  psize;      /**< System page size */      
} _FSM;

#define _FSM_ENSURE_OPEN(FSM_impl_) \
    if (!(FSM_impl_) || !(FSM_impl_)->f) \
        return IW_ERROR_INVALID_STATE;

#define _FSM_ENSURE_OPEN2(FSM_f_) \
    if (!(FSM_f_) || !(FSM_f_)->impl) \
        return IW_ERROR_INVALID_STATE;
       
/**
 * Free-space blocks-tree key
 */
typedef struct {
    /* uint64 offset|length data, chunked in bytes in order to save padding memory in each fsm tree node
      #pragma pack not used to avoid portability issues */
    uint8_t b[8];
    /* Position of divider bit in the block offset|length data. */
    uint8_t div;
} _FSMBK;


#define _FSMBK_RESET(Bk_) \
    memset((Bk_), 0, sizeof(*(Bk_)))

#define _FSMBK_I64(Bk_) \
    (*((uint64_t*) (Bk_)))

#define _FSMBK_OFFSET(Bk_) \
    (_FSMBK_I64(Bk_) & ((((uint64_t) 1) << (Bk_)->div) - 1))

#define _FSMBK_LENGTH(Bk_) \
    ((Bk_)->div ? ((_FSMBK_I64(Bk_) >> (Bk_)->div) & ((((uint64_t) 1) << (64 - (Bk_)->div)) - 1)) : _JBFBK_I64(Bk_))

#define _FSMBK_END(Bk_) \
    (_FSMBK_OFFSET(Bk_) + _FSMBK_LENGTH(Bk_))


        
#include "utils/kbtree.h"
//todo


static const uint64_t _FSM_ZERO8 = 0;
static const uint64_t _FSM_ONE8 = (uint64_t) (-1);
static const int _FSM_YES = 1;
static const int _FSM_NO = 0;
        
#define _FSM_SEQ_IO_BUF_SIZE 8192
#define _FSM_MAGICK 0x19cc7cc

/* Maximum size of block: 1Mb */
#define _FSM_MAX_BLOCK_POW 20

/* Maximum number of records used in allocation statistics */
#define _FSM_MAX_STATS_COUNT 0x0000ffff

#define _FSM_CUSTOM_HDR_DATA_OFFSET \
    (4 /*magic*/ + 1 /*block pow*/ + \
     8 /*fsm bitmap block offset */ + 8 /*fsm bitmap block length*/ + \
     8 /*Number of allocated block with largest offset.*/ + \
     8 /*cumulative record sizes sum */ + 4 /*cumulative record sizes num */ + \
     8 /*record sizes standard variance (deviation^2 * N) */ + \
     32 /*reserved*/ + 4 /*custom hdr size*/)




////////////////////////////////////////////////////////////////////////////////////////////////////

static iwrc _fsm_destroy_locks(_FSM *impl);
static iwrc _fsm_close_impl(_FSM* impl) ;

////////////////////////////////////////////////////////////////////////////////////////////////////

static iwrc _fsm_write(struct IWFS_FSM* f, off_t off, const void *buf, size_t siz, size_t *sp) {
    return 0;
}

static iwrc _fsm_read(struct IWFS_FSM* f, off_t off, void *buf, size_t siz, size_t *sp) {
    return 0;
}

static iwrc _fsm_close(struct IWFS_FSM* f) {
    _FSM_ENSURE_OPEN2(f);
    return _fsm_close_impl(f->impl);
}

static iwrc _fsm_close_impl(_FSM* impl) {
    iwrc rc = 0;
    IWRC(_fsm_destroy_locks(impl), rc);
    impl->f->impl = 0;
    impl->f = 0;
    free(impl);
    return rc;
}

static iwrc _fsm_sync(struct IWFS_FSM* f, iwfs_sync_flags flags) {
    return 0;
}

static iwrc _fsm_state(struct IWFS_FSM* f, IWFS_FSM_STATE* state) {
    return 0;
}

static iwrc _fsm_ensure_size(struct IWFS_FSM* f, off_t size) {
    return 0;
}

static iwrc _fsm_truncate(struct IWFS_FSM* f, off_t size) {
    return 0;
}

static iwrc _fsm_add_mmap(struct IWFS_FSM* f, off_t off, size_t maxlen) {
    return 0;
}

static iwrc _fsm_get_mmap(struct IWFS_FSM* f, off_t off, uint8_t **mm, size_t *sp) {
    return 0;
}

static iwrc _fsm_remove_mmap(struct IWFS_FSM* f, off_t off) {
    return 0;
}

static iwrc _fsm_sync_mmap(struct IWFS_FSM* f, off_t off, int flags) {
    return 0;
}

static iwrc _fsm_lock(struct IWFS_FSM* f, off_t start, off_t len, iwrl_lockflags lflags) {
    return 0;
}

static iwrc _fsm_try_lock(struct IWFS_FSM* f, off_t start, off_t len, iwrl_lockflags lflags) {
    return 0;
}

static iwrc _fsm_unlock(struct IWFS_FSM* f, off_t start, off_t len) {
    return 0;
}

static iwrc _fsm_lwrite(struct IWFS_FSM* f, off_t start, const void *buf, size_t siz, size_t *sp) {
    return 0;
}

static iwrc _fsm_lread(struct IWFS_FSM* f, off_t start, void *buf, size_t siz, size_t *sp) {
    return 0;
}

static iwrc _fsm_allocate(struct IWFS_FSM* f, off_t len, off_t *oaddr, off_t *olen, iwfs_fsm_aflags opts) {
    return 0;
}

static iwrc _fsm_deallocate(struct IWFS_FSM* f, off_t addr, off_t len) {
    return 0;
}

static iwrc _fsm_writehdr(struct IWFS_FSM* f, off_t off, const void *buf, off_t siz) {
    return 0;
}

static iwrc _fsm_readhdr(struct IWFS_FSM* f, off_t off, void *buf, off_t siz) {
    return 0;
}

static iwrc _fsm_clear(struct IWFS_FSM* f, iwfs_fsm_clrfalgs clrflags)  {
    return 0;
}

static iwrc _fsm_init_impl(_FSM *impl, const IWFS_FSM_OPTS *opts) {
    impl->bpow = opts->bpow;
    if (!impl->bpow) {
        impl->bpow = 6; //64bit block
    } else if (impl->bpow > _FSM_MAX_BLOCK_POW) { //Cannot use block greater than 1Mb
        return IWFS_ERROR_INVALID_BLOCK_SIZE;
    }
    impl->psize = iwp_page_size();
    impl->oflags = opts->oflags;
    return 0;
}

static iwrc _fsm_init_locks(_FSM *impl, const IWFS_FSM_OPTS *opts) {
    if (opts->oflags & IWFSM_NOLOCKS) {
        impl->ctlrwlk = 0;
        impl->fsmtx = 0;
        return 0;
    }
    int err;
    impl->ctlrwlk = calloc(1,
                           sizeof(*impl->ctlrwlk)
                           + sizeof(*impl->fsmtx));
    if (!impl->ctlrwlk) {
        return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
    impl->fsmtx = (pthread_mutex_t*)
                  ((char*) impl->ctlrwlk + sizeof(*impl->ctlrwlk));

    err = pthread_rwlock_init(impl->ctlrwlk, 0);
    if (err) {
        free(impl->ctlrwlk);
        impl->ctlrwlk = 0;
        impl->fsmtx = 0;
        return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, err);
    }
    err = pthread_mutex_init(impl->fsmtx, 0);
    if (err) {
        pthread_rwlock_destroy(impl->ctlrwlk);
        free(impl->ctlrwlk);
        impl->ctlrwlk = 0;
        impl->fsmtx = 0;
        return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, err);
    }
    return 0;
}

static iwrc _fsm_destroy_locks(_FSM *impl) {
    if (!impl->ctlrwlk) {
        return 0;
    }
    iwrc rc = 0;
    int err = pthread_mutex_destroy(impl->fsmtx);
    if (err) {
        IWRC(iwrc_set_errno(IW_ERROR_THREADING_ERRNO, err), rc);
    }
    err = pthread_rwlock_destroy(impl->ctlrwlk);;
    if (err) {
        IWRC(iwrc_set_errno(IW_ERROR_THREADING_ERRNO, err), rc);
    }
    free(impl->ctlrwlk);
    impl->ctlrwlk = 0;
    impl->fsmtx = 0;
    return rc;
}


static iwrc _fsm_init_new(_FSM *impl) {
    _FSM_ENSURE_OPEN(impl);
    iwrc rc = 0;
    size_t bmlen, bmoff;
    
    
    
    
    return rc;
}

static iwrc _fsm_init_existing(_FSM *impl) {
    return 0;
}


iwrc iwfs_fsmfile_open(IWFS_FSM *f,
                       const IWFS_FSM_OPTS *opts) {
    assert(f);
    assert(opts);
    iwrc rc = 0;
    IWFS_RWL_STATE rwl_state;
    const char *path = opts->rwlfile.exfile.file.path;

    if (!path) {
        return IW_ERROR_INVALID_ARGS;
    }
    memset(f, 0, sizeof(*f));
    _FSM *impl = f->impl = calloc(1, sizeof(*f->impl));
    if (!impl) {
        return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
    impl->f = f;

    f->write = _fsm_write;
    f->read = _fsm_read;
    f->close = _fsm_close;
    f->sync = _fsm_sync;
    f->state = _fsm_state;

    f->ensure_size = _fsm_ensure_size;
    f->truncate = _fsm_truncate;
    f->add_mmap = _fsm_add_mmap;
    f->get_mmap = _fsm_get_mmap;
    f->remove_mmap = _fsm_remove_mmap;
    f->sync_mmap = _fsm_sync_mmap;

    f->lock = _fsm_lock;
    f->try_lock = _fsm_try_lock;
    f->unlock = _fsm_unlock;
    f->lwrite = _fsm_lwrite;
    f->lread = _fsm_lread;

    f->allocate = _fsm_allocate;
    f->deallocate = _fsm_deallocate;
    f->writehdr = _fsm_writehdr;
    f->readhdr = _fsm_readhdr;
    f->clear = _fsm_clear;

    memset(&rwl_state, 0,  sizeof(rwl_state));

    IWFS_RWL_OPTS rwl_opts = opts->rwlfile;
    rwl_opts.exfile.use_locks = 0;

    rc = _fsm_init_impl(impl, opts);
    if (rc) goto finish;

    rc = _fsm_init_locks(impl, opts);
    if (rc) goto finish;

    rc = iwfs_rwlfile_open(&impl->rwl, &rwl_opts);
    if (rc) goto finish;

    rc = impl->rwl.state(&impl->rwl, &rwl_state);
    if (rc) goto finish;

    if (rwl_state.exfile.fstate.ostatus & IWFS_OPEN_NEW) {
        rc = _fsm_init_new(impl);
    } else {
        rc = _fsm_init_existing(impl);
    }

finish:
    if (rc) {
        if (impl) {
            IWRC(_fsm_close_impl(impl), rc);
            f->impl = 0;
        }
    }
    return rc;
}

static const char* _fsmfile_ecodefn(locale_t locale, uint32_t ecode) {
    if (!(ecode > _IWFS_FSM_ERROR_START && ecode < _IWFS_FSM_ERROR_END)) {
        return 0;
    }
    switch (ecode) {
        case IWFS_ERROR_NO_FREE_SPACE:
            return "No free space. (IWFS_ERROR_NO_FREE_SPACE)";
        case IWFS_ERROR_INVALID_BLOCK_SIZE:
            return "Invalid block size specified. (IWFS_ERROR_INVALID_BLOCK_SIZE)";
    }
    return 0;
}

iwrc iwfs_fsmfile_init(void) {
    static int _fsmfile_initialized = 0;
    if (!__sync_bool_compare_and_swap(&_fsmfile_initialized, 0, 1)) {
        return 0; //initialized already
    }
    return iwlog_register_ecodefn(_fsmfile_ecodefn);
}
