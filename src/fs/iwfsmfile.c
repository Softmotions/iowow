
#include "iwfsmfile.h"
#include "log/iwlog.h"
#include "platform/iwp.h"
#include "utils/iwutils.h"
#include "utils/kbtree.h"
#include "utils/iwbits.h"

#include "iwcfg.h"
#include <pthread.h>

typedef struct IWFS_FSM_IMPL _FSM;

/**
 * Free-space blocks-tree key.
 */
typedef struct {
    /* uint64 offset|length data, chunked in bytes in order to save padding memory in each fsm tree node
      #pragma pack not used to avoid portability issues */
    uint8_t b[8];
    /* Position of divider bit in the block offset|length data. */
    uint8_t div;
} _FSMBK;

/** Additional options for `_fsm_set_bit_status_lw` routine */
typedef enum {
    /**< No options. */
    _FSM_BM_NONE = 0,
    /**< Do not modify bitmap. */
    _FSM_BM_DRY_RUN = 1,
    /**< Perform strict checking of bitmap consistency */
    _FSM_BM_STRICT = 1 << 1
} _fsm_bmopts;

////////////////////////////////////////////////////////////////////////////////////////////////////

static iwrc _fsm_destroy_locks(_FSM *impl);
static iwrc _fsm_close_impl(_FSM* impl) ;
IW_INLINE int _fsm_cmp(_FSMBK a, _FSMBK b);
IW_INLINE iwrc _fsm_ctrl_wlock(_FSM *impl);
IW_INLINE iwrc _fsm_ctrl_rlock(_FSM *impl);

////////////////////////////////////////////////////////////////////////////////////////////////////

static const uint64_t _FSM_ZERO8 = 0;
static const uint64_t _FSM_ONE8 = (uint64_t)(-1);
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
     8 /*number of allocated block with largest offset.*/ + \
     8 /*cumulative record sizes sum */ + 4 /*cumulative record sizes num */ + \
     8 /*record sizes standard variance (deviation^2 * N) */ + \
     32 /*reserved*/ + 4 /*custom hdr size*/)

#define _FSM_ENSURE_OPEN(FSM_impl_) \
    if (!(FSM_impl_) || !(FSM_impl_)->f) \
        return IW_ERROR_INVALID_STATE;

#define _FSM_ENSURE_OPEN2(FSM_f_) \
    if (!(FSM_f_) || !(FSM_f_)->impl) \
        return IW_ERROR_INVALID_STATE;

#define _FSMBK_RESET(Bk_) \
    memset((Bk_), 0, sizeof(*(Bk_)))

#define _FSMBK_I64(Bk_) \
    (*((uint64_t*) (Bk_)))

#define _FSMBK_OFFSET(Bk_) \
    (_FSMBK_I64(Bk_) & ((((uint64_t) 1) << (Bk_)->div) - 1))

#define _FSMBK_LENGTH(Bk_) \
    ((Bk_)->div ? ((_FSMBK_I64(Bk_) >> (Bk_)->div) & ((((uint64_t) 1) << (64 - (Bk_)->div)) - 1)) : _FSMBK_I64(Bk_))

#define _FSMBK_END(Bk_) \
    (_FSMBK_OFFSET(Bk_) + _FSMBK_LENGTH(Bk_))

////////////////////////////////////////////////////////////////////////////////////////////////////

KBTREE_INIT(fsm, _FSMBK, _fsm_cmp)

struct IWFS_FSM_IMPL {
    IWFS_RWL                pool;       /**< Underlying rwl file. */
    uint64_t                bmlen;      /**< Free-space bitmap block length in bytes. */
    uint64_t                bmoff;      /**< Free-space bitmap block offset in bytes. */
    uint64_t                lfbkoff;    /**< Offset of free block chunk with the largest offset. */
    uint64_t                lfbklen;    /**< Length of free block chunk with the largest offset. */
    uint64_t                crzsum;     /**< Cumulative sum of record sizes acquired by `allocate` */
    uint64_t                crzvar;     /**< Record sizes standard variance (deviation^2 * N) */
    uint32_t                hdrlen;     /**< Length of custom file header */
    uint32_t                crznum;     /**< Cumulative number of records acquired by `allocated` */
    IWFS_FSM                *f;         /**< Self reference. */
    kbtree_t(fsm)           *fsm;       /**< Free-space tree */
    uint64_t                *bmptr;     /**< Pointer to the bitmap area */
    pthread_rwlock_t        *ctlrwlk;   /**< Methods RW lock */
    pthread_mutex_t         *fsmtx;     /**< Free-space bitmap mutex */
    size_t                  psize;      /**< System page size */
    iwfs_fsm_openflags      oflags;     /**< Open flags. */
    iwfs_omode              omode;      /**< Open mode. */
    uint8_t                 bpow;       /**< Block size power of 2 */
};

////////////////////////////////////////////////////////////////////////////////////////////////////

IW_INLINE int _fsm_cmp(_FSMBK a, _FSMBK b) {
    uint64_t la = _FSMBK_LENGTH(&a);
    uint64_t lb = _FSMBK_LENGTH(&b);
    int ret = ((lb < la) - (la < lb));
    if (ret) {
        return ret;
    } else {
        uint64_t oa = _FSMBK_OFFSET(&a);
        uint64_t ob = _FSMBK_OFFSET(&b);
        return ((ob < oa) - (oa < ob));
    }
}

IW_INLINE iwrc _fsm_ctrl_wlock(_FSM *impl) {
    int err = impl->ctlrwlk ? pthread_rwlock_wrlock(impl->ctlrwlk) : 0;
    return (err ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, err) : 0);
}

IW_INLINE iwrc _fsm_ctrl_rlock(_FSM *impl) {
    int err = impl->ctlrwlk ? pthread_rwlock_rdlock(impl->ctlrwlk) : 0;
    return (err ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, err) : 0);
}

IW_INLINE iwrc _fsm_ctrl_unlock(_FSM *impl) {
    int err = impl->ctlrwlk ? pthread_rwlock_unlock(impl->ctlrwlk) : 0;
    return (err ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, err) : 0);
}

/**
 * @brief Remove all free blocks from the and of file and trim its size.
 */
static iwrc _fsm_trim_tail_lw(_FSM *impl) {
    iwrc rc;
    uint64_t offset, lastblk;
    int64_t length;
    int hasleft;

    if (!(impl->omode & IWFS_OWRITE)) {
        return 0;
    }
    /* find free space for fsm with lesser offset than actual */
//    rc = _fsm_blk_allocate_aligned_lw(impl,
//                                      (impl->bmlen >> impl->bpow), &offset, &length,
//                                      (impl->bmoff >> impl->bpow),
//                                      IWFSM_ALLOC_NO_EXTEND |
//                                      IWFSM_ALLOC_NO_OVERALLOCATE |
//                                      IWFSM_ALLOC_NO_STATS);
                                      
                                
    return 0;
}


static iwrc _fsm_init_impl(_FSM *impl, const IWFS_FSM_OPTS *opts) {
    impl->oflags = opts->oflags;
    impl->psize = iwp_page_size();
    impl->bpow = opts->bpow;
    if (!impl->bpow) {
        impl->bpow = 6; //64bit block
    } else if (impl->bpow > _FSM_MAX_BLOCK_POW) {
        return IWFS_ERROR_INVALID_BLOCK_SIZE;
    } else if ((1 << impl->bpow) > impl->psize) {
        return IWFS_ERROR_PLATFORM_PAGE;
    }
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

/**
 * @brief Set the allocation bits in the fsm bitmap.
 *
 * @param impl
 * @param offset_bits Bit offset in the bitmap.
 * @param length_bits Number of bits to set
 * @param bit_status  If `1` bits will be set to `1` otherwise `0`
 * @param opts        Operation options
 */
static iwrc _fsm_set_bit_status_lw(_FSM *impl,
                                   uint64_t offset_bits,
                                   int64_t length_bits,
                                   int bit_status,
                                   _fsm_bmopts opts) {
    iwrc rc;
    uint64_t bend = offset_bits + length_bits;
    uint8_t *mmap;
    uint64_t sp, *p, set_mask;
    int set_bits;

    if (bend < offset_bits) {
        return IW_ERROR_OUT_OF_BOUNDS;
    }
    rc = impl->pool.get_mmap(&impl->pool, impl->bmoff, &mmap, &sp);
    if (rc) {
        iwlog_ecode_error3(rc);
        return rc;
    }
    p = ((uint64_t*) mmap) + offset_bits / 64;
    set_bits = 64 - (offset_bits & (64 - 1));
    set_mask = (~((uint64_t) 0) << (offset_bits & (64 - 1)));
    while (length_bits - set_bits >= 0) {
        if (bit_status) {
            if ((opts & _FSM_BM_STRICT) && (*p & set_mask)) {
                rc = IWFS_ERROR_FSM_SEGMENTATION;
            }
            if ((opts & _FSM_BM_DRY_RUN) == 0) {
                *p |= set_mask;
            }
        } else {
            if ((opts & _FSM_BM_STRICT) && ((*p & set_mask) != set_mask)) {
                rc = IWFS_ERROR_FSM_SEGMENTATION;
            }
            if ((opts & _FSM_BM_DRY_RUN) == 0) {
                *p &= ~set_mask;
            }
        }
        length_bits -= set_bits;
        set_bits = 64;
        set_mask = ~((uint64_t) 0);
        p++;
    }
    if (length_bits) {
        set_mask &= (bend & (64 - 1)) ? ((((uint64_t) 1) << (bend & (64 - 1))) - 1) : ~((uint64_t) 0);
        if (bit_status) {
            if ((opts & opts & _FSM_BM_STRICT) && (*p & set_mask)) {
                rc = IWFS_ERROR_FSM_SEGMENTATION;
            }
            if ((opts & _FSM_BM_DRY_RUN) == 0) {
                *p |= set_mask;
            }
        } else {
            if ((opts & _FSM_BM_STRICT) && (*p & set_mask) != set_mask) {
                rc = IWFS_ERROR_FSM_SEGMENTATION;
            }
            if ((opts & _FSM_BM_DRY_RUN) == 0) {
                *p &= ~set_mask;
            }
        }
    }
    return rc;
}

/**
 * @brief Init the given @a bk key with given @a offset and @a length values.
 */
IW_INLINE iwrc _fsm_init_fbk(_FSMBK *bk, uint64_t offset, uint64_t len) {
    uint64_t apply = 0;
    if (offset) {
        bk->div = iwbits_find_last_sbit64(offset) + 1;
        if (len & ~(~((uint64_t) 0) >> bk->div)) {
            iwlog_ecode_error3(IW_ERROR_OVERFLOW);
            return IW_ERROR_OVERFLOW;
        }
        apply |= len;
        apply <<= bk->div;
        apply |= offset;
    } else {
        bk->div = 0;
        apply = len;
    }
    memcpy(bk, &apply, sizeof(apply));
    return 0;
}

/**
 * @brief Remove free space from the fsm tree.
 * @param impl `_FSM`
 * @param offset_blk Offset block number
 * @param length_blk Number of blocks
 */
IW_INLINE iwrc _fsm_del_fbk(_FSM *impl, uint64_t offset_blk, uint64_t length_blk) {
    _FSMBK fbk;
    assert(length_blk);
    iwrc rc = _fsm_init_fbk(&fbk, offset_blk, length_blk);
    if (rc) {
        return rc;
    }
    kb_delp(fsm, impl->fsm, &fbk);
    if (_FSMBK_OFFSET(&fbk) == impl->lfbkoff) {
        impl->lfbkoff = 0;
        impl->lfbklen = 0;
    }
    return 0;
}

/**
 * @brief Deregister free-block chunk from the fsm tree.
 * @param impl `_FSM`
 * @param fbk `_FSMBK` Fsm tree key structure.
 */
IW_INLINE void _fsm_del_fbk2(_FSM *impl, const _FSMBK fbk) {
    kb_delp(fsm, impl->fsm, &fbk);
    if (_FSMBK_OFFSET(&fbk) == impl->lfbkoff) {
        impl->lfbkoff = 0;
        impl->lfbklen = 0;
    }
}

/**
 * @brief Register free space block in the fsm tree.
 * @param impl `_FSM`
 * @param offset_blk Offset block number
 * @param length_blk Number of blocks
 */
IW_INLINE iwrc _fsm_put_fbk(_FSM *impl, uint64_t offset_blk, uint64_t length_blk) {
    _FSMBK fbk;
    assert(length_blk);
    iwrc rc = _fsm_init_fbk(&fbk, offset_blk, length_blk);
    if (rc) {
        return rc;
    }
    kb_putp(fsm, impl->fsm, &fbk);
    if (offset_blk + length_blk >= impl->lfbkoff + impl->lfbklen) {
        impl->lfbkoff = offset_blk;
        impl->lfbklen = length_blk;
    }
    return 0;
}

/**
 * @brief Find a free-space chunk in the fsm tree.
 * @param impl `_FSM`
 * @param offset_blk Offset block number
 * @param length_blk Number of blocks
 */
IW_INLINE _FSMBK* _fsm_get_fbk(_FSM *impl, uint64_t offset_blk, uint64_t length_blk) {
    _FSMBK fbk;
    assert(length_blk);
    iwrc rc  = _fsm_init_fbk(&fbk, offset_blk, length_blk);
    if (rc) {
        return 0;
    }
    return kb_getp(fsm, impl->fsm, &fbk);
}

/**
 * @brief Load existing bitmap area into free-space search tree.
 * @param impl  `_FSM`
 * @param bm    Bitmap area start ptr
 * @param len   Bitmap area length in bytes.
 */
static void _fsm_load_fsm_lw(_FSM *impl, uint8_t *bm, uint64_t len) {
    uint64_t b, bnum = len << 3, cbnum = 0, fbklength = 0, fbkoffset = 0;
    int i;
    if (impl->fsm) {
        kb_destroy(fsm, impl->fsm);
    }
    impl->fsm = kb_init(fsm, KB_DEFAULT_SIZE);
    for (b = 0; b < len; ++b) {
        uint8_t bb = bm[b];
        if (bb == 0) {
            fbklength += 8;
            cbnum += 8;
            continue;
        }
        for (i = 0; i < 8; ++i, ++cbnum) {
            if ((bb & (1 << i)) != 0) {
                if (fbklength > 0) {
                    fbkoffset = cbnum - fbklength;
                    _fsm_put_fbk(impl, fbkoffset, fbklength);
                    fbklength = 0;
                }
            } else {
                fbklength++;
            }
        }
    }
    if (fbklength > 0) {
        fbkoffset = bnum - fbklength;
        _fsm_put_fbk(impl, fbkoffset, fbklength);
    }
}

static iwrc _fsm_read_meta_lr(_FSM *impl) {
    iwrc rc;
    uint8_t hdr[_FSM_CUSTOM_HDR_DATA_OFFSET] = {0};
    uint32_t lnum;
    uint64_t llnum;
    size_t sp, rp = 0;

    assert(impl);

    /*
        [FSM_CTL_MAGICK u32][block pow u8][num blocks u64]
        [bmoffset u64][bmlength u64]
        [u64 crzsum][u32 crznum][u64 crszvar][u256 reserved]
        [custom header size u32][custom header data...]
        [fsm data...]
    */
    rc = impl->pool.read(&impl->pool, 0, hdr, _FSM_CUSTOM_HDR_DATA_OFFSET, &sp);
    if (rc) {
        iwlog_ecode_error3(rc);
        return rc;
    }

    /* Magic */
    memcpy(&lnum, hdr + rp, sizeof(lnum));
    lnum = IW_ITOHL(lnum);
    if (lnum != _FSM_MAGICK) {
        rc = IWFS_ERROR_INVALID_FILEMETA;
        iwlog_ecode_error2(rc, "Invalid file magic number");
        return rc;
    }
    rp += sizeof(lnum);

    /* Block pow */
    assert(sizeof(impl->bpow) == 1);
    memcpy(&impl->bpow, hdr + rp, sizeof(impl->bpow));
    rp += sizeof(impl->bpow);

    if (impl->bpow > _FSM_MAX_BLOCK_POW) {
        rc = IWFS_ERROR_INVALID_FILEMETA;
        iwlog_ecode_error(rc, "Invalid file blocks pow: %u", impl->bpow);
        return rc;
    }
    if ((1 << impl->bpow) > impl->psize) {
        rc = IWFS_ERROR_PLATFORM_PAGE;
        iwlog_ecode_error(rc, "Block size: %d must not be greater than the system page size: %d",
                          (int)(1 << impl->bpow), (int) impl->psize);
    }

    /* Free-space bitmap offset */
    memcpy(&llnum, hdr + rp, sizeof(llnum));
    llnum = IW_ITOHLL(llnum);
    impl->bmoff = llnum;
    rp += sizeof(llnum);

    /* Free-space bitmap length */
    memcpy(&llnum, hdr + rp, sizeof(llnum));
    llnum = IW_ITOHLL(llnum);
    impl->bmlen = llnum;
    if (llnum & (64 - 1)) {
        rc = IWFS_ERROR_INVALID_FILEMETA;
        iwlog_ecode_error(rc, "Free-space bitmap length is not 64bit aligned: %" PRIuMAX "", impl->bmlen);
    }
    rp += sizeof(llnum);

    /* Cumulative sum of record sizes acquired by `allocate` */
    memcpy(&llnum, hdr + rp, sizeof(llnum));
    llnum = IW_ITOHLL(llnum);
    impl->crzsum = llnum;
    rp += sizeof(llnum);

    /* Cumulative number of records acquired by `allocated` */
    memcpy(&lnum, hdr + rp, sizeof(lnum));
    lnum = IW_ITOHL(lnum);
    impl->crznum = lnum;
    rp += sizeof(lnum);

    /* Record sizes standard variance (deviation^2 * N) */
    memcpy(&llnum, hdr + rp, sizeof(llnum));
    llnum = IW_ITOHLL(llnum);
    impl->crzvar = llnum;
    rp += sizeof(llnum);

    /* Reserved */
    rp += 32;

    /* Header size */
    memcpy(&lnum, hdr + rp, sizeof(lnum));
    lnum = IW_ITOHL(lnum);
    impl->hdrlen = lnum;
    rp += sizeof(lnum);

    return rc;
}

/**
 * @brief Flush a current `iwfsmfile` metadata into the file header.
 * @param impl
 * @param is_sync If `1` perform mmap sync.
 * @return
 */
static iwrc _fsm_write_meta_lw(_FSM *impl, int is_sync) {

    uint8_t hdr[_FSM_CUSTOM_HDR_DATA_OFFSET] = {0};
    uint32_t sp = 0, lvalue;
    uint64_t llvalue;
    size_t wlen;

    assert(impl);

    /*
        [FSM_CTL_MAGICK u32][block pow u8][num blocks u64]
        [bmoffset u64][bmlength u64]
        [u64 crzsum][u32 crznum][u64 crszvar][u256 reserved]
        [custom header size u32][custom header data...]
        [fsm data...]
    */

    /* Magic */
    lvalue = IW_HTOIL(_FSM_MAGICK);
    assert(sp + sizeof(lvalue) <= _FSM_CUSTOM_HDR_DATA_OFFSET);
    memcpy(hdr + sp, &lvalue, sizeof(lvalue));
    sp += sizeof(lvalue);

    /* Block pow */
    assert(sizeof(impl->bpow) == 1);
    assert(sp + sizeof(impl->bpow) <= _FSM_CUSTOM_HDR_DATA_OFFSET);
    memcpy(hdr + sp, &impl->bpow, sizeof(impl->bpow));
    sp += sizeof(impl->bpow);

    /* Free-space bitmap offset */
    llvalue = impl->bmoff;
    llvalue = IW_HTOILL(llvalue);
    assert(sp + sizeof(llvalue) <= _FSM_CUSTOM_HDR_DATA_OFFSET);
    memcpy(hdr + sp, &llvalue, sizeof(llvalue));
    sp += sizeof(llvalue);

    /* Free-space bitmap length */
    llvalue = impl->bmlen;
    llvalue = IW_HTOILL(llvalue);
    assert(sp + sizeof(llvalue) <= _FSM_CUSTOM_HDR_DATA_OFFSET);
    memcpy(hdr + sp, &llvalue, sizeof(llvalue));
    sp += sizeof(llvalue);

    /* Cumulative sum of record sizes acquired by `allocate` */
    llvalue = impl->crzsum;
    llvalue = IW_HTOILL(llvalue);
    assert(sp + sizeof(llvalue) <= _FSM_CUSTOM_HDR_DATA_OFFSET);
    memcpy(hdr + sp, &llvalue, sizeof(llvalue));
    sp += sizeof(llvalue);

    /* Cumulative number of records acquired by `allocated` */
    lvalue = impl->crznum;
    lvalue = IW_HTOIL(lvalue);
    assert(sp + sizeof(lvalue) <= _FSM_CUSTOM_HDR_DATA_OFFSET);
    memcpy(hdr + sp, &lvalue, sizeof(lvalue));
    sp += sizeof(lvalue);

    /* Record sizes standard variance (deviation^2 * N) */
    llvalue = impl->crzvar;
    llvalue = IW_HTOILL(llvalue);
    assert(sp + sizeof(lvalue) <= _FSM_CUSTOM_HDR_DATA_OFFSET);
    memcpy(hdr + sp, &llvalue, sizeof(llvalue));
    sp += sizeof(llvalue);

    /* Reserved */
    sp += 32;

    /* Size of header */
    lvalue = impl->hdrlen;
    lvalue = IW_HTOIL(lvalue);
    assert(sp + sizeof(lvalue) <= _FSM_CUSTOM_HDR_DATA_OFFSET);
    memcpy(hdr + sp, &lvalue, sizeof(lvalue));
    sp += sizeof(lvalue);

    assert(sp <= _FSM_CUSTOM_HDR_DATA_OFFSET);
    iwrc rc = impl->pool.write(&impl->pool, 0, hdr, _FSM_CUSTOM_HDR_DATA_OFFSET, &wlen);
    if (!rc) {
        rc = impl->pool.sync_mmap(&impl->pool, 0, 0);
    }
    return rc;
}

/**
 * @brief Search for the first previous set bit position
 *        starting from the specified offset_bit (EXCLUDED).
 */
static uint64_t _fsm_find_prev_set_bit(const uint64_t *addr,
                                       uint64_t offset_bit,
                                       uint64_t min_offset_bit,
                                       int *found) {
    const uint64_t *p;
    uint64_t bit, tmp, size;
    *found = 0;
    if (min_offset_bit >= offset_bit) {
        return 0;
    }
    size = offset_bit - min_offset_bit;
    bit = offset_bit & (64 - 1);
    p = addr + offset_bit / 64;
    if (bit) {
        tmp = (iwbits_reverse_64(*p) >> (64 - bit));
        if (tmp) {
            tmp = iwbits_find_first_sbit64(tmp);
            if (tmp >= size) {
                return 0;
            } else {
                *found = 1;
                assert(offset_bit > tmp);
                return offset_bit > tmp ? offset_bit - tmp - 1 : 0;
            }
        }
        offset_bit -= bit;
        size -= bit;
    }
    while (size & ~(64 - 1)) {
        if ((tmp = *(--p))) {
            *found = 1;
            tmp = iwbits_find_first_sbit64(iwbits_reverse_64(*p));
            assert(offset_bit > tmp);
            return offset_bit > tmp ? offset_bit - tmp - 1 : 0;
        }
        offset_bit -= 64;
        size -= 64;
    }
    if (size == 0) {
        return 0;
    }
    tmp = iwbits_reverse_64(*(--p)) & ((((uint64_t) 1) << size) - 1);
    if (tmp) {
        uint64_t tmp2;
        *found = 1;
        tmp2 = iwbits_find_first_sbit64(tmp);
        assert(offset_bit > tmp2);
        return offset_bit > tmp2 ? offset_bit - tmp2 - 1 : 0;
    } else {
        return 0;
    }
}

/**
 * @brief Search for the first next set bit position
 *        starting from the specified offset bit (INCLUDED).
 */
static uint64_t _fsm_find_next_set_bit(const uint64_t *addr,
                                       uint64_t offset_bit,
                                       uint64_t max_offset_bit,
                                       int *found) {
    uint64_t size, bit, tmp;
    const uint64_t *p = addr + offset_bit / 64;
    *found = 0;
    if (offset_bit >= max_offset_bit) {
        return 0;
    }
    bit = offset_bit & (64 - 1);
    offset_bit -= bit;
    size = max_offset_bit - offset_bit;
    if (bit) {
        tmp = *p & (~((uint64_t) 0) << bit);
        if (tmp) {
            tmp = iwbits_find_first_sbit64(tmp);
            if (tmp >= size) {
                return 0;
            } else {
                *found = 1;
                return offset_bit + tmp;
            }
        }
        if (size <= 64) {
            return 0;
        }
        offset_bit += 64;
        size -= 64;
        p++;
    }
    while (size & ~(64 - 1)) {
        if ((tmp = *(p++))) {
            *found = 1;
            return offset_bit + iwbits_find_first_sbit64(tmp);
        }
        offset_bit += 64;
        size -= 64;
    }
    if (!size) {
        return 0;
    }
    tmp = (*p) & (~((uint64_t) 0) >> (64 - size));
    if (tmp) {
        *found = 1;
        return offset_bit + iwbits_find_first_sbit64(tmp);
    } else {
        return 0;
    }
}

/**
 * @brief Return a previously allocated blocks
 *        back into the free-blocks pool.
 *
 * @param impl `_FSM`
 * @param offset_blk Starting block number of the specified range.
 * @param length_blk Range size in blocks.
 */
static iwrc _fsm_blk_deallocate_lw(_FSM *impl, uint64_t offset_blk, int64_t length_blk) {
    iwrc rc;
    uint64_t left, right;
    int hasleft = 0, hasright = 0;
    uint64_t key_offset = offset_blk, key_length = length_blk;
    uint64_t rm_offset = 0, rm_length = 0;
    uint64_t *addr = impl->bmptr;
    _fsm_bmopts bopts = 0;

    if (impl->oflags & IWFSM_STRICT) {
        bopts |= _FSM_BM_STRICT;
    }
    rc = _fsm_set_bit_status_lw(impl, offset_blk, length_blk, 0, bopts);
    if (rc) {
        return rc;
    }
    /* Merge with neighborhoods */
    left = _fsm_find_prev_set_bit(addr, offset_blk, 0, &hasleft);
    if (impl->lfbkoff > 0 && impl->lfbkoff == offset_blk + length_blk) {
        right = impl->lfbkoff + impl->lfbklen;
        hasright = 1;
    } else {
        right = _fsm_find_next_set_bit(addr, offset_blk + length_blk, impl->lfbkoff, &hasright);
    }
    if (hasleft) {
        if (offset_blk > left + 1) {
            left += 1;
            rm_offset = left;
            rm_length = offset_blk - left;
            assert(_fsm_get_fbk(impl, rm_offset, rm_length));
            IWRC(_fsm_del_fbk(impl, rm_offset, rm_length), rc);
            key_offset = rm_offset;
            key_length += rm_length;
        }
    } else if (offset_blk > 0) { /* zero start */
        rm_offset = 0;
        rm_length = offset_blk;
        assert(_fsm_get_fbk(impl, rm_offset, rm_length));
        IWRC(_fsm_del_fbk(impl, rm_offset, rm_length), rc);
        key_offset = rm_offset;
        key_length += rm_length;
    }
    if (hasright && right > offset_blk + length_blk) {
        rm_offset = offset_blk + length_blk;
        rm_length = right - (offset_blk + length_blk);
        assert(_fsm_get_fbk(impl, rm_offset, rm_length));
        _fsm_del_fbk(impl, rm_offset, rm_length);
        key_length += rm_length;
    }
    IWRC(_fsm_put_fbk(impl, key_offset, key_length), rc);
    return rc;
}


/**
 * @brief Initialize a new free-space bitmap area.
 *
 * If bitmap exists, its content will be moved into newly created area.
 * Blocks from previous bitmap are will disposed and diallocated.
 *
 * @param impl `_FSM`
 * @param bmoff Byte offset of the new bitmap. Value must be page aligned.
 * @param bmlen Byte length of the new bitmap. Value must be page aligned.
                Its length must not be lesser than length of old bitmap.
 */
static iwrc _fsm_init_lw(_FSM *impl, uint64_t bmoff, uint64_t bmlen) {
    iwrc rc;
    uint8_t *mmap, *mmap2;
    uint64_t sp, sp2;
    uint64_t old_bmoff, old_bmlen;
    IWFS_RWL *pool = &impl->pool;
    size_t psize = impl->psize;

    if ((bmlen & ((1 << impl->bpow) - 1)) ||
            (bmoff & ((1 << impl->bpow) - 1)) ||
            (bmoff & (psize - 1)))  {
        return IWFS_ERROR_RANGE_NOT_ALIGNED;
    }

    if (bmlen < impl->bmlen) {
        rc = IW_ERROR_INVALID_ARGS;
        iwlog_ecode_error(rc,
                          "Length of the newly initiated bitmap area (bmlen): %" PRIu64
                          " must not be less than current bitmap area length %" PRIu64 "",
                          bmlen, impl->bmlen);
        return rc;
    }

    if (bmlen * 8 < ((bmoff + bmlen) >> impl->bpow) + 1) {
        rc = IW_ERROR_INVALID_ARGS;
        iwlog_ecode_error(rc,
                          "Length of the newly initiated bitmap area (bmlen): %" PRIu64
                          " is not enough to handle bitmap itself and the file header area.", bmlen);
        return rc;
    }

    rc = pool->get_mmap(pool, bmoff, &mmap, &sp);
    if (rc) {
        iwlog_ecode_error2(rc, "Fail to mmap fsm bitmap area");
        return rc;
    }
    if (sp < bmlen) {
        rc = IWFS_ERROR_NOT_MMAPED;
        iwlog_ecode_error2(rc, "Fail to mmap fsm bitmap area");
    }

    if (impl->bmlen) {
        /* We have an old active bitmap. Lets copy its content to the new location. */
        if (IW_RANGES_OVERLAP(impl->bmoff, impl->bmoff + impl->bmlen,
                              bmoff, bmoff + bmlen)) {
            rc = IW_ERROR_INVALID_ARGS;
            iwlog_ecode_error2(rc, "New and old bitmap areas are overlapping");
            return rc;
        }
        rc = pool->get_mmap(pool, impl->bmoff, &mmap2, &sp2);
        if (rc) {
            iwlog_ecode_error2(rc, "Old bitmap area is not mmaped");
            return rc;
        }
        assert(sp >= sp2);
        assert(!(sp2 & ((1 << impl->bpow) - 1)));
        assert(!((sp2 - sp) & ((1 << impl->bpow) - 1)));
        memcpy(mmap, mmap2, sp2);
        if (sp > sp2) {
            memset(mmap + sp2, 0, sp - sp2);
        }
    } else {
        memset(mmap, 0, sp);
    }

    /* Backup the previous bitmap range */
    old_bmlen = impl->bmlen;
    old_bmoff = impl->bmoff;

    impl->bmoff = bmoff;
    impl->bmlen = bmlen;
    impl->bmptr = (uint64_t*) mmap;

    rc = _fsm_set_bit_status_lw(impl, (bmoff >> impl->bpow), (bmlen >> impl->bpow), 1, _FSM_BM_NONE);
    if (rc) {
        iwlog_ecode_error3(rc);
        goto rollback;
    }
    if (!old_bmlen) { /* First time initialization */
        /* Header allocation */
        rc = _fsm_set_bit_status_lw(impl, 0, (impl->hdrlen >> impl->bpow), 1, _FSM_BM_NONE);
        if (rc) {
            iwlog_ecode_error3(rc);
            goto rollback;
        }
    }
    /* Reload the fsm tree */
    _fsm_load_fsm_lw(impl, mmap, sp);

    /* Sync fsm */
    rc = pool->sync_mmap(pool, bmoff, 0);
    if (rc) {
        iwlog_ecode_error3(rc);
        goto rollback;
    }

    /* Flush new meta */
    rc = _fsm_write_meta_lw(impl, 1);
    if (rc) {
        iwlog_ecode_error3(rc);
        goto rollback;
    }

    if (old_bmlen) {
        /* Now we are save to deallocate the old bitmap */
        rc = _fsm_blk_deallocate_lw(impl, (old_bmoff >> impl->bpow), (old_bmlen >> impl->bpow));
        pool->remove_mmap(pool, old_bmoff);
    }
    return rc;

rollback: /* try to rollback bitmap state */
    impl->bmoff = old_bmoff;
    impl->bmlen = old_bmlen;
    if (old_bmlen > 0) {
        impl->bmptr = (uint64_t*) mmap2;
        _fsm_load_fsm_lw(impl, mmap2, sp2);
    }
    pool->sync_mmap(pool, 0, 0);
    return rc;
}

static iwrc _fsm_init_new(_FSM *impl, const IWFS_FSM_OPTS *opts) {
    _FSM_ENSURE_OPEN(impl);
    iwrc rc;
    uint64_t bmlen, bmoff;
    IWFS_RWL *pool = &impl->pool;

    assert(impl->psize && impl->bpow);

    impl->hdrlen = opts->hdrlen + _FSM_CUSTOM_HDR_DATA_OFFSET;
    impl->hdrlen = IW_ROUNDUP(impl->hdrlen, 1 << impl->bpow);

    bmlen = opts->bmlen > 0 ? IW_ROUNDUP(opts->bmlen, impl->psize) : impl->psize;
    bmoff = IW_ROUNDUP(impl->hdrlen, impl->psize);

    rc = pool->ensure_size(pool, bmoff + bmlen);
    if (rc) return rc;

    /* mmap header */
    rc = pool->add_mmap(pool, 0, impl->hdrlen);
    if (rc) return rc;

    /* mmap the fsm bitmap index */
    rc = pool->add_mmap(pool, bmoff, bmlen);
    if (rc) return rc;

    return _fsm_init_lw(impl, bmoff, bmlen);
}

static iwrc _fsm_init_existing(_FSM *impl) {
    _FSM_ENSURE_OPEN(impl);
    iwrc rc;
    uint8_t *mmap;
    size_t sp;
    IWFS_RWL *pool = &impl->pool;

    rc = _fsm_read_meta_lr(impl);
    if (rc) return rc;

    /* mmap the header part of file */
    rc = pool->add_mmap(pool, 0, impl->hdrlen);
    if (rc) return rc;

    /* mmap the fsm bitmap index */
    rc = pool->add_mmap(pool, impl->bmoff, impl->bmlen);
    if (rc) return rc;

    rc = pool->get_mmap(pool, impl->bmoff, &mmap, &sp);
    if (rc) return rc;

    if (sp < impl->bmlen) {
        rc = IWFS_ERROR_NOT_MMAPED;
        iwlog_ecode_error2(rc, "Fail to mmap fsm bitmap area");
        return rc;
    }
    impl->bmptr = (uint64_t*) mmap;
    _fsm_load_fsm_lw(impl, mmap, impl->bmlen);
    return 0;
}


/*************************************************************************************************
 *                                  Public API                                                   *
 *************************************************************************************************/


static iwrc _fsm_write(struct IWFS_FSM* f, off_t off, const void *buf, size_t siz, size_t *sp) {
    return 0;
}

static iwrc _fsm_read(struct IWFS_FSM* f, off_t off, void *buf, size_t siz, size_t *sp) {
    return 0;
}

static iwrc _fsm_close(struct IWFS_FSM* f) {
    _FSM_ENSURE_OPEN2(f);
    _FSM *impl = f->impl;
    iwrc rc = 0;
    IWRC(_fsm_ctrl_wlock(impl), rc);
    if (impl->omode & IWFS_OWRITE) {
        IWRC(_fsm_trim_tail_lw(impl), rc);
        IWRC(_fsm_write_meta_lw(impl, 1), rc); 
    }
    IWRC(_fsm_ctrl_unlock(impl), rc);
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


iwrc iwfs_fsmfile_open(IWFS_FSM *f,
                       const IWFS_FSM_OPTS *opts) {
    assert(f);
    assert(opts);
    iwrc rc = 0;
    IWFS_RWL_STATE fstate;
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

    IWFS_RWL_OPTS rwl_opts = opts->rwlfile;
    rwl_opts.exfile.use_locks = 0;

    rc = _fsm_init_impl(impl, opts);
    if (rc) goto finish;

    rc = _fsm_init_locks(impl, opts);
    if (rc) goto finish;

    rc = iwfs_rwlfile_open(&impl->pool, &rwl_opts);
    if (rc) goto finish;

    memset(&fstate, 0,  sizeof(fstate));
    rc = impl->pool.state(&impl->pool, &fstate);
    if (rc) goto finish;

    impl->omode = fstate.exfile.file.opts.omode;


    if (fstate.exfile.file.ostatus & IWFS_OPEN_NEW) {
        rc = _fsm_init_new(impl, opts);
    } else {
        rc = _fsm_init_existing(impl);
    }

finish:
    if (rc) {
        if (f->impl) {
            IWRC(_fsm_destroy_locks(f->impl), rc); //we not locked
            IWRC(_fsm_close(f), rc);
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
        case IWFS_ERROR_RANGE_NOT_ALIGNED:
            return "Specified range/offset is not aligned with page/block. (IWFS_ERROR_RANGE_NOT_ALIGNED)";
        case IWFS_ERROR_FSM_SEGMENTATION:
            return "Free-space map segmentation error. (IWFS_ERROR_FSM_SEGMENTATION)";
        case IWFS_ERROR_INVALID_FILEMETA:
            return "Invalid file metadata. (IWFS_ERROR_INVALID_FILEMETA)";
        case IWFS_ERROR_PLATFORM_PAGE:
            return "The block size incompatible with platform page size, data migration required. (IWFS_ERROR_PLATFORM_PAGE)";
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
