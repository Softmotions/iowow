/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2024 Softmotions Ltd <info@softmotions.com>
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

#include "iwfsmfile.h"
#include "iwavl.h"
#include "iwbits.h"
#include "iwlog.h"
#include "iwp.h"
#include "iwutils.h"
#include "iwcfg.h"

#include <pthread.h>

void iwfs_fsmdbg_dump_fsm_tree(IWFS_FSM *f, const char *hdr);

/**
 * Free-space blocks-tree key.
 */
struct bkey {
  uint32_t off;
  uint32_t len;
};

struct bkey_node {
  struct bkey       key;
  struct iwavl_node node;
};

#define BKEY(nptr_) iwavl_entry(nptr_, struct bkey_node, node)->key

/** Additional options for `_fsm_set_bit_status_lw` routine */
typedef uint8_t fsm_bmopts_t;

/** No options. */
#define FSM_BM_NONE ((fsm_bmopts_t) 0x00U)

/** Do not modify bitmap. */
#define FSM_BM_DRY_RUN ((fsm_bmopts_t) 0x01U)

/** Perform strict checking of bitmap consistency */
#define FSM_BM_STRICT ((fsm_bmopts_t) 0x02U)

/* Maximum size of block: 1Mb */
#define FSM_MAX_BLOCK_POW 20

/* Maximum number of records used in allocation statistics */
#define FSM_MAX_STATS_COUNT 0x0000ffff

#define FSM_ENSURE_OPEN(impl_)                                                                          \
  if (!(impl_) || !(impl_)->f) return IW_ERROR_INVALID_STATE;

#define FSM_ENSURE_OPEN2(f_)                                                                             \
  if (!(f_) || !(f_)->impl) return IW_ERROR_INVALID_STATE;

#define FSMBK_OFFSET(b_) ((b_)->off)

#define FSMBK_LENGTH(b_) ((b_)->len)

////////////////////////////////////////////////////////////////////////////////////////////////////

struct fsm {
  IWFS_EXT  pool;                 /**< Underlying rwl file. */
  uint64_t  bmlen;                /**< Free-space bitmap block length in bytes. */
  uint64_t  bmoff;                /**< Free-space bitmap block offset in bytes. */
  uint64_t  lfbkoff;              /**< Offset in blocks of free block chunk with the largest offset. */
  uint64_t  lfbklen;              /**< Length in blocks of free block chunk with the largest offset. */
  uint64_t  crzsum;               /**< Cumulative sum all allocated blocks */
  uint64_t  crzvar;               /**< Record sizes standard variance (deviation^2 * N) */
  uint32_t  hdrlen;               /**< Length of custom file header */
  uint32_t  crznum;               /**< Number of all allocated continuous areas acquired by `allocate` */
  uint32_t  fsmnum;               /**< Number of records in fsm */
  IWFS_FSM *f;                    /**< Self reference. */
  IWDLSNR  *dlsnr;                /**< Data events listener */
  struct iwavl_node *root;        /**< Free-space tree */
  pthread_rwlock_t  *ctlrwlk;     /**< Methods RW lock */
  size_t aunit;                   /**< System allocation unit size.
                                       - Page size on *NIX
                                       - Minimal allocation unit for WIN32 */
  iwfs_fsm_openflags oflags;      /**< Operation mode flags. */
  iwfs_omode omode;               /**< Open mode. */
  uint8_t    bpow;                /**< Block size power for 2 */
  bool       mmap_all;            /**< Mmap all file data */
  iwfs_ext_mmap_opts_t mmap_opts; /**< Defaul mmap options used in `add_mmap` */
};

static iwrc _fsm_ensure_size_lw(struct fsm *fsm, off_t size);

////////////////////////////////////////////////////////////////////////////////////////////////////

IW_INLINE int _fsm_cmp_key(const struct bkey *a, const struct bkey *b) {
  int ret = ((FSMBK_LENGTH(b) < FSMBK_LENGTH(a)) - (FSMBK_LENGTH(a) < FSMBK_LENGTH(b)));
  if (ret) {
    return ret;
  } else {
    return ((FSMBK_OFFSET(b) < FSMBK_OFFSET(a)) - (FSMBK_OFFSET(a) < FSMBK_OFFSET(b)));
  }
}

IW_INLINE int _fsm_cmp_node(const struct iwavl_node *an, const struct iwavl_node *bn) {
  const struct bkey *ak = &BKEY(an);
  const struct bkey *bk = &BKEY(bn);
  return _fsm_cmp_key(ak, bk);
}

IW_INLINE int _fsm_cmp_ctx(const void *ctx, const struct iwavl_node *bn) {
  const struct bkey *ak = ctx;
  const struct bkey *bk = &BKEY(bn);
  return _fsm_cmp_key(ak, bk);
}

IW_INLINE iwrc _fsm_ctrl_wlock(struct fsm *fsm) {
  int rci = fsm->ctlrwlk ? pthread_rwlock_wrlock(fsm->ctlrwlk) : 0;
  return (rci ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci) : 0);
}

IW_INLINE iwrc _fsm_ctrl_rlock(struct fsm *fsm) {
  int rci = fsm->ctlrwlk ? pthread_rwlock_rdlock(fsm->ctlrwlk) : 0;
  return (rci ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci) : 0);
}

IW_INLINE iwrc _fsm_ctrl_unlock(struct fsm *fsm) {
  int rci = fsm->ctlrwlk ? pthread_rwlock_unlock(fsm->ctlrwlk) : 0;
  return (rci ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci) : 0);
}

IW_INLINE iwrc _fsm_bmptr(struct fsm *fsm, uint64_t **bmptr) {
  size_t sp;
  uint8_t *mm;
  *bmptr = 0;
  // get mmap pointer without locked
  iwrc rc = fsm->pool.probe_mmap(&fsm->pool, fsm->mmap_all ? 0 : fsm->bmoff, &mm, &sp);
  RCRET(rc);
  if (fsm->mmap_all) {
    if (sp < fsm->bmoff + fsm->bmlen) {
      return IWFS_ERROR_NOT_MMAPED;
    }
    *bmptr = (uint64_t*) (mm + fsm->bmoff);
  } else {
    if (sp < fsm->bmlen) {
      return IWFS_ERROR_NOT_MMAPED;
    }
    *bmptr = (uint64_t*) mm;
  }
  return 0;
}

IW_INLINE WUR iwrc _fsm_init_bkey_node(struct bkey_node *n, uint64_t offset_blk, uint64_t len_blk) {
  if (offset_blk > (uint32_t) -1 || len_blk > (uint32_t) -1) {
    return IW_ERROR_OVERFLOW;
  }
  n->key.off = (uint32_t) offset_blk;
  n->key.len = (uint32_t) len_blk;
  return 0;
}

IW_INLINE iwrc _fsm_init_bkey(struct bkey *k, uint64_t offset_blk, uint64_t len_blk) {
  if (offset_blk > (uint32_t) -1 || len_blk > (uint32_t) -1) {
    return IW_ERROR_OVERFLOW;
  }
  k->off = (uint32_t) offset_blk;
  k->len = (uint32_t) len_blk;
  return 0;
}

IW_INLINE void _fsm_del_fbk2(struct fsm *fsm, struct iwavl_node *n) {
  iwavl_remove(&fsm->root, n), --fsm->fsmnum;
  struct bkey_node *bk = iwavl_entry(n, struct bkey_node, node);
  if (bk->key.off == fsm->lfbkoff) {
    fsm->lfbkoff = 0;
    fsm->lfbklen = 0;
  }
  free(bk);
}

IW_INLINE void _fsm_del_fbk(struct fsm *fsm, uint64_t offset_blk, uint64_t length_blk) {
  struct bkey bkey;
  if (!_fsm_init_bkey(&bkey, offset_blk, length_blk)) {
    struct iwavl_node *n = iwavl_lookup(fsm->root, &bkey, _fsm_cmp_ctx);
    assert(n);
    if (n) {
      _fsm_del_fbk2(fsm, n);
    }
  }
}

IW_INLINE iwrc _fsm_put_fbk(struct fsm *fsm, uint64_t offset_blk, uint64_t length_blk) {
  iwrc rc = 0;
  struct bkey_node *bk;
  RCB(finish, bk = malloc(sizeof(*bk)));
  RCC(rc, finish, _fsm_init_bkey_node(bk, offset_blk, length_blk));
  if (iwavl_insert(&fsm->root, &bk->node, _fsm_cmp_node)) {
    free(bk);
  } else {
    ++fsm->fsmnum;
    if (offset_blk + length_blk >= fsm->lfbkoff + fsm->lfbklen) {
      fsm->lfbkoff = offset_blk;
      fsm->lfbklen = length_blk;
    }
  }
finish:
  if (rc) {
    free(bk);
  }
  return rc;
}

IW_INLINE const struct iwavl_node* _fsm_find_matching_fblock_lw(
  struct fsm     *fsm,
  uint64_t        offset_blk,
  uint64_t        length_blk,
  iwfs_fsm_aflags opts
  ) {
  struct bkey bk;
  const struct iwavl_node *ub, *lb;
  if (_fsm_init_bkey(&bk, offset_blk, length_blk)) {
    return 0;
  }

  iwavl_lookup_bounds(fsm->root, &bk, _fsm_cmp_ctx, &lb, &ub);

  struct bkey *uk = ub ? &BKEY(ub) : 0;
  struct bkey *lk = lb ? &BKEY(lb) : 0;

  uint64_t lklength = lk ? FSMBK_LENGTH(lk) : 0;
  uint64_t uklength = uk ? FSMBK_LENGTH(uk) : 0;

  if (lklength == length_blk) {
    return lb;
  } else if (uklength == length_blk) {
    return ub;
  }
  if (lklength > length_blk) {
    return lb;
  } else if (uklength > length_blk) {
    return ub;
  }
  return 0;
}

/**
 * @brief Set the allocation bits in the fsm bitmap.
 *
 * @param fms
 * @param offset_bits Bit offset in the bitmap.
 * @param length_bits Number of bits to set
 * @param bit_status  If `1` bits will be set to `1` otherwise `0`
 * @param opts        Operation options
 */
static iwrc _fsm_set_bit_status_lw(
  struct fsm        *fsm,
  const uint64_t     offset_bits,
  const uint64_t     length_bits_,
  const int          bit_status,
  const fsm_bmopts_t opts
  ) {
  iwrc rc;
  size_t sp;
  uint8_t *mm;
  register int64_t length_bits = length_bits_;
  register uint64_t *p, set_mask;
  uint64_t bend = offset_bits + length_bits;
  int set_bits;

  if (bend < offset_bits) { // overflow
    return IW_ERROR_OUT_OF_BOUNDS;
  }
  assert(fsm->bmlen * 8 >= offset_bits + length_bits);
  if (fsm->bmlen * 8 < offset_bits + length_bits) {
    return IWFS_ERROR_FSM_SEGMENTATION;
  }
  if (fsm->mmap_all) {
    rc = fsm->pool.probe_mmap(&fsm->pool, 0, &mm, &sp);
    RCRET(rc);
    if (sp < fsm->bmoff + fsm->bmlen) {
      return IWFS_ERROR_NOT_MMAPED;
    } else {
      mm += fsm->bmoff;
    }
  } else {
    rc = fsm->pool.probe_mmap(&fsm->pool, fsm->bmoff, &mm, &sp);
    RCRET(rc);
    if (sp < fsm->bmlen) {
      return IWFS_ERROR_NOT_MMAPED;
    }
  }
  p = ((uint64_t*) mm) + offset_bits / 64;
  set_bits = 64 - (offset_bits & (64 - 1)); // NOLINT
  set_mask = (~((uint64_t) 0) << (offset_bits & (64 - 1)));

#ifdef IW_BIGENDIAN
  while (length_bits - set_bits >= 0) {
    uint64_t pv = *p;
    pv = IW_ITOHLL(pv);
    if (bit_status) {
      if ((opts & FSM_BM_STRICT) && (pv & set_mask)) {
        rc = IWFS_ERROR_FSM_SEGMENTATION;
      }
      if ((opts & FSM_BM_DRY_RUN) == 0) {
        pv |= set_mask;
        *p = IW_HTOILL(pv);
      }
    } else {
      if ((opts & FSM_BM_STRICT) && ((pv & set_mask) != set_mask)) {
        rc = IWFS_ERROR_FSM_SEGMENTATION;
      }
      if ((opts & FSM_BM_DRY_RUN) == 0) {
        pv &= ~set_mask;
        *p = IW_HTOILL(pv);
      }
    }
    length_bits -= set_bits;
    set_bits = 64;
    set_mask = ~((uint64_t) 0);
    ++p;
  }
  if (length_bits) {
    uint64_t pv = *p;
    pv = IW_ITOHLL(pv);
    set_mask &= (bend & (64 - 1)) ? ((((uint64_t) 1) << (bend & (64 - 1))) - 1) : ~((uint64_t) 0);
    if (bit_status) {
      if ((opts & FSM_BM_STRICT) && (pv & set_mask)) {
        rc = IWFS_ERROR_FSM_SEGMENTATION;
      }
      if ((opts & FSM_BM_DRY_RUN) == 0) {
        pv |= set_mask;
        *p = IW_HTOILL(pv);
      }
    } else {
      if ((opts & FSM_BM_STRICT) && ((pv & set_mask) != set_mask)) {
        rc = IWFS_ERROR_FSM_SEGMENTATION;
      }
      if ((opts & FSM_BM_DRY_RUN) == 0) {
        pv &= ~set_mask;
        *p = IW_HTOILL(pv);
      }
    }
  }
#else
  while (length_bits - set_bits >= 0) {
    if (bit_status) {
      if ((opts & FSM_BM_STRICT) && (*p & set_mask)) {
        rc = IWFS_ERROR_FSM_SEGMENTATION;
      }
      if ((opts & FSM_BM_DRY_RUN) == 0) {
        *p |= set_mask;
      }
    } else {
      if ((opts & FSM_BM_STRICT) && ((*p & set_mask) != set_mask)) {
        rc = IWFS_ERROR_FSM_SEGMENTATION;
      }
      if ((opts & FSM_BM_DRY_RUN) == 0) {
        *p &= ~set_mask;
      }
    }
    length_bits -= set_bits;
    set_bits = 64;
    set_mask = ~((uint64_t) 0);
    ++p;
  }
  if (length_bits) {
    set_mask &= (bend & (64 - 1)) ? ((((uint64_t) 1) << (bend & (64 - 1))) - 1) : ~((uint64_t) 0);
    if (bit_status) {
      if ((opts & FSM_BM_STRICT) && (*p & set_mask)) {
        rc = IWFS_ERROR_FSM_SEGMENTATION;
      }
      if ((opts & FSM_BM_DRY_RUN) == 0) {
        *p |= set_mask;
      }
    } else {
      if ((opts & FSM_BM_STRICT) && ((*p & set_mask) != set_mask)) {
        rc = IWFS_ERROR_FSM_SEGMENTATION;
      }
      if ((opts & FSM_BM_DRY_RUN) == 0) {
        *p &= ~set_mask;
      }
    }
  }
#endif
  if (!rc && fsm->dlsnr) {
    uint64_t so = offset_bits / 8;
    uint64_t lb = length_bits_ + offset_bits % 8;
    uint64_t dl = lb / 8;
    if (lb % 8) {
      ++dl;
    }
    rc = fsm->dlsnr->onwrite(fsm->dlsnr, fsm->bmoff + so, mm + so, dl, 0);
  }
  return rc;
}

/**
 *  @brief Allocate a continuous segment of blocks with page aligned offset.
 *
 *  @param fsm `struct fsm`
 *  @param length_blk Desired segment length in blocks.
 *  @param [in,out] offset_blk Allocated segment offset in blocks will be stored into.
                    It also specified the desired segment offset to provide
 *                  allocation locality.
 *  @param [out] olength_blk Assigned segment length in blocks.
 *  @param  max_offset_blk Maximal offset of allocated block.
 *  @param opts Allocation options.
 */
static iwrc _fsm_blk_allocate_aligned_lw(
  struct fsm           *fsm,
  const uint64_t        length_blk,
  uint64_t             *offset_blk,
  uint64_t             *olength_blk,
  const uint64_t        max_offset_blk,
  const iwfs_fsm_aflags opts
  ) {
  fsm_bmopts_t bopts = FSM_BM_NONE;
  size_t aunit_blk = (fsm->aunit >> fsm->bpow);
  assert(fsm && length_blk > 0);
  if (IW_UNLIKELY(fsm->oflags & IWFSM_STRICT)) {
    bopts |= FSM_BM_STRICT;
  }
  *olength_blk = 0;
  *offset_blk = 0;

  /* First attempt */
  const struct iwavl_node *nn = _fsm_find_matching_fblock_lw(fsm, 0, length_blk + aunit_blk, opts);
  if (!nn) {
    nn = _fsm_find_matching_fblock_lw(fsm, 0, length_blk, opts);
    if (!nn) {
      return IWFS_ERROR_NO_FREE_SPACE;
    }
  }

  struct bkey *nk = &BKEY(nn);
  uint64_t akoff = FSMBK_OFFSET(nk);
  uint64_t aklen = FSMBK_LENGTH(nk);
  uint64_t noff = IW_ROUNDUP(akoff, aunit_blk);

  if ((noff <= max_offset_blk) && (noff < aklen + akoff) && (aklen - (noff - akoff) >= length_blk)) {
    _fsm_del_fbk(fsm, akoff, aklen);
    aklen = aklen - (noff - akoff);
    if (noff > akoff) {
      _fsm_put_fbk(fsm, akoff, noff - akoff);
    }
    if (aklen > length_blk) {
      _fsm_put_fbk(fsm, noff + length_blk, aklen - length_blk);
    }
    *offset_blk = noff;
    *olength_blk = length_blk;
    return _fsm_set_bit_status_lw(fsm, noff, length_blk, 1, bopts);
  }

  aklen = 0;
  akoff = UINT64_MAX;

  // full scan
  for (struct iwavl_node *n = iwavl_first_in_order(fsm->root); n; n = iwavl_next_in_order(n)) {
    struct bkey *k = &BKEY(n);
    uint64_t koff = FSMBK_OFFSET(k);
    uint64_t klen = FSMBK_LENGTH(k);
    if (koff < akoff) {
      noff = IW_ROUNDUP(koff, aunit_blk);
      if (noff <= max_offset_blk && (noff < klen + koff) && (klen - (noff - koff) >= length_blk)) {
        akoff = koff;
        aklen = klen;
      }
    }
  }

  if (akoff == UINT64_MAX) {
    return IWFS_ERROR_NO_FREE_SPACE;
  }
  _fsm_del_fbk(fsm, akoff, aklen);
  noff = IW_ROUNDUP(akoff, aunit_blk);
  aklen = aklen - (noff - akoff);
  if (noff > akoff) {
    _fsm_put_fbk(fsm, akoff, noff - akoff);
  }
  if (aklen > length_blk) {
    _fsm_put_fbk(fsm, noff + length_blk, aklen - length_blk);
  }
  *offset_blk = noff;
  *olength_blk = length_blk;
  return _fsm_set_bit_status_lw(fsm, noff, length_blk, 1, bopts);
}

static void _fsm_node_destroy(struct iwavl_node *root) {
  for (struct iwavl_node *n = iwavl_first_in_postorder(root), *p;
       n && (p = iwavl_get_parent(n), 1);
       n = iwavl_next_in_postorder(n, p)) {
    struct bkey_node *bk = iwavl_entry(n, struct bkey_node, node);
    free(bk);
  }
}

/**
 * @brief Load existing bitmap area into free-space search tree.
 * @param fsm  `struct fsm`
 * @param bm    Bitmap area start ptr
 * @param len   Bitmap area length in bytes.
 */
static void _fsm_load_fsm_lw(struct fsm *fsm, const uint8_t *bm, uint64_t len) {
  uint64_t cbnum = 0, fbklength = 0, fbkoffset = 0;

  _fsm_node_destroy(fsm->root);
  fsm->root = 0;
  fsm->fsmnum = 0;

  for (uint64_t b = 0; b < len; ++b) {
    register uint8_t bb = bm[b];
    if (bb == 0) {
      fbklength += 8;
      cbnum += 8;
    } else if (bb == 0xffU) {
      if (fbklength) {
        fbkoffset = cbnum - fbklength;
        _fsm_put_fbk(fsm, fbkoffset, fbklength);
        fbklength = 0;
      }
      cbnum += 8;
    } else {
      for (int i = 0; i < 8; ++i, ++cbnum) {
        if (bb & (1U << i)) {
          if (fbklength) {
            fbkoffset = cbnum - fbklength;
            _fsm_put_fbk(fsm, fbkoffset, fbklength);
            fbklength = 0;
          }
        } else {
          ++fbklength;
        }
      }
    }
  }
  if (fbklength > 0) {
    fbkoffset = len * 8 - fbklength;
    _fsm_put_fbk(fsm, fbkoffset, fbklength);
  }
}

/**
 * @brief Flush a current `iwfsmfile` metadata into the file header.
 * @param fsm
 * @param is_sync If `1` perform mmap sync.
 * @return
 */
static iwrc _fsm_write_meta_lw(struct fsm *fsm) {
  uint64_t llv;
  size_t wlen;
  uint32_t sp = 0, lv;
  uint8_t hdr[IWFSM_CUSTOM_HDR_DATA_OFFSET] = { 0 };

  /*
      [FSM_CTL_MAGICK u32][block pow u8]
      [bmoffset u64][bmlength u64]
      [u64 crzsum][u32 crznum][u64 crszvar][u256 reserved]
      [custom header size u32][custom header data...]
      [fsm data...]
   */

  /* magic */
  lv = IW_HTOIL(IWFSM_MAGICK);
  assert(sp + sizeof(lv) <= IWFSM_CUSTOM_HDR_DATA_OFFSET);
  memcpy(hdr + sp, &lv, sizeof(lv));
  sp += sizeof(lv);

  /* block pow */
  static_assert(sizeof(fsm->bpow) == 1, "sizeof(fms->bpow) == 1");
  assert(sp + sizeof(fsm->bpow) <= IWFSM_CUSTOM_HDR_DATA_OFFSET);
  memcpy(hdr + sp, &fsm->bpow, sizeof(fsm->bpow));
  sp += sizeof(fsm->bpow);

  /* fsm bitmap block offset */
  llv = fsm->bmoff;
  llv = IW_HTOILL(llv);
  assert(sp + sizeof(llv) <= IWFSM_CUSTOM_HDR_DATA_OFFSET);
  memcpy(hdr + sp, &llv, sizeof(llv));
  sp += sizeof(llv);

  /* fsm bitmap block length */
  llv = fsm->bmlen;
  llv = IW_HTOILL(llv);
  assert(sp + sizeof(llv) <= IWFSM_CUSTOM_HDR_DATA_OFFSET);
  memcpy(hdr + sp, &llv, sizeof(llv));
  sp += sizeof(llv);

  /* Cumulative sum of record sizes acquired by `allocate` */
  llv = fsm->crzsum;
  llv = IW_HTOILL(llv);
  assert(sp + sizeof(llv) <= IWFSM_CUSTOM_HDR_DATA_OFFSET);
  memcpy(hdr + sp, &llv, sizeof(llv));
  sp += sizeof(llv);

  /* Cumulative number of records acquired by `allocated` */
  lv = fsm->crznum;
  lv = IW_HTOIL(lv);
  assert(sp + sizeof(lv) <= IWFSM_CUSTOM_HDR_DATA_OFFSET);
  memcpy(hdr + sp, &lv, sizeof(lv));
  sp += sizeof(lv);

  /* Record sizes standard variance (deviation^2 * N) */
  llv = fsm->crzvar;
  llv = IW_HTOILL(llv);
  assert(sp + sizeof(lv) <= IWFSM_CUSTOM_HDR_DATA_OFFSET);
  memcpy(hdr + sp, &llv, sizeof(llv));
  sp += sizeof(llv);

  /* Reserved */
  sp += 32;

  /* Size of header */
  lv = fsm->hdrlen;
  lv = IW_HTOIL(lv);
  assert(sp + sizeof(lv) <= IWFSM_CUSTOM_HDR_DATA_OFFSET);
  memcpy(hdr + sp, &lv, sizeof(lv));
  sp += sizeof(lv);

  assert(sp == IWFSM_CUSTOM_HDR_DATA_OFFSET);
  return fsm->pool.write(&fsm->pool, 0, hdr, IWFSM_CUSTOM_HDR_DATA_OFFSET, &wlen);
}

/**
 * @brief Search for the first next set bit position
 *        starting from the specified offset bit (INCLUDED).
 */
static uint64_t _fsm_find_next_set_bit(
  const uint64_t   *addr,
  register uint64_t offset_bit,
  const uint64_t    max_offset_bit,
  int              *found
  ) {
  *found = 0;
  register uint64_t bit, size;
  register const uint64_t *p = addr + offset_bit / 64;
  if (offset_bit >= max_offset_bit) {
    return 0;
  }
  bit = offset_bit & (64 - 1);
  offset_bit -= bit;
  size = max_offset_bit - offset_bit;

#ifdef IW_BIGENDIAN
  uint64_t pv = *p;
  if (bit) {
    pv = IW_ITOHLL(pv) & (~((uint64_t) 0) << bit);
    if (pv) {
      pv = iwbits_find_first_sbit64(pv);
      if (pv >= size) {
        return 0;
      } else {
        *found = 1;
        return offset_bit + pv;
      }
    }
    if (size <= 64) {
      return 0;
    }
    offset_bit += 64;
    size -= 64;
    ++p;
  }
  while (size & ~(64 - 1)) {
    pv = *(p++);
    if (pv) {
      *found = 1;
      return offset_bit + iwbits_find_first_sbit64(IW_ITOHLL(pv));
    }
    offset_bit += 64;
    size -= 64;
  }
  if (!size) {
    return 0;
  }
  pv = *p;
  pv = IW_ITOHLL(pv) & (~((uint64_t) 0) >> (64 - size));
  if (pv) {
    *found = 1;
    return offset_bit + iwbits_find_first_sbit64(pv);
  } else {
    return 0;
  }
#else
  register uint64_t tmp;
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
    ++p;
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
#endif
}

/**
 * @brief Search for the first previous set bit position
 *        starting from the specified offset_bit (EXCLUDED).
 */
static uint64_t _fsm_find_prev_set_bit(
  const uint64_t   *addr,
  register uint64_t offset_bit,
  const uint64_t    min_offset_bit,
  int              *found
  ) {
  register const uint64_t *p;
  register uint64_t tmp, bit, size;
  *found = 0;
  if (min_offset_bit >= offset_bit) {
    return 0;
  }
  size = offset_bit - min_offset_bit;
  bit = offset_bit & (64 - 1);
  p = addr + offset_bit / 64;

#ifdef IW_BIGENDIAN
  uint64_t pv;
  if (bit) {
    pv = *p;
    pv = (iwbits_reverse_64(IW_ITOHLL(pv)) >> (64 - bit));
    if (pv) {
      pv = iwbits_find_first_sbit64(pv);
      if (pv >= size) {
        return 0;
      } else {
        *found = 1;
        assert(offset_bit > pv);
        return offset_bit > pv ? offset_bit - pv - 1 : 0;
      }
    }
    offset_bit -= bit;
    size -= bit;
  }
  while (size & ~(64 - 1)) {
    if (*(--p)) {
      pv = *p;
      *found = 1;
      tmp = iwbits_find_first_sbit64(iwbits_reverse_64(IW_ITOHLL(pv)));
      assert(offset_bit > tmp);
      return offset_bit > tmp ? offset_bit - tmp - 1 : 0;
    }
    offset_bit -= 64;
    size -= 64;
  }
  if (size == 0) {
    return 0;
  }
  pv = *(--p);
  tmp = iwbits_reverse_64(IW_ITOHLL(pv)) & ((((uint64_t) 1) << size) - 1);
#else
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
    if (*(--p)) {
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
#endif
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
 * @brief Return a previously allocated blocks
 *        back into the free-blocks pool.
 *
 * @param fms `struct fsm`
 * @param offset_blk Starting block number of the specified range.
 * @param length_blk Range size in blocks.
 */
static iwrc _fsm_blk_deallocate_lw(
  struct fsm    *fsm,
  const uint64_t offset_blk,
  const uint64_t length_blk
  ) {
  iwrc rc;
  uint64_t *bmptr;
  uint64_t left, right;
  int hasleft = 0, hasright = 0;
  uint64_t key_offset = offset_blk, key_length = length_blk;
  uint64_t rm_offset = 0, rm_length = 0;
  uint64_t lfbkoff = fsm->lfbkoff;
  uint64_t end_offset_blk = offset_blk + length_blk;
  fsm_bmopts_t bopts = FSM_BM_NONE;


  if (IW_UNLIKELY(fsm->oflags & IWFSM_STRICT)) {
    bopts |= FSM_BM_STRICT;
  }
  rc = _fsm_set_bit_status_lw(fsm, offset_blk, length_blk, 0, bopts);
  RCRET(rc);

  rc = _fsm_bmptr(fsm, &bmptr);
  RCRET(rc);

  /* Merge with neighborhoods */
  left = _fsm_find_prev_set_bit(bmptr, offset_blk, 0, &hasleft);
  if (lfbkoff && (lfbkoff == end_offset_blk)) {
    right = lfbkoff + fsm->lfbklen;
    hasright = 1;
  } else {
    uint64_t maxoff = lfbkoff ? lfbkoff : (fsm->bmlen << 3);
    right = _fsm_find_next_set_bit(bmptr, end_offset_blk, maxoff, &hasright);
  }

  if (hasleft) {
    if (offset_blk > left + 1) {
      left += 1;
      rm_offset = left;
      rm_length = offset_blk - left;
      _fsm_del_fbk(fsm, rm_offset, rm_length);
      key_offset = rm_offset;
      key_length += rm_length;
    }
  } else if (offset_blk > 0) { /* zero start */
    rm_offset = 0;
    rm_length = offset_blk;
    _fsm_del_fbk(fsm, rm_offset, rm_length);
    key_offset = rm_offset;
    key_length += rm_length;
  }
  if (hasright && (right > end_offset_blk)) {
    rm_offset = end_offset_blk;
    rm_length = right - end_offset_blk;
    _fsm_del_fbk(fsm, rm_offset, rm_length);
    key_length += rm_length;
  }
  IWRC(_fsm_put_fbk(fsm, key_offset, key_length), rc);
  return rc;
}

/**
 * @brief Initialize a new free-space bitmap area.
 *
 * If bitmap exists, its content will be moved into newly created area.
 * Blocks from the previous bitmap are will disposed and deallocated.
 *
 * @param fsm `struct fsm
 * @param bmoff Byte offset of the new bitmap. Value must be page aligned.
 * @param bmlen Byte length of the new bitmap. Value must be page aligned.
                Its length must not be lesser than length of old bitmap.
 */
static iwrc _fsm_init_lw(struct fsm *fsm, uint64_t bmoff, uint64_t bmlen) {
  iwrc rc;
  uint8_t *mm, *mm2;
  size_t sp, sp2;
  uint64_t old_bmoff, old_bmlen;
  IWFS_EXT *pool = &fsm->pool;

  if ((bmlen & ((1U << fsm->bpow) - 1)) || (bmoff & ((1U << fsm->bpow) - 1)) || (bmoff & (fsm->aunit - 1))) {
    return IWFS_ERROR_RANGE_NOT_ALIGNED;
  }
  if (bmlen < fsm->bmlen) {
    rc = IW_ERROR_INVALID_ARGS;
    iwlog_ecode_error(rc, "Length of the newly initiated bitmap area (bmlen): %" PRIu64
                      " must not be lesser than the current bitmap area length %" PRIu64 "",
                      bmlen, fsm->bmlen);
    return rc;
  }
  if (bmlen * 8 < ((bmoff + bmlen) >> fsm->bpow) + 1) {
    rc = IW_ERROR_INVALID_ARGS;
    iwlog_ecode_error(rc, "Length of the newly initiated bitmap area (bmlen): %" PRIu64
                      " is not enough to handle bitmap itself and the file header area.",
                      bmlen);
    return rc;
  }
  rc = _fsm_ensure_size_lw(fsm, bmoff + bmlen);
  RCRET(rc);
  if (fsm->mmap_all) {
    // get mmap area without locking, since we ensured what pool file will not be remapped
    rc = pool->probe_mmap(pool, 0, &mm, &sp);
    RCRET(rc);
    if (sp < bmoff + bmlen) {
      return IWFS_ERROR_NOT_MMAPED;
    } else {
      mm += bmoff;
    }
  } else {
    // get mmap area without locking, since we ensured what pool file will not be remapped
    rc = pool->probe_mmap(pool, bmoff, &mm, &sp);
    RCRET(rc);
    if (sp < bmlen) {
      return IWFS_ERROR_NOT_MMAPED;
    }
  }
  if (fsm->bmlen) {
    /* We have an old active bitmap. Lets copy its content to the new location.*/
    if (IW_RANGES_OVERLAP(fsm->bmoff, fsm->bmoff + fsm->bmlen, bmoff, bmoff + bmlen)) {
      iwlog_ecode_error2(rc, "New and old bitmap areas are overlaped");
      return IW_ERROR_INVALID_ARGS;
    }
    if (fsm->mmap_all) {
      mm2 = mm - bmoff + fsm->bmoff;
    } else {
      rc = pool->probe_mmap(pool, fsm->bmoff, &mm2, &sp2);
      if (!rc && (sp2 < fsm->bmlen)) {
        rc = IWFS_ERROR_NOT_MMAPED;
      }
      if (rc) {
        iwlog_ecode_error2(rc, "Old bitmap area is not mmaped");
        return rc;
      }
    }
    assert(!((fsm->bmlen - bmlen) & ((1U << fsm->bpow) - 1)));
    if (fsm->dlsnr) {
      rc = fsm->dlsnr->onwrite(fsm->dlsnr, bmoff, mm2, fsm->bmlen, 0);
      RCRET(rc);
    }
    memcpy(mm, mm2, fsm->bmlen);
    if (bmlen > fsm->bmlen) {
      memset(mm + fsm->bmlen, 0, bmlen - fsm->bmlen);
      if (fsm->dlsnr) {
        rc = fsm->dlsnr->onset(fsm->dlsnr, bmoff + fsm->bmlen, 0, bmlen - fsm->bmlen, 0);
        RCRET(rc);
      }
    }
  } else {
    mm2 = 0;
    memset(mm, 0, bmlen);
    if (fsm->dlsnr) {
      rc = fsm->dlsnr->onset(fsm->dlsnr, bmoff, 0, bmlen, 0);
      RCRET(rc);
    }
  }

  /* Backup the previous bitmap range */
  old_bmlen = fsm->bmlen;
  old_bmoff = fsm->bmoff;
  fsm->bmoff = bmoff;
  fsm->bmlen = bmlen;

  RCC(rc, rollback, _fsm_set_bit_status_lw(fsm, (bmoff >> fsm->bpow), (bmlen >> fsm->bpow), 1, FSM_BM_NONE));
  if (!old_bmlen) { /* First time initialization */
    /* Header allocation */
    RCC(rc, rollback, _fsm_set_bit_status_lw(fsm, 0, (fsm->hdrlen >> fsm->bpow), 1, FSM_BM_NONE));
  }

  /* Reload fsm tree */
  _fsm_load_fsm_lw(fsm, mm, bmlen);

  /* Flush new meta */
  RCC(rc, rollback, _fsm_write_meta_lw(fsm));
  RCC(rc, rollback, pool->sync(pool, IWFS_FDATASYNC));

  if (old_bmlen) {
    /* Now we are save to deallocate the old bitmap */
    rc = _fsm_blk_deallocate_lw(fsm, (old_bmoff >> fsm->bpow), (old_bmlen >> fsm->bpow));
    if (!fsm->mmap_all) {
      pool->remove_mmap(pool, old_bmoff);
    }
  }
  return rc;

rollback:
  /* try to rollback previous bitmap state */
  fsm->bmoff = old_bmoff;
  fsm->bmlen = old_bmlen;
  if (old_bmlen && mm2) {
    _fsm_load_fsm_lw(fsm, mm2, old_bmlen);
  }
  pool->sync(pool, IWFS_FDATASYNC);
  return rc;
}

/**
 * @brief Resize bitmap area.
 * @param fsm `structfsm
 * @param size New size of bitmap area in bytes.
 */
static iwrc _fsm_resize_fsm_bitmap_lw(struct fsm *fsm, uint64_t size) {
  iwrc rc;
  uint64_t bmoffset = 0, bmlen, sp;
  IWFS_EXT *pool = &fsm->pool;

  if (fsm->bmlen >= size) {
    return 0;
  }
  bmlen = IW_ROUNDUP(size, fsm->aunit); /* align to the system page size. */
  rc = _fsm_blk_allocate_aligned_lw(
    fsm, (bmlen >> fsm->bpow), &bmoffset, &sp, UINT64_MAX,
    IWFSM_ALLOC_NO_STATS | IWFSM_ALLOC_NO_EXTEND | IWFSM_ALLOC_NO_OVERALLOCATE);
  if (!rc) {
    bmoffset = bmoffset << fsm->bpow;
    bmlen = sp << fsm->bpow;
  } else if (rc == IWFS_ERROR_NO_FREE_SPACE) {
    bmoffset = fsm->bmlen * (1 << fsm->bpow) * 8;
    bmoffset = IW_ROUNDUP(bmoffset, fsm->aunit);
  }
  if (!fsm->mmap_all) {
    rc = pool->add_mmap(pool, bmoffset, bmlen, fsm->mmap_opts);
    RCRET(rc);
  }
  rc = _fsm_init_lw(fsm, bmoffset, bmlen);
  if (rc && !fsm->mmap_all) {
    pool->remove_mmap(pool, bmoffset);
  }
  return rc;
}

/**
 * @brief Allocate a continuous segment of blocks.
 *
 * @param fsm `struct fsm
 * @param length_blk Desired segment length in blocks.
 * @param [in,out] offset_blk Allocated segment offset in blocks will be stored into.
 *                It also specified the desired segment offset to provide allocation locality.
 * @param [out] olength_blk Assigned segment length in blocks.
 * @param opts
 */
static iwrc _fsm_blk_allocate_lw(
  struct fsm     *fsm,
  uint64_t        length_blk,
  uint64_t       *offset_blk,
  uint64_t       *olength_blk,
  iwfs_fsm_aflags opts
  ) {
  iwrc rc;
  struct iwavl_node *nn;
  fsm_bmopts_t bopts = FSM_BM_NONE;

  if (opts & IWFSM_ALLOC_PAGE_ALIGNED) {
    while (1) {
      rc = _fsm_blk_allocate_aligned_lw(fsm, length_blk, offset_blk, olength_blk, UINT64_MAX, opts);
      if (rc == IWFS_ERROR_NO_FREE_SPACE) {
        if (opts & IWFSM_ALLOC_NO_EXTEND) {
          return IWFS_ERROR_NO_FREE_SPACE;
        }
        rc = _fsm_resize_fsm_bitmap_lw(fsm, fsm->bmlen << 1);
        RCRET(rc);
        continue;
      }
      if (!rc && (opts & IWFSM_SOLID_ALLOCATED_SPACE)) {
        uint64_t bs = *offset_blk;
        int64_t bl = *olength_blk;
        rc = _fsm_ensure_size_lw(fsm, (bs << fsm->bpow) + (bl << fsm->bpow));
      }
      return rc;
    }
  }

  *olength_blk = length_blk;

start:
  nn = (struct iwavl_node*) _fsm_find_matching_fblock_lw(fsm, *offset_blk, length_blk, opts);
  if (nn) { /* use existing free space block */
    const struct bkey *nk = &BKEY(nn);
    uint64_t nlength = FSMBK_LENGTH(nk);
    *offset_blk = FSMBK_OFFSET(nk);

    _fsm_del_fbk2(fsm, nn);

    if (nlength > length_blk) { /* re-save rest of free-space */
      if (!(opts & IWFSM_ALLOC_NO_OVERALLOCATE) && fsm->crznum) {
        /* todo use lognormal distribution? */
        double_t d = ((double_t) fsm->crzsum / (double_t) fsm->crznum)        /*avg*/
                     - (double) (nlength - length_blk);                       /*rest blk size*/
        double_t s = ((double_t) fsm->crzvar / (double_t) fsm->crznum) * 6.0; /* blk size dispersion * 6 */
        if ((s > 1) && (d > 0) && (d * d > s)) {
          /* its better to attach rest of block to
             the record */
          *olength_blk = nlength;
        } else {
          _fsm_put_fbk(fsm, (*offset_blk + length_blk), (nlength - length_blk));
        }
      } else {
        _fsm_put_fbk(fsm, (*offset_blk + length_blk), (nlength - length_blk));
      }
    }
  } else {
    if (opts & IWFSM_ALLOC_NO_EXTEND) {
      return IWFS_ERROR_NO_FREE_SPACE;
    }
    rc = _fsm_resize_fsm_bitmap_lw(fsm, fsm->bmlen << 1);
    RCRET(rc);
    goto start;
  }

  if (IW_UNLIKELY(fsm->oflags & IWFSM_STRICT)) {
    bopts |= FSM_BM_STRICT;
  }

  rc = _fsm_set_bit_status_lw(fsm, *offset_blk, *olength_blk, 1, bopts);
  if (!rc && !(opts & IWFSM_ALLOC_NO_STATS)) {
    double_t avg;
    /* Update allocation statistics */
    if (fsm->crznum > FSM_MAX_STATS_COUNT) {
      fsm->crznum = 0;
      fsm->crzsum = 0;
      fsm->crzvar = 0;
    }
    ++fsm->crznum;
    fsm->crzsum += length_blk;
    avg = (double_t) fsm->crzsum / (double_t) fsm->crznum; /* average */
    fsm->crzvar
      += (uint64_t) (((double_t) length_blk - avg) * ((double_t) length_blk - avg) + 0.5L); /* variance */
  }
  if (!rc && (opts & IWFSM_SOLID_ALLOCATED_SPACE)) {
    uint64_t bs = *offset_blk;
    int64_t bl = *olength_blk;
    rc = _fsm_ensure_size_lw(fsm, (bs << fsm->bpow) + (bl << fsm->bpow));
  }
  if (!rc && (opts & IWFSM_SYNC_BMAP)) {
    uint64_t *bmptr;
    if (!_fsm_bmptr(fsm, &bmptr)) {
      IWFS_EXT *pool = &fsm->pool;
      rc = pool->sync_mmap(pool, fsm->bmoff, IWFS_SYNCDEFAULT);
    }
  }
  return rc;
}

/**
 * @brief Remove all free blocks from the and of file and trim its size.
 */
static iwrc _fsm_trim_tail_lw(struct fsm *fsm) {
  iwrc rc;
  int hasleft;
  uint64_t length, lastblk, *bmptr;
  IWFS_EXT_STATE fstate;
  uint64_t offset = 0;

  if (!(fsm->omode & IWFS_OWRITE)) {
    return 0;
  }
  /* find free space for fsm with lesser offset than actual */
  rc = _fsm_blk_allocate_aligned_lw(
    fsm, (fsm->bmlen >> fsm->bpow), &offset, &length, (fsm->bmoff >> fsm->bpow),
    IWFSM_ALLOC_NO_EXTEND | IWFSM_ALLOC_NO_OVERALLOCATE | IWFSM_ALLOC_NO_STATS);

  if (rc && (rc != IWFS_ERROR_NO_FREE_SPACE)) {
    return rc;
  }
  if (rc) {
    rc = 0;
  } else if ((offset << fsm->bpow) < fsm->bmoff) {
    offset = offset << fsm->bpow;
    length = length << fsm->bpow;
    assert(offset != fsm->bmoff);
    fsm->pool.add_mmap(&fsm->pool, offset, length, fsm->mmap_opts);
    RCC(rc, finish, _fsm_init_lw(fsm, offset, length));
  } else {
    /* shoud never be reached */
    assert(0);
    RCC(rc, finish, _fsm_blk_deallocate_lw(fsm, offset, length));
  }

  RCC(rc, finish, _fsm_bmptr(fsm, &bmptr)); // -V519

  lastblk = (fsm->bmoff + fsm->bmlen) >> fsm->bpow;
  offset = _fsm_find_prev_set_bit(bmptr, (fsm->bmlen << 3), lastblk, &hasleft);
  if (hasleft) {
    lastblk = offset + 1;
  }
  rc = fsm->pool.state(&fsm->pool, &fstate);
  if (!rc && (fstate.fsize > (lastblk << fsm->bpow))) {
    rc = fsm->pool.truncate(&fsm->pool, lastblk << fsm->bpow);
  }

finish:
  return rc;
}

static iwrc _fsm_init_impl(struct fsm *fsm, const IWFS_FSM_OPTS *opts) {
  fsm->oflags = opts->oflags;
  fsm->aunit = iwp_alloc_unit();
  fsm->bpow = opts->bpow;
  fsm->mmap_all = opts->mmap_all;
  if (!fsm->bpow) {
    fsm->bpow = 6;  // 64bit block
  } else if (fsm->bpow > FSM_MAX_BLOCK_POW) {
    return IWFS_ERROR_INVALID_BLOCK_SIZE;
  } else if ((1U << fsm->bpow) > fsm->aunit) {
    return IWFS_ERROR_PLATFORM_PAGE;
  }
  return 0;
}

static iwrc _fsm_init_locks(struct fsm *fsm, const IWFS_FSM_OPTS *opts) {
  if (opts->oflags & IWFSM_NOLOCKS) {
    fsm->ctlrwlk = 0;
    return 0;
  }
  fsm->ctlrwlk = calloc(1, sizeof(*fsm->ctlrwlk));
  if (!fsm->ctlrwlk) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  int rci = pthread_rwlock_init(fsm->ctlrwlk, 0);
  if (rci) {
    free(fsm->ctlrwlk);
    fsm->ctlrwlk = 0;
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  return 0;
}

static iwrc _fsm_destroy_locks(struct fsm *fsm) {
  if (!fsm->ctlrwlk) {
    return 0;
  }
  iwrc rc = 0;
  int rci = pthread_rwlock_destroy(fsm->ctlrwlk);
  if (rci) {
    IWRC(iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci), rc);
  }
  free(fsm->ctlrwlk);
  fsm->ctlrwlk = 0;
  return rc;
}

static iwrc _fsm_read_meta_lr(struct fsm *fsm) {
  iwrc rc;
  uint32_t lv;
  uint64_t llv;
  size_t sp, rp = 0;
  uint8_t hdr[IWFSM_CUSTOM_HDR_DATA_OFFSET] = { 0 };

  /*
      [FSM_CTL_MAGICK u32][block pow u8]
      [bmoffset u64][bmlength u64]
      [u64 crzsum][u32 crznum][u64 crszvar][u256 reserved]
      [custom header size u32][custom header data...]
      [fsm data...]
   */

  rc = fsm->pool.read(&fsm->pool, 0, hdr, IWFSM_CUSTOM_HDR_DATA_OFFSET, &sp);
  if (rc) {
    iwlog_ecode_error3(rc);
    return rc;
  }

  /* Magic */
  memcpy(&lv, hdr + rp, sizeof(lv)); // -V512
  lv = IW_ITOHL(lv);
  if (lv != IWFSM_MAGICK) {
    rc = IWFS_ERROR_INVALID_FILEMETA;
    iwlog_ecode_error2(rc, "Invalid file magic number");
    return rc;
  }
  rp += sizeof(lv);

  /* Block pow */
  memcpy(&fsm->bpow, hdr + rp, sizeof(fsm->bpow));
  rp += sizeof(fsm->bpow);

  if (fsm->bpow > FSM_MAX_BLOCK_POW) {
    rc = IWFS_ERROR_INVALID_FILEMETA;
    iwlog_ecode_error(rc, "Invalid file blocks pow: %u", fsm->bpow);
    return rc;
  }
  if ((1U << fsm->bpow) > fsm->aunit) {
    rc = IWFS_ERROR_PLATFORM_PAGE;
    iwlog_ecode_error(rc, "Block size: %u must not be greater than system page size: %zu",
                      (1U << fsm->bpow), fsm->aunit);
  }

  /* Free-space bitmap offset */
  memcpy(&llv, hdr + rp, sizeof(llv));
  llv = IW_ITOHLL(llv);
  fsm->bmoff = llv;
  rp += sizeof(llv);

  /* Free-space bitmap length */
  memcpy(&llv, hdr + rp, sizeof(llv));
  llv = IW_ITOHLL(llv);
  fsm->bmlen = llv;
  if (llv & (64 - 1)) {
    rc = IWFS_ERROR_INVALID_FILEMETA;
    iwlog_ecode_error(rc, "Free-space bitmap length is not 64bit aligned: %" PRIuMAX "", fsm->bmlen);
  }
  rp += sizeof(llv);

  /* Cumulative sum of record sizes acquired by `allocate` */
  memcpy(&llv, hdr + rp, sizeof(llv));
  llv = IW_ITOHLL(llv);
  fsm->crzsum = llv;
  rp += sizeof(llv);

  /* Cumulative number of records acquired by `allocated` */
  memcpy(&lv, hdr + rp, sizeof(lv));
  lv = IW_ITOHL(lv);
  fsm->crznum = lv;
  rp += sizeof(lv);

  /* Record sizes standard variance (deviation^2 * N) */
  memcpy(&llv, hdr + rp, sizeof(llv));
  llv = IW_ITOHLL(llv);
  fsm->crzvar = llv;
  rp += sizeof(llv);

  /* Reserved */
  rp += 32;

  /* Header size */
  memcpy(&lv, hdr + rp, sizeof(lv));
  lv = IW_ITOHL(lv);
  fsm->hdrlen = lv;
  rp += sizeof(lv);

  assert(rp == IWFSM_CUSTOM_HDR_DATA_OFFSET);
  return rc;
}

static iwrc _fsm_init_new_lw(struct fsm *fsm, const IWFS_FSM_OPTS *opts) {
  FSM_ENSURE_OPEN(fsm);
  iwrc rc;
  uint64_t bmlen, bmoff;
  IWFS_EXT *pool = &fsm->pool;
  assert(fsm->aunit && fsm->bpow);

  fsm->hdrlen = opts->hdrlen + IWFSM_CUSTOM_HDR_DATA_OFFSET;
  fsm->hdrlen = IW_ROUNDUP(fsm->hdrlen, 1ULL << fsm->bpow);
  bmlen = opts->bmlen > 0 ? IW_ROUNDUP(opts->bmlen, fsm->aunit) : fsm->aunit;
  bmoff = IW_ROUNDUP(fsm->hdrlen, fsm->aunit);

  if (fsm->mmap_all) {
    /* mmap whole file */
    rc = pool->add_mmap(pool, 0, SIZE_T_MAX, fsm->mmap_opts);
    RCRET(rc);
  } else {
    /* mmap header */
    rc = pool->add_mmap(pool, 0, fsm->hdrlen, fsm->mmap_opts);
    RCRET(rc);
    /* mmap the fsm bitmap index */
    rc = pool->add_mmap(pool, bmoff, bmlen, fsm->mmap_opts);
    RCRET(rc);
  }
  return _fsm_init_lw(fsm, bmoff, bmlen);
}

static iwrc _fsm_init_existing_lw(struct fsm *fsm) {
  FSM_ENSURE_OPEN(fsm);
  iwrc rc;
  size_t sp;
  uint8_t *mm;
  IWFS_EXT *pool = &fsm->pool;

  RCC(rc, finish, _fsm_read_meta_lr(fsm));

  if (fsm->mmap_all) {
    /* mmap the whole file */
    RCC(rc, finish, pool->add_mmap(pool, 0, SIZE_T_MAX, fsm->mmap_opts));
    RCC(rc, finish, pool->probe_mmap(pool, 0, &mm, &sp));
    if (sp < fsm->bmoff + fsm->bmlen) {
      rc = IWFS_ERROR_NOT_MMAPED;
      goto finish;
    } else {
      mm += fsm->bmoff;
    }
  } else {
    /* mmap the header of file */
    RCC(rc, finish, pool->add_mmap(pool, 0, fsm->hdrlen, fsm->mmap_opts));
    /* mmap the fsm bitmap index */
    RCC(rc, finish, pool->add_mmap(pool, fsm->bmoff, fsm->bmlen, fsm->mmap_opts));
    RCC(rc, finish, pool->probe_mmap(pool, fsm->bmoff, &mm, &sp));
    if (sp < fsm->bmlen) {
      rc = IWFS_ERROR_NOT_MMAPED;
      goto finish;
    }
  }

  _fsm_load_fsm_lw(fsm, mm, fsm->bmlen);

finish:
  return rc;
}

/**
 * @brief Check if all blocks within the specified range have been `allocated`.
 *
 * @param fsm `struct fsm`
 * @param offset_blk Starting block number of the specified range.
 * @param length_blk Range size in blocks.
 * @param [out] ret Checking result.
 */
static iwrc _fsm_is_fully_allocated_lr(struct fsm *fsm, uint64_t offset_blk, uint64_t length_blk, int *ret) {
  uint64_t end = offset_blk + length_blk;
  *ret = 1;
  if ((length_blk < 1) || (end < offset_blk) || (end > (fsm->bmlen << 3))) {
    *ret = 0;
    return 0;
  }
  iwrc rc = _fsm_set_bit_status_lw(fsm, offset_blk, length_blk, 0, FSM_BM_DRY_RUN | FSM_BM_STRICT);
  if (rc == IWFS_ERROR_FSM_SEGMENTATION) {
    *ret = 0;
    return 0;
  }
  return rc;
}

/*************************************************************************************************
*                                  Public API *
*************************************************************************************************/

static iwrc _fsm_write(struct IWFS_FSM *f, off_t off, const void *buf, size_t siz, size_t *sp) {
  FSM_ENSURE_OPEN2(f);
  struct fsm *fsm = f->impl;
  iwrc rc = _fsm_ctrl_rlock(fsm);
  RCRET(rc);
  if (IW_UNLIKELY(fsm->oflags & IWFSM_STRICT)) {
    int allocated = 0;
    IWRC(_fsm_is_fully_allocated_lr(fsm,
                                    (uint64_t) off >> fsm->bpow,
                                    IW_ROUNDUP(siz, 1ULL << fsm->bpow) >> fsm->bpow,
                                    &allocated), rc);
    if (!rc) {
      if (!allocated) {
        rc = IWFS_ERROR_FSM_SEGMENTATION;
      } else {
        rc = fsm->pool.write(&fsm->pool, off, buf, siz, sp);
      }
    }
  } else {
    rc = fsm->pool.write(&fsm->pool, off, buf, siz, sp);
  }
  _fsm_ctrl_unlock(fsm);
  return rc;
}

static iwrc _fsm_read(struct IWFS_FSM *f, off_t off, void *buf, size_t siz, size_t *sp) {
  FSM_ENSURE_OPEN2(f);
  struct fsm *fsm = f->impl;
  iwrc rc = _fsm_ctrl_rlock(fsm);
  RCRET(rc);
  if (IW_UNLIKELY(fsm->oflags & IWFSM_STRICT)) {
    int allocated = 0;
    IWRC(_fsm_is_fully_allocated_lr(fsm, (uint64_t) off >> fsm->bpow,
                                    IW_ROUNDUP(siz, 1ULL << fsm->bpow) >> fsm->bpow,
                                    &allocated), rc);
    if (!rc) {
      if (!allocated) {
        rc = IWFS_ERROR_FSM_SEGMENTATION;
      } else {
        rc = fsm->pool.read(&fsm->pool, off, buf, siz, sp);
      }
    }
  } else {
    rc = fsm->pool.read(&fsm->pool, off, buf, siz, sp);
  }
  _fsm_ctrl_unlock(fsm);
  return rc;
}

static iwrc _fsm_sync(struct IWFS_FSM *f, iwfs_sync_flags flags) {
  FSM_ENSURE_OPEN2(f);
  iwrc rc = _fsm_ctrl_rlock(f->impl);
  RCRET(rc);
  IWRC(_fsm_write_meta_lw(f->impl), rc);
  IWRC(f->impl->pool.sync(&f->impl->pool, flags), rc);
  IWRC(_fsm_ctrl_unlock(f->impl), rc);
  return rc;
}

static iwrc _fsm_close(struct IWFS_FSM *f) {
  if (!f || !f->impl) {
    return 0;
  }
  iwrc rc = 0;
  struct fsm *fsm = f->impl;
  IWRC(_fsm_ctrl_wlock(fsm), rc);
  if (fsm->root && (fsm->omode & IWFS_OWRITE)) {
    if (!(fsm->oflags & IWFSM_NO_TRIM_ON_CLOSE)) {
      IWRC(_fsm_trim_tail_lw(fsm), rc);
    }
    IWRC(_fsm_write_meta_lw(fsm), rc);
    if (!fsm->dlsnr) {
      IWRC(fsm->pool.sync(&fsm->pool, IWFS_SYNCDEFAULT), rc);
    }
  }
  IWRC(fsm->pool.close(&fsm->pool), rc);
  _fsm_node_destroy(fsm->root);
  IWRC(_fsm_ctrl_unlock(fsm), rc);
  IWRC(_fsm_destroy_locks(fsm), rc);
  f->impl = 0;
  free(fsm);
  return rc;
}

IW_INLINE iwrc _fsm_ensure_size_lw(struct fsm *fsm, off_t size) {
  return fsm->pool.ensure_size(&fsm->pool, size);
}

static iwrc _fsm_ensure_size(struct IWFS_FSM *f, off_t size) {
  FSM_ENSURE_OPEN2(f);
  iwrc rc = _fsm_ctrl_rlock(f->impl);
  RCRET(rc);
  if (f->impl->bmoff + f->impl->bmlen > size) {
    rc = IWFS_ERROR_RESIZE_FAIL;
    goto finish;
  }
  rc = _fsm_ensure_size_lw(f->impl, size);

finish:
  IWRC(_fsm_ctrl_unlock(f->impl), rc);
  return rc;
}

static iwrc _fsm_add_mmap(struct IWFS_FSM *f, off_t off, size_t maxlen, iwfs_ext_mmap_opts_t opts) {
  FSM_ENSURE_OPEN2(f);
  return f->impl->pool.add_mmap(&f->impl->pool, off, maxlen, opts);
}

static iwrc _fsm_remap_all(struct IWFS_FSM *f) {
  FSM_ENSURE_OPEN2(f);
  return f->impl->pool.remap_all(&f->impl->pool);
}

iwrc _fsm_acquire_mmap(struct IWFS_FSM *f, off_t off, uint8_t **mm, size_t *sp) {
  return f->impl->pool.acquire_mmap(&f->impl->pool, off, mm, sp);
}

iwrc _fsm_release_mmap(struct IWFS_FSM *f) {
  return f->impl->pool.release_mmap(&f->impl->pool);
}

static iwrc _fsm_probe_mmap(struct IWFS_FSM *f, off_t off, uint8_t **mm, size_t *sp) {
  FSM_ENSURE_OPEN2(f);
  return f->impl->pool.probe_mmap(&f->impl->pool, off, mm, sp);
}

static iwrc _fsm_remove_mmap(struct IWFS_FSM *f, off_t off) {
  FSM_ENSURE_OPEN2(f);
  return f->impl->pool.remove_mmap(&f->impl->pool, off);
}

static iwrc _fsm_sync_mmap(struct IWFS_FSM *f, off_t off, iwfs_sync_flags flags) {
  FSM_ENSURE_OPEN2(f);
  return f->impl->pool.sync_mmap(&f->impl->pool, off, flags);
}

static iwrc _fsm_allocate(struct IWFS_FSM *f, off_t len, off_t *oaddr, off_t *olen, iwfs_fsm_aflags opts) {
  FSM_ENSURE_OPEN2(f);
  iwrc rc;
  uint64_t sbnum, nlen;
  struct fsm *fsm = f->impl;

  *olen = 0;
  if (!(fsm->omode & IWFS_OWRITE)) {
    return IW_ERROR_READONLY;
  }
  if (len <= 0) {
    return IW_ERROR_INVALID_ARGS;
  }
  /* Required blocks number */
  sbnum = (uint64_t) *oaddr >> fsm->bpow;
  len = IW_ROUNDUP(len, 1ULL << fsm->bpow);

  rc = _fsm_ctrl_wlock(fsm);
  RCRET(rc);
  rc = _fsm_blk_allocate_lw(f->impl, (uint64_t) len >> fsm->bpow, &sbnum, &nlen, opts);
  if (!rc) {
    *olen = (nlen << fsm->bpow);
    *oaddr = (sbnum << fsm->bpow);
  }
  IWRC(_fsm_ctrl_unlock(fsm), rc);
  return rc;
}

static iwrc _fsm_reallocate(struct IWFS_FSM *f, off_t nlen, off_t *oaddr, off_t *olen, iwfs_fsm_aflags opts) {
  FSM_ENSURE_OPEN2(f);
  iwrc rc;
  struct fsm *fsm = f->impl;

  if (!(fsm->omode & IWFS_OWRITE)) {
    return IW_ERROR_READONLY;
  }
  if ((*oaddr & ((1ULL << fsm->bpow) - 1)) || (*olen & ((1ULL << fsm->bpow) - 1))) {
    return IWFS_ERROR_RANGE_NOT_ALIGNED;
  }
  uint64_t sp;
  uint64_t nlen_blk = IW_ROUNDUP((uint64_t) nlen, 1ULL << fsm->bpow) >> fsm->bpow;
  uint64_t olen_blk = (uint64_t) *olen >> fsm->bpow;
  uint64_t oaddr_blk = (uint64_t) *oaddr >> fsm->bpow;
  uint64_t naddr_blk = oaddr_blk;

  if (nlen_blk == olen_blk) {
    return 0;
  }
  rc = _fsm_ctrl_wlock(fsm);
  RCRET(rc);
  if (nlen_blk < olen_blk) {
    rc = _fsm_blk_deallocate_lw(fsm, oaddr_blk + nlen_blk, olen_blk - nlen_blk);
    if (!rc) {
      *oaddr = oaddr_blk << fsm->bpow;
      *olen = nlen_blk << fsm->bpow;
    }
  } else {
    RCC(rc, finish, _fsm_blk_allocate_lw(fsm, nlen_blk, &naddr_blk, &sp, opts));
    if (naddr_blk != oaddr_blk) {
      RCC(rc, finish, fsm->pool.copy(&fsm->pool, *oaddr, (size_t) *olen, naddr_blk << fsm->bpow));
    }
    RCC(rc, finish, _fsm_blk_deallocate_lw(fsm, oaddr_blk, olen_blk));
    *oaddr = naddr_blk << fsm->bpow;
    *olen = sp << fsm->bpow;
  }

finish:
  IWRC(_fsm_ctrl_unlock(fsm), rc);
  return rc;
}

static iwrc _fsm_deallocate(struct IWFS_FSM *f, off_t addr, off_t len) {
  FSM_ENSURE_OPEN2(f);
  iwrc rc;
  struct fsm *fsm = f->impl;
  off_t offset_blk = (uint64_t) addr >> fsm->bpow;
  off_t length_blk = (uint64_t) len >> fsm->bpow;

  if (!(fsm->omode & IWFS_OWRITE)) {
    return IW_ERROR_READONLY;
  }
  if (addr & ((1ULL << fsm->bpow) - 1)) {
    return IWFS_ERROR_RANGE_NOT_ALIGNED;
  }
  rc = _fsm_ctrl_wlock(fsm);
  RCRET(rc);
  if (  IW_RANGES_OVERLAP(offset_blk, offset_blk + length_blk, 0, (fsm->hdrlen >> fsm->bpow))
     || IW_RANGES_OVERLAP(offset_blk, offset_blk + length_blk, (fsm->bmoff >> fsm->bpow),
                          (fsm->bmoff >> fsm->bpow) + (fsm->bmlen >> fsm->bpow))) {
    // Deny deallocations in header or free-space bitmap itself
    IWRC(_fsm_ctrl_unlock(fsm), rc);
    return IWFS_ERROR_FSM_SEGMENTATION;
  }
  rc = _fsm_blk_deallocate_lw(fsm, (uint64_t) offset_blk, (uint64_t) length_blk);
  IWRC(_fsm_ctrl_unlock(fsm), rc);
  return rc;
}

static iwrc _fsm_check_allocation_status(struct IWFS_FSM *f, off_t addr, off_t len, bool allocated) {
  struct fsm *fsm = f->impl;
  if ((addr & ((1ULL << fsm->bpow) - 1)) || (len & ((1ULL << fsm->bpow) - 1))) {
    return IWFS_ERROR_RANGE_NOT_ALIGNED;
  }
  iwrc rc = _fsm_ctrl_rlock(fsm);
  RCRET(rc);
  off_t offset_blk = (uint64_t) addr >> fsm->bpow;
  off_t length_blk = (uint64_t) len >> fsm->bpow;
  if (  IW_RANGES_OVERLAP(offset_blk, offset_blk + length_blk, 0, (fsm->hdrlen >> fsm->bpow))
     || IW_RANGES_OVERLAP(offset_blk, offset_blk + length_blk, (fsm->bmoff >> fsm->bpow),
                          (fsm->bmoff >> fsm->bpow) + (fsm->bmlen >> fsm->bpow))) {
    IWRC(_fsm_ctrl_unlock(fsm), rc);
    return IWFS_ERROR_FSM_SEGMENTATION;
  }
  rc = _fsm_set_bit_status_lw(fsm, (uint64_t) offset_blk, (uint64_t) length_blk,
                              allocated ? 0 : 1, FSM_BM_DRY_RUN | FSM_BM_STRICT);
  IWRC(_fsm_ctrl_unlock(fsm), rc);
  return rc;
}

static iwrc _fsm_writehdr(struct IWFS_FSM *f, off_t off, const void *buf, off_t siz) {
  FSM_ENSURE_OPEN2(f);
  iwrc rc;
  uint8_t *mm;
  if (siz < 1) {
    return 0;
  }
  struct fsm *fsm = f->impl;
  if ((IWFSM_CUSTOM_HDR_DATA_OFFSET + off + siz) > fsm->hdrlen) {
    return IW_ERROR_OUT_OF_BOUNDS;
  }
  rc = fsm->pool.acquire_mmap(&fsm->pool, 0, &mm, 0);
  if (!rc) {
    if (fsm->dlsnr) {
      rc = fsm->dlsnr->onwrite(fsm->dlsnr, IWFSM_CUSTOM_HDR_DATA_OFFSET + off, buf, siz, 0);
    }
    memmove(mm + IWFSM_CUSTOM_HDR_DATA_OFFSET + off, buf, (size_t) siz);
    IWRC(fsm->pool.release_mmap(&fsm->pool), rc);
  }
  return rc;
}

static iwrc _fsm_readhdr(struct IWFS_FSM *f, off_t off, void *buf, off_t siz) {
  FSM_ENSURE_OPEN2(f);
  iwrc rc;
  uint8_t *mm;
  if (siz < 1) {
    return 0;
  }
  struct fsm *fsm = f->impl;
  if ((IWFSM_CUSTOM_HDR_DATA_OFFSET + off + siz) > fsm->hdrlen) {
    return IW_ERROR_OUT_OF_BOUNDS;
  }
  rc = fsm->pool.acquire_mmap(&fsm->pool, 0, &mm, 0);
  if (!rc) {
    memmove(buf, mm + IWFSM_CUSTOM_HDR_DATA_OFFSET + off, (size_t) siz);
    rc = fsm->pool.release_mmap(&fsm->pool);
  }
  return rc;
}

static iwrc _fsm_clear(struct IWFS_FSM *f, iwfs_fsm_clrfalgs clrflags) {
  FSM_ENSURE_OPEN2(f);
  struct fsm *fsm = f->impl;
  uint64_t bmoff, bmlen;
  iwrc rc = _fsm_ctrl_wlock(fsm);
  bmlen = fsm->bmlen;
  if (!bmlen) {
    goto finish;
  }
  if (!fsm->mmap_all && fsm->bmoff) {
    IWRC(fsm->pool.remove_mmap(&fsm->pool, fsm->bmoff), rc);
  }
  bmoff = IW_ROUNDUP(fsm->hdrlen, fsm->aunit);
  if (!fsm->mmap_all) {
    IWRC(fsm->pool.add_mmap(&fsm->pool, bmoff, bmlen, fsm->mmap_opts), rc);
  }
  RCGO(rc, finish);
  fsm->bmlen = 0;
  fsm->bmoff = 0;
  rc = _fsm_init_lw(fsm, bmoff, bmlen);
  if (!rc && (clrflags & IWFSM_CLEAR_TRIM)) {
    rc = _fsm_trim_tail_lw(fsm);
  }

finish:
  IWRC(_fsm_ctrl_unlock(fsm), rc);
  return rc;
}

static iwrc _fsm_extfile(struct IWFS_FSM *f, IWFS_EXT **ext) {
  FSM_ENSURE_OPEN2(f);
  *ext = &f->impl->pool;
  return 0;
}

static iwrc _fsm_state(struct IWFS_FSM *f, IWFS_FSM_STATE *state) {
  FSM_ENSURE_OPEN2(f);
  struct fsm *fsm = f->impl;
  iwrc rc = _fsm_ctrl_rlock(fsm);
  memset(state, 0, sizeof(*state));
  IWRC(fsm->pool.state(&fsm->pool, &state->exfile), rc);
  state->block_size = 1U << fsm->bpow;
  state->oflags = fsm->oflags;
  state->hdrlen = fsm->hdrlen;
  state->blocks_num = fsm->bmlen << 3;
  state->free_segments_num = fsm->fsmnum;
  state->avg_alloc_size = fsm->crznum > 0 ? (double_t) fsm->crzsum / (double_t) fsm->crznum : 0;
  state->alloc_dispersion = fsm->crznum > 0 ? (double_t) fsm->crzvar / (double_t) fsm->crznum : 0;
  IWRC(_fsm_ctrl_unlock(fsm), rc);
  return rc;
}

iwrc iwfs_fsmfile_open(IWFS_FSM *f, const IWFS_FSM_OPTS *opts) {
  assert(f && opts);
  iwrc rc = 0;
  IWFS_EXT_STATE fstate = { 0 };
  const char *path = opts->exfile.file.path;

  memset(f, 0, sizeof(*f));
  RCC(rc, finish, iwfs_fsmfile_init());

  f->write = _fsm_write;
  f->read = _fsm_read;
  f->close = _fsm_close;
  f->sync = _fsm_sync;
  f->state = _fsm_state;

  f->ensure_size = _fsm_ensure_size;
  f->add_mmap = _fsm_add_mmap;
  f->remap_all = _fsm_remap_all;
  f->acquire_mmap = _fsm_acquire_mmap;
  f->probe_mmap = _fsm_probe_mmap;
  f->release_mmap = _fsm_release_mmap;
  f->remove_mmap = _fsm_remove_mmap;
  f->sync_mmap = _fsm_sync_mmap;

  f->allocate = _fsm_allocate;
  f->reallocate = _fsm_reallocate;
  f->deallocate = _fsm_deallocate;
  f->check_allocation_status = _fsm_check_allocation_status;
  f->writehdr = _fsm_writehdr;
  f->readhdr = _fsm_readhdr;
  f->clear = _fsm_clear;
  f->extfile = _fsm_extfile;

  if (!path) {
    return IW_ERROR_INVALID_ARGS;
  }
  struct fsm *fsm = f->impl = calloc(1, sizeof(*f->impl));
  if (!fsm) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  fsm->f = f;
  fsm->dlsnr = opts->exfile.file.dlsnr; // Copy data changes listener address
  fsm->mmap_opts = opts->mmap_opts;

  IWFS_EXT_OPTS rwl_opts = opts->exfile;
  rwl_opts.use_locks = !(opts->oflags & IWFSM_NOLOCKS);

  RCC(rc, finish, _fsm_init_impl(fsm, opts));
  RCC(rc, finish, _fsm_init_locks(fsm, opts));
  RCC(rc, finish, iwfs_exfile_open(&fsm->pool, &rwl_opts));
  RCC(rc, finish, fsm->pool.state(&fsm->pool, &fstate));

  fsm->omode = fstate.file.opts.omode;

  if (fstate.file.ostatus & IWFS_OPEN_NEW) {
    rc = _fsm_init_new_lw(fsm, opts);
  } else {
    rc = _fsm_init_existing_lw(fsm);
  }

finish:
  if (rc) {
    if (f->impl) {
      IWRC(_fsm_destroy_locks(f->impl), rc);  // we are not locked
      IWRC(_fsm_close(f), rc);
    }
  }
  return rc;
}

static const char* _fsmfile_ecodefn(locale_t locale, uint32_t ecode) {
  if (!((ecode > _IWFS_FSM_ERROR_START) && (ecode < _IWFS_FSM_ERROR_END))) {
    return 0;
  }
  switch (ecode) {
    case IWFS_ERROR_NO_FREE_SPACE:
      return "No free space. (IWFS_ERROR_NO_FREE_SPACE)";
    case IWFS_ERROR_INVALID_BLOCK_SIZE:
      return "Invalid block size specified. (IWFS_ERROR_INVALID_BLOCK_SIZE)";
    case IWFS_ERROR_RANGE_NOT_ALIGNED:
      return "Specified range/offset is not aligned with page/block. "
             "(IWFS_ERROR_RANGE_NOT_ALIGNED)";
    case IWFS_ERROR_FSM_SEGMENTATION:
      return "Free-space map segmentation error. (IWFS_ERROR_FSM_SEGMENTATION)";
    case IWFS_ERROR_INVALID_FILEMETA:
      return "Invalid file metadata. (IWFS_ERROR_INVALID_FILEMETA)";
    case IWFS_ERROR_PLATFORM_PAGE:
      return "The block size incompatible with platform page size, data "
             "migration required. (IWFS_ERROR_PLATFORM_PAGE)";
    case IWFS_ERROR_RESIZE_FAIL:
      return "Failed to resize file, "
             "conflicting with free-space map location (IWFS_ERROR_RESIZE_FAIL)";
    default:
      break;
  }
  return 0;
}

iwrc iwfs_fsmfile_init(void) {
  static int _fsmfile_initialized = 0;
  iwrc rc = iw_init();
  RCRET(rc);
  if (!__sync_bool_compare_and_swap(&_fsmfile_initialized, 0, 1)) {
    return 0;  // initialized already
  }
  return iwlog_register_ecodefn(_fsmfile_ecodefn);
}

/*************************************************************************************************
*                                      Debug API                                                *
*************************************************************************************************/

uint64_t iwfs_fsmdbg_number_of_free_areas(IWFS_FSM *f) {
  struct fsm *fsm = f->impl;
  return fsm->fsmnum;
}

uint64_t iwfs_fsmdbg_find_next_set_bit(
  const uint64_t *addr, uint64_t offset_bit, uint64_t max_offset_bit,
  int *found
  ) {
  return _fsm_find_next_set_bit(addr, offset_bit, max_offset_bit, found);
}

uint64_t iwfs_fsmdbg_find_prev_set_bit(
  const uint64_t *addr, uint64_t offset_bit, uint64_t min_offset_bit,
  int *found
  ) {
  return _fsm_find_prev_set_bit(addr, offset_bit, min_offset_bit, found);
}

void iwfs_fsmdbg_dump_fsm_tree(IWFS_FSM *f, const char *hdr) {
  assert(f);
  struct fsm *fsm = f->impl;
  fprintf(stderr, "FSM TREE: %s\n", hdr);
  if (!fsm->root) {
    fprintf(stderr, "NONE\n");
    return;
  }
  for (struct iwavl_node *n = iwavl_first_in_order(fsm->root); n; n = iwavl_next_in_order(n)) {
    struct bkey *k = &BKEY(n);
    uint64_t koff = FSMBK_OFFSET(k);
    uint64_t klen = FSMBK_LENGTH(k);
    fprintf(stderr, "[%" PRIu64 " %" PRIu64 "]\n", koff, klen);
  }
}

const char* byte_to_binary(int x) {
  static char b[9];
  b[0] = '\0';
  int z;
  for (z = 1; z <= 128; z <<= 1) {
    strcat(b, ((x & z) == z) ? "1" : "0");
  }
  return b;
}

iwrc iwfs_fsmdb_dump_fsm_bitmap(IWFS_FSM *f) {
  assert(f);
  size_t sp;
  uint8_t *mm;
  struct fsm *fsm = f->impl;
  iwrc rc;
  if (fsm->mmap_all) {
    rc = fsm->pool.probe_mmap(&fsm->pool, 0, &mm, &sp);
    if (!rc) {
      if (sp <= fsm->bmoff) {
        rc = IWFS_ERROR_NOT_MMAPED;
      } else {
        mm += fsm->bmoff;
        sp = sp - fsm->bmoff;
      }
    }
  } else {
    rc = fsm->pool.probe_mmap(&fsm->pool, fsm->bmoff, &mm, &sp);
  }
  if (rc) {
    iwlog_ecode_error3(rc);
    return rc;
  }
  int i = ((fsm->hdrlen >> fsm->bpow) >> 3);
  // if (impl->bmoff == impl->aunit) {
  //   i += ((impl->bmlen >> impl->bpow) >> 3);
  // }
  for ( ; i < sp && i < fsm->bmlen; ++i) {
    uint8_t b = *(mm + i);
    fprintf(stderr, "%s", byte_to_binary(b));
  }
  printf("\n");
  return 0;
}

iwrc iwfs_fsmdbg_state(IWFS_FSM *f, IWFS_FSMDBG_STATE *d) {
  FSM_ENSURE_OPEN2(f);
  struct fsm *fsm = f->impl;
  iwrc rc = _fsm_ctrl_rlock(fsm);
  memset(d, 0, sizeof(*d));
  IWRC(fsm->pool.state(&fsm->pool, &d->state.exfile), rc);
  d->state.block_size = 1U << fsm->bpow;
  d->state.oflags = fsm->oflags;
  d->state.hdrlen = fsm->hdrlen;
  d->state.blocks_num = fsm->bmlen << 3;
  d->state.free_segments_num = fsm->fsmnum;
  d->state.avg_alloc_size = fsm->crznum > 0 ? (double_t) fsm->crzsum / (double_t) fsm->crznum : 0;
  d->state.alloc_dispersion = fsm->crznum > 0 ? (double_t) fsm->crzvar / (double_t) fsm->crznum : 0;
  d->bmoff = fsm->bmoff;
  d->bmlen = fsm->bmlen;
  d->lfbkoff = fsm->lfbkoff;
  d->lfbklen = fsm->lfbklen;
  IWRC(_fsm_ctrl_unlock(fsm), rc);
  return rc;
}
