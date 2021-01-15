#pragma once
#ifndef IWFSMFILE_H
#define IWFSMFILE_H

/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2021 Softmotions Ltd <info@softmotions.com>
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

/** @file
 *  @brief Auto-expandable file with support of reader/writer address space
           locking and free space block management using bitmaps.
 *  @author Anton Adamansky (adamansky@softmotions.com)
 *
 *  @note  Before using API of this module you should call
 * `iw_init(void)` iowow module initialization routine.
 *
 *  <strong>Features:</strong>
 *
 *  - Address blocks allocation and deallocation using bitmaps.
 *  - Read/write file address space locking.
 *  - Tunable file expansion policies.
 *  - Read/write methods locking option in multithreaded environment.
 *  - File shrinking/truncation support.
 *  - A number mmaped regions can be registered in the file's address space.
 *    These regions used in read/write operation and automatically maintained
 *    during file resize operations.
 *
 * File operations implemented as function pointers contained
 * in `IWFS_FSM` `C` structure.
 * The `iwfs_fsmfile_open(IWFS_FSM *f, const IWFS_FSM_OPTS *opts)` opens file
 * and initializes a given `IWFS_FSM` structure.
 *
 * <strong>File format:</strong>
 * @verbatim
    [FSM_CTL_MAGICK u32][block pow u8]
    [bmoffset u64][bmlength u64]
    [crzsum u64][crznum u32][crszvar u64][reserved u256]
    [custom header size u32][custom header data...]
    [fsm data...] @endverbatim
 *
 * <strong>where:</strong>
 *
 *  - <b>FSM_CTL_MAGICK:</b> Free-space file magic number (32 bit)
 *  - <b>block pow:</b> Block size as power of `2` Eg: `6` means `64` bit block
      size. (8 bit)
 *  - <b>bmoffset:</b> Free space bitmap area offset in bytes (64 bit)
 *  - <b>bmlength:</b> Free space bitmap area length. (64 bit)
 *  - <b>crzsum:</b> Number of allocated blocks. (64 bit)
 *  - <b>crznum:</b> Number of all allocated continuous areas. (32 bit)
 *  - <b>crszvar</b> Allocated areas length standard variance (deviation^2 * N) (64 bit)
 *  - <b>reserved:</b> Reserved space.
 *  - <b>custom header size:</b> Length of custom header area. See
   `IWFS_FSM::writehdr` and `IWFS_FSM::readhdr`
 */

#include "iwexfile.h"
#include <stdbool.h>
#include <math.h>

IW_EXTERN_C_START

/** Free space allocation flags
 *  @see IWFS_FSM::allocate
 */
typedef uint8_t iwfs_fsm_aflags;

/** Use default allocation settings */
#define IWFSM_ALLOC_DEFAULTS ((iwfs_fsm_aflags) 0x00U)

/** Do not @em overallocate a requested free space in order to reduce fragmentation  */
#define IWFSM_ALLOC_NO_OVERALLOCATE ((iwfs_fsm_aflags) 0x01U)

/** Do not extend the file and its bitmap free space mapping in the case if
 * file size expansion is required.
 * In this case the `IWFS_ERROR_NO_FREE_SPACE` error will be raised.*/
#define IWFSM_ALLOC_NO_EXTEND ((iwfs_fsm_aflags) 0x02U)

/** Force offset of an allocated space to be page aligned. */
#define IWFSM_ALLOC_PAGE_ALIGNED ((iwfs_fsm_aflags) 0x04U)

/** Do not collect internal allocation stats for this allocation. */
#define IWFSM_ALLOC_NO_STATS ((iwfs_fsm_aflags) 0x08U)

/** Force all of the allocated address space backed by real file address space. */
#define IWFSM_SOLID_ALLOCATED_SPACE ((iwfs_fsm_aflags) 0x10U)

/** Do msync of bitmap allocation index. */
#define IWFSM_SYNC_BMAP ((iwfs_fsm_aflags) 0x20U)

#define IWFSM_MAGICK 0x19cc7cc
#define IWFSM_CUSTOM_HDR_DATA_OFFSET                                                                          \
  (4 /*magic*/ + 1 /*block pow*/ + 8 /*fsm bitmap block offset */ + 8        /*fsm bitmap block length*/            \
   + 8 /*all allocated block length sum */ + 4                               /*number of all allocated areas */                              \
   + 8 /* allocated areas length standard variance (deviation^2 * N) */ + 32 /*reserved*/                      \
   + 4 /*custom hdr size*/)

/** File cleanup flags used in `IWFS_FSM::clear` */
typedef uint8_t iwfs_fsm_clrfalgs;

/** Perform file size trimming after cleanup */
#define IWFSM_CLEAR_TRIM ((iwfs_fsm_clrfalgs) 0x01U)

/** `IWFS_FSM` file open modes used in `IWFS_FSM_OPTS` */
typedef uint8_t iwfs_fsm_openflags;

/** Do not use threading locks */
#define IWFSM_NOLOCKS ((iwfs_fsm_openflags) 0x01U)

/** Strict block checking for alloc/dealloc operations. 10-15% performance overhead. */
#define IWFSM_STRICT ((iwfs_fsm_openflags) 0x02U)

/** Do not trim fsm file on close */
#define IWFSM_NO_TRIM_ON_CLOSE ((iwfs_fsm_openflags) 0x04U)

/**
 * @brief Error codes specific to `IWFS_FSM`.
 */
typedef enum {
  _IWFS_FSM_ERROR_START = (IW_ERROR_START + 4000UL),
  IWFS_ERROR_NO_FREE_SPACE,      /**< No free space. */
  IWFS_ERROR_INVALID_BLOCK_SIZE, /**< Invalid block size specified */
  IWFS_ERROR_RANGE_NOT_ALIGNED,
  /**< Specified range/offset is not aligned with
       page/block */
  IWFS_ERROR_FSM_SEGMENTATION,   /**< Free-space map segmentation error */
  IWFS_ERROR_INVALID_FILEMETA,   /**< Invalid file-metadata */
  IWFS_ERROR_PLATFORM_PAGE,
  /**< Platform page size incopatibility, data
       migration required. */
  IWFS_ERROR_RESIZE_FAIL,        /**< Failed to resize file   */
  _IWFS_FSM_ERROR_END,
} iwfs_fsm_ecode;

/**
 * @brief `IWFS_FSM` file options.
 * @see iwfs_fsmfile_open(IWFS_FSM *f, const IWFS_FSM_OPTS *opts)
 */
typedef struct IWFS_FSM_OPTS {
  IWFS_EXT_OPTS exfile;
  size_t   bmlen;                 /**< Initial size of free-space bitmap */
  uint32_t hdrlen;                /**< Length of custom file header.*/
  iwfs_fsm_openflags   oflags;    /**< Operation mode flags */
  iwfs_ext_mmap_opts_t mmap_opts; /**< Defaul mmap options used in `add_mmap` */
  uint8_t bpow;                   /**< Block size power for 2 */
  bool    mmap_all;               /**< Mmap all file data */
} IWFS_FSM_OPTS;

/**
 * @brief `IWFS_FSM` file state container.
 * @see IWFS_FSM::state
 */
typedef struct IWFS_FSM_STATE {
  IWFS_EXT_STATE exfile;      /**< File pool state */
  size_t block_size;          /**< Size of data block in bytes. */
  iwfs_fsm_openflags oflags;  /**< Operation mode flags. */
  uint32_t hdrlen;            /**< Length of custom file header length in bytes */
  uint64_t blocks_num;        /**< Number of available data blocks. */
  uint64_t free_segments_num; /**< Number of free (deallocated) continuous data
                                 segments. */
  double_t avg_alloc_size;    /**< Average allocation number of blocks */
  double_t alloc_dispersion;  /**< Average allocation blocks dispersion */
} IWFS_FSM_STATE;

typedef struct IWFS_FSMDBG_STATE {
  IWFS_FSM_STATE state;
  uint64_t       bmoff;
  uint64_t       bmlen;
  uint64_t       lfbklen;
  uint64_t       lfbkoff;
} IWFS_FSMDBG_STATE;

/**
 * @brief Auto-expandable file with support of reader/writer address space
 * locking
 *        and free space blocks management using bitmaps.
 */
typedef struct IWFS_FSM {
  struct IWFS_FSM_IMPL *impl;

  /**
   * @brief Allocate a continuous address space within a file
   *        with length greater or equal to the desired @a len bytes.
   *
   * `Offset` and  `length` allocated area will be block size aligned.
   *
   * @param f `IWFS_FSM` file.
   * @param len Desired length of an allocated area in bytes.
   * @param [in,out] oaddr Placeholder for the address of an allocated area.
   *                       Value of @a oaddr passed to this function used as
   * `hint` in order
   *                       to allocate area located closely to the specified @a
   * oaddr value.
   * @param [out] olen Actual length of an allocated area in bytes.
   * @param opts Allocation options bitmask flag @ref iwfs_fsm_aflags
   * @return `0` on success or error code.
   */
  iwrc (*allocate)(
    struct IWFS_FSM *f, off_t len, off_t *oaddr, off_t *olen,
    iwfs_fsm_aflags opts);

  /**
   * @brief Reallocate and adjust a size of an allocated block.
   *
   * If the given @a nlen value lesser than actual length of segment @a olen in
   * that case
   * segment will be truncated.
   *
   * @param f `IWFS_FSM` file.
   * @param nlen Desired length of segment in bytes.
   * @param oaddr [in,out] Address of an allocated segment. Placeholder for new
   * address of reallocated segment.
   * @param olen [in,out] Length of an allocated segment. Placeholder for length
   * of reallocated segment.
   * @param opts Allocation options bitmask flag @ref iwfs_fsm_aflags
   * @return `0` on success or error code.
   */
  iwrc (*reallocate)(
    struct IWFS_FSM *f, off_t nlen, off_t *oaddr, off_t *olen,
    iwfs_fsm_aflags opts);

  /**
   * @brief Free a previously allocated area.
   * @param addr Address space offset in bytes <em>it must be block size
   * aligned</em>.
   * @param len Length of area to release.
   * @return `0` on success or error code.
   */
  iwrc (*deallocate)(struct IWFS_FSM *f, off_t addr, off_t len);


  /**
   * @brief Check allocation status of region specified by @a addr and @a len
   * @return `0` on success or error code.
   */
  iwrc (*check_allocation_status)(struct IWFS_FSM *f, off_t addr, off_t len, bool allocated);

  /**
   * @brief Write a data to the custom file header.
   *
   * A custom file header size specified in IWFS_FSM_OPTS::hdrlen options on
   * file creation.
   *
   * @param off Offset position relative to custom header start offset.
   * @param buf Data buffer to write
   * @param siz Number of bytes of @a buf to write into header.
   * @return `0` on success or error code.
   */
  iwrc (*writehdr)(struct IWFS_FSM *f, off_t off, const void *buf, off_t siz);

  /**
   * @brief Read a data from the custom file header.
   *
   * A custom file header size specified in IWFS_FSM_OPTS::hdrlen options on
   * file creation.
   *
   * @param off Offset position relative to custom header start offset.
   * @param [out] buf Data buffer to read into
   * @param Number of bytes to read
   */
  iwrc (*readhdr)(struct IWFS_FSM *f, off_t off, void *buf, off_t siz);

  /**
   * @brief Cleanup all allocated data blocks and reset the file to the initial
   * empty state.
   *
   * @param clrflags
   * @return `0` on success or error code.
   */
  iwrc (*clear)(struct IWFS_FSM *f, iwfs_fsm_clrfalgs clrflags);

  /* See iwexfile.h */

  /** @see IWFS_EXT::ensure_size */
  iwrc (*ensure_size)(struct IWFS_FSM *f, off_t size);


  /** @see IWFS_EXT::add_mmap */
  iwrc (*add_mmap)(struct IWFS_FSM *f, off_t off, size_t maxlen, iwfs_ext_mmap_opts_t opts);


  /** @see IWFS_EXT::remap_all */
  iwrc (*remap_all)(struct IWFS_FSM *f);

  /**
   * @brief Get a pointer to the registered mmap area starting at `off`.
   *
   * WARNING: Internal read lock will be acquired and
   *          must be released by subsequent `release_mmap()` call
   *          after all activity with mmaped region has finished.
   *
   * @see IWFS_FSM::add_mmap
   * @see IWFS_EXT::acquire_mmap
   */
  iwrc (*acquire_mmap)(struct IWFS_FSM *f, off_t off, uint8_t **mm, size_t *sp);

  /**
   * @brief Retrieve mmaped region by its offset @a off
   */
  iwrc (*probe_mmap)(struct IWFS_FSM *f, off_t off, uint8_t **mm, size_t *sp);

  /**
   * @brief Release the lock acquired by successfull call of `acquire_mmap()`
   */
  iwrc (*release_mmap)(struct IWFS_FSM *f);

  /** @see IWFS_EXT::remove_mmap */
  iwrc (*remove_mmap)(struct IWFS_FSM *f, off_t off);

  /** @see IWFS_EXT::sync_mmap */
  iwrc (*sync_mmap)(struct IWFS_FSM *f, off_t off, iwfs_sync_flags flags);

  /* See iwfile.h */

  /** @see IWFS_FILE::write */
  iwrc (*write)(
    struct IWFS_FSM *f, off_t off, const void *buf, size_t siz,
    size_t *sp);

  /** @see IWFS_FILE::read */
  iwrc (*read)(
    struct IWFS_FSM *f, off_t off, void *buf, size_t siz,
    size_t *sp);

  /** @see IWFS_FILE::close */
  iwrc (*close)(struct IWFS_FSM *f);

  /** @see IWFS_FILE::sync */
  iwrc (*sync)(struct IWFS_FSM *f, iwfs_sync_flags flags);

  /** @see IWFS_FILE::state */
  iwrc (*state)(struct IWFS_FSM *f, IWFS_FSM_STATE *state);

  /** get access to the underlying iwextfile instance */
  iwrc (*extfile)(struct IWFS_FSM *f, IWFS_EXT **ext);
} IWFS_FSM;

/**
 * @brief Open `IWFS_FSM` file.
 *
 * <strong>Example:</strong>
 *
 * Open a buffer pool file for multithreaded env with fibonacci file resize
 * policy with block size of 64 bytes and custom file header of 255 bytes
 * length.
 *
 * @code {.c}
 *  IWFS_FSM_OPTS opts = {
 *       .exfile = {
 *          .file = {
 *              .path       = "myfile.dat",
 *              .omode      = IWFS_OWRITE | IWFS_OCREATE,
 *              .lock_mode  = IWP_WLOCK
 *          },
 *          .rspolicy       = iw_exfile_szpolicy_fibo
 *        },
 *       .bpow = 6,              // 2^6 bytes block size
 *       .hdrlen = 255,          // Size of custom file header
 *       .oflags = IWFSM_STRICT  // Use verbose free-space bitmap checking for
 *                               // allocations (10-15% overhead)
 *  };
 *
 *  IWFS_FSM f;
 *  size_t sp;
 *  off_t space_len, space_addr = 0;
 *
 *  iwrc rc = iwfs_fsmfile_open(&f, &opts);
 *
 *  //Allocate 2 blocks of file space
 *  rc = f.allocate(&f, 128, &space_addr, &space_len, 0);
 *  if (!rc) {
 *      int data = 33;
 *      // Write some data to the allocated block with writer lock acquired on
 *      // `[space_addr, sizeof(data))`
 *      rc = f.lwrite(&f, space_addr, &data, sizeof(data), &sp);
 *      ...
 *  }
 *  ...
 * @endcode
 *
 * @param f File handle
 * @param opts File open options
 * @relatesalso IWFS_FSM
 */
IW_EXPORT WUR iwrc iwfs_fsmfile_open(IWFS_FSM *f, const IWFS_FSM_OPTS *opts);

/**
 * @brief Init `iwfsmfile` submodule.
 */
IW_EXPORT WUR iwrc iwfs_fsmfile_init(void);

IW_EXTERN_C_END

#endif
