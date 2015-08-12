#ifndef IWFSMFILE_H
#define IWFSMFILE_H

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

/** @file
 *  @brief Auto-expandable file with support of reader/writer address space locking
 *         and free space block management using bitmaps.
 *  @author Anton Adamansky (adamansky@gmail.com)
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
 *    These regions used in read/write operation and automatically maintained during file resize
 *    operations.
 *
 * File operations implemented as function pointers contained in `IWFS_FSM` `C` structure.
 * The `iwfs_fsmfile_open(IWFS_FSM *f, const IWFS_FSM_OPTS *opts)` opens file and initializes a given `IWFS_FSM` structure.
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
 *  - <b>block pow:</b> Block size as power of `2` Eg: `6` means `64` bit block size. (8 bit)
 *  - <b>bmoffset:</b> Free space bitmap area offset in bytes (64 bit)
 *  - <b>bmlength:</b> Free space bitmap area length. (64 bit)
 *  - <b>crzsum:</b> Number of allocated blocks. (64 bit)
 *  - <b>crznum:</b> Number of all allocated continuous areas. (32 bit)
 *  - <b>crszvar</b> Allocated areas length standard variance (deviation^2 * N) (64 bit)
 *  - <b>reserved:</b> Reserved space.
 *  - <b>custom header size:</b> Length of custom header area. See `IWFS_FSM::writehdr` and `IWFS_FSM::readhdr`
 */

#include "iwrwlfile.h"
#include <math.h>

/**
 * @brief Free space allocation flags.
 * @see IWFS_FSM::allocate
 */
typedef enum {
    
    /**< Use default allocation settings */
    IWFSM_ALLOC_DEFAULTS =  0x00U,

    /** Do not @em overallocate a requested free space in order to reduce fragmentation  */
    IWFSM_ALLOC_NO_OVERALLOCATE = 0x01U,

    /** Do not extend the file and its bitmap free space mapping in the case if
     * file size expansion is required.
     * In this case the `IWFS_ERROR_NO_FREE_SPACE` error will be raised.*/
    IWFSM_ALLOC_NO_EXTEND = 0x02U,

    /** Force offset of an allocated space to be page aligned. */
    IWFSM_ALLOC_PAGE_ALIGNED = 0x04U,

    /** Do not update(collect) internal allocation stats for this allocation. */
    IWFSM_ALLOC_NO_STATS = 0x08U
    
} iwfs_fsm_aflags;

/**
 * @brief File cleanup flags used in `IWFS_FSM::clear`
 * @see IWFS_FSM::clear
 */
typedef enum {
    IWFSM_CLEAR_TRIM = 0x01U /**< Perform file size trimming after cleanup */
} iwfs_fsm_clrfalgs;

/**
 * @brief Error codes specific to `IWFS_FSM`.
 */
typedef enum {
    _IWFS_FSM_ERROR_START = (IW_ERROR_START + 4000UL),
    IWFS_ERROR_NO_FREE_SPACE,       /**< No free space. */
    IWFS_ERROR_INVALID_BLOCK_SIZE,  /**< Invalid block size specified */
    IWFS_ERROR_RANGE_NOT_ALIGNED,   /**< Specified range/offset is not aligned with page/block */
    IWFS_ERROR_FSM_SEGMENTATION,    /**< Free-space map segmentation error */
    IWFS_ERROR_INVALID_FILEMETA,    /**< Invalid file-metadata */
    IWFS_ERROR_PLATFORM_PAGE,       /**< Platform page size incopatibility, data migration required. */
    _IWFS_FSM_ERROR_END
} iwfs_fsm_ecode;

/**
 * @brief `IWFS_FSM` file open modes used in `IWFS_FSM_OPTS`
 * @see IWFS_FSM_OPTS::oflags
 */
typedef enum {
    IWFSM_NOLOCKS       = 0x01U,     /**< Do not use threading locks */
    IWFSM_STRICT        = 0x02U      /**< Strict block checking for alloc/dealloc operations. 10-15% performance overhead. */
} iwfs_fsm_openflags;

/**
 * @brief `IWFS_FSM` file options.
 * @see iwfs_fsmfile_open(IWFS_FSM *f, const IWFS_FSM_OPTS *opts)
 */
typedef struct IWFS_FSM_OPTS {
    IWFS_RWL_OPTS       rwlfile;
    iwfs_fsm_openflags  oflags;     /**< Operation mode flags */
    uint8_t             bpow;       /**< Block size power of 2 */
    size_t              bmlen;      /**< Initial size of free-space bitmap */
    size_t              hdrlen;     /**< Length of custom file header.*/
    int                 sync_flags; /**< Default msync flags for mmap_sync operations (MS_ASYNC,MS_SYNC,MS_INVALIDATE) */
} IWFS_FSM_OPTS;


/**
 * @brief `IWFS_FSM` file state container.
 * @see IWFS_FSM::state
 */
typedef struct IWFS_FSM_STATE {
    IWFS_RWL_STATE      rwlfile;            /**< File pool state */
    size_t              block_size;         /**< Size of data block in bytes. */
    iwfs_fsm_openflags  oflags;             /**< Operation mode flags. */
    uint32_t            hdrlen;             /**< Length of custom file header length in bytes */
    uint64_t            blocks_num;         /**< Number of available data blocks. */
    uint64_t            free_segments_num;  /**< Number of free (deallocated) continuous data segments. */
    double_t            avg_alloc_size;     /**< Average allocation number of blocks */
    double_t            alloc_dispersion;   /**< Average allocation blocks dispersion */
} IWFS_FSM_STATE;


typedef struct IWFS_FSMDBG_STATE {
    IWFS_FSM_STATE state;
    uint64_t       bmoff;
    uint64_t       bmlen;
    uint64_t       lfbklen;
    uint64_t       lfbkoff;
} IWFS_FSMDBG_STATE;

/**
 * @brief Auto-expandable file with support of reader/writer address space locking
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
     * @param len Desired length of an allocated area.
     * @param [in,out] oaddr Placeholder for the address of an allocated area. 
     *                       Value of @a oaddr passed to this function used as `hint` in order 
     *                       to allocate area located closely to the specified @a oaddr value.
     * @param [out] len Actual length of an allocated area in bytes.
     * @param opts Allocation options bitmask flag @ref iwfs_fsm_aflags
     * @return `0` on success or error code.
     */
    iwrc(*allocate)(struct IWFS_FSM* f, off_t len, off_t *oaddr, off_t *olen, iwfs_fsm_aflags opts);
    
    /**
     * @brief Free a previously allocated area. 
     * @param addr Address space offset in bytes <em>it must be block size aligned</em>.
     * @param len Length of area to release.
     * @return `0` on success or error code.
     */
    iwrc(*deallocate)(struct IWFS_FSM* f, off_t addr, off_t len);
    
    /**
     * @brief Write a data to the custom file header.
     * 
     * A custom file header size specified in IWFS_FSM_OPTS::hdrlen options on file creation.
     * 
     * @param off Offset position relative to custom header start offset.
     * @param buf Data buffer to write
     * @param siz Number of bytes of @a buf to write into header.
     * @return `0` on success or error code.
     */
    iwrc(*writehdr)(struct IWFS_FSM* f, off_t off, const void *buf, off_t siz);
    
    /**
     * @brief Read a data from the custom file header.
     * 
     * A custom file header size specified in IWFS_FSM_OPTS::hdrlen options on file creation.
     * 
     * @param off Offset position relative to custom header start offset.
     * @param [out] buf Data buffer to read into
     * @param Number of bytes to read
     */
    iwrc(*readhdr)(struct IWFS_FSM* f, off_t off, void *buf, off_t siz);
    
    /**
     * @brief Cleanup all allocated data blocks and reset the file to the initial empty state.
     * 
     * @param clrflags 
     * @return `0` on success or error code.
     */
    iwrc(*clear)(struct IWFS_FSM* f, iwfs_fsm_clrfalgs clrflags);
    
    /* See iwrwlfile.h */
    
    /** @see IWFS_RWL::lock */
    iwrc(*lock)(struct IWFS_FSM* f, off_t off, off_t len, iwrl_lockflags lflags);
    
    /** @see IWFS_RWL::try_lock */
    iwrc(*try_lock)(struct IWFS_FSM* f, off_t off, off_t len, iwrl_lockflags lflags);
    
    /** @see IWFS_RWL::unlock */
    iwrc(*unlock)(struct IWFS_FSM* f, off_t off, off_t len);
    
    /** @see IWFS_RWL::lwrite */
    iwrc(*lwrite)(struct IWFS_FSM* f, off_t off, const void *buf, size_t siz, size_t *sp);
    
    /** @see IWFS_RWL::lread */
    iwrc(*lread)(struct IWFS_FSM* f, off_t off, void *buf, size_t siz, size_t *sp);
    
    /* See iwexfile.h */
    
    /** @see IWFS_EXT::ensure_size */
    iwrc(*ensure_size)(struct IWFS_FSM* f, off_t size);
    
    /** @see IWFS_EXT::truncate */
    iwrc(*truncate)(struct IWFS_FSM* f, off_t size);
    
    /** @see IWFS_EXT::add_mmap */
    iwrc(*add_mmap)(struct IWFS_FSM* f, off_t off, size_t maxlen);
    
    /** @see IWFS_EXT::get_mmap */
    iwrc(*get_mmap)(struct IWFS_FSM* f, off_t off, uint8_t **mm, size_t *sp);
    
    /** @see IWFS_EXT::remove_mmap */
    iwrc(*remove_mmap)(struct IWFS_FSM* f, off_t off);
    
    /** @see IWFS_EXT::sync_mmap */
    iwrc(*sync_mmap)(struct IWFS_FSM* f, off_t off, int flags);

    /* See iwfile.h */
    
    /** @see IWFS_FILE::write */
    iwrc(*write)(struct IWFS_FSM* f, off_t off, const void *buf, size_t siz, size_t *sp);
    
    /** @see IWFS_FILE::read */
    iwrc(*read)(struct IWFS_FSM* f, off_t off, void *buf, size_t siz, size_t *sp);
    
    /** @see IWFS_FILE::close */
    iwrc(*close)(struct IWFS_FSM* f);
    
    /** @see IWFS_FILE::sync */
    iwrc(*sync)(struct IWFS_FSM* f, iwfs_sync_flags flags);
    
    /** @see IWFS_FILE::state */
    iwrc(*state)(struct IWFS_FSM* f, IWFS_FSM_STATE* state);

} IWFS_FSM;

/**
 * @brief Open `IWFS_FSM` file.
 * 
 * <strong>Example:</strong>
 * 
 * Open a buffer pool file for multithreaded env with fibonacci file resize policy with 
 * block size of 64 bytes and custom file header of 255 bytes length.
 * 
 * @code {.c}
 *  IWFS_FSM_OPTS opts = {
 *       .rwlfile = {
 *           .exfile  = {
 *               .file = {
 *                  .path       = "myfile.dat",
 *                  .omode      = IWFS_OWRITE | IWFS_OCREATE,
 *                  .lock_mode  = IWP_WLOCK
 *              },
 *              .rspolicy       = iw_exfile_szpolicy_fibo
 *            }
 *        },
 *       .bpow = 6,              // 2^6 bytes block size
 *       .hdrlen = 255,          // Size of custom file header
 *       .oflags = IWFSM_STRICT  // Use verbose free-space bitmap checking for allocations (10-15% overhead)
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
 *      //Write some data to the allocated block with writer lock acquired on `[space_addr, sizeof(data))`
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
IW_EXPORT WUR iwrc iwfs_fsmfile_open(IWFS_FSM *f,
                                     const IWFS_FSM_OPTS *opts);
/**
 * @brief Init `iwfsmfile` submodule.
 */
IW_EXPORT WUR iwrc iwfs_fsmfile_init(void);

#endif
