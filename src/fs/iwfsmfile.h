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
 *  @brief Auto-expandable file with support of read/write address space locking
 *         and free space block management using bitmaps.
 *
 *  Features:
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
 * File structure:
 *
 * @verbatim
 *
 *       [FSM_CTL_MAGICK u32][block pow u8]
 *       [bmoffset u64][bmlength u64]
 *       [u64 crzsum][u32 crznum][u64 crszvar][u256 reserved]
 *       [custom header size u32][custom header data...]
 *       [fsm data...]
 * 
 * @endverbatim
 *
 */

#include "iwrwlfile.h"
#include <math.h>

/**
 * @brief Free space allocation flags.
 */
typedef enum {
    /** Use default allocation settings */
    IWFSM_ALLOC_DEFAULTS =  0x00U,

    /** Do not @em overallocate a requested free space in order to reduce fragmentation  */
    IWFSM_ALLOC_NO_OVERALLOCATE = 0x01U,

    /** Do not extend the file and its bitmap free space mapping in the case if
     * file size expansion is required.
     * In this case the `IWFS_ERROR_NO_FREE_SPACE` error will be raised.*/
    IWFSM_ALLOC_NO_EXTEND = 0x02U,

    /** Force offset of an alocated space to be page aligned. */
    IWFSM_ALLOC_PAGE_ALIGNED = 0x04U,

    /** Do not update(collect) internal allocation stats */
    IWFSM_ALLOC_NO_STATS = 0x08U
} iwfs_fsm_aflags;

/**
 * @brief File cleanup flags.
 * @sa clear
 */
typedef enum {
    IWFSM_CLEAR_TRIM = 0x01 /**< Perform file trimming after cleanup */
} iwfs_fsm_clrfalgs;

/**
 * @enum iwfs_ext_ecode
 * @brief Error codes specific to this module.
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

typedef enum {
    IWFSM_NOLOCKS       = 0x01,     /**< Do not use threading locks */
    IWFSM_STRICT        = 0x02      /**< Strict block checking for alloc/dealloc operations */
} iwfs_fsm_openflags;

typedef struct IWFS_FSM_OPTS {
    IWFS_RWL_OPTS       rwlfile;
    iwfs_fsm_openflags  oflags;     /**< Operation mode flags */
    uint8_t             bpow;       /**< Block size power of 2 */
    size_t              bmlen;      /**< Initial size of free-space bitmap */
    size_t              hdrlen;     /**< Length of custom file header.*/
} IWFS_FSM_OPTS;


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


typedef struct IWFS_FSM {
    struct IWFS_FSM_IMPL *impl;

    /* See iwfile.h */
    iwrc(*write)(struct IWFS_FSM* f, off_t off, const void *buf, size_t siz, size_t *sp);
    iwrc(*read)(struct IWFS_FSM* f, off_t off, void *buf, size_t siz, size_t *sp);
    iwrc(*close)(struct IWFS_FSM* f);
    iwrc(*sync)(struct IWFS_FSM* f, iwfs_sync_flags flags);
    iwrc(*state)(struct IWFS_FSM* f, IWFS_FSM_STATE* state);

    /* See iwexfile.h */
    iwrc(*ensure_size)(struct IWFS_FSM* f, off_t size);
    iwrc(*truncate)(struct IWFS_FSM* f, off_t size);
    iwrc(*add_mmap)(struct IWFS_FSM* f, off_t off, size_t maxlen);
    iwrc(*get_mmap)(struct IWFS_FSM* f, off_t off, uint8_t **mm, size_t *sp);
    iwrc(*remove_mmap)(struct IWFS_FSM* f, off_t off);
    iwrc(*sync_mmap)(struct IWFS_FSM* f, off_t off, int flags);

    /* See iwrwlfile.h */
    iwrc(*lock)(struct IWFS_FSM* f, off_t off, off_t len, iwrl_lockflags lflags);
    iwrc(*try_lock)(struct IWFS_FSM* f, off_t off, off_t len, iwrl_lockflags lflags);
    iwrc(*unlock)(struct IWFS_FSM* f, off_t off, off_t len);
    iwrc(*lwrite)(struct IWFS_FSM* f, off_t off, const void *buf, size_t siz, size_t *sp);
    iwrc(*lread)(struct IWFS_FSM* f, off_t off, void *buf, size_t siz, size_t *sp);

    iwrc(*allocate)(struct IWFS_FSM* f, off_t len, off_t *oaddr, off_t *olen, iwfs_fsm_aflags opts);
    iwrc(*deallocate)(struct IWFS_FSM* f, off_t addr, off_t len);
    iwrc(*writehdr)(struct IWFS_FSM* f, off_t off, const void *buf, off_t siz);
    iwrc(*readhdr)(struct IWFS_FSM* f, off_t off, void *buf, off_t siz);
    iwrc(*clear)(struct IWFS_FSM* f, iwfs_fsm_clrfalgs clrflags);

} IWFS_FSM;

/**
 * @brief Open file.
 * @param f File handle
 * @param opts File open options
 */
IW_EXPORT iwrc iwfs_fsmfile_open(IWFS_FSM *f,
                                 const IWFS_FSM_OPTS *opts);
/**
 * @brief Init `iwfsmfile` submodule.
 */
IW_EXPORT iwrc iwfs_fsmfile_init(void);

#endif
