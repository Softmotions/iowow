#ifndef IWEXFILE_H
#define IWEXFILE_H

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
 *  @brief Auto-expandable file.
 *
 *  Features:
 *  - Tunable file expansion policies.
 *  - Read/write methods locking option in multithreaded environment.
 *  - File shrinking/truncation support.
 *  - A number mmaped regions can be registered in the file's address space.
 *    These regions used in read/write operation and automatically maintained during file resize
 *    operations.
 */

#include "iwfile.h"

struct IWFS_EXFILE_OPTS;
struct IWFS_EXFILE;

/**
 * @enum iwfs_extfile_ecode
 * @brief Error codes specific to this module.
 */
typedef enum {
    _IWFS_EXFILE_ERROR_START = (IW_ERROR_START + 2000UL),
    IWFS_ERROR_MMAP_OVERLAP, /**< Region is mmaped already, mmaping overlaps */
    IWFS_ERROR_NOT_MMAPED,   /**< Region is not mmaped */
    IWFS_ERROR_RESIZE_POLICY_FAIL, /**< Invalid result of resize policy function. */
    _IWFS_EXFILE_ERROR_END
} iwfs_extfile_ecode;

/**
 * @brief File resize policy function type.
 *
 * This function called in the following cases:
 *  - When a file needs to be resized. Returned new file size cannot
 *      be lesser than requested @a nsize and must be page aligned.
 *  - When a file is closed. In this case the first argument @a nsize
 *      will be set to `-1` and function should return `0`.
 *      This call can be used in order to release resources allocated for @a ctx
 *      private data.
 *
 * @param nsize Desired file size.
 * @param csize Current file size.
 * @param f File reference.
 * @param ctx Function context data pointer. A function is allowed to initialize this pointer
 *        by oun private data stucture.
 *
 * @return Computed new file size.
 */
typedef off_t(*IW_EXFILE_RSPOLICY)(off_t nsize, off_t csize, struct IWFS_EXFILE *f, void **ctx);

/**
 * @brief Fibonacci resize file policy strategy.
 *
 * New `file_size(n+1) = MAX(file_size(n) + file_size(n-1), nsize)`
 */
IW_EXPORT off_t iw_exfile_szpolicy_fibo(off_t nsize, off_t csize, struct IWFS_EXFILE *f, void **ctx);

/**
 * @brief Rational number `IW_RNUM` file size multiplication policy.
 * 
 * New `file_size = MAX(file_size * (N/D), nsize)`
 */
IW_EXPORT off_t iw_exfile_szpolicy_mul(off_t nsize, off_t csize, struct IWFS_EXFILE *f, void **ctx);

/**
 * @struct IWFS_EXFILE_OPTS
 * @brief File options.
 */
typedef struct IWFS_EXFILE_OPTS {
    IWFS_FILE_OPTS          file;          /**< Underlying file options */
    off_t                   initial_size;   /**< Initial file size */
    int                     use_locks;      /**< If `1` file operation will be guarded by rw lock */
    IW_EXFILE_RSPOLICY      rspolicy;      /**< File resize policy function ptr. */
    void                    *rspolicy_ctx;  /**< Custom opaque data for policy functions. */
} IWFS_EXFILE_OPTS;

typedef struct IWFS_EXFILE_STATE {
    IWFS_FILE_STATE fstate;     /**< Simple file state */
    off_t fsize;                /**< Current file size */
} IWFS_EXFILE_STATE;

typedef struct IWFS_EXFILE {
    struct IWFS_EXFILE_IMPL *impl;

    /* See iwfile.h */
    iwrc(*write)(struct IWFS_EXFILE* f, off_t off, const void *buf, size_t siz, size_t *sp);
    iwrc(*read)(struct IWFS_EXFILE* f, off_t off, void *buf, size_t siz, size_t *sp);
    iwrc(*close)(struct IWFS_EXFILE* f);
    iwrc(*sync)(struct IWFS_EXFILE* f, iwfs_sync_flags flags);
    iwrc(*state)(struct IWFS_EXFILE* f, IWFS_EXFILE_STATE* state);

    /* Exfile specific methods */
    iwrc(*ensure_size)(struct IWFS_EXFILE* f, off_t size);
    iwrc(*truncate)(struct IWFS_EXFILE* f, off_t size);
    iwrc(*add_mmap)(struct IWFS_EXFILE* f, off_t off, size_t maxlen);
    iwrc(*get_mmap)(struct IWFS_EXFILE* f, off_t off, uint8_t **mm, size_t *sp);
    iwrc(*remove_mmap)(struct IWFS_EXFILE* f, off_t off);
    iwrc(*sync_mmap)(struct IWFS_EXFILE* f, off_t off, int flags);

} IWFS_EXFILE;

/**
 * @brief Open exfile.
 * @param f Exfile handle
 * @param opts File open options
 */
IW_EXPORT iwrc iwfs_exfile_open(IWFS_EXFILE *f,
                                const IWFS_EXFILE_OPTS *opts);

/**
 * @brief Init `iwexfile` submodule.
 */
IW_EXPORT iwrc iwfs_exfile_init(void);


#endif
