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
 *  @author Anton Adamansky (adamansky@gmail.com)
 *
 * @note  Before using API of this module you should call
 * `iw_init(void)` iowow module initialization routine.
 *
 * <strong>Features:</strong>
 *  - Tuneable file expansion policies.
 *    Custom file resize policies supported by specifying `IWFS_EXT_OPTS::rspolicy` option value.
 *    The following policies are implemented:
 *      - Exact. File resizing fits exactly to the size required by `write` operation. T
 *        his is the default behaviour.
 *      - Fibonacci policy. Next file size computed accourding to
 *          fibonacci sequence of previous file sizes: `file_size(n+1) = MAX(file_size(n) + file_size(n-1), nsize)`
 *      - Multiplication resize policy. Next file size: `file_size(n+1) = N * file_size(n)` where
 *         `N` is a rational number `IW_RNUM` greater than `1`
 *  - Read/write locking over a file's address space in multithreaded environment.
 *  - File shrinking/truncation support.
 *  - A number mmaped regions can be registered in the file's address space.
 *    These regions used in read/write operation and automatically maintained during file resize
 *    operations.
 */

#include "iwfile.h"

struct IWFS_EXT_OPTS;
struct IWFS_EXT;

/**
 * @enum iwfs_ext_ecode
 * @brief Error codes specific to this module.
 */
typedef enum {
    _IWFS_EXT_ERROR_START = (IW_ERROR_START + 3000UL),
    IWFS_ERROR_MMAP_OVERLAP,        /**< Region is mmaped already, mmaping overlaps */
    IWFS_ERROR_NOT_MMAPED,          /**< Region is not mmaped */
    IWFS_ERROR_RESIZE_POLICY_FAIL,  /**< Invalid result of resize policy function. */
    _IWFS_EXT_ERROR_END
} iwfs_ext_ecode;

/**
 * @brief File resize policy function type.
 *
 * This function called in the following cases:
 *  - When a file needs to be resized. Returned new file size cannot
 *      be lesser than requested @a nsize and must be `page aligned`.
 *  - When a file is closed. In this case the first argument @a nsize
 *      will be set to `-1` and function should return `0`.
 *      This call can be used in order to release resources allocated for @a ctx
 *      private data used in function.
 *
 * @param nsize Desired file size.
 * @param csize Current file size.
 * @param f File reference.
 * @param ctx Function context data pointer. A function is allowed to initialize this pointer
 *        by oun private data stucture.
 *
 * @return Computed new file size.
 */
typedef off_t(*IW_EXT_RSPOLICY)(off_t nsize, off_t csize, struct IWFS_EXT *f, void **ctx);

/**
 * @brief Fibonacci resize file policy.
 *
 * New `file_size(n+1) = MAX(file_size(n) + file_size(n-1), nsize)`
 */
IW_EXPORT off_t iw_exfile_szpolicy_fibo(off_t nsize, off_t csize, struct IWFS_EXT *f, void **ctx);

/**
 * @brief Rational number `IW_RNUM` file size multiplication policy.
 *
 * New `file_size = MAX(file_size * (N/D), nsize)`
 */
IW_EXPORT off_t iw_exfile_szpolicy_mul(off_t nsize, off_t csize, struct IWFS_EXT *f, void **ctx);

/**
 * @struct IWFS_EXT_OPTS
 * @brief File options.
 */
typedef struct IWFS_EXT_OPTS {
    IWFS_FILE_OPTS          file;           /**< Underlying file options */
    off_t                   initial_size;   /**< Initial file size */
    int                     use_locks;      /**< If `1` file operation will be guarded by rw lock */
    IW_EXT_RSPOLICY         rspolicy;       /**< File resize policy function ptr. */
    void                    *rspolicy_ctx;  /**< Custom opaque data for policy functions. */
} IWFS_EXT_OPTS;

/**
 * @struct IWFS_EXT_STATE
 * @brief File state container.
 * @see iwrc IWFS_EXT::state(struct IWFS_EXT *f, IWFS_EXT_STATE* state)
 */
typedef struct IWFS_EXT_STATE {
    IWFS_FILE_STATE file;     /**< Simple file state */
    off_t fsize;              /**< Current file size */
} IWFS_EXT_STATE;

/**
 * @brief Auto-expandable file.
 */
typedef struct IWFS_EXT {
    struct IWFS_EXT_IMPL *impl;

    /**
     * @fn iwrc ensure_size(struct IWFS_EXT *f, off_t off)
     * @brief Ensures that a file's physical address space contains a given offset @a off  
     * 
     * Various file expansion algorithms can be used for new space allocation, 
     * see the features section for further explanation.
     * 
     * @param f `IWFS_EXT`
     * @param off File offset what have to be within physically allocated file address space.
     * @return `0` on success or error code.
     * 
     * @see off_t iw_exfile_szpolicy_fibo(off_t nsize, off_t csize, struct IWFS_EXT *f, void **ctx)
     * @see off_t iw_exfile_szpolicy_mul(off_t nsize, off_t csize, struct IWFS_EXT *f, void **ctx)
     */
    iwrc(*ensure_size)(struct IWFS_EXT *f, off_t off);

    /**
     * @fn iwrc IWFS_EXT::truncate(struct IWFS_EXT *f, off_t off)
     * @brief Set the end of this file to the specified offset @a off exactly. 
     */
    iwrc(*truncate)(struct IWFS_EXT *f, off_t off);

    /**
     * @fn iwrc IWFS_EXT::add_mmap(struct IWFS_EXT *f, off_t off, size_t len)
     * @brief Register an address space specified by @a off and @a len as memory mmaped region 
     * within this file. 
     * 
     * It is not required for this region be physically represented in the file's address space. 
     * As soon as this region will be used for reading/writing it will be mmaped and 
     * direct mmaped memory access will be used for IO in this area.
     * 
     * For example:
     * @code {.c}
     *     f.add_mmap(&f, 10, 20);
     *     f.read(&f, 5, buf, 10, sp); //read [5-15) bytes
     *     // [5-10) bytes will be read using system `pread`
     *     // [10-15) bytes will be retrieved by direct `memcpy` from mmapped region 
     * @endcode
     * 
     * Pointer to this region can be retrieved by  `IWFS_EXT::get_mmap`
     * 
     * @param f `IWFS_EXT`
     * @param off Offset of mmaped region
     * @param len Length of mmaped region
     * @return `0` on success or error code.
     */
    iwrc(*add_mmap)(struct IWFS_EXT *f, off_t off, size_t len);

    /**
     * @fn iwrc IWFS_EXT::get_mmap(struct IWFS_EXT *f, off_t off, uint8_t **mm, size_t *sp)
     * @brief Retrieve mmaped region by its offset @a off
     * 
     * If region was not mmaped previously with IWFS_EXT::add_mmap
     * the `IWFS_ERROR_NOT_MMAPED` error code will be returned.
     * 
     * @param f `IWFS_EXT`
     * @param off Region start offset
     * @param mm [out] Pointer assigned to start of mmaped region of `NULL` if error occurred .
     * @param sp [out] Length of region
     * @return `0` on success or error code.
     */
    iwrc(*get_mmap)(struct IWFS_EXT *f, off_t off, uint8_t **mm, size_t *sp);

    /**
     * @fn iwrc IWFS_EXT::remove_mmap(struct IWFS_EXT *f, off_t off)
     * @brief Unmap mmaped region identified by @a off
     * 
     * The `IWFS_ERROR_NOT_MMAPED` will returned 
     * if region was not previously mapped with IWFS_EXT::add_mmap
     * 
     * @param f `IWFS_EXT`
     * @param off Region start offset
     * @return `0` on success or error code.
     */
    iwrc(*remove_mmap)(struct IWFS_EXT *f, off_t off);

    /**
     * @fn iwrc IWFS_EXT::sync_mmap(struct IWFS_EXT *f, off_t off, int flags)
     * @brief Synchronize a file with a mmaped region identified by @a off offset.
     * 
     * The `IWFS_ERROR_NOT_MMAPED` will returned 
     * if region was not previously mapped with IWFS_EXT::add_mmap
     * 
     * @param f `IWFS_EXT`
     * @param off Region start offset
     * @param flags Sync flags one of: `MS_ASYNC, MS_SYNC, and MS_INVALIDATE` from `msync` 
     */
    iwrc(*sync_mmap)(struct IWFS_EXT *f, off_t off, int flags);

    /* See iwfile.h */

    /** @fn iwrc IWFS_EXT::write(struct IWFS_EXT *f, off_t off, const void *buf, size_t siz, size_t *sp)
     *  @see iwrc IWFS_FILE::write
     */
    iwrc(*write)(struct IWFS_EXT *f, off_t off, const void *buf, size_t siz, size_t *sp);

    /** @fn iwrc IWFS_EXT::read(struct IWFS_EXT *f, off_t off, void *buf, size_t siz, size_t *sp)
     *  @see iwrc IWFS_FILE::read
     */
    iwrc(*read)(struct IWFS_EXT *f, off_t off, void *buf, size_t siz, size_t *sp);

    /** @fn iwrc IWFS_EXT::close(struct IWFS_EXT *f)
     *  @see iwrc IWFS_FILE::close
     */
    iwrc(*close)(struct IWFS_EXT *f);

    /** @fn iwrc IWFS_EXT::sync(struct IWFS_EXT  *f, iwfs_sync_flags flags)
     *  @see iwrc IWFS_FILE::sync
     */
    iwrc(*sync)(struct IWFS_EXT *f, iwfs_sync_flags flags);

    /** @fn  iwrc IWFS_EXT::state(struct IWFS_EXT *f, IWFS_EXT_STATE* state)
     *  @see iwrc IWFS_FILE::state
     **/
    iwrc(*state)(struct IWFS_EXT *f, IWFS_EXT_STATE* state);

} IWFS_EXT;

/**
 * @brief Open exfile.
 * @param f Exfile handle. Simple memory placeholder.
 * @param opts File open options. Initialized file options.
 * @return Error code of `0` on success.
 * @relatesalso IWFS_EXT
 */
IW_EXPORT iwrc iwfs_exfile_open(IWFS_EXT *f,
                                const IWFS_EXT_OPTS *opts);

/**
 * @brief Init `iwexfile` submodule.
 */
IW_EXPORT iwrc iwfs_exfile_init(void);

#endif
