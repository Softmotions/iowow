#pragma once
#ifndef IWEXFILE_H
#define IWEXFILE_H

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
 *  copies of the Software, and to permit persons to whom the Software is
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
 *  @brief Auto-expandable file.
 *  @author Anton Adamansky (adamansky@softmotions.com)
 *
 * @note  Before using API of this module you should call
 *
 * `iw_init(void)` iowow module initialization routine.
 *
 * <strong>Features:</strong>
 *  - Tuneable file expansion policies.
 *    Custom file resize policies supported by specifying
 * `IWFS_EXT_OPTS::rspolicy` option value.
 *    The following policies are implemented:
 *      - Exact. File resizing fits exactly to the size required by `write`
 *        operation. This is the default behaviour.
 *      - Fibonacci policy. Next file size computed accourding to
 *        fibonacci sequence of previous file sizes:
          `file_size(n+1) = MAX(file_size(n) + file_size(n-1), nsize)`
 *      - Multiplication resize policy. Next file size:
          `file_size(n+1) = N * file_size(n)` where
 *        `N` is a rational number `IW_RNUM` greater than `1`
 *  - Read/write locking over a file's address space in multithreaded
 *    environment.
 *  - File shrinking/truncation support.
 *  - A number mmaped regions can be registered in the file's address space.
 *    These regions used in read/write operation and automatically maintained
 *    during file resize operations.
 *
 * File operations implemented as function pointers contained in `IWFS_EXT` `C`
 * structure.
 * The `iwrc iwfs_exfile_open(IWFS_EXT *f, const IWFS_EXT_OPTS *opts);` opens
 * file and initializes a given `IWFS_EXT` structure.
 */

#include "iwfile.h"

IW_EXTERN_C_START

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
  IWFS_ERROR_RESIZE_POLICY_FAIL,  /**< Invalid result of resize policy function.*/
  IWFS_ERROR_MAXOFF,              /**< Maximum file offset reached. */
  _IWFS_EXT_ERROR_END,
} iwfs_ext_ecode;

typedef uint8_t iwfs_ext_mmap_opts_t;
/** Use shared mmaping synchronized with file data */
#define IWFS_MMAP_SHARED ((iwfs_ext_mmap_opts_t) 0x00U)
/** Use private mmap */
#define IWFS_MMAP_PRIVATE ((iwfs_ext_mmap_opts_t) 0x01U)

/**
 * @brief File resize policy function type.
 *
 * This function called in the following cases:
 *  - When a file needs to be resized. Returned new file size cannot
 *    be lesser than requested @a nsize and must be `page aligned`.
 *  - When a file is closed. In this case the first argument @a nsize
 *    will be set to `-1` and function should return `0`.
 *    This call can be used in order to release resources allocated for @a ctx
 *    private data used in function.
 *
 * @param nsize Desired file size.
 * @param csize Current file size.
 * @param f File reference.
 * @param ctx Function context data pointer. A function is allowed to initialize
 * this pointer by own private data stucture.
 *
 * @return Computed new file size.
 */
typedef off_t (*IW_EXT_RSPOLICY)(
  off_t nsize, off_t csize, struct IWFS_EXT *f,
  void **ctx);

/**
 * @brief Fibonacci resize file policy.
 *
 * New `file_size(n+1) = MAX(file_size(n) + file_size(n-1), nsize)`
 */
IW_EXPORT off_t iw_exfile_szpolicy_fibo(
  off_t nsize, off_t csize,
  struct IWFS_EXT *f, void **ctx);

/**
 * @brief Rational number `IW_RNUM` file size multiplication policy.
 *
 * New `file_size = MAX(file_size * (N/D), nsize)`
 */
IW_EXPORT off_t iw_exfile_szpolicy_mul(
  off_t nsize, off_t csize,
  struct IWFS_EXT *f, void **ctx);

/**
 * @brief `IWFS_EXT` file options.
 * @see iwrc iwfs_exfile_open(IWFS_EXT *f, const IWFS_EXT_OPTS *opts)
 */
typedef struct IWFS_EXT_OPTS {
  IWFS_FILE_OPTS file; /**< Underlying file options */
  off_t initial_size;  /**< Initial file size */
  bool  use_locks;     /**< If `true` file operations will be guarded by rw lock. Default: `false` */

  IW_EXT_RSPOLICY rspolicy; /**< File resize policy function ptr. Default:
                               `exact size policy`  */
  void *rspolicy_ctx;       /**< Custom opaque data for policy functions.
                                 Default: `0` */
  uint64_t maxoff;          /**< Maximum allowed file offset. Unlimited if zero.
                                 If maximum offset is reached `IWFS_ERROR_MAXOFF` will be reported. */
} IWFS_EXT_OPTS;

/**
 * @struct IWFS_EXT_STATE
 * @brief `IWFS_EXT` file state info.
 * @see IWFS_EXT::state
 */
typedef struct IWFS_EXT_STATE {
  IWFS_FILE_STATE file; /**< Simple file state */
  off_t fsize;          /**< Current file size */
} IWFS_EXT_STATE;

/**
 * @brief Auto-expandable file.
 */
typedef struct IWFS_EXT {
  struct IWFS_EXT_IMPL *impl;

  /**
   * @brief Ensures that a file's physical address space contains a given offset
   * @a off
   *
   * Various algorithms can be used for new space allocation,
   * see the features section for further explanation.
   *
   * @param f `IWFS_EXT`
   * @param off File offset what have to be within physically allocated file
   *            address space.
   * @return `0` on success or error code.
   *
   * @see off_t iw_exfile_szpolicy_fibo(off_t nsize, off_t csize, struct
   * IWFS_EXT *f, void **ctx)
   * @see off_t iw_exfile_szpolicy_mul(off_t nsize, off_t csize, struct IWFS_EXT
   * *f, void **ctx)
   */
  iwrc (*ensure_size)(struct IWFS_EXT *f, off_t off);

  /**
   * @brief Set the end of this file to the specified offset @a off exactly.
   */
  iwrc (*truncate)(struct IWFS_EXT *f, off_t off);

  iwrc (*truncate_unsafe)(struct IWFS_EXT *f, off_t off);

  /**
   * @brief Register an address space specified by @a off and @a len as memory
   * mmaped region
   * within this file.
   *
   * It is not required for this region be physically represented in the file's
   * address space.
   * As soon as this region will be used for reading/writing it will be mmaped
   * and direct mmaped memory access will be used for IO in this area.
   *
   * For example:
   * @code {.c}
   *     f.add_mmap(&f, 10, 20);
   *     f.read(&f, 5, buf, 10, sp); // read [5-15) bytes
   *     // [5-10) bytes will be read using system `pread`
   *     // [10-15) bytes will be retrieved by direct `memcpy` from mmapped
   * region
   * @endcode
   *
   * Pointer to this region can be retrieved by  `IWFS_EXT::acquire_mmap`
   *
   * @param f `IWFS_EXT`
   * @param off Offset of mmaped region
   * @param len Length of mmaped region
   * @return `0` on success or error code.
   */
  iwrc (*add_mmap)(struct IWFS_EXT *f, off_t off, size_t len, iwfs_ext_mmap_opts_t opts);

  iwrc (*add_mmap_unsafe)(struct IWFS_EXT *f, off_t off, size_t len, iwfs_ext_mmap_opts_t opts);

  /**
   * @brief Retrieve mmaped region by its offset @a off and keep file as read locked.
   *
   * If region was not mmaped previously with IWFS_EXT::add_mmap
   * the `IWFS_ERROR_NOT_MMAPED` error code will be returned.
   *
   * WARNING: Internal read lock will be acquired and
   *          must be released by subsequent `release_mmap()` call
   *          after all activity with mmaped region has finished.
   *
   * @param f `IWFS_EXT`
   * @param off Region start offset
   * @param [out] mm Pointer assigned to start of mmaped region of `NULL` if
   *                 error occurred.
   * @param [out] sp Length of region
   * @return `0` on success or error code.
   */
  iwrc (*acquire_mmap)(struct IWFS_EXT *f, off_t off, uint8_t **mm, size_t *sp);

  /**
   * @brief Retrieve mmaped region by its offset @a off
   */
  iwrc (*probe_mmap)(struct IWFS_EXT *f, off_t off, uint8_t **mm, size_t *sp);

  iwrc (*probe_mmap_unsafe)(struct IWFS_EXT *f, off_t off, uint8_t **mm, size_t *sp);

  /**
   * @brief Release the lock acquired by successfull call of `acquire_mmap()`
   */
  iwrc (*release_mmap)(struct IWFS_EXT *f);

  /**
   * @brief Unmap mmaped region identified by @a off
   *
   * The `IWFS_ERROR_NOT_MMAPED` will returned
   * if region was not previously mapped with IWFS_EXT::add_mmap
   *
   * @param f `IWFS_EXT`
   * @param off Region start offset
   * @return `0` on success or error code.
   */
  iwrc (*remove_mmap)(struct IWFS_EXT *f, off_t off);

  iwrc (*remove_mmap_unsafe)(struct IWFS_EXT *f, off_t off);

  /**
   * @brief Synchronize a file with a mmaped region identified by @a off offset.
   *
   * The `IWFS_ERROR_NOT_MMAPED` will returned
   * if region was not previously mapped with IWFS_EXT::add_mmap
   *
   * @param f `IWFS_EXT`
   * @param off Region start offset
   * @param flags Sync flags.
   * @return `0` on success or error code.
   */
  iwrc (*sync_mmap)(struct IWFS_EXT *f, off_t off, iwfs_sync_flags flags);

  iwrc (*sync_mmap_unsafe)(struct IWFS_EXT *f, off_t off, iwfs_sync_flags flags);

  /**
   * @brief Remap all mmaped regions.
   *
   * @param f `IWFS_EXT`
   */
  iwrc (*remap_all)(struct IWFS_EXT *f);

  /* See iwfile.h */

  /**  @see IWFS_FILE::write */
  iwrc (*write)(
    struct IWFS_EXT *f, off_t off, const void *buf, size_t siz,
    size_t *sp);

  /**  @see IWFS_FILE::read */
  iwrc (*read)(
    struct IWFS_EXT *f, off_t off, void *buf, size_t siz,
    size_t *sp);

  /** @see IWFS_FILE::close */
  iwrc (*close)(struct IWFS_EXT *f);

  /**  @see IWFS_FILE::sync */
  iwrc (*sync)(struct IWFS_EXT *f, iwfs_sync_flags flags);

  /**  @see IWFS_FILE::state */
  iwrc (*state)(struct IWFS_EXT *f, IWFS_EXT_STATE *state);

  /**  @see IWFS_FILE::copy */
  iwrc (*copy)(struct IWFS_EXT *f, off_t off, size_t siz, off_t noff);
} IWFS_EXT;

/**
 * @brief Open exfile.
 *
 * <strong>Example:</strong>
 *
 * Open a file for multithreaded env with fibonacci file resize policy and
 * initial size to 4K
 *
 * @code {.c}
 *  IWFS_EXT_OPTS opts = {
 *      .file = {
 *          .path       = "myfile.dat",
 *          .omode      = IWFS_OWRITE | IWFS_OCREATE,
 *          .lock_mode  = IWP_WLOCK
 *      },
 *      .initial_size   = 4096,
 *      .use_locks      = true,
 *      .rspolicy       = iw_exfile_szpolicy_fibo
 *  };
 *  IWFS_EXT f;
 *  iwrc rc = iwfs_exfile_open(&f, &opts);
 *
 *  rc = f.write(&f, ...);
 *  ...
 * @endcode
 *
 *
 * @param f Exfile handle. Simple memory placeholder.
 * @param opts File open options. Initialized file options.
 * @return Error code of `0` on success.
 * @relatesalso IWFS_EXT
 */
IW_EXPORT WUR iwrc iwfs_exfile_open(IWFS_EXT *f, const IWFS_EXT_OPTS *opts);

/**
 * @brief Init `iwexfile` submodule.
 */
IW_EXPORT WUR iwrc iwfs_exfile_init(void);

IW_EXTERN_C_END

#endif
