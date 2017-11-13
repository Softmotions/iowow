#pragma once
#ifndef IWRWLFILE_H
#define IWRWLFILE_H

//
/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2017 Softmotions Ltd <info@softmotions.com>
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
 *  @brief Auto-expandable file with support of reader/writer address space
 *         locking within a threads.
 *  @author Anton Adamansky (adamansky@softmotions.com)
 *
 *  @note  Before using API of this module you should call
 *         `iw_init(void)` iowow module initialization routine.
 *
 *  Features:
 *  - Read/write file address space locking.
 *  - Tuneable file expansion policies.
 *  - Read/write methods locking option in multithreaded environment.
 *  - File shrinking/truncation support.
 *  - A number mmaped regions can be registered in the file's address space.
 *    These regions used in read/write operation and automatically maintained
 *    during file resize operations.
 *
 * File operations implemented as function pointers contained in `IWFS_RWL` `C`
 * structure.
 * The `iwfs_rwlfile_open(IWFS_RWL *f, const IWFS_RWL_OPTS *opts)` opens file
 * and initializes a given `IWFS_RWL` structure.
 */

#include "iwexfile.h"
#include "iwrlock.h"

IW_EXTERN_C_START

/**
 * @brief `IWFS_RWL` file open options.
 */
typedef struct IWFS_RWL_OPTS {
  IWFS_EXT_OPTS exfile; /**< Underlying auto-expandable file options */
} IWFS_RWL_OPTS;

/**
 * @brief `IWFS_RWL` file state container.
 */
typedef struct IWFS_RWL_STATE {
  IWFS_EXT_STATE exfile; /**< Underlying `IWFS_EXT` state. */
  int num_ranges;        /**< Overall number of locked ranges */
  int num_write_ranges;  /**< Number of writer locked ranges */
} IWFS_RWL_STATE;

/**
 * @brief Auto-expandable file with support of reader/writer address space
 * locking within a threads.
 */
typedef struct IWFS_RWL {
  struct IWFS_RWL_IMPL *impl;

  /**
   * @brief Acquire a lock over the address range specified by @a off and @a
   * len.
   *
   * Lock type is specified by @ref iwrl_lockflags flags.
   * If the given address range intersects with some other write locked range
   * owned by another thread
   * the current thread be blocked until that lock is held.
   *
   * @param f `IWFS_RWL`
   * @param off Locked address space offsets.
   * @param len Length of locked spaces.
   * @param lflags A locking typem either `IWRL_READ` or `IWRL_WRITE`
   * @return `0` on success or error code
   */
  iwrc(*lock)(struct IWFS_RWL *f, off_t off, off_t len, iwrl_lockflags lflags);

  /**
   * @brief Try to acquire a lock over the address range specified by @a off and
   * @a len.
   *
   * Lock type is specified by @ref `iwrl_lockflags` flags.
   * If the given address range intersects with some other write locked range
   * owned by another thread
   * the call will fail with `IW_ERROR_FALSE` error code.
   *
   * @param f `IWFS_RWL`
   * @param off Locked address space offsets.
   * @param len Length of locked spaces.
   * @param lflags A locking typem either `IWRL_READ` or `IWRL_WRITE`
   * @return `0` on success or error code
   */
  iwrc(*try_lock)(struct IWFS_RWL *f, off_t off, off_t len,
                  iwrl_lockflags lflags);

  /**
   * @brief Release the previously acquired address space lock.
   * If the specified space not been locked by this thread the method will
   * return with success `0`
   *
   * @param f `IWFS_RWL`
   * @param off Locked address space offsets.
   * @param len Length of locked spaces.
   */
  iwrc(*unlock)(struct IWFS_RWL *f, off_t off, off_t len);

  /**
   * @brief Acquire a `IWRL_WRITE` lock then write bytes to the locked space.
   *
   * @param f `IWFS_RWL`
   * @param off Offset from start of the file where bytes will write.
   * @param buf Buffer to write.
   * @param siz Number of bytes to write.
   * @param [out] sp Number of bytes actually written
   * @return `0` on success or error code.
   * @see iwrc IWFS_FILE::write
   */
  iwrc(*lwrite)(struct IWFS_RWL *f, off_t off, const void *buf, size_t siz,
                size_t *sp);

  /**
  * @brief Acquire a `IWRL_READ` lock then read bytes from the locked space.
  *
  * @param f `IWFS_RWL`
  * @param off Offset from start of the file.
  * @param buf Buffer to read into.
  * @param siz Number of bytes to read.
  * @param [out] sp Number of bytes actually read.
  * @return `0` on success or error code.
  * @see iwrc IWFS_FILE::read
  */
  iwrc(*lread)(struct IWFS_RWL *f, off_t off, void *buf, size_t siz,
               size_t *sp);

  /* See iwexfile.h */

  /** @see IWFS_EXT::ensure_size */
  iwrc(*ensure_size)(struct IWFS_RWL *f, off_t size);

  /** @see IWFS_EXT::truncate */
  iwrc(*truncate)(struct IWFS_RWL *f, off_t size);

  /** @see IWFS_EXT::add_mmap */
  iwrc(*add_mmap)(struct IWFS_RWL *f, off_t off, size_t maxlen);

  /** @see IWFS_EXT::get_mmap */
  iwrc(*get_mmap)(struct IWFS_RWL *f, off_t off, uint8_t **mm, size_t *sp);

  /** @see IWFS_EXT::get_mmap */
  iwrc(*release_mmap)(struct IWFS_RWL *f);

  /** @see IWFS_EXT::remove_mmap */
  iwrc(*remove_mmap)(struct IWFS_RWL *f, off_t off);

  /** @see IWFS_EXT::sync_mmap */
  iwrc(*sync_mmap)(struct IWFS_RWL *f, off_t off, int flags);

  /* See iwfile.h */

  /** @see IWFS_FILE::write  */
  iwrc(*write)(struct IWFS_RWL *f, off_t off, const void *buf, size_t siz,
               size_t *sp);

  /** @see IWFS_FILE::read  */
  iwrc(*read)(struct IWFS_RWL *f, off_t off, void *buf, size_t siz,
              size_t *sp);

  /** @see IWFS_FILE::close  */
  iwrc(*close)(struct IWFS_RWL *f);

  /** @see IWFS_FILE::sync  */
  iwrc(*sync)(struct IWFS_RWL *f, iwfs_sync_flags flags);

  /** @see IWFS_FILE::state  */
  iwrc(*state)(struct IWFS_RWL *f, IWFS_RWL_STATE *state);

  /**  @see IWFS_FILE::copy */
  iwrc(*copy)(struct IWFS_RWL *f, off_t off, size_t siz, off_t noff);

} IWFS_RWL;

/**
 * @brief Open file.
 * @param f File handle
 * @param opts File open options
 * @relatesalso IWFS_RWL
 */
IW_EXPORT WUR iwrc iwfs_rwlfile_open(IWFS_RWL *f, const IWFS_RWL_OPTS *opts);

/**
 * @brief Init `iwrwlfile` submodule.
 */
IW_EXPORT WUR iwrc iwfs_rwlfile_init(void);

IW_EXTERN_C_END

#endif
