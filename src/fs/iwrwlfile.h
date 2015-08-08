#ifndef IWRWLFILE_H
#define IWRWLFILE_H

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
 *  @brief Auto-expandable file with support of read/write address space locking.
 *
 *  Features:
 *  - Read/write file address space locking.
 *  -
 *  - Tunable file expansion policies.
 *  - Read/write methods locking option in multithreaded environment.
 *  - File shrinking/truncation support.
 *  - A number mmaped regions can be registered in the file's address space.
 *    These regions used in read/write operation and automatically maintained during file resize
 *    operations.
 */

#include "iwexfile.h"
#include "utils/iwrlock.h"


typedef struct IWFS_RWL_OPTS {
    IWFS_EXT_OPTS exfile;
} IWFS_RWL_OPTS;

typedef struct IWFS_RWL_STATE {
    IWFS_EXT_STATE exfile;  /**< Underlying `IWFS_EXT` state. */
    int num_ranges;         /**< Overall number of locked ranges */
    int num_write_ranges;   /**< Number of write locked ranges */
} IWFS_RWL_STATE;

typedef struct IWFS_RWL {
    struct IWFS_RWL_IMPL *impl;

    /* See iwfile.h */
    iwrc(*write)(struct IWFS_RWL* f, off_t off, const void *buf, size_t siz, size_t *sp);
    iwrc(*read)(struct IWFS_RWL* f, off_t off, void *buf, size_t siz, size_t *sp);
    iwrc(*close)(struct IWFS_RWL* f);
    iwrc(*sync)(struct IWFS_RWL* f, iwfs_sync_flags flags);
    iwrc(*state)(struct IWFS_RWL* f, IWFS_RWL_STATE* state);

    /* See iwexfile.h */
    iwrc(*ensure_size)(struct IWFS_RWL* f, off_t size);
    iwrc(*truncate)(struct IWFS_RWL* f, off_t size);
    iwrc(*add_mmap)(struct IWFS_RWL* f, off_t off, size_t maxlen);
    iwrc(*get_mmap)(struct IWFS_RWL* f, off_t off, uint8_t **mm, size_t *sp);
    iwrc(*remove_mmap)(struct IWFS_RWL* f, off_t off);
    iwrc(*sync_mmap)(struct IWFS_RWL* f, off_t off, int flags);

    iwrc(*lock)(struct IWFS_RWL* f, off_t off, off_t len, iwrl_lockflags lflags);
    iwrc(*try_lock)(struct IWFS_RWL* f, off_t off, off_t len, iwrl_lockflags lflags);
    iwrc(*unlock)(struct IWFS_RWL* f, off_t off, off_t len);
    iwrc(*lwrite)(struct IWFS_RWL* f, off_t off, const void *buf, size_t siz, size_t *sp);
    iwrc(*lread)(struct IWFS_RWL* f, off_t off, void *buf, size_t siz, size_t *sp);

} IWFS_RWL;


/**
 * @brief Open file.
 * @param f File handle
 * @param opts File open options
 */
IW_EXPORT iwrc iwfs_rwlfile_open(IWFS_RWL *f,
                                const IWFS_RWL_OPTS *opts);

/**
 * @brief Init `iwrwlfile` submodule.
 */
IW_EXPORT iwrc iwfs_rwlfile_init(void);



#endif
