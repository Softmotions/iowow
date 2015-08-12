#ifndef IWRLOCK_H
#define IWRLOCK_H

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
 *  @brief Implement `fcntl()` rw-locking style over abstract address space within a threads.   
 *  @author Anton Adamansky (adamansky@gmail.com)
 */
 
#include "basedefs.h"
#include <sys/types.h>


IW_EXTERN_C_START

typedef struct _IWRLOCK IWRLOCK;

typedef enum {
    IWRL_READ  = 0x00,     /**< Read lock */
    IWRL_WRITE = 0x01      /**< Write lock */
} iwrl_lockflags;

/**
 * @brief Allocate new `IWRLOCK` structure.
 * @param [out] lk Pointer to the allocated lock structure.
 * @return `0` or error code.
 */
IW_EXPORT iwrc iwrl_new(IWRLOCK **lk);

/**
 * @brief Destroys `IWRLOCK`
 * @return `0` or error code.
 */
IW_EXPORT iwrc iwrl_destroy(IWRLOCK *lk);

/**
 * @brief Acquire a lock for the address range specified by @a start and @a len.
 *        If `is_write != 0` a write lock will be acquired, otherwise a
 *        read lock will be used.
 *
 * @param lk        `IWRLOCK` pointer.
 * @param start     Offset of the first byte of locked address space.
 * @param len       Length in bytes of locked space.
 * @param flags     Locking flags. `0` - for read locks otherwise write lock.
 * @return  `0` or error code.
 */
IW_EXPORT iwrc iwrl_lock(IWRLOCK *lk, off_t start, off_t len, iwrl_lockflags flags);

/**
 * @brief Try to acquire a lock for the address range specified by @a start and @a len.
 *        If lock cannot be acquired without waiting this function returns
 *        `IW_ERROR_FALSE` error code as response status.
 * @param lk        `IWRLOCK` pointer.
 * @param start     Offset of the first byte of locked address space.
 * @param len       Length in bytes of locked space
 * @param flags     Locking flags. `0` - for read locks otherwise write lock
 * @return `0` on success, `IW_ERROR_FALSE` if lock cannot be acquired without waiting,
 *          or error code.
 */
IW_EXPORT iwrc iwrl_trylock(IWRLOCK *lk, off_t start, off_t len, iwrl_lockflags flags);

/**
 * @brief Release acquired range lock.
 * @param lk        `IWRLOCK` pointer.
 * @param start     Offset of the first byte of locked address space.
 * @param len       Length in bytes of locked space.
 */
IW_EXPORT iwrc iwrl_unlock(IWRLOCK *lk, off_t start, off_t len);

/**
 * @brief Returns number of reader/writer locked ranges.
 * @param lk        `IWRLOCK` pointer.
 * @param [out] ret Number of reader/writer ranges placeholder.
 * @return `0` on success or error coded
 */
IW_EXPORT iwrc iwrl_num_ranges(IWRLOCK *lk,  int *ret);

/**
 * @brief Returns number of write-locked ranges.
 * @param lk        `IWRLOCK` pointer.
 * @param [out] ret Number of write ranges placeholder.
 * @return `0` on success or error code
 */
IW_EXPORT iwrc iwrl_write_ranges(IWRLOCK *lk, int *ret);


IW_EXTERN_C_END

#endif
