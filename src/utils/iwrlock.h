#ifndef IWRLOCK_H
#define IWRLOCK_H

/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2018 Softmotions Ltd <info@softmotions.com>
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
 *  @brief Implement `fcntl()` rw-locking style over abstract address space
 *         within a threads.
 *  @author Anton Adamansky (adamansky@softmotions.com)
 */

#include "basedefs.h"
#include <sys/types.h>

IW_EXTERN_C_START

typedef struct _IWRLOCK IWRLOCK;

/**
 * @brief RW locking modes.
 */
typedef enum {
  IWRL_READ = 0x00, /**< Reader lock */
  IWRL_WRITE = 0x01 /**< Writee lock */
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
IW_EXPORT iwrc iwrl_lock(IWRLOCK *lk, off_t start, off_t len,
                         iwrl_lockflags flags);

/**
 * @brief Try to acquire a lock for the address range specified by @a start and
 * @a len.
 *        If lock cannot be acquired without waiting this function returns
 *        `IW_ERROR_FALSE` error code as response status.
 * @param lk        `IWRLOCK` pointer.
 * @param start     Offset of the first byte of locked address space.
 * @param len       Length in bytes of locked space
 * @param flags     Locking flags. `0` - for read locks otherwise write lock
 * @return `0` on success, `IW_ERROR_FALSE` if lock cannot be acquired without
 * waiting,
 *          or error code.
 */
IW_EXPORT iwrc iwrl_trylock(IWRLOCK *lk, off_t start, off_t len,
                            iwrl_lockflags flags);

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
IW_EXPORT iwrc iwrl_num_ranges(IWRLOCK *lk, int *ret);

/**
 * @brief Returns number of write-locked ranges.
 * @param lk        `IWRLOCK` pointer.
 * @param [out] ret Number of write ranges placeholder.
 * @return `0` on success or error code
 */
IW_EXPORT iwrc iwrl_write_ranges(IWRLOCK *lk, int *ret);

IW_EXTERN_C_END

#endif
