/** @file
 *  @brief Implement `fcntl()` rw-locking style over abstract address space within a threads.   
 */

#ifndef IWRLOCK_H
#define IWRLOCK_H

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
 * @param lk [out] Pointer to the allocated lock structure.
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
 * @brief Returns number of read/write locked ranges.
 * @param lk        `IWRLOCK` pointer.
 * @param ret [out] Number of read/write ranges placeholder.
 * @return `0` on success or error coded
 */
IW_EXPORT iwrc iwrl_num_lockers(IWRLOCK *lk,  int *ret);

/**
 * @brief Returns number of write-locked ranges.
 * @param lk        `IWRLOCK` pointer.
 * @param ret [out] Number of write ranges placeholder.
 * @return `0` on success or error code
 */
IW_EXPORT iwrc iwrl_num_writers(IWRLOCK *lk, int *ret);


IW_EXTERN_C_END

#endif
