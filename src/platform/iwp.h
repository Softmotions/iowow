/** @file */

#ifndef IWP_H
#define IWP_H

#include "basedefs.h"
#include <stdint.h>
#include <stdio.h>

/**
 * @enum iwp_ecode
 * @brief Error codes.
 */
typedef enum {
    _IWP_ERROR_FS_START = (IW_ERROR_START + 2000UL),
    _IWP_ERROR_FS_END
} iwp_ecode;

/**
 * @enum iwp_lockmode
 * @brief File locking mode.
 */
typedef enum {
    IWP_NOLOCK = 0x00UL, /**< No lock on file. */
    IWP_RLOCK  = 0x01UL, /**< Acquire read lock on file. */
    IWP_WLOCK  = 0x02UL, /**< Acquire write lock on file. */
    IWP_NBLOCK = 0x04UL  /**< Do not block current thread if file have been locked by another process. */
} iwp_lockmode;

/**
 * @brief Get current time in milliseconds.
 *
 * @param [out] time Time returned
 * @return `0` for success, or error code
 */
IW_EXPORT iwrc iwp_current_time_ms(int64_t *time);

/**
 * @enum IWP_FILE_TYPE
 * @brief File type.
 */
typedef enum {
    IWP_TYPE_FILE,  /**< Ordinary file. */
    IWP_TYPE_DIR,   /**< Directory. */
    IWP_LINK,       /**< Symlink. */
    IWP_OTHER       /**< Other file types, eg soc, block, pipe.. */
} iwp_file_type;

/**
 * @brief File info.
 */
typedef struct IWP_FILE_STAT {
    uint64_t size;          /**< File size. */
    uint64_t atime;         /**< Time of last access. */
    uint64_t ctime;         /**< Time of last status change. */
    uint64_t mtime;         /**< Time of last modification. */
    iwp_file_type ftype;    /**< File type. */
} IWP_FILE_STAT;

/**
 * @brief Stat the file specified by @a path.
 *
 * @param path File path
 * @param stat [out] File stat info placeholder.
 * @return `0` on sucess or error code.
 */
IW_EXPORT iwrc iwp_fstat(const char *path, IWP_FILE_STAT *stat);

/**
 * @brief Lock the file.
 *
 * @param fd File handle.
 * @param lmode Lock mode specified.
 * @return `0` on sucess or error code.
 */
IW_EXPORT iwrc iwp_flock(HANDLE fd, iwp_lockmode lmode);

/**
 * @brief Unlock the file specified by @a fd
 * @param fd File handle
 * @return `0` on sucess or error code.
 */
IW_EXPORT iwrc iwp_unlock(HANDLE fd);

/**
 * @brief Init iwp module.
 * @return `0` on success or error code.
 */
IW_EXPORT iwrc iwp_init(void);


#endif
