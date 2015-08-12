#ifndef IWP_H
#define IWP_H

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
 *  @author Anton Adamansky (adamansky@gmail.com)
 **/

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
 *
 * File locking mode acquired by process opened this file.
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
 * @enum iwp_file_type
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
    off_t size;          /**< File size. */
    uint64_t atime;         /**< Time of last access. */
    uint64_t ctime;         /**< Time of last status change. */
    uint64_t mtime;         /**< Time of last modification. */
    iwp_file_type ftype;    /**< File type. */
} IWP_FILE_STAT;

/**
 * @brief Stat the file specified by @a path.
 *
 * @param path File path
 * @param [out] stat File stat info placeholder.
 * @return `0` on sucess or error code.
 */
IW_EXPORT iwrc iwp_fstat(const char *path, IWP_FILE_STAT *stat);

/**
 * @brief Lock the file. 
 *
 * @param fh File handle.
 * @param lmode Lock mode specified.
 * @return `0` on sucess or error code.
 */
IW_EXPORT iwrc iwp_flock(HANDLE fh, iwp_lockmode lmode);

/**
 * @brief Unlock the file specified by @a fh
 * @param fh File handle
 * @return `0` on sucess or error code.
 */
IW_EXPORT iwrc iwp_unlock(HANDLE fh);


/**
 * @brief Close the specified file handle (File descriptor).
 * @param fh File handle.
 */
IW_EXPORT iwrc iwp_closefh(HANDLE fh);


/**
 * @brief Read @a siz bytes from file @a fh
 *        into @a buf at the specified offset @a off.
 *
 * @param fh        File handle.
 * @param off       Offset from start of the file.
 * @param [out] buf       Buffer into which bytes will read.
 * @param siz       Number of bytes to read.
 * @param [out] sp  Number of bytes read actually
 * @return `0` on sucess or error code.
 */
IW_EXPORT iwrc iwp_read(HANDLE fh, off_t off, void *buf,
                        size_t siz, size_t *sp);


/**
 * @brief Write @a siz bytes into file @a fh 
 *        at the specified offset @a off 
 *        from buffer @a buf.
 * 
 * @param fh    File handle.
 * @param off   Offset from start of the file.
 * @param buf   Data buffer to write.
 * @param siz   Number of bytes to write.
 * @param [out] sp   Number of bytes written.
 * @return `0` on sucess or error code.
 */
IW_EXPORT iwrc iwp_write(HANDLE fh, off_t off, const void *buf,
                         size_t siz, size_t *sp);

/**
 * @brief Get system page size.
 */
IW_EXPORT size_t iwp_page_size(void);


/**
 * @brief Truncate a file specified by @a fh to a size of @a len bytes
 * @param fh File handle
 * @param len File size
 * @return `0` on sucess or error code.
 */
IW_EXPORT iwrc iwp_ftruncate(HANDLE fh, off_t len);


/**
 * @brief Pause execution of current thread 
 *        to the specified @a ms time in milliseconds.
 * @param ms Thread pause time
 */
IW_EXPORT iwrc iwp_sleep(uint64_t ms);


/**
 * @brief Init iwp module.
 * @return `0` on success or error code.
 */
IW_EXPORT WUR iwrc iwp_init(void);


#endif
