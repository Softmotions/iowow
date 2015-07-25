/** @file */

#ifndef IWP_H
#define IWP_H

#include "basedefs.h"
#include <stdint.h>
#include <stdio.h>

/**
 * @brief Get current time in milliseconds.
 *
 * @param [out] time Time returned
 * @return 0 for success, or -1 for failure (in which case errno is set appropriately)
 */
IW_EXPORT int iwp_current_time_ms(int64_t *time);

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





#endif
