/** @file
 *  @brief Auto-expandable file.
 *
 *  Features:
 *  - Support tunable file expansion policies.
 *  - Support of RW method locking in multithreaded environment.
 *  - File shrinking/truncation support.
 *  - A number mmaped regions can be registered in the file's address space.
 *    These regions used in read/write operation and automatically maintained during file resize
 *    operations.
 */

#ifndef IWEXFILE_H
#define IWEXFILE_H

#include "iwfile.h"

struct IWFS_EXFILE_OPTS;

/**
 * @brief File resize policy function type.
 * @return Computed new file size.
 */
typedef off_t(*IW_EXFILE_RSPOLICY_FN)(off_t size, struct IWFS_EXFILE_OPTS *opts);

/**
 * @struct IWFS_EXFILE_OPTS
 * @brief File options.
 */
typedef struct IWFS_EXFILE_OPTS {
    IWFS_FILE_OPTS fopts;               /**< Underlying file options */
    off_t initial_size;                 /**< Initial file size */
    IW_EXFILE_RSPOLICY_FN *rspolicy;    /**< File resize policy function ptr. */
    void *ctx;                          /**< Custom opaque data */
    int lock_methods;                   /**< If `1` file operation will be guarded by rw lock */
} IWFS_EXFILE_OPTS;


struct IWFS_EXFILE_IMPL;
typedef struct IWFS_EXFILE_IMPL IWFS_EXFILE_IMPL;

typedef struct IWFS_EXFILE {
    IWFS_EXFILE_IMPL *impl;
} IWFS_EXFILE;

//IW_EXPORT iwrc iwfs_exfile_open()

/**
 * @brief Init `iwexfile` submodule.
 */
IW_EXPORT iwrc iwfs_exfile_init(void);


#endif
