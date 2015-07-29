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
struct IWFS_EXFILE;


/**
 * @enum iwfs_extfile_ecode
 * @brief Error codes.
 */
typedef enum {
    _IWFS_EXFILE_ERROR_START = (IW_ERROR_START + 2000UL),
    IWFS_ERROR_MMAP_OVERLAP,
    IWFS_ERROR_NOT_MMAPED,
    _IWFS_EXFILE_ERROR_END
} iwfs_extfile_ecode;

/**
 * @brief File resize policy function type.
 * Returned size cannot be lesser than requested @a size and must be page aligned.
 *
 * @param size requested size
 * @return Computed new file size.
 */
typedef off_t(*IW_EXFILE_RSPOLICY)(off_t size, struct IWFS_EXFILE *f, void *ctx);

/**
 * @struct IWFS_EXFILE_OPTS
 * @brief File options.
 */
typedef struct IWFS_EXFILE_OPTS {
    IWFS_FILE_OPTS          fopts;          /**< Underlying file options */
    off_t                   initial_size;   /**< Initial file size */
    int                     use_locks;      /**< If `1` file operation will be guarded by rw lock */
    IW_EXFILE_RSPOLICY      rspolicy;      /**< File resize policy function ptr. */
    void                    *rspolicy_ctx;  /**< Custom opaque data for policy functions. */
} IWFS_EXFILE_OPTS;

typedef struct IWFS_EXFILE_STATE {
    IWFS_FILE_STATE fstate; /**< Simple file state */
    off_t fsize;             /**< Current file size */
} IWFS_EXFILE_STATE;

struct _EXFILE_IMPL;
typedef struct _EXFILE_IMPL _EXFILE_IMPL;

typedef struct IWFS_EXFILE {
    _EXFILE_IMPL *impl;

    iwrc(*write)(struct IWFS_EXFILE* f, off_t off, const void *buf, size_t siz, size_t *sp);
    iwrc(*read)(struct IWFS_EXFILE* f, off_t off, void *buf, size_t siz, size_t *sp);
    iwrc(*close)(struct IWFS_EXFILE* f);
    iwrc(*sync)(struct IWFS_EXFILE* f, const IWFS_FILE_SYNC_OPTS *opts);
    iwrc(*state)(struct IWFS_EXFILE* f, IWFS_EXFILE_STATE* state);

    iwrc(*ensure_size)(struct IWFS_EXFILE* f, off_t size);
    iwrc(*truncate)(struct IWFS_EXFILE* f, off_t size);
    iwrc(*add_mmap)(struct IWFS_EXFILE* f, off_t off, size_t maxlen);
    iwrc(*get_mmap)(struct IWFS_EXFILE* f, off_t off, uint8_t **mm, size_t *sp);
    iwrc(*remove_mmap)(struct IWFS_EXFILE* f, off_t off);
    iwrc(*sync_mmap)(struct IWFS_EXFILE* f, off_t off, int flags);

} IWFS_EXFILE;

/**
 * @brief Open exfile.
 * @param f Exfile handle
 * @param opts File open options
 */
IW_EXPORT iwrc iwfs_exfile_open(IWFS_EXFILE *f,
                                const IWFS_EXFILE_OPTS *opts);

/**
 * @brief Init `iwexfile` submodule.
 */
IW_EXPORT iwrc iwfs_exfile_init(void);


#endif
