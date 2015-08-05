#ifndef IW_FILE_H
#define IW_FILE_H

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

/**
 * @file
 * @brief Simple read-write file abstraction implementation.
 */

#include "log/iwlog.h"
#include "platform/iwp.h"

/**
 * @enum iwfs_ecode
 * @brief Error codes.
 */
typedef enum {
    _IWFS_ERROR_FS_START = (IW_ERROR_START + 1000UL),
    _IWFS_ERROR_FS_END
} iwfs_ecode;

/**
 * @enum iwfs_omode
 * @brief File open modes
 */
typedef enum {
    IWFS_OREAD   = 0x01UL,     /**< Open as a reader. */
    IWFS_OWRITE  = 0x02UL,     /**< Open as a writer. */
    IWFS_OCREATE = 0x04UL,     /**< Writer creating. */
    IWFS_OTRUNC  = 0x08UL      /**< Writer truncating. */
} iwfs_omode;

/**
 * @enum iwfs_openstatus
 * @brief Status of an open file operation.
 */
typedef enum {
    IWFS_OPEN_FAIL      = 0x00UL, /**< Open failed. */
    IWFS_OPEN_NEW       = 0x01UL, /**< Open success, new file've been created. */
    IWFS_OPEN_EXISTING  = 0x02UL  /**< Open success, existing file've been opened. */
} iwfs_openstatus;

#define IWFS_DEFAULT_OMODE (IWFS_OCREATE)
#define IWFS_DEFAULT_LOCKMODE (IWP_NOLOCK)
#define IWFS_DEFAULT_FILEMODE 00644 /**< Default permission of created files */


/**
 * @struct IWFS_FILE_OPTS
 * @brief File options.
 * @see
 */
typedef struct {
    const char      *path;      /**< Required file path. */
    iwfs_omode      open_mode;  /**< File open mode. */
    iwp_lockmode    lock_mode;  /**< File locking mode. */
    /**< Specifies the permissions to use in case a new file is created,
         @sa int ::open(const char *pathname, int flags, mode_t mode) */
    int             filemode;
} IWFS_FILE_OPTS;

/**
 * @struct IWFS_FILE_STATE
 * @brief File state
 */
typedef struct {
    int is_open;                /**< `1` if file in open state */
    iwfs_openstatus ostatus;    /**< File open status. */
    IWFS_FILE_OPTS opts;        /**< File open options. */
    HANDLE fh;                  /**< File handle */
} IWFS_FILE_STATE;

/**
 * @enum iwfs_file_sync_flags
 * @brief Sync file data options.
 * @see int sync(struct IWFS_FILE *f, iwfs_sync_flags flags)
 */
typedef enum {
    IWFS_FDATASYNC  = 0x01,  /**< Use `fdatasync` mode */
    IWFS_NO_MMASYNC = 0x02   /**< Do not use `MS_ASYNC` mmap sync mode */
} iwfs_sync_flags;

/**
 * @struct IWFS_FILE
 * @brief Simple file implementation.
 */
typedef struct IWFS_FILE {

    struct IWFS_FILE_IMPL *impl; /**< Implementation specific data */

#define IWFS_FILE_METHODS(IW_self) \
    iwrc (*write)  (IW_self, off_t off, const void *buf, size_t siz, size_t *sp); \
    iwrc (*read)   (IW_self, off_t off, void *buf, size_t siz, size_t *sp); \
    iwrc (*close)  (IW_self); \
    iwrc (*sync)   (IW_self, iwfs_sync_flags flags); \
    iwrc (*state)  (IW_self, IWFS_FILE_STATE* state)

    /**
     * @fn int write(struct IWFS_FILE *f, off_t off, const void *buf, size_t siz, size_t *sp)
     * @brief Write @a buf bytes into the file
     *
     * @param f `struct IWFS_FILE` pointer
     * @param off Offset from start of the file where bytes will write.
     * @param buf Buffer to write.
     * @param siz Number of bytes to write.
     * @param [out] sp Number of bytes actually written
     * @return `0` on success or error code.
     */
    iwrc(*write)(struct IWFS_FILE *f, off_t off, const void *buf, size_t siz, size_t *sp);

    /**
     * @fn int read(struct IWFS_FILE *f, off_t off, void *buf, size_t siz, size_t *sp)
     * @brief Read @a siz bytes into @a buf at the specified offset @a off
     *
     * @param f `struct IWFS_FILE` pointer.
     * @param off Offset from start of the file.
     * @param buf Buffer to read into.
     * @param siz [out] sp Number of bytes actually read.
     * @return `0` on success or error code.
     */
    iwrc(*read)(struct IWFS_FILE *f, off_t off, void *buf, size_t siz, size_t *sp);

    /**
     * @fn int close(struct IWFS_FILE *f)
     * @brief Closes this file.
     *
     * @return `0` on success or error code.
     */
    iwrc(*close)(struct IWFS_FILE *f);

    /**
     * @fn int sync(struct IWFS_FILE *f, iwfs_sync_flags flags)
     * @brief Sync file data with fs.
     *
     * @param f `struct IWFS_FILE` pointer.
     * @param opts File sync options.
     */
    iwrc(*sync)(struct IWFS_FILE *f, iwfs_sync_flags flags);

    /**
     * @fn int state(struct IWFS_FILE *f, IWFS_FILE_STATE* state)
     * @brief Return current file state
     *
     * @param f `struct IWFS_FILE` pointer.
     * @param [out] state File state placeholder.
     * @return `0` on success or error code.
     *
     * @see struct IWFS_FILE_STATE
     */
    iwrc(*state)(struct IWFS_FILE *f, IWFS_FILE_STATE* state);

} IWFS_FILE;

/**
 * @brief Open file and initialize the given @a f structure.
 *
 * @param f `struct IWFS_FILE` pointer.
 * @param opts [in] File open options
 */
IW_EXPORT iwrc iwfs_file_open(IWFS_FILE *f,
                              const IWFS_FILE_OPTS *opts);

/**
 * @brief Init `iwfile` submodule.
 */
IW_EXPORT iwrc iwfs_file_init(void);


#endif
