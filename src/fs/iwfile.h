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
 * @author Anton Adamansky (adamansky@gmail.com)
 * 
 * @note  Before using API of this module you should call 
 * `iw_init(void)` iowow module initialization routine.  
 * 
 * File operations implemented as function pointers contained in `IWFS_FILE` `C` structure.
 * The `iwfs_file_open(IWFS_FILE *f, const IWFS_FILE_OPTS *opts)` opens file and initializes a given `IWFS_FILE` structure. 
 * 
 * <strong>Common use case:</strong>.
 * @code {.c}
 * 
 *      #include <iowow/iwfile.h>
 * 
 *      iw_init(); //Initialize iowoow library
 * 
 *      IWFS_FILE f;
 *      IWFS_FILE_OPTS opts = { //File options
 *          .path = "file path",
 *          ...
 *      };
 *      iwrc rc = iwfs_file_open(&f, &opts);
 *      if (!rc) {
 *          .. //read/write operations
 *          rc = f.close(&f);
 *      }
 * @endcode
 */

#include "iowow.h"
#include "iwlog.h"
#include "iwp.h"

/**
 * @enum iwfs_omode
 * @brief File open modes.
 */
typedef enum {
    IWFS_OREAD   = 0x01UL,     /**< Open file as a reader. */
    IWFS_OWRITE  = 0x02UL,     /**< Open file as a writer. */
    IWFS_OCREATE = 0x04UL,     /**< If file is missing it will be created on open. */
    IWFS_OTRUNC  = 0x08UL      /**< Truncate file on open. */
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
#define IWFS_DEFAULT_FILEMODE 00666 /**< Default permission of created files */

/**
 * @brief `IWFS_FILE` file options.
 * @see iwrc iwfs_file_open(IWFS_FILE *f, const IWFS_FILE_OPTS *opts)
 */
typedef struct {
    const char      *path;      /**< Required file path. */
    iwfs_omode      omode;      /**< File open mode. */
    iwp_lockmode    lock_mode;  /**< File locking mode. */
    /**< Specifies the permissions to use in case a new file is created,
         `int open(const char *pathname, int flags, mode_t mode)` */
    int             filemode;
} IWFS_FILE_OPTS;

/**
 * @brief `IWFS_FILE` file state info.
 * @see IWFS_FILE::state
 */
typedef struct {
    int             is_open;    /**< `1` if file in open state */
    iwfs_openstatus ostatus;    /**< File open status. */
    IWFS_FILE_OPTS  opts;       /**< File open options. */
    HANDLE          fh;         /**< File handle */
} IWFS_FILE_STATE;

/**
 * @enum iwfs_sync_flags
 * @brief Sync file data options.
 * @see IWFS_FILE::sync
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

    /**
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
     * @brief Read @a siz bytes into @a buf at the specified offset @a off
     *
     * @param f `struct IWFS_FILE` pointer.
     * @param off Offset from start of the file.
     * @param buf Buffer to read into.
     * @param siz Number of bytes to read. 
     * @param [out] sp Number of bytes actually read.
     * @return `0` on success or error code.
     */
    iwrc(*read)(struct IWFS_FILE *f, off_t off, void *buf, size_t siz, size_t *sp);

    /**
     * @brief Closes this file.
     * @return `0` on success or error code.
     */
    iwrc(*close)(struct IWFS_FILE *f);

    /**    
     * @brief Sync file data with fs.
     * @param f `struct IWFS_FILE` pointer.
     * @param opts File sync options.
     */
    iwrc(*sync)(struct IWFS_FILE *f, iwfs_sync_flags flags);

    /**
     * @brief Return current file state.
     * @param f `struct IWFS_FILE` pointer.
     * @param [out] state File state placeholder.
     * @return `0` on success or error code.
     *
     * @see struct IWFS_FILE_STATE
     */
    iwrc(*state)(struct IWFS_FILE *f, IWFS_FILE_STATE* state);

} IWFS_FILE;

/**
 * @brief Open file and initialize a given @a f structure.
 * 
 * <strong>File open options:</strong>
 * @code {.c}
 *   opts = {
 *      .path = "file path",  //File path. This options value is requied.
 *      .omode =  ...,        //File open mode. 
 *                            //    Default: `IWFS_DEFAULT_OMODE`  
 *      .lock_mode = ...,     //File locking mode acquired by process opened this file. 
 *                            //    Default: `IWP_NOLOCK`
 *      .filemode = ..        //Specifies the permissions to use in case a new file is created.
                              //    Default: `00644`  
 *   }
 * @endcode
 * 
 *
 * @param f `struct IWFS_FILE` pointer.
 * @param opts [in] File open options
 * @return `0` on success or error code.
 * @relatesalso IWFS_FILE
 */
IW_EXPORT WUR iwrc iwfs_file_open(IWFS_FILE *f,
                              const IWFS_FILE_OPTS *opts);

/**
 * @brief Init `iwfile` submodule.
 */
IW_EXPORT WUR iwrc iwfs_file_init(void);

#endif
