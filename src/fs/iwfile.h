#pragma once
#ifndef IW_FILE_H
#define IW_FILE_H

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

/**
 * @file
 * @brief Simple read-write file abstraction implementation.
 * @author Anton Adamansky (adamansky@softmotions.com)
 *
 * @note  Before using API of this module you should call
 * `iw_init(void)` iowow module initialization routine.
 *
 * File operations implemented as function pointers contained in `IWFS_FILE` `C`
 * structure.
 * The `iwfs_file_open(IWFS_FILE *f, const IWFS_FILE_OPTS *opts)` opens file and
 * initializes a given `IWFS_FILE` structure.
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

IW_EXTERN_C_START

/**
 * @enum iwfs_omode
 * @brief File open modes.
 */
typedef enum {
  IWFS_OREAD = 0x01UL,   /**< Open file as a reader. */
  IWFS_OWRITE = 0x02UL,  /**< Open file as a writer. */
  IWFS_OCREATE = 0x04UL, /**< If file is missing it will be created on open. */
  IWFS_OTRUNC = 0x08UL   /**< Truncate file on open. */
} iwfs_omode;

/**
 * @enum iwfs_openstatus
 * @brief Status of an open file operation.
 */
typedef enum {
  IWFS_OPEN_FAIL = 0x00UL, /**< Open failed. */
  IWFS_OPEN_NEW = 0x01UL,  /**< Open success, new file've been created. */
  IWFS_OPEN_EXISTING =
    0x02UL /**< Open success, existing file've been opened. */
} iwfs_openstatus;

#define IWFS_DEFAULT_OMODE (IWFS_OCREATE)
#define IWFS_DEFAULT_LOCKMODE (IWP_NOLOCK)
#define IWFS_DEFAULT_FILEMODE                    \
  00666 /**< Default permission of created files \
*/

/**
 * @brief `IWFS_FILE` file options.
 * @see iwrc iwfs_file_open(IWFS_FILE *f, const IWFS_FILE_OPTS *opts)
 */
typedef struct {
  const char *path;       /**< Required file path. */
  iwfs_omode omode;       /**< File open mode. */
  iwp_lockmode lock_mode; /**< File locking mode. */
  /**< Specifies the permissions to use in case a new file is created,
       `int open(const char *pathname, int flags, mode_t mode)` */
  int filemode;
} IWFS_FILE_OPTS;

/**
 * @brief `IWFS_FILE` file state info.
 * @see IWFS_FILE::state
 */
typedef struct {
  int is_open;             /**< `1` if file in open state */
  iwfs_openstatus ostatus; /**< File open status. */
  IWFS_FILE_OPTS opts;     /**< File open options. */
  HANDLE fh;               /**< File handle */
} IWFS_FILE_STATE;

/**
 * @enum iwfs_sync_flags
 * @brief Sync file data options.
 * @see IWFS_FILE::sync
 */
typedef enum {
  IWFS_FDATASYNC = 0x01, /**< Use `fdatasync` mode */
} iwfs_sync_flags;

/**
 * @struct IWFS_FILE
 * @brief Simple file implementation.
 */
typedef struct IWFS_FILE {
  void *impl; /**< Implementation specific data */

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
  iwrc(*write)(struct IWFS_FILE *f, off_t off, const void *buf,
               size_t siz, size_t *sp);

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
  iwrc(*read)(struct IWFS_FILE *f, off_t off, void *buf,
              size_t siz, size_t *sp);

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
  iwrc(*state)(struct IWFS_FILE *f, IWFS_FILE_STATE *state);

  /**
   * @brief Copy data within a file
   * @param f `struct IWFS_FILE` pointer.
   * @param off Data offset
   * @param siz Data size
   * @param noff New data offset
   */
  iwrc(*copy)(struct IWFS_FILE *f, off_t off, size_t siz, off_t noff);

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
 *      .lock_mode = ...,     //File locking mode acquired by process opened
 this file.
 *                            //    Default: `IWP_NOLOCK`
 *      .filemode = ..        //Specifies the permissions to use in case a new
 file is created.
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
IW_EXPORT WUR iwrc iwfs_file_open(IWFS_FILE *f, const IWFS_FILE_OPTS *opts);

/**
 * @brief Init `iwfile` submodule.
 */
IW_EXPORT WUR iwrc iwfs_file_init(void);

IW_EXTERN_C_END
#endif
