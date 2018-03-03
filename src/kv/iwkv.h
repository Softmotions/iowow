#pragma once
#ifndef IWKV_H
#define IWKV_H

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
 *  @brief Persistent key-value store based on skiplist
 *         datastructure (https://en.wikipedia.org/wiki/Skip_list).
 *  @author Anton Adamansky (adamansky@softmotions.com)
 *
 * <strong>Features:<strong>
 * - Ability to store multiple key-value databases in a single file.
 * - Practically unlimited number of databases.
 * - Ultra-fast asc/desc traversal of database records.
 * - Native support of 4/8 byte integer keys
 * - Support of key value represented as sorted array of integers.
 *
 * <strong>Limitations:<strong>
 * - Maximum number of databases is limited by `0x3ffffff0`
 * - Maximum databases file size is ~255 GB or more precisely
 *   `0x3fffffffc0` rownded down to the system page size:
 *  - `0x3ffffff000` for 4K os page size
 *  - `0x3fffffe000` for 8K os page size
 * - Total size of a single key+value record must be not greater
 *   than `0xfffffff` bytes (~255Mb)
 */

#include "iowow.h"
#include "iwfile.h"
#include <stddef.h>
#include <stdbool.h>

/**
 * @brief IWKV specific error codes.
 */
typedef enum {
  _IWKV_ERROR_START = (IW_ERROR_START + 5000UL),
  IWKV_ERROR_NOTFOUND,             /**< Key not found (IWKV_ERROR_NOTFOUND) */
  IWKV_ERROR_KEY_EXISTS,           /**< Key exists. (IWKV_ERROR_KEY_EXISTS) */
  IWKV_ERROR_MAXKVSZ,              /**< Size of Key+value must be not greater than 0xfffffff bytes (IWKV_ERROR_MAXKVSZ) */
  IWKV_ERROR_CORRUPTED,            /**< Database file invalid or corrupted (IWKV_ERROR_CORRUPTED) */
  IWKV_ERROR_DUP_VALUE_SIZE,       /**< Value size is not compatible for insertion into sorted values array (IWKV_ERROR_DUP_VALUE_SIZE) */
  IWKV_ERROR_KEY_NUM_VALUE_SIZE,   /**< Given key is not compatible to store as number (IWKV_ERROR_KEY_NUM_VALUE_SIZE)  */
  IWKV_ERROR_INCOMPATIBLE_DB_MODE, /**< Incorpatible database open mode (IWKV_ERROR_INCOMPATIBLE_DB_MODE) */
  _IWKV_ERROR_END,
  /* Internal error codes */
  _IWKV_ERROR_KVBLOCK_FULL,
  _IWKV_ERROR_REQUIRE_NLEVEL,
} iwkv_ecode;

/**
 * @brief Database file open modes.
 */
typedef enum {
  IWKV_NOLOCKS  = 0x1,      /**< Do not use any threading locks */
  IWKV_RDONLY   = 0x2,      /**< Open storage in read-only mode */
  IWKV_TRUNC    = 0x4       /**< Truncate database file on open */
} iwkv_openflags;

/**
 * @brief Database initialization modes.
 */
typedef enum {
  IWDB_UINT32_KEYS = 0x1,     /**< Database keys are 32bit unsigned integers */
  IWDB_UINT64_KEYS = 0x2,     /**< Database keys are 64bit unsigned integers */
  IWDB_DUP_UINT32_VALS = 0x4, /**< Array of sorted uint32 values stored as key value */
  IWDB_DUP_UINT64_VALS = 0x8  /**< Array of sorted uint64 values stored as key value */
} iwdb_flags_t;

/**
 * @brief Value store modes used in `iwkv_put` and `iwkv_cursor_set` functions.
 */
typedef enum {
  IWKV_NO_OVERWRITE = 0x1,   /**< Do not overwrite value for an existing key */
  IWKV_DUP_REMOVE =   0x2,   /**< Remove value from duplicated values array.
                                  Usable only for IWDB_DUP_XXX DB database modes */
  IWKV_SYNC =         0x4    /**< Flush changes on disk after operation */                                
} iwkv_opflags;

struct IWKV;
typedef struct IWKV *IWKV;

struct IWDB;
typedef struct IWDB *IWDB;

/**
 * @brief IWKV specific open options.
 */
typedef struct IWKV_OPTS {
  char *path;              /**< Path to database file */
  iwkv_openflags oflags;   /**< Bitmask of database file open modes */
} IWKV_OPTS;

/**
 * @brief Value data container.
 */
typedef struct IWKV_val {
  void  *data;            /**< Value buffer */
  size_t  size;           /**< Value buffer size */
} IWKV_val;

/**
 * @brief Cursor opaque handler.
 */
struct IWKV_cursor;
typedef struct IWKV_cursor *IWKV_cursor;

/**
 * @brief Database cursor operations/position flags.
 */
typedef enum IWKV_cursor_op {
  IWKV_CURSOR_BEFORE_FIRST = 1, /**< Set cursor before first record */
  IWKV_CURSOR_AFTER_LAST,       /**< Set cursor after last record */
  IWKV_CURSOR_NEXT,             /**< Move cursor to next record */
  IWKV_CURSOR_PREV,             /**< Move cursor to previous record */
  IWKV_CURSOR_EQ,               /**< Set cursor to the specified key value */
  IWKV_CURSOR_GE                /**< Set cursor to the key which greater of equal key specified */
} IWKV_cursor_op;

/**
 * @brief Initialize iwkv storage.
 * @details This method must be called before using of any iwkv api function.
 * @note iwkv implicitly initialized by iw_init()
 */
IW_EXPORT WUR iwrc iwkv_init(void);

/**
 * @brief Open iwkv store.
 * @code {.c}
 *  IWKV iwkv;
 *  IWKV_OPTS opts = {
 *    .path = "mystore.db"
 *  };
 *  iwrc rc = iwkv_open(&opts, &iwkv);
 * @endcode
 * @note Any opened iwkv store must be closed by iwkv_close() after usage.
 * @param opts Database open options.
 * @param [out] iwkvp Pointer to @ref IWKV structure.
 */
IW_EXPORT WUR iwrc iwkv_open(const IWKV_OPTS *opts, IWKV *iwkvp);

/**
 * @brief Acquire iwkv database identified by `dbid`.
 * @details In the case if no database matched `dbid` 
 *          a new database will be created using specified`dbid` and `flags`.
 * @note Database doesn't require to be explicitly closed.
 * @note Database `flags` argument must be same for all subsequent calls after first call
 *       otherwise `IWKV_ERROR_INCOMPATIBLE_DB_MODE` will be reported.
 * @param iwkv Pointer to @ref IWKV store
 * @param dbid Database identifier
 * @param flags Database initialization flags
 * @param [out] dbp Pointer to database opaque structure.
 */
IW_EXPORT WUR iwrc iwkv_db(IWKV iwkv, uint32_t dbid, iwdb_flags_t flags, IWDB *dbp);

/**
 * @brief Destroy existing database and cleanup all its data.
 * @param dbp Pointer to database opened.
 */
IW_EXPORT iwrc iwkv_db_destroy(IWDB *dbp);

/**
 * @brief Sync iwkv store state with disk.
 * @param iwkv Pointer to iwkv store.
 */
IW_EXPORT iwrc iwkv_sync(IWKV iwkv);

/**
 * @brief Close iwkv store.
 * @note Upon successfull call of iwkv_close()
 *       no farther operations on store or any of its databases allowed.
 * @param iwkvp
 */
IW_EXPORT iwrc iwkv_close(IWKV *iwkvp);

/**
 * @brief Store record in database identified by `db`.
 * @details Behavior varies depending on `opflags` value:
 *  - IWKV_NO_OVERWRITE If a key record already exists in database 
 *
 * @param db Database id
 * @param key Key data
 * @param val Value data
 * @param opflags Options used for put operation.
 */
IW_EXPORT iwrc iwkv_put(IWDB db, const IWKV_val *key, const IWKV_val *val, iwkv_opflags opflags);

/**
 * @brief Get value for a given `key`.
 *
 * If not matching record found `IWKV_ERROR_NOTFOUND` will be returned.
 * @param db Database id
 * @param key Key data
 * @param [out] oval Value associated with `key` or `NULL`
 */
IW_EXPORT iwrc iwkv_get(IWDB db, const IWKV_val *key, IWKV_val *oval);

/**
 * @brief Remove record identified by `key`.
 *
 * Returns `IWKV_ERROR_NOTFOUND` is no matching key found
 * @param db Database id
 * @param key Key data
 */
IW_EXPORT iwrc iwkv_del(IWDB db, const IWKV_val *key);

/**
 * @brief Destroy key/value data holder.
 */
IW_EXPORT void iwkv_val_dispose(IWKV_val *kval);

/**
 * @brief Dispose data holders for key and value respectively.
 * @param key Key data holder
 * @param val Value data holder
 */
IW_EXPORT void iwkv_kv_dispose(IWKV_val *key, IWKV_val *val);

/**
 * @brief Open database cursor.
 * @param db Database id
 * @param cur Pointer to an allocated cursor structure to be initialized
 * @param op Cursor open mode/initial positions flags
 * @param key Optional key argument, required to point cursor to the given key.
 */
IW_EXPORT WUR iwrc iwkv_cursor_open(IWDB db,
                                    IWKV_cursor *cur,
                                    IWKV_cursor_op op,
                                    const IWKV_val *key);
/**
 * @brief Move cursor to the next position.
 * @param cur Opened cursor object
 * @param op Cursor position operation
 */
IW_EXPORT WUR iwrc iwkv_cursor_to(IWKV_cursor cur, IWKV_cursor_op op);

/**
 * @brief Move cursor to the next position.
 * @param cur Opened cursor object
 * @param op Cursor position operation
 * @param key Optional key argument used to move cursor to the given key.
 */
IW_EXPORT WUR iwrc iwkv_cursor_to_key(IWKV_cursor cur, IWKV_cursor_op op, const IWKV_val *key);

/**
 * @brief Get key and value at current cursor position.
 * @param cur Opened cursor object
 * @param okey Key holder to be initialized by key at current position
 * @param oval Value holder to be initialized by value at current position
 */
IW_EXPORT iwrc iwkv_cursor_get(IWKV_cursor cur, IWKV_val *okey, IWKV_val *oval);

/**
 * @brief Get value at current cursor position.
 * @param cur Opened cursor object
 * @param oval Value holder to be initialized by value at current position 
 */
IW_EXPORT iwrc iwkv_cursor_val(IWKV_cursor cur, IWKV_val *oval);

/**
 * @brief Get key at current cursor position.
 * @param cur Opened cursor object
 * @param oval Key holder to be initialized by key at current position 
 */
IW_EXPORT iwrc iwkv_cursor_key(IWKV_cursor cur, IWKV_val *okey);

/**
 * @brief Set record value at current cursor position.
 * @param cur Opened cursor object
 * @param val Value holder
 * @param opflags Update value mode
 */
IW_EXPORT iwrc iwkv_cursor_set(IWKV_cursor cur, IWKV_val *val, iwkv_opflags opflags);

/**
 * @brief Get length of value array at current cursor position.
 * @note Usable only for `IWDB_DUP_UINT32_VALS` and `IWDB_DUP_UINT64_VALS` database modes. 
 * @param cur Opened cursor object
 * @param [out] onum Output number
 */
IW_EXPORT iwrc iwkv_cursor_dup_num(const IWKV_cursor cur, uint32_t *onum);

/**
 * @brief Add element to value array at current cursor position.
 * @param cur Opened cursor object
 * @param dv Number to be added
 */
IW_EXPORT iwrc iwkv_cursor_dup_add(IWKV_cursor cur, uint64_t dv);

/**
 * @brief Remove element from value array at current cursor position.
 * @param cur Opened cursor object
 * @param dv Number to be removed
 */
IW_EXPORT iwrc iwkv_cursor_dup_rm(IWKV_cursor cur, uint64_t dv);

/**
 * @brief Test if given number contains in value array at current cursor position.
 * @param cur Opened cursor object
 * @param dv Value to test
 * @param [out] out Boolean result 
 */
IW_EXPORT iwrc iwkv_cursor_dup_contains(const IWKV_cursor cur, uint64_t dv, bool *out);

/**
 * @brief Iterate over all elements in array of numbers at current cursor position.  
 * @param cur Opened cursor 
 * @param visitor Elements visitor function 
 * @param opaq Opaque data passed to visitor function
 * @param start Optional pointer to number iteration will start from
 * @param down Iteration direction
 */
IW_EXPORT iwrc iwkv_cursor_dup_iter(const IWKV_cursor cur,
                                    bool(*visitor)(uint64_t dv, void *opaq),
                                    void *opaq,
                                    const uint64_t *start,
                                    bool down);
/**
 * @brief Close cursor object.
 * @param cur Opened cursor
 */
IW_EXPORT iwrc iwkv_cursor_close(IWKV_cursor *cur);

// Do not print random levels of skiplist blocks
#define IWKVD_PRINT_NO_LEVEVELS 0x1

// Print record values
#define IWKVD_PRINT_VALS 0x2

void iwkvd_db(FILE *f, IWDB db, int flags);

#endif
