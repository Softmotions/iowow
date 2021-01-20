#pragma once
#ifndef IWKV_H
#define IWKV_H

/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2021 Softmotions Ltd <info@softmotions.com>
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
 *  @brief Persistent key-value storage based on skiplist
 *         datastructure (https://en.wikipedia.org/wiki/Skip_list).
 *  @author Anton Adamansky (adamansky@softmotions.com)
 *
 * <strong>Features:<strong>
 * - Simple design of key value storage
 * - Lightweight shared/static library: 200Kb
 * - Support of multiple key-value databases within a single file
 * - Compound keys supported
 * - Ultra-fast traversal of database records
 * - Native support of integer keys
 *
 * <strong>Limitations:<strong>
 * - Maximum iwkv storage file size: 512 GB (0x7fffffff80)
 * - Total size of a single key+value record must be not greater than 255Mb (0xfffffff)
 * - In-memory cache for every opened database takes ~130Kb, cache can be disposed by `iwkv_db_cache_release()`
 */

#include "iowow.h"
#include "iwfsmfile.h"
#include <stddef.h>
#include <stdbool.h>

IW_EXTERN_C_START

// Max key + value size: 255Mb
#define IWKV_MAX_KVSZ 0xfffffff

/**
 * @brief IWKV error codes.
 */
typedef enum {
  _IWKV_ERROR_START = (IW_ERROR_START + 5000UL),
  IWKV_ERROR_NOTFOUND,                    /**< Key not found (IWKV_ERROR_NOTFOUND) */
  IWKV_ERROR_KEY_EXISTS,                  /**< Key already exists (IWKV_ERROR_KEY_EXISTS) */
  IWKV_ERROR_MAXKVSZ,
  /**< Size of Key+value must be not greater than 0xfffffff bytes
     (IWKV_ERROR_MAXKVSZ) */
  IWKV_ERROR_CORRUPTED,                   /**< Database file invalid or corrupted (IWKV_ERROR_CORRUPTED) */
  IWKV_ERROR_DUP_VALUE_SIZE,
  /**< Value size is not compatible for insertion into sorted values array
     (IWKV_ERROR_DUP_VALUE_SIZE) */
  IWKV_ERROR_KEY_NUM_VALUE_SIZE,
  /**< Given key is not compatible to storage as number
     (IWKV_ERROR_KEY_NUM_VALUE_SIZE)  */
  IWKV_ERROR_INCOMPATIBLE_DB_MODE,        /**< Incorpatible database open mode (IWKV_ERROR_INCOMPATIBLE_DB_MODE) */
  IWKV_ERROR_INCOMPATIBLE_DB_FORMAT,
  /**< Incompatible database format version, please migrate database data
     (IWKV_ERROR_INCOMPATIBLE_DB_FORMAT) */
  IWKV_ERROR_CORRUPTED_WAL_FILE,          /**< Corrupted WAL file (IWKV_ERROR_CORRUPTED_WAL_FILE) */
  IWKV_ERROR_VALUE_CANNOT_BE_INCREMENTED,
  /**< Stored value cannot be incremented/descremented
     (IWKV_ERROR_VALUE_CANNOT_BE_INCREMENTED) */
  IWKV_ERROR_WAL_MODE_REQUIRED,
  /**< Operation requires WAL enabled database. (IWKV_ERROR_WAL_MODE_REQUIRED)
   */
  IWKV_ERROR_BACKUP_IN_PROGRESS,          /**< Backup operation in progress. (IWKV_ERROR_BACKUP_IN_PROGRESS) */
  _IWKV_ERROR_END,
  // Internal only
  _IWKV_RC_KVBLOCK_FULL,
  _IWKV_RC_REQUIRE_NLEVEL,
  _IWKV_RC_END,
} iwkv_ecode;

/** Database file open modes. */
typedef uint8_t iwkv_openflags;
/** Open storage file in read-only mode */
#define IWKV_RDONLY ((iwkv_openflags) 0x02U)
/** Truncate storage file on open */
#define IWKV_TRUNC            ((iwkv_openflags) 0x04U)
#define IWKV_NO_TRIM_ON_CLOSE ((iwkv_openflags) 0x08U)

/** Database initialization modes */
typedef uint8_t iwdb_flags_t;

/** Floating point number keys represented as string (char*) value. */
#define IWDB_REALNUM_KEYS ((iwdb_flags_t) 0x10U)

/** Variable-length number keys */
#define IWDB_VNUM64_KEYS ((iwdb_flags_t) 0x20U)

/**
 * Enable compound database keys. Keys stored in the following format: `<key value prefix><numeric key suffix>`
 * Allows associate one `key value` with many references represented as VNUM64 (eg.: Non unique table indexes).
 * @see IWKV_val.compound
 */
#define IWDB_COMPOUND_KEYS ((iwdb_flags_t) 0x40U)

/**  Record store modes used in `iwkv_put()` and `iwkv_cursor_set()` functions. */
typedef uint8_t iwkv_opflags;

/** Do not overwrite value for an existing key.
   `IWKV_ERROR_KEY_EXISTS` will be returned in such cases. */
#define IWKV_NO_OVERWRITE ((iwkv_opflags) 0x01U)

/** Flush changes on disk after operation */
#define IWKV_SYNC ((iwkv_opflags) 0x04U)

/** Increment/decrement stored UINT32|UINT64 value by given INT32|INT64 number
    `IWKV_ERROR_KEY_EXISTS` does not makes sense if this flag set. */
#define IWKV_VAL_INCREMENT ((iwkv_opflags) 0x10U)

struct _IWKV;
typedef struct _IWKV*IWKV;

struct _IWDB;
typedef struct _IWDB*IWDB;

/**
 * @brief Write ahead log (WAL) options.
 */
typedef struct IWKV_WAL_OPTS {
  bool     enabled;                 /**< WAL enabled */
  bool     check_crc_on_checkpoint; /**< Check CRC32 sum of data blocks during checkpoint. Default: false */
  uint32_t savepoint_timeout_sec;   /**< Savepoint timeout seconds. Default: 10 sec */
  uint32_t checkpoint_timeout_sec;  /**< Checkpoint timeout seconds. Default: 300 sec (5 min); */
  size_t   wal_buffer_sz;           /**< WAL file intermediate buffer size. Default: 8Mb */
  uint64_t checkpoint_buffer_sz;    /**< Checkpoint buffer size in bytes. Default: 1Gb */
  iwrc (*wal_lock_interceptor)(bool, void*);
  /**< Optional function called
       - before acquiring
       - after releasing
       exclusive database lock by WAL checkpoint thread.
       In the case of `before lock` first argument will be set to true */
  void *wal_lock_interceptor_opaque;/**< Opaque data for `wal_lock_interceptor` */
} IWKV_WAL_OPTS;

/**
 * @brief IWKV storage open options.
 */
typedef struct IWKV_OPTS {
  const char *path;                 /**< Path to database file */
  uint32_t    random_seed;          /**< Random seed used for iwu random generator */
  /**
   * Database storage format version.
   * Leave it as zero for the latest supported format.
   * Used only for newly created databases,
   */
  int32_t fmt_version;
  iwkv_openflags oflags;            /**< Bitmask of database file open modes */
  bool file_lock_fail_fast;         /**< Do not wait and raise error if database is locked by another process */
  IWKV_WAL_OPTS wal;                /**< WAL options */
} IWKV_OPTS;

/**
 * @brief Data container for key/value.
 */
typedef struct IWKV_val {
  void  *data;           /**< Data buffer */
  size_t size;           /**< Data buffer size */
  /** Extra key part used for key comparison.
   *  If set to non zero and database is created with `IWDB_COMPOUND_KEYS` mode
   *  keys will behave as compound: `<key value><compound>` consisting of two parts.
   *  `compound` field ignored if db not in `IWDB_COMPOUND_KEYS` mode.
   */
  int64_t compound;
} IWKV_val;

/**
 * @brief Cursor opaque handler.
 */
struct _IWKV_cursor;
typedef struct _IWKV_cursor*IWKV_cursor;

/**
 * @brief Database cursor operations and position flags.
 */
typedef enum IWKV_cursor_op {
  IWKV_CURSOR_BEFORE_FIRST = 1, /**< Set cursor to position before first record */
  IWKV_CURSOR_AFTER_LAST,       /**< Set cursor to position after last record */
  IWKV_CURSOR_NEXT,             /**< Move cursor to the next record */
  IWKV_CURSOR_PREV,             /**< Move cursor to the previous record */
  IWKV_CURSOR_EQ,               /**< Set cursor to the specified key value */
  IWKV_CURSOR_GE,               /**< Set cursor to the key which greater or equal key specified */
} IWKV_cursor_op;

/**
 * @brief Initialize iwkv storage.
 * @details This method must be called before using of any iwkv public API function.
 * @note iwkv implicitly initialized by iw_init()
 */
IW_EXPORT WUR iwrc iwkv_init(void);

/**
 * @brief Open iwkv storage.
 * @code {.c}
 *  IWKV iwkv;
 *  IWKV_OPTS opts = {
 *    .path = "mystore.db"
 *  };
 *  iwrc rc = iwkv_open(&opts, &iwkv);
 * @endcode
 * @note Any opened iwkv storage must be closed by `iwkv_close()` after usage.
 * @param opts Database open options.
 * @param [out] iwkvp Pointer to @ref IWKV structure.
 */
IW_EXPORT WUR iwrc iwkv_open(const IWKV_OPTS *opts, IWKV *iwkvp);

/**
 * @brief Get iwkv database handler identified by specified `dbid` number.
 * @details In the case if no database matched `dbid`
 *          a new database will be created using specified function arguments.
 *
 * @note Database handler doesn't require to be explicitly closed or freed.
 *       Although it may be usefull to release database cache memory of unused databases
 *       dependening on memory requirements of your application by `iwkv_db_cache_release()`.
 * @note Database `flags` argument must be same for all subsequent
 *       calls after first call for particular database,
 *       otherwise `IWKV_ERROR_INCOMPATIBLE_DB_MODE` will be reported.
 *
 * @param iwkv Pointer to @ref IWKV handler
 * @param dbid Database identifier
 * @param flags Database initialization flags
 * @param [out] dbp Pointer to database opaque structure
 */
IW_EXPORT WUR iwrc iwkv_db(IWKV iwkv, uint32_t dbid, iwdb_flags_t flags, IWDB *dbp);

/**
 * @brief Create new database with next available database id.
 * @see iwrc iwkv_db()
 *
 * @param flags Database initialization flags
 * @param [out] dbidp Database identifier placeholder will be filled with next available id.
 * @param [out] dbp Pointer to database opaque structure
 */
IW_EXPORT WUR iwrc iwkv_new_db(IWKV iwkv, iwdb_flags_t dbflg, uint32_t *dbidp, IWDB *dbp);

/**
 * @brief Frees memory resources used by database cache
 *        until to next database access operation (get/put/cursor).
 *        Typicaly it will free ~130Kb of memory per database in use.
 *
 * @param db Database handler
 */
IW_EXPORT iwrc iwkv_db_cache_release(IWDB db);

/**
 * @brief Destroy(drop) existing database and cleanup all of its data.
 *
 * @param dbp Pointer to database opened.
 */
IW_EXPORT iwrc iwkv_db_destroy(IWDB *dbp);

/**
 * @brief Sync iwkv storage state with disk.
 *
 * @note It will cause deadlock if current thread holds opened cursors and WAL is enabled,
 *       use method with caution.
 *
 * @param iwkv IWKV handler.
 * @param flags Sync flags.
 */
IW_EXPORT iwrc iwkv_sync(IWKV iwkv, iwfs_sync_flags flags);

/**
 * @brief Close iwkv storage.
 * @details Upon successfull call of iwkv_close()
 * no farther operations on storage or any of its databases are allowed.
 *
 * @param iwkvp
 */
IW_EXPORT iwrc iwkv_close(IWKV *iwkvp);

/**
 * @brief Store record in database.
 *
 * iwkv_opflags opflags:
 * - `IWKV_NO_OVERWRITE` If a key is already exists the `IWKV_ERROR_KEY_EXISTS` error will returned.
 * - `IWKV_SYNC` Flush changes on disk after operation
 *
 * @note `iwkv_put()` adds a new value to sorted values array for existing keys if
 * database created with `IWDB_DUP_UINT32_VALS`|`IWDB_DUP_UINT64_VALS` flags
 *
 * @param db Database handler
 * @param key Key data container
 * @param val Value data container
 * @param opflags Put options used
 */
IW_EXPORT iwrc iwkv_put(IWDB db, const IWKV_val *key, const IWKV_val *val, iwkv_opflags opflags);

/**
 * @brief Intercepts old(replaced) value in put operation.
 * @note If `oldval` is not zero IWKV_PUT_HANDLER responsive for releasing it using iwkv_val_dispose()
 * @warning Use `IWKV_PUT_HANDLER` with caution: mind deadlocks.
 *
 * @param key Key used in put operation
 * @param val Value used in put operation
 * @param oldval Old value which will be replaced by `val` may be `NULL`
 * @param op Arbitrary opaqued data passed to this handler
 */
typedef iwrc (*IWKV_PUT_HANDLER)(const IWKV_val *key, const IWKV_val *val, IWKV_val *oldval, void *op);

/**
 * @brief Store record in database.
 * @see iwkv_put()
 */
IW_EXPORT iwrc iwkv_puth(
  IWDB db, const IWKV_val *key, const IWKV_val *val,
  iwkv_opflags opflags, IWKV_PUT_HANDLER ph, void *phop);

/**
 * @brief Get value for given `key`.
 *
 * @note If not matching record found `IWKV_ERROR_NOTFOUND` will be returned.
 * @note On success a returned value must be freed with `iwkv_val_dispose()`
 *
 * @param db Database handler
 * @param key Key data
 * @param [out] oval Value associated with `key` or `NULL`
 */
IW_EXPORT iwrc iwkv_get(IWDB db, const IWKV_val *key, IWKV_val *oval);

/**
 * @brief Get value for given `key` and copy it into provided `vbuf` using up to `vbufsz` bytes.
 *
 * @param db Database handler
 * @param key Key data
 * @param vbuf Pointer to value buffer
 * @param vbufsz Value buffer size
 * @param [out] vsz Actual value size
 */
IW_EXPORT iwrc iwkv_get_copy(IWDB db, const IWKV_val *key, void *vbuf, size_t vbufsz, size_t *vsz);

/**
 * @brief Set arbitrary data associated with database.
 * Database write lock will acquired for this operation.
 *
 * @param db Database handler
 * @param buf Data buffer
 * @param sz  Size of data buffer
 */
IW_EXPORT iwrc iwkv_db_set_meta(IWDB db, void *buf, size_t sz);

/**
 * @brief Get arbitrary data associated with database.
 * @param db Database handler
 * @param buf Output buffer
 * @param sz Size of target buffer
 * @param [out] rsz Number of bytes read actually
 */
IW_EXPORT iwrc iwkv_db_get_meta(IWDB db, void *buf, size_t sz, size_t *rsz);

/**
 * @brief Remove record identified by `key`.
 *
 * Returns `IWKV_ERROR_NOTFOUND` is no matching key found
 * @param db Database handler
 * @param key Key data container
 */
IW_EXPORT iwrc iwkv_del(IWDB db, const IWKV_val *key, iwkv_opflags opflags);

/**
 * @brief Destroy key/value data container.
 *
 */
IW_EXPORT void iwkv_val_dispose(IWKV_val *kval);

/**
 * @brief Dispose data containers for key and value respectively.
 *
 * @note This method is shortland of:
 * @code {.c}
 *  iwkv_kv_dispose(key);
 *  iwkv_kv_dispose(val);
 * @endcode
 *
 * @param key Key data containers
 * @param val Value data containers
 */
IW_EXPORT void iwkv_kv_dispose(IWKV_val *key, IWKV_val *val);

/**
 * @brief Open database cursor.
 *
 * @param db Database handler
 * @param cur Pointer to an allocated cursor structure to be initialized
 * @param op Cursor open mode/initial positions flags
 * @param key Optional key argument, required to point cursor to the given key.
 */
IW_EXPORT WUR iwrc iwkv_cursor_open(
  IWDB            db,
  IWKV_cursor    *cur,
  IWKV_cursor_op  op,
  const IWKV_val *key);

/**
 * @brief Move cursor to the next position.
 *
 * @param cur Opened cursor object
 * @param op Cursor position operation
 */
IW_EXPORT WUR iwrc iwkv_cursor_to(IWKV_cursor cur, IWKV_cursor_op op);

/**
 * @brief Move cursor to the next position.
 *
 * @param cur Opened cursor object
 * @param op Cursor position operation
 * @param key Optional key argument used to move cursor to the given key.
 */
IW_EXPORT WUR iwrc iwkv_cursor_to_key(IWKV_cursor cur, IWKV_cursor_op op, const IWKV_val *key);

/**
 * @brief Get key and value at current cursor position.
 * @note Data stored in okey/oval containers must be freed with `iwkv_val_dispose()`.
 *
 * @param cur Opened cursor object
 * @param okey Key container to be initialized by key at current position. Can be null.
 * @param oval Value container to be initialized by value at current position. Can be null.
 */
IW_EXPORT iwrc iwkv_cursor_get(IWKV_cursor cur, IWKV_val *okey, IWKV_val *oval);

/**
 * @brief Get value at current cursor position.
 * @note Data stored in `oval` container must be freed with `iwkv_val_dispose()`.
 * @param cur Opened cursor object
 * @param oval Value holder to be initialized by value at current position
 */
IW_EXPORT iwrc iwkv_cursor_val(IWKV_cursor cur, IWKV_val *oval);

/**
 * @brief Copy value data to the specified buffer at the current cursor position.
 * @note At most of `bufsz` bytes will be copied into `vbuf`.
 *
 * @param cur Opened cursor object
 * @param vbuf Pointer to value buffer
 * @param vbufsz Value buffer size
 * @param [out] vsz Actual value size
 */
IW_EXPORT iwrc iwkv_cursor_copy_val(IWKV_cursor cur, void *vbuf, size_t vbufsz, size_t *vsz);

/**
 * @brief Get key at current cursor position.
 * @note Data stored in okey container must be freed with `iwkv_val_dispose()`.
 *
 * @param cur Opened cursor object
 * @param oval Key holder to be initialized by key at current position
 */
IW_EXPORT iwrc iwkv_cursor_key(IWKV_cursor cur, IWKV_val *okey);

/**
 * @brief Copy key data to the specified buffer at the current cursor position.
 * @note At most of `bufsz` bytes will be copied into `kbuf`.
 *
 * @param cur Opened cursor object
 * @param kbuf Pointer to value buffer, can be zero if kbufsz is zero too.
 * @param kbufsz Key buffer size, cab be zero.
 * @param [out] ksz Actual key size
 * @param [out] compound Compound key part value, can be zero.
 */
IW_EXPORT iwrc iwkv_cursor_copy_key(IWKV_cursor cur, void *kbuf, size_t kbufsz, size_t *ksz, int64_t *compound);

IW_EXPORT iwrc iwkv_cursor_is_matched_key(IWKV_cursor cur, const IWKV_val *key, bool *ores, int64_t *ocompound);

/**
 * @brief Set record value at current cursor position.
 * @note This is equivalent to `iwkv_put()` operation.
 *
 * iwkv_opflags opflags:
 * - `IWKV_NO_OVERWRITE` If a key is already exists the `IWKV_ERROR_KEY_EXISTS` error will returned.
 * - `IWKV_SYNC` Flush changes on disk after operation
 *
 * @note `iwkv_cursor_set()` adds a new value to sorted values array for existing keys if
 * database created with `IWDB_DUP_UINT32_VALS`|`IWDB_DUP_UINT64_VALS` flags
 *
 * @param cur Opened cursor object
 * @param val Value holder
 * @param opflags Update value mode
 */
IW_EXPORT iwrc iwkv_cursor_set(IWKV_cursor cur, IWKV_val *val, iwkv_opflags opflags);

IW_EXPORT iwrc iwkv_cursor_seth(
  IWKV_cursor cur, IWKV_val *val, iwkv_opflags opflags,
  IWKV_PUT_HANDLER ph, void *phop);

/**
 * @brief Remove record value at current cursor position.
 * @param cur Opened cursor object
 */
IW_EXPORT iwrc iwkv_cursor_del(IWKV_cursor cur, iwkv_opflags opflags);

/**
 * @brief Close cursor object.
 * @param cur Opened cursor
 */
IW_EXPORT iwrc iwkv_cursor_close(IWKV_cursor *cur);

/**
 * Creates an online database backup image and copies it into the specified `target_file`.
 * During online backup phase read/write database operations are not
 * blocked for significant amount of time. Backup finish time is
 * placed into `ts` as number of milliseconds since epoch.
 * Online backup guaranties what all records before `ts` timestamp will
 * be stored in backup image. Later, online backup image can be
 * opened as ordinary database file.
 *
 * @note In order to avoid deadlocks: close all opened database cursors
 * before calling this method.
 *
 * @param iwkv
 * @param [out] ts Backup completion timestamp
 * @param target_file backup file path
 */
IW_EXPORT iwrc iwkv_online_backup(IWKV iwkv, uint64_t *ts, const char *target_file);

/**
 * @brief Get database file status info.
 * @note Database should be in opened state.
 *
 * @see IWFS_FILE::state
 * @param db Database handler
 * @param [out] out IWFS_FSM_STATE placeholder iwkv file state
 */
IW_EXPORT iwrc iwkv_state(IWKV iwkv, IWFS_FSM_STATE *out);

// Do not print random levels of skiplist blocks
#define IWKVD_PRINT_NO_LEVEVELS 0x1

// Print record values
#define IWKVD_PRINT_VALS 0x2

void iwkvd_db(FILE *f, IWDB db, int flags, int plvl);

IW_EXTERN_C_END

#endif
