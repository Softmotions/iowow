#pragma once
#ifndef IWKV_H
#define IWKV_H

#include "iowow.h"
#include "iwfile.h"
#include <stddef.h>
#include <stdbool.h>

/**
 * @brief IWKV specific rrror codes.
 */
typedef enum {
  _IWKV_ERROR_START = (IW_ERROR_START + 5000UL),
  IWKV_ERROR_NOTFOUND,             /**< Key not found (IWKV_ERROR_NOTFOUND) */
  IWKV_ERROR_KEY_EXISTS,           /**< Key exists. (IWKV_ERROR_KEY_EXISTS) */
  IWKV_ERROR_MAXKVSZ,              /**< Size of Key+value must be lesser than 0xfffffff bytes (IWKV_ERROR_MAXKVSZ) */
  IWKV_ERROR_MAXDBSZ,              /**< Database file size reached its maximal limit: 0x3fffffffc0 (IWKV_ERROR_MAXDBSZ) */
  IWKV_ERROR_CORRUPTED,            /**< Database file invalid or corrupted (IWKV_ERROR_CORRUPTED) */
  IWKV_ERROR_DUP_VALUE_SIZE,       /**< Value size is not compatible for insertion into sorted values array (IWKV_ERROR_DUP_VALUE_SIZE) */
  IWKV_ERROR_INCOMPATIBLE_DB_MODE, /**< Incorpatible database open mode (IWKV_ERROR_INCOMPATIBLE_DB_MODE) */
  IWKV_ERROR_CURSOR_SEEK_AGAIN,    /**< Perform cursor seek operation again (IWKV_ERROR_CURSOR_SEEK_AGAIN) */
  _IWKV_ERROR_END,
  /* Internal error codes */
  _IWKV_ERROR_KVBLOCK_FULL,
  _IWKV_ERROR_REQUIRE_WL,
  _IWKV_ERROR_REQUIRE_NLEVEL,
  _IWKV_ERROR_REQUIRE_WLOCK,
  _IWKV_ERROR_AGAIN,
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
 * @brief Database creation modes.
 */
typedef enum {
  IWDB_DUP_INT32_VALS = 0x1, /**< Array of sorted uint32 values stored as key value */
  IWDB_DUP_INT64_VALS = 0x2  /**< Array of sorted uint64 values stored as key value */
} iwdb_flags_t;

/**
 * @brief Value store modes used in `iwkv_put` and `iwkv_cursor_set` functions.
 */
typedef enum {
  IWKV_NO_OVERWRITE = 0x1,   /**< Do not overwrite value for an existing key */
  IWKV_DUP_REMOVE =   0x2    /**< Remove value from duplicated values array.
                                  Usable only for IWDB_DUP_X DB flags */
} iwkv_opflags;

struct IWKV;
typedef struct IWKV *IWKV;

struct IWDB;
typedef struct IWDB *IWDB;

/**
 * @brief IWKV open options.
 */
typedef struct IWKV_OPTS {
  char *path;              /**< Path to database file */
  iwkv_openflags oflags;   /**< Bitmask of db file open modes */
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

typedef enum IWKV_cursor_op {
  IWKV_CURSOR_BEFORE_FIRST = 1,
  IWKV_CURSOR_AFTER_LAST,
  IWKV_CURSOR_NEXT,
  IWKV_CURSOR_PREV,
  IWKV_CURSOR_EQ,
  IWKV_CURSOR_LE
} IWKV_cursor_op;

IW_EXPORT WUR iwrc iwkv_init(void);

IW_EXPORT WUR iwrc iwkv_open(const IWKV_OPTS *opts, IWKV *iwkvp);

IW_EXPORT WUR iwrc iwkv_db(IWKV iwkv, uint32_t dbid, iwdb_flags_t flags, IWDB *dbp);

IW_EXPORT iwrc iwkv_db_destroy(IWDB *dbp);

IW_EXPORT iwrc iwkv_sync(IWKV iwkv);

IW_EXPORT iwrc iwkv_close(IWKV *iwkvp);

IW_EXPORT iwrc iwkv_put(IWDB db, const IWKV_val *key, const IWKV_val *val, iwkv_opflags opflags);

IW_EXPORT iwrc iwkv_get(IWDB db, const IWKV_val *key, IWKV_val *oval);

IW_EXPORT iwrc iwkv_del(IWDB db, const IWKV_val *key);

IW_EXPORT void iwkv_val_dispose(IWKV_val *kval);

IW_EXPORT void iwkv_kv_dispose(IWKV_val *key, IWKV_val *val);

IW_EXPORT WUR iwrc iwkv_cursor_open(IWDB db,
                                    IWKV_cursor *cur,
                                    IWKV_cursor_op op,
                                    const IWKV_val *key,
                                    bool pessimistic_write);

IW_EXPORT WUR iwrc iwkv_cursor_to(IWKV_cursor cur, IWKV_cursor_op op);

IW_EXPORT WUR iwrc iwkv_cursor_to_key(IWKV_cursor cur, IWKV_cursor_op op, const IWKV_val *key);

IW_EXPORT iwrc iwkv_cursor_get(IWKV_cursor cur, IWKV_val *okey, IWKV_val *oval);

IW_EXPORT iwrc iwkv_cursor_val(IWKV_cursor cur, IWKV_val *oval);

IW_EXPORT iwrc iwkv_cursor_key(IWKV_cursor cur, IWKV_val *okey);

IW_EXPORT iwrc iwkv_cursor_set(IWKV_cursor cur, IWKV_val *val, iwkv_opflags opflags);

IW_EXPORT iwrc iwkv_cursor_dup_num(const IWKV_cursor cur, uint32_t *onum);

IW_EXPORT iwrc iwkv_cursor_dup_add(IWKV_cursor cur, uint64_t dv);

IW_EXPORT iwrc iwkv_cursor_dup_rm(IWKV_cursor cur, uint64_t dv);

IW_EXPORT iwrc iwkv_cursor_dup_contains(const IWKV_cursor cur, uint64_t dv, bool *out);

IW_EXPORT iwrc iwkv_cursor_dup_iter(const IWKV_cursor cur,
                                    bool(*visitor)(uint64_t dv, void *opaq),
                                    void *opaq,
                                    const uint64_t *start,
                                    bool down);

IW_EXPORT iwrc iwkv_cursor_close(IWKV_cursor *cur);

// Do not print random levels of skiplist blocks
#define IWKVD_PRINT_NO_LEVEVELS 0x1

// Print record values
#define IWKVD_PRINT_VALS 0x2

void iwkvd_db(FILE *f, IWDB db, int flags);

#endif
