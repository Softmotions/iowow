#pragma once
#ifndef IWKV_H
#define IWKV_H

#include "iowow.h"
#include "iwfile.h"
#include <stddef.h>

typedef enum {
  _IWKV_ERROR_START = (IW_ERROR_START + 5000UL),
  IWKV_ERROR_NOTFOUND,        /**< Key not found (IWKV_ERROR_NOTFOUND) */
  IWKV_ERROR_KEY_EXISTS,      /**< Key already exists. (IWKV_ERROR_KEY_EXISTS) */
  IWKV_ERROR_MAXKVSZ,         /**< Size of Key+value must be lesser than 0xfffffff bytes (IWKV_ERROR_MAXKVSZ) */
  IWKV_ERROR_MAXDBSZ,         /**< Database file size reached its maximal limit: 0x3fffffffc0 (IWKV_ERROR_MAXDBSZ) */
  IWKV_ERROR_CORRUPTED,       /**< Database file invalid or corrupted (IWKV_ERROR_CORRUPTED) */
  IWKV_ERROR_DUP_VALUE_SIZE,  /**< Value size is not compatible for insertion into duplicated key values array (IWKV_ERROR_DUP_VALUE_SIZE) */
  IWKV_ERROR_INCOMPATIBLE_DB_MODE, /**< Incorpatible database open mode (IWKV_ERROR_INCOMPATIBLE_DB_MODE) */
  _IWKV_ERROR_END,
  /* Internal error codes */
  _IWKV_ERROR_KVBLOCK_FULL,
  _IWKV_ERROR_REQUIRE_WL,
  _IWKV_ERROR_REQUIRE_NLEVEL,
  _IWKV_ERROR_REQUIRE_WLOCK,
  _IWKV_ERROR_AGAIN,
  _IWKV_ERROR_ABORT
} iwkv_ecode;

typedef enum {
  IWKV_NOLOCKS  = 1U,      /**< Do not use any threading locks */
  IWKV_RDONLY   = 1U << 1, /**< Open storage in read-only mode */
  IWKV_TRUNC    = 1U << 2  /**< Truncate database file on open */
} iwkv_openflags;

typedef enum {
  IWDB_DUP_INT32_VALS = 1U,      /**< Duplicated uint32 values allowed */
  IWDB_DUP_INT64_VALS = 1U << 1  /**< Duplicated uint64 values allowed */
} iwdb_flags_t;

typedef enum {
  IWKV_NO_OVERWRITE = 1U,       /**< Do not overwrite value for an existing key */
  IWKV_DUP_REMOVE =   1U << 1   /**< Remove value from duplicated values array.
                                     Usable only for IWDB_DUP_X DB flags */
} iwkv_opflags;

struct IWKV;
typedef struct IWKV *IWKV;

struct IWDB;
typedef struct IWDB *IWDB;

typedef struct IWKV_OPTS {
  char *path;
  iwkv_openflags oflags;
} IWKV_OPTS;

typedef struct IWKV_val {
  size_t  size;
  void  *data;
} IWKV_val;

struct IWKV_cursor;
typedef struct IWKV_cursor *IWKV_cursor;

typedef enum IWKV_cursor_op {
  IWKV_FIRST,
  IWKV_FIRST_DUP,
  IWKV_LAST,
  IWKV_LAST_DUP,
  IWKV_NEXT,
  IWKV_NEXT_DUP,
  IWKV_PREV,
  IWKV_PREV_DUP,
  IWKV_SET_EQ,
  IWKV_SET_GE
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

// Do not print random levels of skiplist blocks
#define IWKVD_PRINT_NO_LEVEVELS 0x1

// Print record values
#define IWKVD_PRINT_VALS 0x2

void iwkvd_db(FILE *f, IWDB db, int flags);

#endif
