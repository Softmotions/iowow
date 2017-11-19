#pragma once
#ifndef IWKV_H
#define IWKV_H

#include "iowow.h"
#include "iwfile.h"
#include <stddef.h>

typedef enum {
  _IWKV_ERROR_START = (IW_ERROR_START + 5000UL),
  IWKV_ERROR_NOTFOUND,   /**< Key not found (IWKV_ERROR_NOTFOUND) */
  IWKV_ERROR_KEY_EXISTS, /**< Key already exists. (IWKV_ERROR_KEY_EXISTS) */  
  IWKV_ERROR_MAXKVSZ,    /**< Size of Key+value must be lesser than 0xfffffff bytes (IWKV_ERROR_MAXKVSZ) */
  IWKV_ERROR_MAXDBSZ,    /**< Database file size reached its maximal limit: 0x3fffffffc0 (IWKV_ERROR_MAXDBSZ) */
  IWKV_ERROR_CORRUPTED,  /**< Database file invalid or corrupted (IWKV_ERROR_CORRUPTED) */
  _IWKV_ERROR_KVBLOCK_FULL,
  _IWKV_ERROR_REQUIRE_WL,
  _IWKV_ERROR_END
} iwkv_ecode;

typedef enum {
  IWKV_NOLOCKS  = 0x01U,  /**< Do not use any threading locks */
  IWKV_RDONLY   = 0x02U,  /**< Open storage in read-only mode */
  IWKV_TRUNC    = 0x04U   /**< Truncate database file on open */
} iwkv_openflags;

typedef enum {
  IWDB_DUP_INT32_VALS = 0x1,  /**< Duplicated uint32 values allowed */
  IWDB_DUP_INT64_VALS = 0x2,  /**< Duplicated uint64 values allowed */
  IWDB_DUP_SORTED = 0x4       /**< Sort duplicated values  */
} iwdb_flags_t;

typedef enum {
  IWKV_NO_OVERWRITE = 0x1
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

IW_EXPORT WUR iwrc iwkv_init(void);

IW_EXPORT WUR iwrc iwkv_open(const IWKV_OPTS *opts, IWKV *iwkvp);

IW_EXPORT WUR iwrc iwkv_db(IWKV iwkv, uint32_t dbid, iwdb_flags_t flags, IWDB *dbp);

IW_EXPORT iwrc iwkv_db_destroy(IWDB* dbp);

IW_EXPORT iwrc iwkv_sync(IWKV iwkv);

IW_EXPORT iwrc iwkv_close(IWKV *iwkvp);

IW_EXPORT iwrc iwkv_put(IWDB db, const IWKV_val *key, const IWKV_val *val, iwkv_opflags opflags);

IW_EXPORT iwrc iwkv_get(IWDB db, const IWKV_val *key, IWKV_val *oval);

IW_EXPORT iwrc iwkv_del(IWDB db, const IWKV_val *key);

IW_EXPORT void iwkv_kv_dispose(IWKV_val *key, IWKV_val *val);

#endif
