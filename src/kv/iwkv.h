#pragma once
#ifndef IWKV_H
#define IWKV_H

#include "iowow.h"
#include "iwfile.h"
#include <stddef.h>

typedef enum {
  _IWKV_ERROR_START = (IW_ERROR_START + 5000UL),
  IWKV_ERROR_NOTFOUND,  /**< Key not found (IWKV_ERROR_NOTFOUND) */
  IWKV_ERROR_MAXKVSZ,   /**< Size of Key+value must be lesser than 0xfffffff bytes (IWKV_ERROR_MAXKVSZ) */
  IWKV_ERROR_CORRUPTED, /**< Database file invalid or corrupted (IWKV_ERROR_CORRUPTED) */
  _IWKV_ERROR_KVBLOCK_FULL,
  _IWKV_ERROR_END
} iwkv_ecode;

typedef enum {
  IWKV_NOLOCKS  = 0x01U,  /**< Do not use any threading locks */
  IWKV_RDONLY   = 0x02U,  /**< Open storage in read-only mode */
  IWKV_TRUNC    = 0x04U   /**< Truncate database file on open */
} iwkv_openflags;

typedef enum {
  IWKV_OVERWRITE = 1
} iwkv_putflags;

struct IWKV;
typedef struct IWKV *IWKV;

typedef struct IWKV_OPTS {
  char *path;
  iwkv_openflags oflags;
} IWKV_OPTS;

typedef struct IWKV_val {
  size_t  size;
  void  *data;
} IWKV_val;

IW_EXPORT WUR iwrc iwkv_init(void);

IW_EXPORT WUR iwrc iwkv_open(IWKV_OPTS *opts, IWKV *iwkvp);

IW_EXPORT iwrc iwkv_close(IWKV *iwkvp);

IW_EXPORT iwrc iwkv_put(IWKV iwkv, int ns, IWKV_val *key, IWKV_val *val, iwkv_putflags flags);

IW_EXPORT iwrc iwkv_get(IWKV iwkv, int ns, IWKV_val *key, IWKV_val *oval);

IW_EXPORT iwrc iwkv_del(IWKV iwkv, int ns, IWKV_val *key);

IW_EXPORT void iwkv_disposekv(IWKV_val *key, IWKV_val *val);

#endif
