#pragma once
#ifndef IWRDB_H
#define IWRDB_H

#include "basedefs.h"
#include <stdio.h>

IW_EXTERN_C_START

typedef uint8_t iwrdb_oflags_t;
#define IWRDB_NOLOCKS ((iwrdb_oflags_t) 0x01U)

typedef struct _IWRDB*IWRDB;

IW_EXPORT iwrc iwrdb_open(const char *path, iwrdb_oflags_t oflags, size_t bufsz, IWRDB *db);

IW_EXPORT iwrc iwrdb_sync(IWRDB db);

IW_EXPORT iwrc iwrdb_append(IWRDB db, const void *data, int len, uint64_t *oref);

IW_EXPORT iwrc iwrdb_patch(IWRDB db, uint64_t ref, off_t skip, const void *data, int len);

IW_EXPORT iwrc iwrdb_close(IWRDB *db);

IW_EXPORT iwrc iwrdb_read(IWRDB db, uint64_t ref, off_t skip, void *buf, int len, size_t *sp);

IW_EXTERN_C_END
#endif
