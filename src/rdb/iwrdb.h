#pragma once
#ifndef IWRDB_H
#define IWRDB_H

#include "basedefs.h"

IW_EXTERN_C_START;

typedef uint8_t iwrdb_oflags_t;
#define IWRDB_NOLOCKS ((iwrdb_oflags_t) 0x01U)

typedef struct iwrdb*IWRDB;

IW_EXPORT iwrc iwrdb_open(const char *path, iwrdb_oflags_t oflags, size_t bufsz, struct iwrdb **open);

IW_EXPORT iwrc iwrdb_sync(struct iwrdb *db);

IW_EXPORT iwrc iwrdb_append(struct iwrdb *db, const void *data, int len, uint64_t *oref);

IW_EXPORT iwrc iwrdb_patch(struct iwrdb *db, uint64_t ref, off_t skip, const void *data, int len);

IW_EXPORT iwrc iwrdb_close(struct iwrdb **db, bool no_sync);

IW_EXPORT iwrc iwrdb_read(struct iwrdb *db, uint64_t ref, off_t skip, void *buf, int len);

IW_EXPORT HANDLE iwrdb_file_handle(struct iwrdb *db);

/// Returns logical data end offset including internal cache buffer.
/// Returns `-1` int the case of error.
IW_EXPORT off_t iwrdb_offset_end(struct iwrdb *db);

IW_EXPORT uint8_t* iwrdb_mmap(struct iwrdb *db, bool readonly, int madv, size_t *msiz);

IW_EXPORT void iwrdb_munmap(struct iwrdb *db);

IW_EXTERN_C_END;
#endif
