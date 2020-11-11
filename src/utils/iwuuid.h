#pragma once
#ifndef IWUUID_H
#define IWUUID_H

#include "basedefs.h"

IW_EXTERN_C_START

#define IW_UUID_STR_LEN 36

/**
 * Creates random UUID v4 string and fill a provided `buf`
 * with capacity of 36 bytes at least.
 * @note Does't write terminating `NULL` byte.
 */
IW_EXPORT void iwu_uuid4_fill(char dest[static IW_UUID_STR_LEN]);

IW_EXPORT bool iwu_uuid_valid(const char *uuid);

IW_EXTERN_C_END

#endif
