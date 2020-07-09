#pragma once
#ifndef MURMUR_H
#define MURMUR_H

/**************************************************************************************************
 * MurmurHash3 was written by Austin Appleby, and is placed in the
 * public domain. The author hereby disclaims copyright to this source
 * code.
 *************************************************************************************************/

#include "basedefs.h"

IW_EXTERN_C_START

IW_EXPORT void murmur3_set_seed(const uint32_t seed);

IW_EXPORT uint32_t murmur3(const char *key, size_t len);

IW_EXTERN_C_END

#endif
