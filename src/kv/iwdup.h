#pragma once
#ifndef IWKV_DUP
#define IWKV_DUP

#include "iwkv.h"

#define IWKV_DUP_MAXVNUM_BUFSZ 512

iwrc iwkv_dup_init(const IWKV_val *val, IWKV_val *uval);

size_t iwkv_dup_num(uint8_t *vp, size_t vlen);

iwrc iwkv_dup_update(uint8_t *vp, size_t vlen, iwkv_opflags opflags, IWKV_val *uval);

#endif
