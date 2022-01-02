#pragma once
#ifndef IWAL_H
#define IWAL_H

/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2022 Softmotions Ltd <info@softmotions.com>
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
 *  @brief Write Ahead Logging (WAL) module.
 */
#include "iwkv.h"
#include "iwfsmfile.h"

IW_EXTERN_C_START

typedef enum {
  WOP_SET = 1,
  WOP_COPY,
  WOP_WRITE,
  WOP_RESIZE,
  WOP_FIXPOINT,
  WOP_RESET,
  WOP_SEP = 127, /**< WAL file separator */
} wop_t;

#pragma pack(push, 1)
typedef struct WBSEP {
  uint8_t  id;
  uint8_t  pad[3];
  uint32_t crc;
  uint32_t len;
} WBSEP;

typedef struct WBRESET {
  uint8_t id;
  uint8_t pad[3];
} WBRESET;

typedef struct WBSET {
  uint8_t  id;
  uint8_t  pad[3];
  uint32_t val;
  off_t    off;
  off_t    len;
} WBSET;

typedef struct WBCOPY {
  uint8_t id;
  uint8_t pad[3];
  off_t   off;
  off_t   len;
  off_t   noff;
} WBCOPY;

typedef struct WBWRITE {
  uint8_t  id;
  uint8_t  pad[3];
  uint32_t crc;
  uint32_t len;
  off_t    off;
} WBWRITE;

typedef struct WBRESIZE {
  uint8_t id;
  uint8_t pad[3];
  off_t   osize;
  off_t   nsize;
} WBRESIZE;

typedef struct WBFIXPOINT {
  uint8_t  id;
  uint8_t  pad[3];
  uint64_t ts;
} WBFIXPOINT;
#pragma pack(pop)

iwrc iwal_create(IWKV iwkv, const IWKV_OPTS *opts, IWFS_FSM_OPTS *fsmopts, bool recover_backup);

iwrc iwal_sync(IWKV iwkv);

iwrc iwal_poke_checkpoint(IWKV iwkv, bool force);

iwrc iwal_poke_savepoint(IWKV iwkv);

iwrc iwal_savepoint_exl(IWKV iwkv, bool sync);

void iwal_shutdown(IWKV iwkv);

bool iwal_synched(IWKV iwkv);

iwrc iwal_online_backup(IWKV iwkv, uint64_t *ts, const char *target_file);

IW_EXTERN_C_END
#endif
