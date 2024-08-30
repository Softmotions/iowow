#pragma once
#ifndef IWDLSNR_H
#define IWDLSNR_H

#include "basedefs.h"
#include <stdbool.h>

IW_EXTERN_C_START;

/**
 * @brief File data events listener.
 */
struct iwdlsnr {
  /**
   * @brief Before file open event.
   *
   * @param path File path
   * @param mode File open mode same as in open(2)
   */
  iwrc (*onopen)(struct iwdlsnr *self, const char *path, int mode);

  /**
   * @brief Before file been closed.
   */
  iwrc (*onclosing)(struct iwdlsnr *self);

  /**
   * @brief Write @a val value starting at @a off @a len bytes
   */
  iwrc (*onset)(struct iwdlsnr *self, off_t off, uint8_t val, off_t len, int flags);

  /**
   * @brief Copy @a len bytes from @a off offset to @a noff offset
   */
  iwrc (*oncopy)(struct iwdlsnr *self, off_t off, off_t len, off_t noff, int flags);

  /**
   * @brief Write @buf of @a len bytes at @a off
   */
  iwrc (*onwrite)(struct iwdlsnr *self, off_t off, const void *buf, off_t len, int flags);

  /**
   * @brief File need to be resized.
   *
   * @param osize Old file size
   * @param nsize New file size
   * @param [out] handled File resizing handled by llistener.
   */
  iwrc (*onresize)(struct iwdlsnr *self, off_t osize, off_t nsize, int flags, bool *handled);

  /**
   * @brief File sync successful
   */
  iwrc (*onsynced)(struct iwdlsnr *self, int flags);
};

typedef struct iwdlsnr IWDLSNR;

IW_EXTERN_C_END;

#endif // !IWDLSNR_H
