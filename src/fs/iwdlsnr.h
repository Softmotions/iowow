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
   * @brief Write @a len bytes at @a off, given its previous content in @a old.
   *
   * Optional. Allows the listener to log only the bytes that actually changed
   * between @a old and @a new. When not set, callers must use `onwrite`.
   *
   * @param off Region offset
   * @param old Previous content of the region (@a len bytes)
   * @param new Current content of the region (@a len bytes)
   * @param len Region length
   */
  iwrc (*onwrite_diff)(struct iwdlsnr *self, off_t off, const uint8_t *old, const uint8_t *new, off_t len, int flags);

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


IW_EXTERN_C_END;

#endif // !IWDLSNR_H
