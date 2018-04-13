#pragma once
#ifndef IWDLSNR_H
#define IWDLSNR_H

#include "basedefs.h"
#include <unistd.h>
#include <stdbool.h>

IW_EXTERN_C_START

/**
 * @brief File data events listener
 */
typedef struct IWDLSNR {

  /**
   * @brief Write @a val value starting at @a off @a len bytes
   */
  iwrc(*onset)(off_t off, uint8_t val, uint64_t len);

  /**
   * @brief Copy @a len bytes from @a off offset to @a noff offset
   */
  iwrc(*oncopy)(off_t off, uint64_t len, off_t noff);

  /**
   * @brief Write @buf of @a len bytes at @a off
   */
  iwrc(*onwrite)(off_t off, const void *buf, uint64_t len);

  /**
   * @brief File need to be resized.
   *
   * @param osize Old file size
   * @param nsize New file size
   * @param [out] handled File resizing handled by llistener.
   */
  iwrc(*onresize)(uint64_t osize, uint64_t nsize, bool *handled);

  /**
   * @brief File sync successful
   */
  iwrc(*onsynced)(void);

} IWDLSNR;

IW_EXTERN_C_END

#endif // !IWDLSNR_H
