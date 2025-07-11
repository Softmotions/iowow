//
/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2024 Softmotions Ltd <info@softmotions.com>
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


#include "iwcfg.h"
#include "log/iwlog.h"
#include "iwutils.h"
#include "iwp.h"

// Hardcoded requirements (fixme)
static_assert(sizeof(off_t) == 8, "sizeof(off_t) == 8 bytes");

iwrc iwfs_init(void);
iwrc iwkv_init(void);
iwrc jbl_init(void);

iwrc iw_init(void) {
  iwrc rc;
  static int _iw_initialized = 0;
  if (!__sync_bool_compare_and_swap(&_iw_initialized, 0, 1)) {
    return 0;  // initialized already
  }
  RCC(rc, finish, iwlog_init());
  RCC(rc, finish, iwu_init());
  RCC(rc, finish, iwp_init());
  RCC(rc, finish, jbl_init());

  uint64_t ts;
  RCC(rc, finish, iwp_current_time_ms(&ts, false));
  ts = IW_SWAB64(ts);
  ts >>= 32;
  iwu_rand_seed(ts);

  RCC(rc, finish, iwfs_init());
  RCC(rc, finish, iwkv_init());

finish:
  return rc;
}

const char* iowow_version_full(void) {
  return IOWOW_VERSION;
}

unsigned int iowow_version_major(void) {
  return IOWOW_VERSION_MAJOR;
}

unsigned int iowow_version_minor(void) {
  return IOWOW_VERSION_MINOR;
}

unsigned int iowow_version_patch(void) {
  return IOWOW_VERSION_PATCH;
}
