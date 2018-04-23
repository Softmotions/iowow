//
/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2018 Softmotions Ltd <info@softmotions.com>
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
// CMakeLists.txt defines: -D_LARGEFILE_SOURCE=1 -D_FILE_OFFSET_BITS=64
static_assert(sizeof(off_t) == 8, "sizeof(off_t) == 8 bytes");

iwrc iwfs_init(void);
iwrc iwp_init(void);
iwrc iwkv_init(void);

iwrc iw_init(void) {
  iwrc rc;
  static int _iw_initialized = 0;
  if (!__sync_bool_compare_and_swap(&_iw_initialized, 0, 1)) {
    return 0;  // initialized already
  }
  rc = iwlog_init();
  RCGO(rc, finish);

  rc = iwp_init();
  RCGO(rc, finish);

  uint64_t ts;
  rc = iwp_current_time_ms(&ts, false);
  RCRET(rc);
  ts = IW_SWAB64(ts);
  ts >>= 32;
  iwu_rand_seed(ts);

  rc = iwfs_init();
  RCGO(rc, finish);

  rc = iwkv_init();
  RCGO(rc, finish);

finish:
  return rc;
}

const char *iowow_version_full(void) {
  return IOWOW_VERSION;
}

unsigned int iwow_version_major(void) {
  return IOWOW_VERSION_MAJOR;
}

unsigned int iwow_version_minor(void) {
  return IOWOW_VERSION_MINOR;
}

unsigned int iwow_version_patch(void) {
  return IOWOW_VERSION_PATCH;
}

//__attribute__((constructor))
//void lock_constructor() {
//  iwrc rc = iw_init();
//}
