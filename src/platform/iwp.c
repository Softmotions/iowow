//
/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2021 Softmotions Ltd <info@softmotions.com>
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


#include "log/iwlog.h"
#include "platform/iwp.h"
#include "utils/iwutils.h"
#include "utils/iwuuid.h"
#include <stdio.h>

#if (defined(_WIN32) || defined(__WIN32__))
#include <direct.h>
#endif

unsigned int iwcpuflags = 0;
static iwrc _iwp_init_impl(void);

#if defined(__linux) || defined(__unix) || defined(__APPLE__)
#include "unix/unix.c"
#elif defined(_WIN32)
#include "win32/win32.c"
#else
#error Unsupported platform
#endif

// Thanks to https://attractivechaos.wordpress.com/2017/09/04/on-cpu-dispatch
static unsigned int x86_simd(void) {

#if defined(__i386__) || defined(__amd64__)
  unsigned int eax, ebx, ecx, edx, flag = 0;
# ifdef _MSC_VER
  int cpuid[4];
  __cpuid(cpuid, 1);
  eax = cpuid[0], ebx = cpuid[1], ecx = cpuid[2], edx = cpuid[3];
# else
  __asm volatile ("cpuid" : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx) : "a" (1));
# endif
  if (edx >> 25 & 1) {
    flag |= IWCPU_SSE;
  }
  if (edx >> 26 & 1) {
    flag |= IWCPU_SSE2;
  }
  if (ecx >> 0 & 1) {
    flag |= IWCPU_SSE3;
  }
  if (ecx >> 19 & 1) {
    flag |= IWCPU_SSE4_1;
  }
  if (ecx >> 20 & 1) {
    flag |= IWCPU_SSE4_2;
  }
  if (ecx >> 28 & 1) {
    flag |= IWCPU_AVX;
  }
  if (ebx >> 5 & 1) {
    flag |= IWCPU_AVX2;
  }
  if (ebx >> 16 & 1) {
    flag |= IWCPU_AVX512F;
  }
  return flag;
#else
  return 0;
#endif
}

iwrc iwp_copy_bytes(HANDLE fh, off_t off, size_t siz, off_t noff) {
  if (INVALIDHANDLE(fh)) {
    return IW_ERROR_INVALID_HANDLE;
  }
  int overlap = IW_RANGES_OVERLAP(off, off + siz, noff, noff + siz);
  size_t sp, sp2;
  iwrc rc = 0;
  off_t pos = 0;
  uint8_t buf[4096];
  if (overlap && (noff > off)) {
    // todo resolve it!!
    return IW_ERROR_OVERFLOW;
  }
#if !defined(__APPLE__) && !defined(_WIN32)
  if (siz > sizeof(buf)) {
    posix_fadvise(fh, off, siz, POSIX_FADV_SEQUENTIAL);
  }
#endif
  while (pos < siz) {
    rc = iwp_pread(fh, off + pos, buf, MIN(sizeof(buf), (siz - pos)), &sp);
    if (rc || !sp) {
      break;
    } else {
      rc = iwp_pwrite(fh, noff + pos, buf, sp, &sp2);
      pos += sp;
      if (rc) {
        break;
      }
      if (sp != sp2) {
        rc = IW_ERROR_INVALID_STATE;
        break;
      }
    }
  }
#if !defined(__APPLE__) && !defined(_WIN32)
  if (siz > sizeof(buf)) {
    posix_fadvise(fh, off, siz, POSIX_FADV_NORMAL);
  }
#endif
  return rc;
}

char* iwp_allocate_tmpfile_path(const char *prefix) {
  size_t plen = prefix ? strlen(prefix) : 0;
  char tmpdir[PATH_MAX + 1];
  size_t tlen = iwp_tmpdir(tmpdir, sizeof(tmpdir));
  if (!tlen) {
    return 0;
  }
  char *res = malloc(tlen + sizeof(IW_PATH_STR) - 1 + plen + IW_UUID_STR_LEN + 1 /*NULL*/);
  if (!res) {
    return 0;
  }
  char *wp = res;
  memcpy(wp, tmpdir, tlen);
  wp += tlen;
  memcpy(wp, IW_PATH_STR, sizeof(IW_PATH_STR) - 1);
  wp += sizeof(IW_PATH_STR) - 1;
  if (plen && prefix) {
    memcpy(wp, prefix, plen);
    wp += plen;
  }
  iwu_uuid4_fill(wp);
  wp += IW_UUID_STR_LEN;
  *wp = 0;
  return res;
}

iwrc iwp_mkdirs(const char *path) {
  /* Adapted from http://stackoverflow.com/a/2336245/119527 */
  const size_t len = strlen(path);
  char _path[PATH_MAX];
  char *p;

  errno = 0;
  /* Copy string so its mutable */
  if (len > sizeof(_path) - 1) {
    errno = ENAMETOOLONG;
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
  strcpy(_path, path);

  /* Iterate the string */
  for (p = _path + 1; *p; p++) {
    if (*p == '/') {
      /* Temporarily truncate */
      *p = '\0';
      #if (defined(_WIN32) || defined(__WIN32__))
      if (_mkdir(_path) != 0) {
      #else
      if (mkdir(_path, S_IRWXU) != 0) {
      #endif
        if (errno != EEXIST) {
          return iwrc_set_errno(IW_ERROR_ERRNO, errno);
        }
      }
      *p = '/';
    }
  }
  #if (defined(_WIN32) || defined(__WIN32__))
  if (_mkdir(_path) != 0) {
  #else
  if (mkdir(_path, S_IRWXU) != 0) {
  #endif
    if (errno != EEXIST) {
      return iwrc_set_errno(IW_ERROR_ERRNO, errno);
    }
  }
  return 0;
}

iwrc iwp_init(void) {
  iwcpuflags = x86_simd();
  _iwp_init_impl();
  return 0;
}
