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


#include "log/iwlog.h"
#include "platform/iwp.h"
#include "utils/iwutils.h"
#include "utils/iwuuid.h"
#include "utils/iwxstr.h"

#if defined(_WIN32)
#include <direct.h>
#endif

#include <libgen.h>
#include <string.h>

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

char* iwp_allocate_tmpfile_path2(const char *prefix, const char *tmpdir) {
  size_t tlen;
  char path[PATH_MAX + 1];
  size_t plen = prefix ? strlen(prefix) : 0;

  if (tmpdir && *tmpdir != '\0') {
    tlen = strlen(tmpdir);
  } else {
    tlen = iwp_tmpdir(path, sizeof(path));
    tmpdir = path;
  }

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

char* iwp_allocate_tmpfile_path(const char *prefix) {
  return iwp_allocate_tmpfile_path2(prefix, 0);
}

IW_ALLOC char* iwp_path_join(const char *parent, const char *path) {
  if (!path) {
    return 0;
  }
  if (!parent || *parent == '\0' || *path == '\0') {
    return strdup(path);
  }
  int len = strlen(parent);
  while (len > 0 && parent[len - 1] == IW_PATH_CHR) {
    --len;
  }
  if (!len) {
    return strdup(path);
  }
  const char *rp = path;
  while (*rp == IW_PATH_CHR) {
    ++rp;
  }
  return iwxstr_printf_alloc("%.*s" IW_PATH_STR "%s", len, parent, rp);
}

char* iwp_dirname(char *path) {
  return dirname(path);
}

char* iwp_basename(char *path) {
  size_t i;
  if (!path || !*path) {
    return ".";
  }
  i = strlen(path) - 1;
#ifdef _WIN32
  for ( ; i && (path[i] == '/' || path[i] == '\\'); i--) path[i] = 0;
  for ( ; i && (path[i - 1] != '/' && path[i - 1] != '\\'); i--) ;
 #else
  for ( ; i && path[i] == '/'; i--) path[i] = 0;
  for ( ; i && path[i - 1] != '/'; i--) ;
 #endif
  return path + i;
}

iwrc iwp_mkdirs(const char *path) {
  /* Adapted from http://stackoverflow.com/a/2336245/119527 */
  iwrc rc = 0;
  const size_t len = strlen(path);
  char buf[PATH_MAX + 1];
  char *p, *ppath = buf;

  errno = 0;
  /* Copy string so its mutable */
  if (len >= sizeof(buf)) {
    ppath = malloc(len + 1);
    if (!ppath) {
      return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
  }
  memcpy(ppath, path, len + 1);

  /* Iterate the string */
  for (p = ppath + 1; *p; p++) {
#ifdef _WIN32
    if (*p == '/' || *p == '\\') {
#else
    if (*p == '/') {
#endif
      /* Temporarily truncate */
      *p = '\0';
      #if (defined(_WIN32) || defined(__WIN32__))
      if (_mkdir(ppath) != 0) {
      #else
      if (mkdir(ppath, S_IRWXU) != 0) {
      #endif
        if (errno != EEXIST) {
          rc = iwrc_set_errno(IW_ERROR_ERRNO, errno);
          goto finish;
        }
      }
      *p = '/';
    }
  }
  #if (defined(_WIN32) || defined(__WIN32__))
  if (_mkdir(ppath) != 0) {
  #else
  if (mkdir(ppath, S_IRWXU) != 0) {
  #endif
    if (errno != EEXIST) {
      rc = iwrc_set_errno(IW_ERROR_ERRNO, errno);
      goto finish;
    }
  }

finish:
  if (ppath != buf) {
    free(ppath);
  }
  return rc;
}

iwrc iwp_mkdirs_for_file(const char *path) {
  char buf[PATH_MAX + 1];
  char *ppath = buf;
  const size_t len = strlen(path);
  if (len >= sizeof(buf)) {
    ppath = malloc(len + 1);
    if (!ppath) {
      return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
  }
  memcpy(ppath, path, len + 1);
  iwp_dirname(ppath);
  iwrc rc = iwp_mkdirs(ppath);
  if (ppath != buf) {
    free(ppath);
  }
  return rc;
}

iwrc iwp_init(void) {
  iwcpuflags = x86_simd();
  _iwp_init_impl();
  return 0;
}

iwrc iwp_copy_file(const char *src, const char *dst) {
  iwrc rc = 0;
  char buf[8192];
  FILE *sf = fopen(src, "rb");
  if (!sf) {
    return errno;
  }
  FILE *df = fopen(dst, "wb");
  if (!df) {
    rc = errno;
    fclose(sf);
    return rc;
  }
  size_t nr = 0;
  while (1) {
    nr = fread(buf, 1, sizeof(buf), sf);
    if (nr) {
      nr = fwrite(buf, 1, nr, df);
      if (!nr) {
        rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
        break;
      }
    } else if (feof(sf)) {
      break;
    } else if (ferror(sf)) {
      rc = IW_ERROR_IO;
      break;
    }
  }
  fclose(sf);
  fclose(df);
  return rc;
}

iwrc iwp_rename_file(const char *src, const char *dst) {
  if (rename(src, dst) == -1) {
    if (errno == EXDEV) {
      int rc = iwp_copy_file(src, dst);
      if (!rc) {
        unlink(src);
      }
      return rc;
    } else {
      return errno;
    }
  }
  return 0;
}
