// clang-format off
/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2017 Softmotions Ltd <info@softmotions.com>
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
// clang-format on

#include "platform/iwp.h"
#include "log/iwlog.h"
#include "iwcfg.h"

#include <time.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#define _IW_TIMESPEC2MS(IW_ts) ((IW_ts).tv_sec * 1000) + (uint64_t) round((IW_ts).tv_nsec / 1.0e6)

iwrc iwp_current_time_ms(int64_t *time) {
  struct timespec spec;
  if (clock_gettime(CLOCK_REALTIME, &spec) < 0) {
    *time = 0;
    return IW_ERROR_ERRNO;
  }
  *time = _IW_TIMESPEC2MS(spec);
  return 0;
}

IW_EXPORT iwrc iwp_fstat(const char *path, IWP_FILE_STAT *fstat) {
  assert(path);
  assert(fstat);
  iwrc rc = 0;
  struct stat st = {0};
  
  memset(fstat, 0, sizeof(*fstat));
  if (stat(path, &st)) {
    return (errno == ENOENT) ? IW_ERROR_NOT_EXISTS : IW_ERROR_IO_ERRNO;
  }
  
  fstat->atime = _IW_TIMESPEC2MS(st.st_atim);
  fstat->mtime = _IW_TIMESPEC2MS(st.st_mtim);
  fstat->ctime = _IW_TIMESPEC2MS(st.st_ctim);
  fstat->size = st.st_size;
  
  if (S_ISREG(st.st_mode)) {
    fstat->ftype = IWP_TYPE_FILE;
  } else if (S_ISDIR(st.st_mode)) {
    fstat->ftype = IWP_TYPE_DIR;
  } else if (S_ISLNK(st.st_mode)) {
    fstat->ftype = IWP_LINK;
  } else {
    fstat->ftype = IWP_OTHER;
  }
  return rc;
}

iwrc iwp_flock(HANDLE fd, iwp_lockmode lmode) {
  assert(!INVALIDHANDLE(fd));
  if (lmode == IWP_NOLOCK) {
    return 0;
  }
  struct flock lock = {.l_type = (lmode & IWP_WLOCK) ? F_WRLCK : F_RDLCK, .l_whence = SEEK_SET};
  while (fcntl(fd, (lmode & IWP_NBLOCK) ? F_SETLK : F_SETLKW, &lock) == -1) {
    if (errno != EINTR) {
      return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    }
  }
  return 0;
}

iwrc iwp_unlock(HANDLE fd) {
  assert(!INVALIDHANDLE(fd));
  struct flock lock = {.l_type = F_UNLCK, .l_whence = SEEK_SET};
  while (fcntl(fd, F_SETLKW, &lock) == -1) {
    if (errno != EINTR) {
      return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    }
  }
  return 0;
}

iwrc iwp_closefh(HANDLE fh) {
  if (INVALIDHANDLE(fh)) {
    return 0;
  }
  if (close(fh) == -1) {
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
  return 0;
}

iwrc iwp_read(HANDLE fh, off_t off, void *buf, size_t siz, size_t *sp) {
  assert(buf && sp);
  ssize_t rs = pread(fh, buf, siz, off);
  if (rs == -1) {
    *sp = 0;
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  } else {
    *sp = rs;
    return 0;
  }
}

iwrc iwp_write(HANDLE fh, off_t off, const void *buf, size_t siz, size_t *sp) {
  assert(buf && sp);
  ssize_t ws = pwrite(fh, buf, siz, off);
  if (ws == -1) {
    *sp = 0;
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  } else {
    *sp = ws;
    return 0;
  }
}

size_t iwp_page_size(void) {
  static off_t _iwp_pagesize = 0;
  if (!_iwp_pagesize) {
    _iwp_pagesize = sysconf(_SC_PAGESIZE);
  }
  return _iwp_pagesize;
}

iwrc iwp_ftruncate(HANDLE fh, off_t len) {
  int rv = ftruncate(fh, len);
  return !rv ? 0 : iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
}

iwrc iwp_sleep(uint64_t ms) {
  iwrc rc = 0;
  struct timespec req;
  req.tv_sec = ms / 1000UL;
  req.tv_nsec = (ms % 1000UL) * 1000UL * 1000UL;
  if (nanosleep(&req, NULL)) {
    rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, errno);
  }
  return rc;
}
