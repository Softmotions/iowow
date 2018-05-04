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
#include "platform/iwp.h"
#include "utils/iwutils.h"


#include <time.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <ftw.h>

#ifdef __APPLE__
#define st_atim st_atimespec
#define st_ctim st_ctimespec
#define st_mtim st_mtimespec
#endif

#define _IW_TIMESPEC2MS(IW_ts) ((IW_ts).tv_sec * 1000) + (uint64_t) round((IW_ts).tv_nsec / 1.0e6)

iwrc iwp_current_time_ms(uint64_t *time, bool monotonic) {
  struct timespec spec;
  
#ifdef IW_HAVE_CLOCK_MONOTONIC
  clockid_t clockid = monotonic ? CLOCK_MONOTONIC : CLOCK_REALTIME;
#else
  clockid_t clockid = CLOCK_REALTIME;
#endif
  if (clock_gettime(clockid, &spec) < 0) {
    *time = 0;
    return IW_ERROR_ERRNO;
  }
  *time = _IW_TIMESPEC2MS(spec);
  return 0;
}

static iwrc _iwp_fstat(const char *path, HANDLE fd, IWP_FILE_STAT *fs) {
  assert(fs);
  iwrc rc = 0;
  struct stat st = {0};
  memset(fs, 0, sizeof(*fs));
  if (path) {
    if (stat(path, &st)) {
      return (errno == ENOENT) ? IW_ERROR_NOT_EXISTS : IW_ERROR_IO_ERRNO;
    }
  } else {
    if (fstat(fd, &st)) {
      return (errno == ENOENT) ? IW_ERROR_NOT_EXISTS : IW_ERROR_IO_ERRNO;
    }
  }
  fs->atime = _IW_TIMESPEC2MS(st.st_atim);
  fs->mtime = _IW_TIMESPEC2MS(st.st_mtim);
  fs->ctime = _IW_TIMESPEC2MS(st.st_ctim);
  fs->size = st.st_size;
  
  if (S_ISREG(st.st_mode)) {
    fs->ftype = IWP_TYPE_FILE;
  } else if (S_ISDIR(st.st_mode)) {
    fs->ftype = IWP_TYPE_DIR;
  } else if (S_ISLNK(st.st_mode)) {
    fs->ftype = IWP_LINK;
  } else {
    fs->ftype = IWP_OTHER;
  }
  return rc;
}

iwrc iwp_fstat(const char *path, IWP_FILE_STAT *fs) {
  return _iwp_fstat(path, 0, fs);
}

iwrc iwp_fstath(HANDLE fh, IWP_FILE_STAT *fs) {
  return _iwp_fstat(0, fh, fs);
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

iwrc iwp_pread(HANDLE fh, off_t off, void *buf, size_t siz, size_t *sp) {
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

iwrc iwp_pwrite(HANDLE fh, off_t off, const void *buf, size_t siz, size_t *sp) {
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

iwrc iwp_write(HANDLE fh, const void *buf, size_t size) {
  do {
    const char *rp = buf;
    int wb = write(fh, rp, size);
    switch (wb) {
      case -1:
        if (errno != EINTR) {
          return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
        }
      case 0:
        break;
      default:
        rp += wb;
        size -= wb;
        break;
    }
  } while (size > 0);
  return 0;
}

iwrc iwp_lseek(HANDLE fh, off_t offset, iwp_seek_origin origin, off_t *pos) {
  int whence = SEEK_SET;
  if (origin == IWP_SEEK_CUR) {
    whence = SEEK_CUR;
  } else if (origin == IWP_SEEK_END) {
    whence = SEEK_END;
  }
  off_t off = lseek(fh, offset, whence);
  if (off < 0) {
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  } else {
    if (pos) {
      *pos = off;
    }
    return 0;
  }
}

iwrc iwp_copy_bytes(HANDLE fh, off_t off, size_t siz, off_t noff) {
  int overlap = IW_RANGES_OVERLAP(off, off + siz, noff, noff + siz);
  size_t sp, sp2;
  iwrc rc = 0;
  off_t pos = 0;
  uint8_t buf[4096];
  if (overlap && noff > off) {
    // todo resolve it!!
    return IW_ERROR_OVERFLOW;
  }
#ifndef __APPLE__
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
#ifndef __APPLE__
  if (siz > sizeof(buf)) {
    posix_fadvise(fh, off, siz, POSIX_FADV_NORMAL);
  }
#endif
  return rc;
}

size_t iwp_page_size(void) {
  static off_t _iwp_pagesize = 0;
  if (!_iwp_pagesize) {
    _iwp_pagesize = sysconf(_SC_PAGESIZE);
  }
  return _iwp_pagesize;
}

iwrc iwp_ftruncate(HANDLE fh, off_t len) {
  int rci = ftruncate(fh, len);
  return !rci ? 0 : iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
}

iwrc iwp_fallocate(HANDLE fh, off_t len) {
#ifndef __APPLE__
  int rci = posix_fallocate(fh, 0, len);
  return !rci ? 0 : iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
#else
  fstore_t fstore = {
    .fst_flags = F_ALLOCATECONTIG,
    .fst_posmode = F_PEOFPOSMODE,
    .fst_length = len
  };
  fcntl(fh, F_PREALLOCATE, &fstore);
  int rci = ftruncate(fh, len);
  return !rci ? 0 : iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
#endif
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


static int _rmfile(const char *pathname, const struct stat *sbuf, int type, struct FTW *ftwb) {
  if (remove(pathname) < 0) {
    perror(pathname);
    return -1;
  }
  return 0;
}

iwrc iwp_removedir(const char *path) {
  if (nftw(path, _rmfile, 10, FTW_DEPTH | FTW_MOUNT | FTW_PHYS) < 0) {
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
  return 0;
}

iwrc iwp_exec_path(char *opath) {
  pid_t pid;
  char path[MAXPATHLEN];
  char epath[MAXPATHLEN];
  
  memset(epath, 0, sizeof(epath));
  pid = getpid();
  sprintf(path, "/proc/%d/exe", pid);
  if (readlink(path, epath, MAXPATHLEN - 1) == -1) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  } else {
    strncpy(opath, epath, MAXPATHLEN);
  }
  return 0;
}

uint16_t iwp_num_cpu_cores() {
  long res = sysconf(_SC_NPROCESSORS_ONLN);
  return res > 0 ? res : 1;
}

iwrc iwp_fsync(HANDLE fh) {
  int rci = fsync(fh);
  return rci ? iwrc_set_errno(IW_ERROR_IO_ERRNO, errno) : 0;
}

iwrc iwp_fdatasync(HANDLE fh) {
  int rci = fdatasync(fh);
  return rci ? iwrc_set_errno(IW_ERROR_IO_ERRNO, errno) : 0;
}
