//
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
#include <pthread.h>

#if defined(__linux__)
#include <sys/prctl.h>
#elif defined(__FreeBSD__) || defined(__DragonFly__) || defined(__OpenBSD__)
#include <pthread_np.h>
#include <sys/sysctl.h>
#endif

#ifdef __APPLE__
#include <libproc.h>

#define st_atim st_atimespec
#define st_ctim st_ctimespec
#define st_mtim st_mtimespec
#endif

#define _IW_TIMESPEC2MS(IW_ts) (((IW_ts).tv_sec * 1000ULL) + lround((IW_ts).tv_nsec / 1.0e6))

IW_EXPORT iwrc iwp_clock_get_time(int clock_id, struct timespec *t) {
#if (defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && __MAC_OS_X_VERSION_MAX_ALLOWED < 101200)
  struct timeval now;
  int rci = gettimeofday(&now, NULL);
  if (rci) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
  t->tv_sec = now.tv_sec;
  t->tv_nsec = now.tv_usec * 1000ULL;
#else
  int rci = clock_gettime(clock_id, t);
  if (rci) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
#endif
  return 0;
}

iwrc iwp_current_time_ms(uint64_t *time, bool monotonic) {
  struct timespec spec;
#ifdef IW_HAVE_CLOCK_MONOTONIC
  iwrc rc = iwp_clock_get_time(monotonic ? CLOCK_MONOTONIC : CLOCK_REALTIME, &spec);
#else
  iwrc rc = iwp_clock_get_time(CLOCK_REALTIME, &spec);
#endif
  if (rc) {
    *time = 0;
    return rc;
  }
  *time = _IW_TIMESPEC2MS(spec);
  return 0;
}

static iwrc _iwp_fstat(const char *path, HANDLE fd, IWP_FILE_STAT *fs) {
  assert(fs);
  iwrc rc = 0;
  struct stat st = { 0 };
  memset(fs, 0, sizeof(*fs));
  if (path) {
    if (stat(path, &st)) {
      return (errno == ENOENT) ? IW_ERROR_NOT_EXISTS : iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    }
  } else {
    if (fstat(fd, &st)) {
      return (errno == ENOENT) ? IW_ERROR_NOT_EXISTS : iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    }
  }
  fs->atime = _IW_TIMESPEC2MS(st.st_atim);
  fs->mtime = _IW_TIMESPEC2MS(st.st_mtim);
  fs->ctime = _IW_TIMESPEC2MS(st.st_ctim);
  fs->size = (uint64_t) st.st_size;

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

iwrc iwp_flock(HANDLE fh, iwp_lockmode lmode) {
  if (INVALIDHANDLE(fh)) {
    return IW_ERROR_INVALID_HANDLE;
  }
  if (lmode == IWP_NOLOCK) {
    return 0;
  }
  struct flock lock = { .l_type = (lmode & IWP_WLOCK) ? F_WRLCK : F_RDLCK, .l_whence = SEEK_SET };
  while (fcntl(fh, (lmode & IWP_NBLOCK) ? F_SETLK : F_SETLKW, &lock) == -1) {
    if (errno != EINTR) {
      return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    }
  }
  return 0;
}

iwrc iwp_unlock(HANDLE fh) {
  if (INVALIDHANDLE(fh)) {
    return IW_ERROR_INVALID_HANDLE;
  }
  struct flock lock = { .l_type = F_UNLCK, .l_whence = SEEK_SET };
  while (fcntl(fh, F_SETLKW, &lock) == -1) {
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
  ssize_t rci;

again:
  rci = pread(fh, buf, siz, off);
  if (rci < 0) {
    *sp = 0;
    if (errno == EINTR) {
      goto again;
    } else if (errno == EWOULDBLOCK || errno == IW_ERROR_AGAIN) {
      return IW_ERROR_AGAIN;
    }
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
  *sp = rci;
  return 0;
}

iwrc iwp_read(HANDLE fh, void *buf, size_t count, size_t *sp) {
  ssize_t rs;

again:
  rs = read(fh, buf, count);
  if (rs < 0) {
    *sp = 0;
    if (errno == EINTR) {
      goto again;
    } else if (errno == EWOULDBLOCK || errno == EAGAIN) {
      return IW_ERROR_AGAIN;
    }
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
  *sp = rs;
  return 0;
}

iwrc iwp_pwrite(HANDLE fh, off_t off, const void *buf, size_t siz, size_t *sp) {
  ssize_t ws;

again:
  ws = pwrite(fh, buf, siz, off);
  if (ws < 0) {
    *sp = 0;
    if (errno == EINTR) {
      goto again;
    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return IW_ERROR_AGAIN;
    }
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
  *sp = ws;
  return 0;
}

iwrc iwp_write(HANDLE fh, const void *buf, size_t size) {
  const char *rp = buf;
  do {
    ssize_t wb = write(fh, rp, size);
    if (wb < 0) {
      if (errno == EINTR) {
        continue;
      } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return IW_ERROR_AGAIN;
      }
      return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    } else {
      rp += wb;
      size -= wb;
    }
  } while (size > 0);
  return 0;
}

iwrc iwp_lseek(HANDLE fh, off_t offset, iwp_seek_origin origin, off_t *pos) {
  if (pos) {
    *pos = 0;
  }
  if (INVALIDHANDLE(fh)) {
    return IW_ERROR_INVALID_HANDLE;
  }
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

size_t iwp_page_size(void) {
  static long int _iwp_pagesize = 0;
  if (!_iwp_pagesize) {
    _iwp_pagesize = sysconf(_SC_PAGESIZE);
  }
  return (size_t) _iwp_pagesize;
}

size_t iwp_alloc_unit(void) {
  return iwp_page_size();
}

iwrc iwp_ftruncate(HANDLE fh, off_t len) {
  int rci = ftruncate(fh, len);
  return !rci ? 0 : iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
}

iwrc iwp_fallocate(HANDLE fh, off_t len) {
#if defined(__APPLE__)
  fstore_t fstore = {
    .fst_flags   = F_ALLOCATECONTIG,
    .fst_posmode = F_PEOFPOSMODE,
    .fst_length  = len
  };
  fcntl(fh, F_PREALLOCATE, &fstore);
#endif
  int rci = ftruncate(fh, len);
  return !rci ? 0 : iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
}

iwrc iwp_sleep(uint64_t ms) {
  iwrc rc = 0;
  struct timespec req;
  req.tv_sec = ms / 1000UL;
  req.tv_nsec = (ms % 1000UL) * 1000UL * 1000UL;
again:
  if (nanosleep(&req, NULL) == -1) {
    if (errno == EINTR) {
      goto again;
    }
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

iwrc iwp_exec_path(char *opath, size_t opath_maxlen) {
 #if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
  const int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1 };
  if (sysctl(mib, 4, opath, &opath_maxlen, 0, 0) < 0) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
  return 0;
 #elif defined(__linux__)
  char *path = "/proc/self/exe";
  ssize_t ret = readlink(path, opath, opath_maxlen);
  if (ret == -1) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  } else if (ret < opath_maxlen) {
    opath[ret] = '\0';
  } else if (opath_maxlen > 0) {
    opath[opath_maxlen - 1] = '\0';
  }
  return 0;
#elif defined(__APPLE__)
  pid_t pid = getpid();
  int ret = proc_pidpath(pid, opath, opath_maxlen);
  if (ret < 0) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
#else
  // TODO:
  return IW_ERROR_NOT_IMPLEMENTED;
#endif
}

uint16_t iwp_num_cpu_cores(void) {
  long res = sysconf(_SC_NPROCESSORS_ONLN);
  return (uint16_t) (res > 0 ? res : 1);
}

iwrc iwp_fsync(HANDLE fh) {
  int rci = fsync(fh);
  return rci ? iwrc_set_errno(IW_ERROR_IO_ERRNO, errno) : 0;
}

iwrc iwp_fdatasync(HANDLE fh) {
#ifdef __APPLE__
  if (fcntl(fh, F_FULLFSYNC) == -1) {
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
#else
  if (fdatasync(fh) == -1) {
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
#endif
  return 0;
}

size_t iwp_tmpdir(char *out, size_t len) {
  const char *tdir;
#ifdef IW_TMPDIR
  tdir = IW_TMPDIR;
#else
  tdir = getenv("TMPDIR");
  if (!tdir) {
  #ifdef P_tmpdir
    tdir = P_tmpdir;
  #else
    tdir = "/tmp";
  #endif
  }
#endif
  size_t tlen = strlen(tdir);
  size_t nw = MIN(len, tlen);
  memcpy(out, tdir, nw);
  return nw;
}

void iwp_set_current_thread_name(const char *name) {
#if (defined(__APPLE__) && defined(__MACH__)) || defined(__linux__)
  // On linux and OS X the name may not be longer than 16 bytes, including
  // the null terminator. Truncate the name to 15 characters.
  char buf[16];
  strncpy(buf, name, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';
  name = buf;
#endif

#if defined(__linux__)
  prctl(PR_SET_NAME, name);
#elif defined(__NetBSD__)
  rv = pthread_setname_np(pthread_self(), "%s", (void*) name);
#elif defined(__APPLE__)
  pthread_setname_np(name);
#else
  pthread_setname_np(pthread_self(), name);
#endif
}

static iwrc _iwp_init_impl(void) {
  iwp_page_size(); // init statics
  return 0;
}
