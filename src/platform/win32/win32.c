#include <io.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "iwcfg.h"

#define _NANOSECONDS_PER_TICK     100ULL
#define _NANOSECONDS_PER_SECOND   1000000000ULL
#define _TICKS_PER_SECOND         10000000ULL
#define _TICKS_PER_MILLISECOND    10000ULL
#define _SEC_TO_UNIX_EPOCH        11644473600ULL
#define _TICKS_TO_UNIX_EPOCH (_TICKS_PER_SECOND * _SEC_TO_UNIX_EPOCH)
#define _TIMESPEC2MS(IW_ts) ((IW_ts).tv_sec * 1000) + (uint64_t) round((IW_ts).tv_nsec / 1.0e6)

IW_INLINE uint64_t _iwp_filetime2ticks(const FILETIME *ft) {
  uint64_t ticks = ((uint64_t) ft->dwHighDateTime << 32) + ft->dwLowDateTime;
  if (ticks < _TICKS_TO_UNIX_EPOCH) {
    return 0;
  }
  ticks -= _TICKS_TO_UNIX_EPOCH;
  return ticks;
}

IW_INLINE void _iwp_filetime2timespec(const FILETIME *ft, struct timespec *spec) {
  uint64_t ticks = _iwp_filetime2ticks(ft);
  spec->tv_sec = ticks / _TICKS_PER_SECOND;
  spec->tv_nsec = (ticks % _TICKS_PER_SECOND) * _NANOSECONDS_PER_TICK;
}

IW_INLINE uint64_t _iwp_filetime2millisecons(const FILETIME *ft) {
  uint64_t ticks = _iwp_filetime2ticks(ft);
  return ticks / _TICKS_PER_MILLISECOND;
}

static void _iwp_clock_gettime(int clock, struct timespec *spec) {
  FILETIME ft;
  GetSystemTimeAsFileTime(&ft);
  _iwp_filetime2timespec(&ft, spec);
}

iwrc iwp_current_time_ms(uint64_t *time, bool monotonic) {
  FILETIME ft;
  GetSystemTimeAsFileTime(&ft);
  *time = _iwp_filetime2millisecons(&ft);
  return 0;
}

iwrc iwp_fsync(HANDLE h) {
  if (INVALIDHANDLE(h)) {
    return IW_ERROR_INVALID_HANDLE;
  }
  if (!FlushFileBuffers(h)) {
    return iwrc_set_werror(IW_ERROR_IO_ERRNO, GetLastError());
  }
  return 0;
}

iwrc iwp_fdatasync(HANDLE fh) {
  return iwp_fsync(fh);
}

static SYSTEM_INFO sysinfo;

static void _iwp_getsysinfo() {
  GetSystemInfo(&sysinfo);
}

size_t iwp_page_size(void) {
  return sysinfo.dwPageSize;
}

size_t iwp_alloc_unit(void) {
  return sysinfo.dwAllocationGranularity;
}

uint16_t iwp_num_cpu_cores() {
  return sysinfo.dwNumberOfProcessors;
}

iwrc iwp_ftruncate(HANDLE fh, off_t len) {
  LARGE_INTEGER size;
  size.QuadPart = len;
  if (!SetFilePointerEx(fh, size, NULL, FILE_BEGIN)) {
    return iwrc_set_werror(IW_ERROR_IO_ERRNO, GetLastError());
  }
  if (!SetEndOfFile(fh)) {
    return iwrc_set_werror(IW_ERROR_IO_ERRNO, GetLastError());
  }
  return 0;
}

iwrc iwp_fallocate(HANDLE fh, off_t len) {
  return iwp_ftruncate(fh, len);
}

iwrc iwp_fstat(const char *path, IWP_FILE_STAT *fs) {
  memset(fs, 0, sizeof(*fs));
  struct stat st = {0};
  if (stat(path, &st)) {
    return (errno == ENOENT) ? IW_ERROR_NOT_EXISTS : iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
  fs->atime = 1000ULL * st.st_atime;
  fs->mtime = 1000ULL * st.st_mtime;
  fs->ctime = 1000ULL * st.st_ctime;
  fs->size = st.st_size;
  if (S_ISREG(st.st_mode)) {
    fs->ftype = IWP_TYPE_FILE;
  } else if (S_ISDIR(st.st_mode)) {
    fs->ftype = IWP_TYPE_DIR;
  } else {
    fs->ftype = IWP_OTHER;
  }
  return 0;
}

iwrc iwp_fstath(HANDLE fh, IWP_FILE_STAT *fs) {
  memset(fs, 0, sizeof(*fs));
  BY_HANDLE_FILE_INFORMATION info;
  if (INVALIDHANDLE(fh)) {
    return IW_ERROR_INVALID_HANDLE;
  }
  if (!GetFileInformationByHandle(fh, &info)) {
    uint32_t err = GetLastError();
    if (err == ERROR_FILE_NOT_FOUND)  {
      return IW_ERROR_NOT_EXISTS;
    }
    return iwrc_set_werror(IW_ERROR_IO_ERRNO, GetLastError());
  }
  fs->atime = _iwp_filetime2millisecons(&info.ftLastAccessTime);
  fs->ctime = _iwp_filetime2millisecons(&info.ftCreationTime);
  fs->mtime = _iwp_filetime2millisecons(&info.ftLastWriteTime);
  ULARGE_INTEGER ul = {
    .LowPart = info.nFileSizeLow,
    .HighPart = info.nFileSizeHigh
  };
  fs->size = ul.QuadPart;
  if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
    fs->ftype = IWP_TYPE_DIR;
  } else {
    fs->ftype = IWP_TYPE_FILE;
  }
  return 0;
}

iwrc iwp_closefh(HANDLE fh) {
  if (INVALIDHANDLE(fh)) {
    return 0;
  }
  if (!CloseHandle(fh)) {
    return iwrc_set_werror(IW_ERROR_IO_ERRNO, GetLastError());
  }
  return 0;
}

iwrc iwp_flock(HANDLE fh, iwp_lockmode lmode) {
  if (INVALIDHANDLE(fh)) {
    return IW_ERROR_INVALID_HANDLE;
  }
  if (lmode == IWP_NOLOCK) {
    return 0;
  }
  DWORD type = 0; /* shared lock with waiting */
  OVERLAPPED offset = {0};
  if (lmode & IWP_WLOCK) type = LOCKFILE_EXCLUSIVE_LOCK;
  if (lmode & IWP_NBLOCK) type |= LOCKFILE_FAIL_IMMEDIATELY;
  if (!LockFileEx(fh, type, 0, ULONG_MAX, ULONG_MAX, &offset)) {
    return iwrc_set_werror(IW_ERROR_ERRNO, GetLastError());
  }
  return 0;
}

iwrc iwp_unlock(HANDLE fh) {
  if (INVALIDHANDLE(fh)) {
    return IW_ERROR_INVALID_HANDLE;
  }
  OVERLAPPED offset = {0};
  if (!UnlockFileEx(fh, 0, ULONG_MAX, ULONG_MAX, &offset)) {
    return iwrc_set_werror(IW_ERROR_ERRNO, GetLastError());
  } else {
    return 0;
  }
}

iwrc iwp_pread(HANDLE fh, off_t off, void *buf, size_t siz, size_t *sp) {
  if (INVALIDHANDLE(fh)) {
    return IW_ERROR_INVALID_HANDLE;
  }
  if (!buf || !sp) {
    return IW_ERROR_INVALID_ARGS;
  }
  DWORD rdb;
  ULARGE_INTEGER bigint;
  OVERLAPPED offset = {0};
  bigint.QuadPart = off;
  offset.Offset = bigint.LowPart;
  offset.OffsetHigh = bigint.HighPart;
  if (!ReadFile(fh, buf, siz, &rdb, &offset)) {
    *sp = 0;
    return iwrc_set_werror(IW_ERROR_IO_ERRNO, GetLastError());
  }
  *sp = rdb;
  return 0;
}

iwrc iwp_pwrite(HANDLE fh, off_t off, const void *buf, size_t siz, size_t *sp) {
  if (INVALIDHANDLE(fh)) {
    return IW_ERROR_INVALID_HANDLE;
  }
  if (!buf || !sp) {
    return IW_ERROR_INVALID_ARGS;
  }
  DWORD wrb;
  ULARGE_INTEGER bigint;
  OVERLAPPED offset = {0};
  bigint.QuadPart = off;
  offset.Offset = bigint.LowPart;
  offset.OffsetHigh = bigint.HighPart;
  if (!WriteFile(fh, buf, siz, &wrb, &offset)) {
    *sp = 0;
    return iwrc_set_werror(IW_ERROR_IO_ERRNO, GetLastError());
  }
  *sp = wrb;
  return 0;
}

iwrc iwp_write(HANDLE fh, const void *buf, size_t size) {
  if (INVALIDHANDLE(fh)) {
    return IW_ERROR_INVALID_HANDLE;
  }
  DWORD written;
  if (!WriteFile(fh, buf, size, &written, NULL)) {
    return iwrc_set_werror(IW_ERROR_IO_ERRNO, GetLastError());
  }
  return 0;
}

iwrc iwp_lseek(HANDLE fh, off_t offset, iwp_seek_origin origin, off_t *pos) {
  if (INVALIDHANDLE(fh)) {
    return IW_ERROR_INVALID_HANDLE;
  }
  int w;
  LARGE_INTEGER loff, noff;
  loff.QuadPart = offset;
  if (origin == IWP_SEEK_CUR) {
    w = FILE_CURRENT;
  } else if (origin == IWP_SEEK_END) {
    w = FILE_END;
  } else {
    w = FILE_BEGIN;
  }
  if (!SetFilePointerEx(fh, loff, &noff, w)) {
    return iwrc_set_werror(IW_ERROR_IO_ERRNO, GetLastError());
  }
  if (pos) {
    *pos = noff.QuadPart;
  }
  return 0;
}

size_t iwp_tmpdir(char *out, size_t len) {
  return GetTempPathA(len, out);
}

static iwrc _iwp_init_impl() {
  _iwp_getsysinfo();
  return 0;
}
