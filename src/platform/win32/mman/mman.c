// Based on https://github.com/witwall/mman-win32

#include "mman.h"
#include "log/iwlog.h"
#include <errno.h>
#include <io.h>

#ifndef FILE_MAP_EXECUTE
#define FILE_MAP_EXECUTE    0x0020
#endif /* FILE_MAP_EXECUTE */

static int __map_mman_error(const DWORD err, const int deferr) {
  if (!err) {
    return 0;
  }
  iwrc rc = IW_ERROR_FAIL;
  iwrc_set_werror(rc, err);
  iwlog_ecode_error3(rc);
  return deferr;
}

static DWORD __map_mmap_prot_page(const int prot, const int flags) {
  DWORD protect = 0;
  if (prot == PROT_NONE) {
    return protect;
  }
  if ((prot & PROT_EXEC)) {
    protect = ((prot & PROT_WRITE)) ?
              PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
  } else {
    protect = ((prot & PROT_WRITE) && !(flags & MAP_PRIVATE)) ?
              PAGE_READWRITE : PAGE_READONLY;
  }
  return protect;
}

static DWORD __map_mmap_prot_file(const int prot, const int flags) {
  DWORD desiredAccess = 0;
  if (prot == PROT_NONE) {
    return desiredAccess;
  }
  if ((prot & PROT_READ)) {
    desiredAccess |= FILE_MAP_READ;
  }
  if ((prot & PROT_WRITE)) {
    if (flags & MAP_PRIVATE) {
      desiredAccess |= FILE_MAP_COPY;
    } else {
      desiredAccess |= FILE_MAP_WRITE;
    }
  }
  if ((prot & PROT_EXEC)) {
    desiredAccess |= FILE_MAP_EXECUTE;
  }
  return desiredAccess;
}

void *mmap(void *addr, size_t len, int prot, int flags, HANDLE fh, OffsetType off) {
  HANDLE fm;
  void *map = MAP_FAILED;
  
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4293)
#endif
  
  const DWORD dwFileOffsetLow = (sizeof(OffsetType) <= sizeof(DWORD)) ?
                                (DWORD)off : (DWORD)(off & 0xFFFFFFFFL);
  const DWORD dwFileOffsetHigh = (sizeof(OffsetType) <= sizeof(DWORD)) ?
                                 (DWORD)0 : (DWORD)((off >> 32) & 0xFFFFFFFFL);
  const DWORD protect = __map_mmap_prot_page(prot, flags);
  const DWORD desiredAccess = __map_mmap_prot_file(prot, flags);
  const OffsetType maxSize = off + (OffsetType)len;
  const DWORD dwMaxSizeLow = (sizeof(OffsetType) <= sizeof(DWORD)) ?
                             (DWORD)maxSize : (DWORD)(maxSize & 0xFFFFFFFFL);
  const DWORD dwMaxSizeHigh = (sizeof(OffsetType) <= sizeof(DWORD)) ?
                              (DWORD)0 : (DWORD)((maxSize >> 32) & 0xFFFFFFFFL);
                              
#ifdef _MSC_VER
#pragma warning(pop)
#endif
                              
  errno = 0;
  if (len == 0
      /* Unsupported flag combinations */
      || (flags & MAP_FIXED) != 0
      /* Usupported protection combinations */
      || prot == PROT_EXEC) {
    errno = EINVAL;
    return MAP_FAILED;
  }
  if (!(flags & MAP_ANONYMOUS) && fh == INVALID_HANDLE_VALUE) {
    errno = EBADF;
    return MAP_FAILED;
  }
  fm = CreateFileMapping(fh, NULL, protect, dwMaxSizeHigh, dwMaxSizeLow, NULL);
  if (fm == NULL) {
    errno = __map_mman_error(GetLastError(), EPERM);
    return MAP_FAILED;
  }
  map = MapViewOfFile(fm, desiredAccess, dwFileOffsetHigh, dwFileOffsetLow, len);
  CloseHandle(fm);
  if (map == NULL) {
    errno = __map_mman_error(GetLastError(), EPERM);
    return MAP_FAILED;
  }
  return map;
}

int munmap(void *addr, size_t len) {
  if (UnmapViewOfFile(addr)) {
    return 0;
  }
  errno =  __map_mman_error(GetLastError(), EPERM);
  return -1;
}

int msync(void *addr, size_t len, int flags) {
  if (FlushViewOfFile(addr, len)) {
    return 0;
  }
  errno =  __map_mman_error(GetLastError(), EPERM);
  return -1;
}

int mlock(const void *addr, size_t len) {
  if (VirtualLock((LPVOID)addr, len)) {
    return 0;
  }
  errno =  __map_mman_error(GetLastError(), EPERM);
  return -1;
}

int munlock(const void *addr, size_t len) {
  if (VirtualUnlock((LPVOID)addr, len)) {
    return 0;
  }
  errno =  __map_mman_error(GetLastError(), EPERM);
  return -1;
}
