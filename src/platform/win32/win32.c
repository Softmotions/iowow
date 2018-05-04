#include <io.h>
#include "iwcfg.h"
#include <math.h>

#define _IW_TIMESPEC2MS(IW_ts) ((IW_ts).tv_sec * 1000) + (uint64_t) round((IW_ts).tv_nsec / 1.0e6)

struct timespec {
  long tv_sec;
  long tv_nsec;
};

static int _iw_clock_gettime(int clock, struct timespec *spec) {
  __int64 wintime;
  GetSystemTimeAsFileTime((FILETIME *)&wintime);
  wintime      -= 116444736000000000ll; //1jan1601 to 1jan1970
  spec->tv_sec  = wintime / 10000000ll;          //seconds
  spec->tv_nsec = wintime % 10000000ll * 100;    //nano-seconds
  return 0;
}

iwrc iwp_current_time_ms(uint64_t *time, bool monotonic) {
  struct timespec spec;
  if (_iw_clock_gettime(0, &spec) < 0) {
    *time = 0;
    return IW_ERROR_ERRNO;
  }
  *time = _IW_TIMESPEC2MS(spec);
  return 0;
}

//int fdatasync(int fd) {
//  return _commit(fd);
//}

iwrc iwp_fsync(HANDLE h) {
  DWORD err;
  if (h == INVALID_HANDLE_VALUE) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (!FlushFileBuffers(h)) {
    err = GetLastError();
    return iwrc_set_werror(IW_ERROR_IO_ERRNO, err);
  }
  return 0;
}
