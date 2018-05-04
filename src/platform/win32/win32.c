#include <io.h>
#include "iwcfg.h"

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
