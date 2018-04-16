#include "iwkv_internal.h"

typedef struct IWAL {
  IWDLSNR lsnr;
  char *path;
} IWAL;

iwrc iwal_create(IWKV iwkv, const IWKV_OPTS *opts, IWFS_FSM_OPTS *fsmopts) {
  assert(!iwkv->dlsnr);
  if (!opts) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;


  //IWAL *iwal =
  // Now force all fsm data to be privately mmaped.
  // We will apply wal log to main database file
  // then re-read our private mmaps
  fsmopts->mmap_all = true;
  fsmopts->mmap_opts = IWFS_MMAP_PRIVATE;
  return rc;
}


iwrc iwal_sync(IWKV iwkv) {
  return 0;
}

iwrc iwal_checkpoint(IWKV iwkv, bool force) {


  return 0;
}

iwrc iwal_close(IWKV iwkv) {


  return 0;
}
