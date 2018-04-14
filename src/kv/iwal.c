#include "iwal.h"
#include "iwcfg.h"

typedef struct IWAL {
  IWDLSNR lsnr;
  IWAL_OPTS opts;
  const char *path;
} IWAL;

iwrc iwal_create(const IWAL_OPTS *opts, IWDLSNR **olsnr) {
  if (!opts || !olsnr) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;

  return rc;
}

void iwal_reset_write_bytes_count() {

}

off_t iwal_get_write_bytes_count() {
  return 0;
}

iwrc iwal_sync() {
  return 0;
}

void iwal_destroy(IWDLSNR *lsnr) {
  if (!lsnr) {

  }
}





