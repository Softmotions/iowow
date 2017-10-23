#include "iwkv.h"
#include "iwlog.h"


static const char *_iwkv_ecodefn(locale_t locale, uint32_t ecode) {
  if (!(ecode > _IWKV_ERROR_START && ecode < _IWKV_ERROR_END)) {
    return 0;
  }
  switch (ecode) {
  case IWKV_ERROR_NOTFOUND:
    return "Key not found. (IWKV_ERROR_NOTFOUND)";
  }
  return 0;
}

iwrc iwkv_init(void) {
  static int _iwkv_initialized = 0;
  iwrc rc = iw_init();
  if (rc) return rc;
  if (!__sync_bool_compare_and_swap(&_iwkv_initialized, 0, 1)) {
    return 0;  // initialized already
  }
  return iwlog_register_ecodefn(_iwkv_ecodefn);
}
