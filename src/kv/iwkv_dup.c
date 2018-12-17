#include "iwcfg.h"
#include "iwutils.h"
#include "iwkv_dup.h"

iwrc iwkv_dup_init(const IWKV_val *val, IWKV_val *uval) {
  size_t len;
  int64_t llv;
  char buf[IW_VNUMBUFSZ];
  if (val->size == sizeof(int32_t)) {
    int32_t lv;
    memcpy(&lv, val->data, sizeof(int32_t));
    llv = lv;
  } else if (val->size == sizeof(int64_t)) {
    memcpy(&llv, val->data, sizeof(int64_t));
  } else {
    return IWKV_ERROR_DUP_VALUE_SIZE;
  }
  IW_SETVNUMBUF64(len, buf, llv);
  uval->size = len;
  uval->data = malloc(len);
  if (!uval->data) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  memcpy(uval->data, buf, len);
  return 0;
}

iwrc iwkv_dup_update(const IWKV_val *val, iwkv_opflags opflags, IWKV_val *uval) {
  iwrc rc = 0;

  return rc;
}
