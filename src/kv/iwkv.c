
#include "iwkv.h"
#include "iwlog.h"
#include "iwutils.h"
#include "iwfsmfile.h"
#include "iwcfg.h"

// Number of _KV blocks in _KVBLK
#define KVIDXSZ 63 

typedef struct IMPL {
  IWFS_FSM fsm;
} IMPL;

// Key/Value pair
typedef struct _KV {
  uint8_t *key;
  uint8_t *val;
  size_t keysz;
  size_t valsz;
} _KV;

// _KV index: Offset and length.
typedef struct _KVIDX {
  uint32_t off; /**< _KV block offset relative to `end` of _KVBLK */
  uint32_t len; /**< Length of  */
} _KVIDX;

// _KVBLK: [blen:u1,pplen:u2,[pp1:vn,pl1:vn,...,pp63,pl63]____[[pair],...]]
typedef struct _KVBLK {
  uint8_t szpow;        /**< Block size power of 2 */
  _KVIDX kvidx[KVIDXSZ];   /**< KV pairs index */
} _KVBLK;


static iwrc _kvblk_create(IMPL *impl, _KVBLK **oblk) {
  iwrc rc = 0;
  
  return rc;
}

static void _kvblk_release(_KVBLK **blk) {
  assert(blk && *blk);
  free(*blk);
  *blk = 0;
}

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
