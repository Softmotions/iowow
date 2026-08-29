#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "basedefs.h"

#define IW_STEPBOX_MAX_STEP_KINDS 255

static_assert(IW_STEPBOX_MAX_STEP_KINDS <= (uint8_t) -1, "");

struct iw_stepbox {
  atomic_int steps[255];
  void       (*lsnr)(struct iw_stepbox*, uint8_t, int inc);
  void      *user_data;
};

static IW_NOINLINE int iw_stepbox_on(struct iw_stepbox *b, uint8_t idx, int inc) {
  int ret = (b->steps[idx] += inc);
  if (b->lsnr) {
    b->lsnr(b, idx, inc);
  }
  return ret;
}

static void iw_stepbox_reset(struct iw_stepbox *b, void (*lsnr)(struct iw_stepbox*, uint8_t, int)) {
  memset(b, 0, sizeof(*b));
  b->lsnr = lsnr;
}
