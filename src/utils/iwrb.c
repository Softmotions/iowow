#include "iwrb.h"

#include <stdlib.h>
#include <string.h>

IWRB* iwrb_create(size_t usize, size_t len) {
  IWRB *rb = malloc(sizeof(*rb) + usize * len);
  if (!rb) {
    return 0;
  }
  rb->pos = 0;
  rb->len = len;
  rb->usize = usize;
  rb->buf = (char*) rb + sizeof(*rb);
  return rb;
}

void iwrb_destroy(IWRB *rb) {
  free(rb);
}

IWRB* iwrb_wrap(void *buf, size_t len, size_t usize) {
  if (len < sizeof(IWRB) + usize) {
    return 0;
  }
  IWRB *rb = buf;
  rb->pos = 0;
  rb->len = (len - sizeof(IWRB)) / usize;
  rb->usize = usize;
  rb->buf = (char*) buf + sizeof(*rb);
  return rb;
}

void iwrb_put(IWRB *rb, void *buf) {
  if (rb->pos != 0) {
    size_t upos = rb->pos > 0 ? rb->pos : -rb->pos;
    if (upos == rb->len) {
      memcpy(rb->buf, buf, rb->usize);
      rb->pos = 1;
    } else {
      memcpy(rb->buf, buf, upos);
      rb->pos = rb->pos > 0 ? rb->pos + 1 : rb->pos - 1;
    }
  } else {
    memcpy(rb->buf, buf, rb->usize);
    rb->pos = -1;
  }
}

void* iwrb_peek(const IWRB *rb) {
  if (rb->pos == 0) {
    return 0;
  }
  size_t upos = rb->pos > 0 ? rb->pos : -rb->pos;
  return rb->buf + (rb->pos - 1) * rb->usize;
}

void iwrb_iter_init(const IWRB *rb, IWRB_ITER *iter) {
  iter->rb = rb;
  iter->pos = rb->pos > 0 ? rb->pos : -rb->pos;
}

void* iwrb_iter_prev(IWRB_ITER *iter) {
  const IWRB *rb = iter->rb;
  if (rb->pos == 0) {
    return 0;
  }
  if (rb->pos < 0) {
    if (iter->pos == 0 || iter->pos > -rb->pos) {
      return 0;
    }
    return rb->buf + --iter->pos * rb->usize;
  } else {
    if (iter->pos == 0) {
      iter->pos = rb->len;
    }
    return rb->buf + --iter->pos * rb->usize;
  }
}
