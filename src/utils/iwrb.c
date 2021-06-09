#include "iwrb.h"

#include <stdlib.h>
#include <string.h>

IWRB* iwrb_create(size_t unit_size, size_t size) {
  IWRB *rb = malloc(sizeof(*rb) + unit_size * size);
  if (!rb) {
    return 0;
  }
  rb->pos = 0;
  rb->size = size;
  rb->usize = unit_size;
  rb->buf = (char*) rb + sizeof(*rb);
  return rb;
}

void iwrb_destroy(IWRB *rb) {
  free(rb);
}

IWRB* iwrb_wrap(void *buf, size_t buf_len, size_t unit_size) {
  if (buf_len < sizeof(IWRB) + unit_size) {
    return 0;
  }
  IWRB *rb = buf;
  rb->pos = 0;
  rb->size = (buf_len - sizeof(IWRB)) / unit_size;
  rb->usize = unit_size;
  rb->buf = (char*) buf + sizeof(*rb);
  return rb;
}

void iwrb_put(IWRB *rb, void *buf) {
  if (rb->pos != 0) {
    ssize_t upos = rb->pos > 0 ? rb->pos : -rb->pos;
    if (upos + 1 > rb->size) {
      memcpy(rb->buf, buf, rb->usize);
      rb->pos = rb->pos > 0 ? 1 : -1;
    } else {
      memcpy(rb->buf, buf, upos);
      rb->pos = rb->pos > 0 ? rb->pos + 1 : rb->pos - 1;
    }
  } else {
    memcpy(rb->buf, buf, rb->usize);
    rb->pos = -1;
  }
}
