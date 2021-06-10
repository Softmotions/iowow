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

void iwrb_destroy(IWRB **rbp) {
  if (rbp && *rbp) {
    free(*rbp);
    *rbp = 0;
  }
}

IWRB* iwrb_wrap(void *buf, size_t len, size_t usize) {
  if (buf == 0 || len < sizeof(IWRB) + usize) {
    return 0;
  }
  IWRB *rb = buf;
  rb->pos = 0;
  rb->len = (len - sizeof(IWRB)) / usize;
  rb->usize = usize;
  rb->buf = (char*) buf + sizeof(*rb);
  return rb;
}

void iwrb_put(IWRB *rb, const void *buf) {
  if (rb->pos != 0) {
    size_t upos = rb->pos > 0 ? rb->pos : -rb->pos;
    if (upos == rb->len) {
      memcpy(rb->buf, buf, rb->usize);
      rb->pos = 1;
    } else {
      memcpy(rb->buf + upos * rb->usize, buf, rb->usize);
      rb->pos = rb->pos > 0 ? rb->pos + 1 : rb->pos - 1;
    }
  } else {
    memcpy(rb->buf, buf, rb->usize);
    rb->pos = -1;
  }
}

void iwrb_back(IWRB *rb) {
  if (rb->pos > 0) {
    --rb->pos;
  } else if (rb->pos < 0) {
    ++rb->pos;
  }
}

void* iwrb_peek(const IWRB *rb) {
  if (rb->pos == 0) {
    return 0;
  }
  size_t upos = rb->pos > 0 ? rb->pos : -rb->pos;
  return rb->buf + (upos - 1) * rb->usize;
}

void iwrb_clear(IWRB *rb) {
  rb->pos = 0;
}

size_t iwrb_num_cached(const IWRB *rb) {
  if (rb->pos <= 0) {
    return -rb->pos;
  } else {
    return rb->len;
  }
}

void iwrb_iter_init(const IWRB *rb, IWRB_ITER *iter) {
  iter->rb = rb;
  iter->pos = rb->pos > 0 ? rb->pos : -rb->pos;
  iter->ipos = rb->pos > 0 ? -rb->pos : rb->pos;
}

void* iwrb_iter_prev(IWRB_ITER *iter) {
  const IWRB *rb = iter->rb;
  if (iter->ipos == 0) {
    return 0;
  }
  if (rb->pos < 0) {
    if (iter->pos == 0) {
      return 0;
    }
    if (iter->ipos < 0) {
      iter->ipos = -iter->ipos;
    }
    return rb->buf + --iter->pos * rb->usize;
  } else {
    if (iter->pos == 0) {
      iter->pos = rb->len;
    }
    if (iter->ipos < 0) {
      iter->ipos = -iter->ipos;
    } else if (iter->ipos == iter->pos) {
      iter->ipos = 0;
      return 0;
    }
    return rb->buf + --iter->pos * rb->usize;
  }
}
