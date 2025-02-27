#pragma once
#ifndef IWCSV_H
#define IWCSV_H

#include "iwlog.h"
#include "iwconv.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

struct iwcsv {
  char *buf;
  char *wp;
  char *ep;
  int   ncol; // Column number
};

/// Wraps a given `linebuf` in order to store assembled CSV line.
/// Recommended linebuf size: 4096.
///
/// Returns
/// - IW_ERROR_INVALID_ARGS if len of given line buf is not enouth to store a single character exclusing `\0`
/// - `len` must be aligned by 8 otherwise IW_ERROR_INVALID_ARGS
///
static iwrc iwcsv_wrap_line_buffer(char *linebuf, size_t len, struct iwcsv **out) {
  if (!out || !linebuf || len < sizeof(struct iwcsv) + 2 /* one data byte + '\0' */) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (len & 7) {
    return IW_ERROR_INVALID_ARGS;
  }
  *out = 0;
  struct iwcsv *w = (void*) (linebuf + len - sizeof(*w));
  w->wp = w->buf = linebuf;
  w->ep = (char*) w - 1;
  w->ncol = 0;
  *w->ep = '\0';
  return 0;
}

 #define WW(c_)                        \
         if (w->wp == w->ep) return 0; \
         *w->wp = (c_);                \
         ++w->wp

/// Returns non zero if CSV line built successfully
static const char* iwcsv_line_flush(struct iwcsv *w) {
  WW('\r');
  WW('\n');
  *w->wp = '\0';
  w->wp = w->buf;
  w->ncol = 0;
  return w->buf;
}

static bool iwcsv_column_add(struct iwcsv *w, const char *s, int slen) {
  if (slen < 0) {
    slen = strlen(s);
  }
  bool q = false;
  for (int i = 0; !q && i < slen; ++i) {
    switch (s[i]) {
      case ' ':
      case ',':
      case '\t':
      case '\n':
      case '\r':
        q = true;
        break;
    }
  }
  if (w->ncol++) {
    WW(',');
  }
  if (q) {
    WW('"');
  }
  for (const char *ep = s + slen; s < ep; ++s) {
    if (*s == '"') {
      WW('"');
    }
    WW(*s);
  }
  if (q) {
    WW('"');
  }
  return true;
}

static bool iwcsv_column_add_i64(struct iwcsv *w, int64_t n) {
  char buf[IWNUMBUF_SIZE];
  iwitoa(n, buf, sizeof(buf));
  return iwcsv_column_add(w, buf, -1);
}

#undef WW
#endif
