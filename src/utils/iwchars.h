#pragma once
#ifndef IWCHARS_H
#define IWCHARS_H

#include "basedefs.h"
#include <stdbool.h>

IW_INLINE bool iwchars_is_blank(char c) {
  return c == 32 || c == 9;
}

IW_INLINE bool iwchars_is_space(char c) {
  return c == 32 || (c >= 9 && c <= 13);
}

IW_INLINE bool iwchars_is_digit(char c) {
  return c >= 48 && c <= 57;
}

IW_INLINE bool iwchars_is_alpha(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

IW_INLINE bool iwchars_is_alnum(char c) {
  return iwchars_is_alpha(c) || iwchars_is_digit(c);
}

static bool iwchars_is_digits(const char *str, int len) {
  for (int i = 0; i < len; ++i) {
    if (!iwchars_is_digit(str[i])) {
      return false;
    }
  }
  return true;
}

#endif
