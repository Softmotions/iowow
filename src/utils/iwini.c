/* inih -- simple .INI file parser

   SPDX-License-Identifier: BSD-3-Clause

   Copyright (C) 2009-2020, Ben Hoyt

   inih is released under the New BSD license (see LICENSE.txt). Go to the project
   home page for more info:

   https://github.com/benhoyt/inih

 */

#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "iwini.h"
#include "iwchars.h"

#include <stdio.h>
#include <string.h>


#if !IWINI_USE_STACK
#if IWINI_CUSTOM_ALLOCATOR
#include <stddef.h>
void* iwini_malloc(size_t size);
void iwini_free(void *ptr);
void* iwini_realloc(void *ptr, size_t size);

#else
#include <stdlib.h>
#define iwini_malloc  malloc
#define iwini_free    free
#define iwini_realloc realloc
#endif
#endif

#define MAX_SECTION 127
#define MAX_NAME    127

/* Used by ini_parse_string() to keep track of string parsing state. */
typedef struct {
  const char *ptr;
  size_t      num_left;
} ini_parse_string_ctx;

/* Strip whitespace chars off end of given string, in place. Return s. */
static char* rstrip(char *s) {
  char *p = s + strlen(s);
  while (p > s && iwchars_is_space(*--p)) {
    *p = '\0';
  }
  return s;
}

/* Return pointer to first non-whitespace char in given string. */
static char* lskip(const char *s) {
  while (*s && iwchars_is_space(*s)) {
    s++;
  }
  return (char*) s;
}

/* Return pointer to first char (of chars) or inline comment in given string,
   or pointer to NUL at end of string if neither found. Inline comment must
   be prefixed by a whitespace character to register as a comment. */
static char* find_chars_or_comment(const char *s, const char *chars) {
#if IWINI_ALLOW_INLINE_COMMENTS
  int was_space = 0;
  while (  *s && (!chars || !strchr(chars, *s))
        && !(was_space && strchr(IWINI_INLINE_COMMENT_PREFIXES, *s))) {
    was_space = iwchars_is_space(*s);
    s++;
  }
#else
  while (*s && (!chars || !strchr(chars, *s))) {
    s++;
  }
#endif
  return (char*) s;
}

/* Similar to strncpy, but ensures dest (size bytes) is
   NUL-terminated, and doesn't pad with NULs. */
static char* strncpy0(char *dest, const char *src, size_t size) {
  /* Could use strncpy internally, but it causes gcc warnings (see issue #91) */
  size_t i;
  for (i = 0; i < size - 1 && src[i]; i++) {
    dest[i] = src[i];
  }
  dest[i] = '\0';
  return dest;
}

/* See documentation in header file. */
int iwini_parse_stream(
  iwini_reader reader, void *stream, iwini_handler handler,
  void *user
  ) {
  /* Uses a fair bit of stack (use heap instead if you need to) */
#if IWINI_USE_STACK
  char line[IWINI_MAX_LINE];
  int max_line = IWINI_MAX_LINE;
#else
  char *line;
  size_t max_line = IWINI_INITIAL_ALLOC;
#endif
#if IWINI_ALLOW_REALLOC && !IWINI_USE_STACK
  char *new_line;
  size_t offset;
#endif
  char section[MAX_SECTION] = "";
  char prev_name[MAX_NAME] = "";

  char *start;
  char *end;
  char *name;
  char *value;
  int lineno = 0;
  int error = 0;

#if !IWINI_USE_STACK
  line = (char*) iwini_malloc(IWINI_INITIAL_ALLOC);
  if (!line) {
    return -2;
  }
#endif

#if IWINI_HANDLER_LINENO
#define HANDLER(u, s, n, v) handler(u, s, n, v, lineno)
#else
#define HANDLER(u, s, n, v) handler(u, s, n, v)
#endif

  /* Scan through stream line by line */
  while (reader(line, max_line, stream) != NULL) {
#if IWINI_ALLOW_REALLOC && !IWINI_USE_STACK
    offset = strlen(line);
    while (offset == max_line - 1 && line[offset - 1] != '\n') {
      max_line *= 2;
      if (max_line > IWINI_MAX_LINE) {
        max_line = IWINI_MAX_LINE;
      }
      new_line = iwini_realloc(line, max_line);
      if (!new_line) {
        iwini_free(line);
        return -2;
      }
      line = new_line;
      if (reader(line + offset, (int) (max_line - offset), stream) == NULL) {
        break;
      }
      if (max_line >= IWINI_MAX_LINE) {
        break;
      }
      offset += strlen(line + offset);
    }
#endif

    lineno++;

    start = line;
#if IWINI_ALLOW_BOM
    if (  (lineno == 1) && ((unsigned char) start[0] == 0xEF)
       && ((unsigned char) start[1] == 0xBB)
       && ((unsigned char) start[2] == 0xBF)) {
      start += 3;
    }
#endif
    start = lskip(rstrip(start));

    if (strchr(IWINI_START_COMMENT_PREFIXES, *start)) {
      /* Start-of-line comment */
    }
#if IWINI_ALLOW_MULTILINE
    else if (*prev_name && *start && (start > line)) {
      /* Non-blank line with leading whitespace, treat as continuation
         of previous name's value (as per Python configparser). */
      if (!HANDLER(user, section, prev_name, start) && !error) {
        error = lineno;
      }
    }
#endif
    else if (*start == '[') {
      /* A "[section]" line */
      end = find_chars_or_comment(start + 1, "]");
      if (*end == ']') {
        *end = '\0';
        strncpy0(section, start + 1, sizeof(section));
        *prev_name = '\0';
#if IWINI_CALL_HANDLER_ON_NEW_SECTION
        if (!HANDLER(user, section, NULL, NULL) && !error) {
          error = lineno;
        }
#endif
      } else if (!error) {
        /* No ']' found on section line */
        error = lineno;
      }
    } else if (*start) {
      /* Not a comment, must be a name[=:]value pair */
      end = find_chars_or_comment(start, "=:");
      if ((*end == '=') || (*end == ':')) {
        *end = '\0';
        name = rstrip(start);
        value = end + 1;
#if IWINI_ALLOW_INLINE_COMMENTS
        end = find_chars_or_comment(value, NULL);
        if (*end) {
          *end = '\0';
        }
#endif
        value = lskip(value);
        rstrip(value);

        /* Valid name[=:]value pair found, call handler */
        strncpy0(prev_name, name, sizeof(prev_name));
        if (!HANDLER(user, section, name, value) && !error) {
          error = lineno;
        }
      } else if (!error) {
        /* No '=' or ':' found on name[=:]value line */
#if IWINI_ALLOW_NO_VALUE
        *end = '\0';
        name = rstrip(start);
        if (!HANDLER(user, section, name, NULL) && !error) {
          error = lineno;
        }
#else
        error = lineno;
#endif
      }
    }

#if IWINI_STOP_ON_FIRST_ERROR
    if (error) {
      break;
    }
#endif
  }

#if !IWINI_USE_STACK
  iwini_free(line);
#endif

  return error;
}

/* See documentation in header file. */
int iwini_parse_file(FILE *file, iwini_handler handler, void *user) {
  return iwini_parse_stream((iwini_reader) fgets, file, handler, user);
}

/* See documentation in header file. */
int iwini_parse(const char *filename, iwini_handler handler, void *user) {
  FILE *file;
  int error;

  file = fopen(filename, "r");
  if (!file) {
    return -1;
  }
  error = iwini_parse_file(file, handler, user);
  fclose(file);
  return error;
}

/* An ini_reader function to read the next line from a string buffer. This
   is the fgets() equivalent used by ini_parse_string(). */
static char* ini_reader_string(char *str, int num, void *stream) {
  ini_parse_string_ctx *ctx = (ini_parse_string_ctx*) stream;
  const char *ctx_ptr = ctx->ptr;
  size_t ctx_num_left = ctx->num_left;
  char *strp = str;
  char c;

  if ((ctx_num_left == 0) || (num < 2)) {
    return NULL;
  }

  while (num > 1 && ctx_num_left != 0) {
    c = *ctx_ptr++;
    ctx_num_left--;
    *strp++ = c;
    if (c == '\n') {
      break;
    }
    num--;
  }

  *strp = '\0';
  ctx->ptr = ctx_ptr;
  ctx->num_left = ctx_num_left;
  return str;
}

/* See documentation in header file. */
int iwini_parse_string(const char *string, iwini_handler handler, void *user) {
  ini_parse_string_ctx ctx;

  ctx.ptr = string;
  ctx.num_left = strlen(string);
  return iwini_parse_stream((iwini_reader) ini_reader_string, &ctx, handler,
                            user);
}
