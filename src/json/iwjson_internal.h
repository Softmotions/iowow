#pragma once
#ifndef IWJSON_INTERNAL_H
#define IWJSON_INTERNAL_H

/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2026 Softmotions Ltd <info@softmotions.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *************************************************************************************************/

/**
 * @file iwjson_internal.h
 * @brief Internal private declarations of the JSON modules.
 *
 * This header is shared between the JSON DOM module (`iwjbn.c`), the JSON text serializer
 * (`iwjser.c`) and the binary Binn backed document module (`iwjbl.c`). It must not be used
 * outside of `src/json` and it is not installed.
 */

#include "iwjson.h"

#include <stdarg.h>
#include <stdio.h>

/** Maximal JSON document nesting level. */
#define JBL_MAX_NESTING_LEVEL BINN_MAX_NESTING_LEVELS

/**
 * @brief Estimates the size of a buffer able to hold the `vsnprintf()` result of `format`.
 *
 * @return Required buffer size including the terminating `\0`, or a negative value on a format error.
 */
IW_INLINE int _jbl_printf_estimate_size(const char *format, va_list ap) {
  char buf[1];
  int ret = vsnprintf(buf, sizeof(buf), format, ap);
  if (ret < 0) {
    return ret;
  } else {
    return ret + 1;
  }
}

// --- JSON text serialization primitives (iwjser.c)
// Shared by the DOM and the Binn document printers.

/** Prints the `num` value as JSON number. */
iwrc _jbl_write_double(double num, jbl_json_printer pt, void *op);

/** Prints the `num` value as JSON integer. */
iwrc _jbl_write_int(int64_t num, jbl_json_printer pt, void *op);

/**
 * @brief Prints `str` as a quoted and escaped JSON string.
 *
 * @param str String to print. Not zero.
 * @param len String length in bytes, or a negative value to use `strlen(str)`.
 */
iwrc _jbl_write_json_string(const char *str, int len, jbl_json_printer pt, void *op, jbl_print_flags_t pf);

// --- JSON DOM helpers shared between the DOM and the Binn modules

/** Appends the `node` to the children of the `parent` container node. */
void _jbn_add_item(struct jbl_node *parent, struct jbl_node *node);

/** Parses an rfc6901 JSON pointer allocating its memory in `pool` if given, or with `malloc()`. */
iwrc _jbl_ptr_pool(const char *path, struct jbl_ptr **jpp, struct iwpool *pool);

/** Applies the JSON Patch operations `p` to the DOM tree `root`. */
iwrc _jbl_patch_node(struct jbl_node *root, const struct jbl_patch *p, size_t cnt, struct iwpool *pool);

/** Converts a JSON Patch document DOM tree `node` into an array of patch operations. */
iwrc _jbl_create_patch(struct jbl_node *node, struct jbl_patch **pptr, int *cntp, struct iwpool *pool);

#endif
