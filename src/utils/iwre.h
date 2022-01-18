#pragma once
#ifndef IWRE_H
#define IWRE_H

/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2022 Softmotions Ltd <info@softmotions.com>
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

#include <setjmp.h>
#include "basedefs.h"

struct RE_Insn;

struct RE_Compiled {
  int size;
  struct RE_Insn *first;
  struct RE_Insn *last;
};

#define RE_COMPILED_INITIALISER { 0, 0, 0 }

struct re {
  const char *expression;
  const char *position;
  jmp_buf    *error_env;
  int   error_code;
  char *error_message;
  struct RE_Compiled code;
  const char       **matches;
  int nmatches;
#ifdef RE_EXTRA_MEMBERS
  RE_MEMBERS
#endif
};

#define RE_INITIALISER(EXPR) { (EXPR), 0, 0, 0, 0, RE_COMPILED_INITIALISER, 0, 0 }

#define RE_ERROR_NONE     0
#define RE_ERROR_NOMATCH  -1
#define RE_ERROR_NOMEM    -2
#define RE_ERROR_CHARSET  -3
#define RE_ERROR_SUBEXP   -4
#define RE_ERROR_SUBMATCH -5
#define RE_ERROR_ENGINE   -6

IW_EXPORT IW_ALLOC struct re* iwre_new(const char *expression);
IW_EXPORT int iwre_match(struct re *re, const char *input);
IW_EXPORT void iwre_release(struct re *re);
IW_EXPORT void iwre_reset(struct re *re, const char *expression);
IW_EXPORT void iwre_free(struct re *re);
IW_EXPORT char* iwre_escape(char *string, int liberal);

#endif /* __lwre_h_ */
