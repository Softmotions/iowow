#pragma once
#ifndef JBL_INTERNAL_H
#define JBL_INTERNAL_H

/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2024 Softmotions Ltd <info@softmotions.com>
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

#include "iwlog.h"
#include "iwjson.h"
#include "iwbinn.h"
#include "iwpool.h"
#include "iwconv.h"

#define JBL_MAX_NESTING_LEVEL 999

struct jbl {
  binn bn;
  struct jbl_node *node;
};

/**
 * @brief struct jbl* visitor context
 */
typedef struct _JBL_VCTX {
  binn *bn;         /**< Root node from which started visitor */
  void *op;         /**< Arbitrary opaque data */
  void *result;
  struct iwpool *pool; /**< Pool placeholder, initialization is responsibility of `JBL_VCTX` creator */
  int  pos;            /**< Aux position, not actually used by visitor core */
  bool terminate;
  bool found;       /**< Used in _jbl_at() */
} JBL_VCTX;

typedef jbn_visitor_cmd_t jbl_visitor_cmd_t;

typedef struct _JBL_PATCHEXT {
  const JBL_PATCH *p;
  JBL_PTR path;
  JBL_PTR from;
} JBL_PATCHEXT;

typedef struct _JBLDRCTX {
  struct iwpool   *pool;
  struct jbl_node *root;
} JBLDRCTX;

iwrc jbl_from_buf_keep_onstack(struct jbl *jbl, void *buf, size_t bufsz);
iwrc jbl_from_buf_keep_onstack2(struct jbl *jbl, void *buf);

iwrc _jbl_write_double(double num, jbl_json_printer pt, void *op);
iwrc _jbl_write_int(int64_t num, jbl_json_printer pt, void *op);
iwrc _jbl_write_json_string(const char *str, int len, jbl_json_printer pt, void *op, jbl_print_flags_t pf);
iwrc _jbl_node_from_binn(const binn *bn, struct jbl_node **node, bool clone_strings, struct iwpool *pool);
iwrc _jbl_binn_from_node(binn *res, struct jbl_node *node);
iwrc _jbl_from_node(struct jbl *jbl, struct jbl_node *node);
bool _jbl_at(struct jbl *jbl, JBL_PTR jp, struct jbl *res);
int _jbl_compare_nodes(struct jbl_node *n1, struct jbl_node *n2, iwrc *rcp);

typedef jbl_visitor_cmd_t (*JBL_VISITOR)(int lvl, binn *bv, const char *key, int idx, JBL_VCTX *vctx, iwrc *rc);
iwrc _jbl_visit(binn_iter *iter, int lvl, JBL_VCTX *vctx, JBL_VISITOR visitor);

bool _jbl_is_eq_atomic_values(struct jbl *v1, struct jbl *v2);
int _jbl_cmp_atomic_values(struct jbl *v1, struct jbl *v2);

BOOL binn_read_next_pair2(int expected_type, binn_iter *iter, int *klidx, char **pkey, binn *value);

#endif
