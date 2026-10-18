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

#include "iwlog.h"
#include "iwjbl.h"
#include "iwjbn.h"
#include "iwconv.h"
#include "iwxstr.h"
#include "iwjson_internal.h"

#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief `struct jbl` visitor context.
 */
struct jbl_vctx {
  struct binn *bn;     /**< Root binn value from which the visitor started. */
  void *op;            /**< Arbitrary opaque data of the visitor. */
  void *result;        /**< Visitor result placeholder. */
  struct iwpool *pool; /**< Pool placeholder, initialized by the creator. */
  int  pos;            /**< Aux position. Not used by the visitor core. */
  bool terminate;      /**< If `true` the traversal is terminated immediately. */
};

/**
 * @brief `struct jbl` visitor callback.
 */
typedef jbn_visitor_cmd_t (*jbl_visitor)(
  int              lvl,
  struct binn     *bv,
  const char      *key,
  int              idx,
  struct jbl_vctx *vctx,
  iwrc            *rc);

/** Context of the `struct binn` to `struct jbl_node` conversion. */
struct jbl_ldr_ctx {
  struct iwpool   *pool;  /**< Allocation pool. Optional. */
  struct jbl_node *root;  /**< Root of the produced tree. */
};

static inline jbl_type_t _jbl_binn_type(int btype) {
  switch (btype) {
    case BINN_TYPE_NULL:
      return JBV_NULL;
    case BINN_TYPE_TEXT:
      return JBV_STR;
    case BINN_TYPE_OBJECT:
    case BINN_TYPE_MAP:
      return JBV_OBJECT;
    case BINN_TYPE_LIST:
      return JBV_ARRAY;
    case BINN_TYPE_TRUE:
    case BINN_TYPE_FALSE:
      return JBV_BOOL;
    case BINN_TYPE_UINT8:
    case BINN_TYPE_UINT16:
    case BINN_TYPE_UINT32:
    case BINN_TYPE_UINT64:
    case BINN_TYPE_INT8:
    case BINN_TYPE_INT16:
    case BINN_TYPE_INT32:
    case BINN_TYPE_INT64:
      return JBV_I64;
    case BINN_TYPE_FLOAT:
    case BINN_TYPE_DOUBLE:
      return JBV_F64;
    default:
      return JBV_NONE;
  }
}

//--- Construction

iwrc jbl_create_empty_object(struct jbl **jblp) {
  struct jbl *jbl = *jblp = calloc(1, sizeof(**jblp));
  if (!*jblp) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  if (!binn_create_value(&jbl->bn, &(struct binn_create_spec) { .type = BINN_TYPE_OBJECT })) {
    free(jbl);
    return JBL_ERROR_CREATION;
  }
  return 0;
}

iwrc jbl_create_empty_array(struct jbl **jblp) {
  struct jbl *jbl = *jblp = calloc(1, sizeof(**jblp));
  if (!*jblp) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  if (!binn_create_value(&jbl->bn, &(struct binn_create_spec) { .type = BINN_TYPE_LIST })) {
    free(jbl);
    return JBL_ERROR_CREATION;
  }
  return 0;
}

static inline iwrc _add_keyed(struct jbl *jbl, struct binn *h, const char *key) {
  jbl_type_t t = jbl_type(jbl);
  if (key) {
    if (t != JBV_OBJECT) {
      return JBL_ERROR_INVALID;
    }
  } else if (t != JBV_ARRAY) {
    return JBL_ERROR_INVALID;
  }
  struct binn *bv = &jbl->bn;
  if (key) {
    if (!binn_add_keyed(bv, key, *binnv(h))) {
      return JBL_ERROR_CREATION;
    }
  } else {
    if (!binn_add(bv, *binnv(h), 0)) {
      return JBL_ERROR_CREATION;
    }
  }
  return 0;
}

//--- Value mutation

iwrc jbl_set_int64(struct jbl *jbl, const char *key, int64_t v) {
  struct binn h = BINN_INITIALIZER;
  if (!binn_create_i64c(&h, v)) {
    return JBL_ERROR_CREATION;
  }
  iwrc rc = _add_keyed(jbl, &h, key);
  binn_destroy(&h);
  return rc;
}

iwrc jbl_set_f64(struct jbl *jbl, const char *key, double v) {
  struct binn h = BINN_INITIALIZER;
  if (!binn_create_f64c(&h, v)) {
    return JBL_ERROR_CREATION;
  }
  iwrc rc = _add_keyed(jbl, &h, key);
  binn_destroy(&h);
  return rc;
}

iwrc jbl_set_string(struct jbl *jbl, const char *key, const char *v) {
  struct binn h = BINN_INITIALIZER;
  if (!binn_create_text(&h, v, -1)) {
    return JBL_ERROR_CREATION;
  }
  iwrc rc = _add_keyed(jbl, &h, key);
  binn_destroy(&h);
  return rc;
}

iwrc jbl_set_bool(struct jbl *jbl, const char *key, bool v) {
  struct binn h = BINN_INITIALIZER;
  if (!binn_create_bool(&h, v)) {
    return JBL_ERROR_CREATION;
  }
  iwrc rc = _add_keyed(jbl, &h, key);
  binn_destroy(&h);
  return rc;
}

iwrc jbl_set_null(struct jbl *jbl, const char *key) {
  struct binn h = BINN_INITIALIZER;
  if (!binn_create_null(&h)) {
    return JBL_ERROR_CREATION;
  }
  iwrc rc = _add_keyed(jbl, &h, key);
  binn_destroy(&h);
  return rc;
}

iwrc jbl_set_string_printf(struct jbl *jbl, const char *key, const char *format, ...) {
  iwrc rc = 0;
  va_list ap;

  va_start(ap, format);
  int size = _jbl_printf_estimate_size(format, ap);
  if (size < 0) {
    va_end(ap);
    return IW_ERROR_INVALID_ARGS;
  }
  va_end(ap);

  va_start(ap, format);
  char *buf = malloc(size);
  RCGA(buf, finish);
  vsnprintf(buf, size, format, ap);
  va_end(ap);

  rc = jbl_set_string(jbl, key, buf);
finish:
  free(buf);
  return rc;
}

iwrc jbl_from_json_printf_va(struct jbl **jblp, const char *format, va_list va) {
  iwrc rc = 0;
  va_list cva;
  va_copy(cva, va);
  int size = _jbl_printf_estimate_size(format, va);
  if (size < 0) {
    va_end(cva);
    return IW_ERROR_INVALID_ARGS;
  }
  char *buf = malloc(size);
  RCGA(buf, finish);
  vsnprintf(buf, size, format, cva);
  va_end(cva);

  rc = jbl_from_json(jblp, buf);
finish:
  free(buf);
  return rc;
}

iwrc jbl_from_json_printf(struct jbl **jblp, const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  iwrc rc = jbl_from_json_printf_va(jblp, format, ap);
  va_end(ap);
  return rc;
}

iwrc jbl_set_empty_array(struct jbl *jbl, const char *key) {
  struct jbl v = JBL_INITIALIZER;
  if (!binn_create_value(&v.bn, &(struct binn_create_spec) { .type = BINN_TYPE_LIST })) {
    binn_destroy(&v.bn);
    return JBL_ERROR_CREATION;
  }
  iwrc rc = jbl_set_nested(jbl, key, &v);
  binn_destroy(&v.bn);
  return rc;
}

iwrc jbl_set_empty_object(struct jbl *jbl, const char *key) {
  struct jbl v = JBL_INITIALIZER;
  if (!binn_create_value(&v.bn, &(struct binn_create_spec) { .type = BINN_TYPE_OBJECT })) {
    binn_destroy(&v.bn);
    return JBL_ERROR_CREATION;
  }
  iwrc rc = jbl_set_nested(jbl, key, &v);
  binn_destroy(&v.bn);
  return rc;
}

iwrc jbl_set_nested(struct jbl *jbl, const char *key, struct jbl *v) {
  return _add_keyed(jbl, &v->bn, key);
}

//--- Construction from a serialized buffer

iwrc jbl_init_from_buf(struct jbl *jbl, void *buf, size_t bufsz, bool wrap) {
  bool casted = false;
  if (wrap) {
    if (!binn_from(&jbl->bn, (struct binn_val) { buf, bufsz }, &casted) || casted) {
      return JBL_ERROR_INVALID_BUFFER;
    }
  } else if (!binn_copy_from(&jbl->bn, (struct binn_val) { buf, bufsz })) {
    return JBL_ERROR_INVALID_BUFFER;
  }
  return 0;
}

iwrc jbl_create_from_buf(struct jbl **jblp, void *buf, size_t bufsz, bool wrap) {
  struct jbl *jbl = *jblp = calloc(1, sizeof(**jblp));
  if (!jbl) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  iwrc rc = jbl_init_from_buf(jbl, buf, bufsz, wrap);
  if (rc) {
    free(jbl);
    return rc;
  }
  return 0;
}

//--- Lifecycle

iwrc jbl_clone(struct jbl *src, struct jbl **targetp) {
  struct jbl *jbl = *targetp = calloc(1, sizeof(**targetp));
  if (!jbl) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  if (!binn_copy_from(&jbl->bn, (struct binn_val) { src, sizeof(*src) })) {
    free(jbl);
    return JBL_ERROR_CREATION;
  }
  return 0;
}

void jbl_destroy(struct jbl **jblp) {
  if (*jblp) {
    struct jbl *jbl = *jblp;
    binn_destroy(&jbl->bn);
    free(jbl);
    *jblp = 0;
  }
}

void jbl_reset(struct jbl *jbl) {
  if (jbl) {
    binn_destroy(&jbl->bn);
    jbl->node = 0;
  }
}

//--- Introspection

jbl_type_t jbl_type(struct jbl *jbl) {
  if (jbl) {
    return _jbl_binn_type(jbl->bn.type);
  }
  return JBV_NONE;
}

size_t jbl_count(struct jbl *jbl) {
  return (size_t) jbl->bn.count;
}

size_t jbl_size(struct jbl *jbl) {
  return jbl->bn.size;
}

size_t jbl_structure_size(void) {
  return sizeof(struct jbl);
}

iwrc jbl_from_json(struct jbl **jblp, const char *jsonstr) {
  *jblp = 0;
  iwrc rc = 0;
  struct iwpool *pool = iwpool_create(2 * strlen(jsonstr));
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  struct jbl *jbl;
  struct jbl_node *node;
  rc = jbn_from_json(jsonstr, &node, pool);
  RCGO(rc, finish);
  if (node->type == JBV_OBJECT) {
    rc = jbl_create_empty_object(&jbl);
    RCGO(rc, finish);
  } else if (node->type == JBV_ARRAY) {
    rc = jbl_create_empty_array(&jbl);
    RCGO(rc, finish);
  } else {
    // TODO: Review
    rc = JBL_ERROR_CREATION;
    goto finish;
  }
  rc = jbl_fill_from_node(jbl, node);
  if (!rc) {
    *jblp = jbl;
  }

finish:
  iwpool_destroy(pool);
  return rc;
}

//--- JSON text serialization

static iwrc _jbl_as_json(struct binn *bn, jbl_json_printer pt, void *op, int lvl, jbl_print_flags_t pf) {
  iwrc rc = 0;
  struct binn_iter iter;
  bool pretty = pf & JBL_PRINT_PRETTY;

#define PT(data_, size_, ch_, count_) do {        \
          rc = pt(data_, size_, ch_, count_, op); \
          RCGO(rc, finish);                       \
} while (0)

  switch (bn->type) {
    case BINN_TYPE_LIST:
      if (!binn_iter_init((struct binn_val) { bn, sizeof(*bn) }, &iter)) {
        rc = JBL_ERROR_INVALID;
        goto finish;
      }
      PT(0, 0, '[', 1);
      if (bn->count && pretty) {
        PT(0, 0, '\n', 1);
      }
      for (int i = 0; binn_iter_next(&iter); ++i) {
        if (pretty) {
          PT(0, 0, ' ', lvl + 1);
        }
        rc = _jbl_as_json(&iter.binn, pt, op, lvl + 1, pf);
        RCGO(rc, finish);
        if (i < bn->count - 1) {
          PT(0, 0, ',', 1);
        }
        if (pretty) {
          PT(0, 0, '\n', 1);
        }
      }
      if (bn->count && pretty) {
        PT(0, 0, ' ', lvl);
      }
      PT(0, 0, ']', 1);
      break;

    case BINN_TYPE_OBJECT:
    case BINN_TYPE_MAP:
      if (!binn_iter_init((struct binn_val) { bn, sizeof(*bn) }, &iter)) {
        rc = JBL_ERROR_INVALID;
        goto finish;
      }
      PT(0, 0, '{', 1);
      if (bn->count && pretty) {
        PT(0, 0, '\n', 1);
      }
      for (int i = 0; binn_iter_next(&iter); ++i) {
        if (pretty) {
          PT(0, 0, ' ', lvl + 1);
        }
        if (bn->type == BINN_TYPE_OBJECT) {
          RCC(rc, finish, _jbl_write_json_string(iter.key, -1, pt, op, pf));
        } else {
          PT(0, 0, '"', 1);
          rc = _jbl_write_int(iter.idx, pt, op);
          RCGO(rc, finish);
          PT(0, 0, '"', 1);
        }
        if (pretty) {
          PT(": ", -1, 0, 0);
        } else {
          PT(0, 0, ':', 1);
        }
        RCC(rc, finish, _jbl_as_json(&iter.binn, pt, op, lvl + 1, pf));
        if (i < bn->count - 1) {
          PT(0, 0, ',', 1);
        }
        if (pretty) {
          PT(0, 0, '\n', 1);
        }
      }
      if (bn->count && pretty) {
        PT(0, 0, ' ', lvl);
      }
      PT(0, 0, '}', 1);
      break;

    case BINN_TYPE_TEXT: {
      struct binn_val tv = binn_text_get(bn);
      rc = _jbl_write_json_string(tv.buf, (int) tv.size, pt, op, pf);
      break;
    }

    case BINN_TYPE_UINT8:
    case BINN_TYPE_UINT16:
    case BINN_TYPE_UINT32:
    case BINN_TYPE_UINT64:
    case BINN_TYPE_INT8:
    case BINN_TYPE_INT16:
    case BINN_TYPE_INT32:
    case BINN_TYPE_INT64:
      rc = _jbl_write_int(binn_i64_get(bn), pt, op);
      break;
    case BINN_TYPE_FLOAT:
    case BINN_TYPE_DOUBLE:
      rc = _jbl_write_double(binn_f64_get(bn), pt, op);
      break;
    case BINN_TYPE_TRUE:
      PT("true", 4, 0, 0);
      break;
    case BINN_TYPE_FALSE:
      PT("false", 5, 0, 0);
      break;
    case BINN_TYPE_NULL:
      PT("null", 4, 0, 0);
      break;
    default:
      iwlog_ecode_error3(IW_ERROR_ASSERTION);
      rc = IW_ERROR_ASSERTION;
      break;
  }

finish:
  return rc;
#undef PT
}

iwrc jbl_as_json(struct jbl *jbl, jbl_json_printer pt, void *op, jbl_print_flags_t pf) {
  if (!jbl || !pt) {
    return IW_ERROR_INVALID_ARGS;
  }
  return _jbl_as_json(&jbl->bn, pt, op, 0, pf);
}

//--- Value access

int64_t jbl_get_i64(struct jbl *jbl) {
  return binn_i64_get(&jbl->bn);
}

int32_t jbl_get_i32(struct jbl *jbl) {
  return (int32_t) binn_i64_get(&jbl->bn);
}

double jbl_get_f64(struct jbl *jbl) {
  return binn_f64_get(&jbl->bn);
}

const char* jbl_get_str(struct jbl *jbl) {
  return binn_text_get(&jbl->bn).buf;
}

const char* jbl_get_str2(struct jbl *jbl, size_t *out_len) {
  struct binn_val bv = binn_text_get(&jbl->bn);
  if (out_len) {
    *out_len = bv.size;
  }
  return bv.buf;
}

size_t jbl_copy_strn(struct jbl *jbl, char *buf, size_t bufsz) {
  struct binn_val bv = binn_text_get(&jbl->bn);
  size_t ret = MIN(bv.size, bufsz);
  memcpy(buf, bv.buf, ret);
  if (bufsz && ret < bufsz) {
    buf[ret] = '\0';
  }
  return ret;
}

//--- Object property access

jbl_type_t jbl_object_get_type(struct jbl *jbl, const char *key) {
  struct binn res;
  if (jbl && binn_keyed_get(&jbl->bn, key, &res)) {
    jbl_type_t ret = _jbl_binn_type(res.type);
    binn_destroy(&res);
    return ret;
  } else {
    return JBV_NONE;
  }
}

iwrc jbl_object_get_i64(struct jbl *jbl, const char *key, int64_t *out) {
  *out = 0;
  struct binn res;
  if (jbl && binn_keyed_get(&jbl->bn, key, &res)) {
    if (binn_is_int_number(&res) || binn_is_fp_number(&res)) {
      *out = binn_i64_get(&res);
      binn_destroy(&res);
      return 0;
    }
    binn_destroy(&res);
  }
  return JBL_ERROR_CREATION;
}

iwrc jbl_object_get_f64(struct jbl *jbl, const char *key, double *out) {
  *out = 0;
  struct binn res;
  if (jbl && binn_keyed_get(&jbl->bn, key, &res)) {
    if (binn_is_int_number(&res) || binn_is_fp_number(&res)) {
      *out = binn_f64_get(&res);
      binn_destroy(&res);
      return 0;
    }
    binn_destroy(&res);
  }
  return JBL_ERROR_CREATION;
}

iwrc jbl_object_get_bool(struct jbl *jbl, const char *key, bool *out) {
  *out = false;
  struct binn res;
  if (jbl && binn_keyed_get(&jbl->bn, key, &res)) {
    if (binn_is_boolean(&res)) {
      *out = binn_bool_get(&res);
      binn_destroy(&res);
      return 0;
    }
    binn_destroy(&res);
  }
  return JBL_ERROR_CREATION;
}

iwrc jbl_object_get_str(struct jbl *jbl, const char *key, const char **out) {
  *out = 0;
  struct binn res;
  if (jbl && binn_keyed_get(&jbl->bn, key, &res)) {
    if (binn_is_text(&res)) {
      *out = binn_text_get(&res).buf;
      binn_destroy(&res);
      return 0;
    }
    binn_destroy(&res);
  }
  return JBL_ERROR_CREATION;
}

iwrc jbl_object_get_str2(struct jbl *jbl, const char *key, const char **out, size_t *out_len) {
  *out = 0;
  *out_len = 0;
  struct binn res;
  if (jbl && binn_keyed_get(&jbl->bn, key, &res)) {
    if (binn_is_text(&res)) {
      struct binn_val bv = binn_text_get(&res);
      *out = bv.buf;
      *out_len = bv.size;
      binn_destroy(&res);
      return 0;
    }
    binn_destroy(&res);
  }
  return JBL_ERROR_CREATION;
}

iwrc jbl_object_get_jbl(struct jbl *jbl, const char *key, struct jbl *out) {
  if (binn_keyed_get(&jbl->bn, key, &out->bn)) {
    return 0;
  }
  return JBL_ERROR_CREATION;
}

//--- Binary serialization

size_t jbl_serialized_size(const struct jbl *jbl) {
  return binn_serialized_size(&jbl->bn);
}

iwrc jbl_serialize_into(const struct jbl *jbl, uint8_t *out_buf, size_t out_bufsz) {
  struct binn_val bv = binn_serialize_into(&jbl->bn, out_buf, out_bufsz);
  return bv.buf ? 0 : iwrc_set_errno(IW_ERROR_ERRNO, errno);
}

iwrc jbl_serialize(
  const struct jbl *jbl,
  bool (*consumer)(const uint8_t *buf, size_t bufsz, void *op),
  void *op) {
  if (!binn_serialize(&jbl->bn, consumer, op)) {
    return IW_ERROR_FAIL;
  }
  return 0;
}

//--- JSON pointer

static iwrc _jbl_visit_children(
  const struct binn *container, int lvl, struct jbl_vctx *vctx, jbl_visitor visitor) {
  iwrc rc = 0;
  struct binn_iter iter;
  jbn_visitor_cmd_t cmd;

  if (lvl > JBL_MAX_NESTING_LEVEL) {
    return JBL_ERROR_MAX_NESTING_LEVEL_EXCEEDED;
  }
  if (!container) {
    container = vctx->bn;
  }
  if (!binn_is_container(container)) {
    return JBL_ERROR_INVALID;
  }
  if (!binn_iter_init(*binnv(container), &iter)) {
    return JBL_ERROR_INVALID;
  }

  const bool is_list = binn_is_list(container);
  const bool is_map = binn_is_map(container);

  for (int pos = 0; !vctx->terminate && binn_iter_next(&iter); ++pos) {
    struct binn *bv = &iter.binn;
    const char *key = (is_list || is_map) ? 0 : iter.key;
    int idx = is_list ? pos : (is_map ? iter.idx : -1);
    cmd = visitor(lvl, bv, key, idx, vctx, &rc);
    RCRET(rc);
    if (cmd & JBL_VCMD_TERMINATE) {
      vctx->terminate = true;
      break;
    }
    if (!(cmd & JBL_VCMD_SKIP_NESTED) && binn_is_container(bv)) {
      rc = _jbl_visit_children(bv, lvl + 1, vctx, visitor);
      RCRET(rc);
    }
  }

  return rc;
}

static inline bool _jbl_visitor_update_jptr_cursor(struct jbl_vctx *vctx, int lvl, const char *key, int idx) {
  struct jbl_ptr *jp = vctx->op;
  if (lvl < jp->cnt) {
    if (vctx->pos >= lvl) {
      vctx->pos = lvl - 1;
    }
    if (vctx->pos + 1 == lvl) {
      const char *keyptr;
      char buf[IWNUMBUF_SIZE];
      if (key) {
        keyptr = key;
      } else {
        iwitoa(idx, buf, IWNUMBUF_SIZE);
        keyptr = buf;
      }
      if (!strcmp(keyptr, jp->n[lvl]) || ((jp->n[lvl][0] == '*') && (jp->n[lvl][1] == '\0'))) {
        vctx->pos = lvl;
        return (jp->cnt == lvl + 1);
      }
    }
  }
  return false;
}

static jbn_visitor_cmd_t _jbl_get_visitor(
  int lvl, struct binn *bv, const char *key, int idx, struct jbl_vctx *vctx,
  iwrc *rc) {
  struct jbl_ptr *jp = vctx->op;
  assert(jp);
  if (_jbl_visitor_update_jptr_cursor(vctx, lvl, key, idx)) { // Pointer matched
    struct jbl *jbl = malloc(sizeof(struct jbl));
    if (!jbl) {
      *rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
      return JBL_VCMD_TERMINATE;
    }
    if (!binn_create_view_from(&jbl->bn, bv)) {
      return JBL_VCMD_TERMINATE;
    }
    jbl->node = 0;
    vctx->result = jbl;
    return JBL_VCMD_TERMINATE;
  } else if (jp->cnt < lvl + 1) {
    return JBL_VCMD_SKIP_NESTED;
  }
  return JBL_VCMD_OK;
}

iwrc jbl_at2(struct jbl *jbl, struct jbl_ptr *jp, struct jbl **res) {
  if (jp->cnt == 0) {
    struct jbl *rv;
    RCRA(rv = malloc(sizeof(struct jbl)));
    if (!binn_create_view_from(&rv->bn, &jbl->bn)) {
      free(rv);
      return JBL_ERROR_CREATION;
    }
    rv->node = 0;
    *res = rv;
    return 0;
  }
  struct jbl_vctx vctx = {
    .bn = &jbl->bn,
    .op = jp,
    .pos = -1
  };
  iwrc rc = _jbl_visit_children(0, 0, &vctx, _jbl_get_visitor);
  if (rc) {
    *res = 0;
  } else {
    if (!vctx.result) {
      rc = JBL_ERROR_PATH_NOTFOUND;
      *res = 0;
    } else {
      *res = (struct jbl*) vctx.result;
    }
  }
  return rc;
}

iwrc jbl_at(struct jbl *jbl, const char *path, struct jbl **res) {
  struct jbl_ptr *jp;
  iwrc rc = _jbl_ptr_pool(path, &jp, 0);
  if (rc) {
    *res = 0;
    return rc;
  }
  rc = jbl_at2(jbl, jp, res);
  free(jp);
  return rc;
}

//--- DOM tree conversion

static iwrc _jbl_create_node(
  struct jbl_ldr_ctx *ctx,
  const struct binn  *bv,
  struct jbl_node    *parent,
  const char         *key,
  int                 klidx,
  struct jbl_node   **node,
  bool                clone_strings) {
  if (node) {
    *node = 0;
  }
  iwrc rc = 0;
  struct jbl_node *n;
  if (IW_LIKELY(ctx->pool)) {
    n = iwpool_alloc(sizeof(*n), ctx->pool);
  } else {
    n = malloc(sizeof(*n));
  }
  if (!n) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  memset(n, 0, sizeof(*n));
  // The key memory is owned by the binn iterator and is invalidated on the next iteration,
  // so it must always be copied into the node storage.
  if (key) {
    if (IW_LIKELY(ctx->pool)) {
      n->key = iwpool_strndup(ctx->pool, key, klidx, &rc);
      RCGO(rc, finish);
    } else {
      RCB(finish, n->key = strndup(key, klidx));
    }
  }
  n->klidx = klidx;
  n->parent = parent;
  switch (bv->type) {
    case BINN_TYPE_NULL:
      n->type = JBV_NULL;
      break;
    case BINN_TYPE_TEXT:
    case BINN_TYPE_DATE:
    case BINN_TYPE_DATETIME:
    case BINN_TYPE_TIME:
    case BINN_TYPE_DECIMAL: {
      n->type = JBV_STR;
      struct binn_val v = binn_text_get(bv);
      n->vsize = (int) v.size;
      if (!clone_strings) {
        n->vptr = v.buf;
      } else if (IW_LIKELY(ctx->pool)) {
        n->vptr = iwpool_strndup(ctx->pool, v.buf, v.size, &rc);
        RCGO(rc, finish);
      } else {
        RCB(finish, n->vptr = strndup(v.buf, v.size));
      }
      break;
    }
    case BINN_TYPE_OBJECT:
    case BINN_TYPE_MAP:
      n->type = JBV_OBJECT;
      break;
    case BINN_TYPE_LIST:
      n->type = JBV_ARRAY;
      break;
    case BINN_TYPE_TRUE:
      n->type = JBV_BOOL;
      n->vbool = true;
      break;
    case BINN_TYPE_FALSE:
      n->type = JBV_BOOL;
      n->vbool = false;
      break;
      break;
    case BINN_TYPE_UINT8:
    case BINN_TYPE_UINT16:
    case BINN_TYPE_UINT32:
    case BINN_TYPE_UINT64:
    case BINN_TYPE_INT8:
    case BINN_TYPE_INT16:
    case BINN_TYPE_INT32:
    case BINN_TYPE_INT64:
      n->type = JBV_I64;
      n->vi64 = binn_i64_get(bv);
      break;
    case BINN_TYPE_FLOAT:
    case BINN_TYPE_DOUBLE:
      n->vf64 = binn_f64_get(bv);
      n->type = JBV_F64;
      break;
    default:
      rc = JBL_ERROR_CREATION;
      goto finish;
  }
  if (parent) {
    _jbn_add_item(parent, n);
  }

finish:
  if (rc) {
    free(n);
  } else {
    if (node) {
      *node = n;
    }
  }
  return rc;
}

static iwrc _jbl_node_from_binn_impl(
  struct jbl_ldr_ctx *ctx,
  const struct binn  *bn,
  struct jbl_node    *parent,
  const char         *key,
  int                 klidx,
  bool                clone_strings) {
  iwrc rc = 0;
  struct binn_iter iter;

  switch (bn->type) {
    case BINN_TYPE_OBJECT:
    case BINN_TYPE_MAP:
      rc = _jbl_create_node(ctx, bn, parent, key, klidx, &parent, clone_strings);
      RCRET(rc);
      if (!ctx->root) {
        ctx->root = parent;
      }
      if (!binn_iter_init(*binnv(bn), &iter)) {
        return JBL_ERROR_INVALID;
      }
      while (binn_iter_next(&iter)) {
        rc = _jbl_node_from_binn_impl(ctx, &iter.binn, parent, iter.key, iter.idx, clone_strings);
        RCRET(rc);
      }
      break;

    case BINN_TYPE_LIST:
      rc = _jbl_create_node(ctx, bn, parent, key, klidx, &parent, clone_strings);
      RCRET(rc);
      if (!ctx->root) {
        ctx->root = parent;
      }
      if (!binn_iter_init(*binnv(bn), &iter)) {
        return JBL_ERROR_INVALID;
      }
      for (int i = 0; binn_iter_next(&iter); ++i) {
        rc = _jbl_node_from_binn_impl(ctx, &iter.binn, parent, 0, i, clone_strings);
        RCRET(rc);
      }
      break;
    default: {
      rc = _jbl_create_node(ctx, bn, parent, key, klidx, 0, clone_strings);
      RCRET(rc);
      break;
    }
  }
  return rc;
}

static iwrc _jbl_node_from_binn(const struct binn *bn, struct jbl_node **node, bool clone_strings, struct iwpool *pool) {
  struct jbl_ldr_ctx ctx = {
    .pool = pool
  };
  iwrc rc = _jbl_node_from_binn_impl(&ctx, bn, 0, 0, -1, clone_strings);
  if (rc) {
    *node = 0;
  } else {
    *node = ctx.root;
  }
  return rc;
}

static iwrc _jbl_from_node_impl(struct binn *res, struct jbl_node *node) {
  iwrc rc = 0;
  switch (node->type) {
    case JBV_OBJECT:
      if (!binn_create_object(res)) {
        return JBL_ERROR_CREATION;
      }
      for (struct jbl_node *n = node->child; n; n = n->next) {
        struct binn bv;
        rc = _jbl_from_node_impl(&bv, n);
        RCRET(rc);
        if (!binn_add_keyed2(res, n->key, n->klidx, *binnv(&bv))) {
          rc = JBL_ERROR_CREATION;
        }
        binn_destroy(&bv);
        RCRET(rc);
      }
      break;
    case JBV_ARRAY:
      if (!binn_create_list(res)) {
        return JBL_ERROR_CREATION;
      }
      for (struct jbl_node *n = node->child; n; n = n->next) {
        struct binn bv;
        rc = _jbl_from_node_impl(&bv, n);
        RCRET(rc);
        if (!binn_add(res, *binnv(&bv), 0)) {
          rc = JBL_ERROR_CREATION;
        }
        binn_destroy(&bv);
        RCRET(rc);
      }
      break;
    case JBV_STR:
      if (!binn_create_text(res, node->vptr, node->vsize)) {
        return JBL_ERROR_CREATION;
      }
      break;
    case JBV_I64:
      if (!binn_create_i64c(res, node->vi64)) {
        return JBL_ERROR_CREATION;
      }
      break;
    case JBV_F64:
      if (!binn_create_f64c(res, node->vf64)) {
        return JBL_ERROR_CREATION;
      }
      break;
    case JBV_BOOL:
      if (!binn_create_bool(res, node->vbool)) {
        return JBL_ERROR_CREATION;
      }
      break;
    case JBV_NULL:
      if (!binn_create_null(res)) {
        return JBL_ERROR_CREATION;
      }
      break;
    case JBV_NONE:
      rc = JBL_ERROR_CREATION;
      break;
  }
  return rc;
}

static iwrc _jbl_binn_from_node(struct binn *res, struct jbl_node *node) {
  return _jbl_from_node_impl(res, node);
}

//--- Patching

static iwrc _jbl_patch(struct jbl *jbl, const struct jbl_patch *p, size_t cnt, struct iwpool *pool) {
  if (cnt < 1) {
    return 0;
  }
  if (!jbl || !p) {
    return IW_ERROR_INVALID_ARGS;
  }
  struct binn bv;
  struct binn *bn;
  struct jbl_node *root;

  iwrc rc = _jbl_node_from_binn(&jbl->bn, &root, false, pool);
  RCRET(rc);

  rc = _jbl_patch_node(root, p, cnt, pool);
  RCRET(rc);

  if (root->type != JBV_NONE) {
    rc = _jbl_from_node_impl(&bv, root);
    RCRET(rc);
    bn = &bv;
  } else {
    bn = 0;
  }
  binn_destroy(&jbl->bn);
  if (bn) {
    memcpy(&jbl->bn, bn, sizeof(jbl->bn));
  } else {
    binn_reset(&jbl->bn);
    root->type = JBV_NONE;
  }
  return rc;
}

iwrc jbl_to_node(struct jbl *jbl, struct jbl_node **node, bool clone_strings, struct iwpool *pool) {
  if (jbl->node) {
    *node = jbl->node;
    return 0;
  }
  return _jbl_node_from_binn(&jbl->bn, node, clone_strings, pool);
}

iwrc jbl_patch(struct jbl *jbl, const struct jbl_patch *p, size_t cnt) {
  if (cnt < 1) {
    return 0;
  }
  if (!jbl || !p) {
    return IW_ERROR_INVALID_ARGS;
  }
  struct iwpool *pool = iwpool_create(jbl->bn.size);
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  iwrc rc = _jbl_patch(jbl, p, cnt, pool);
  iwpool_destroy(pool);
  return rc;
}

iwrc jbl_patch_from_json(struct jbl *jbl, const char *patchjson) {
  if (!jbl || !patchjson) {
    return IW_ERROR_INVALID_ARGS;
  }
  struct jbl_patch *p;
  struct jbl_node *patch;
  int cnt = (int) strlen(patchjson);
  struct iwpool *pool = iwpool_create(MAX(cnt, 1024U));
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  iwrc rc = jbn_from_json(patchjson, &patch, pool);
  RCGO(rc, finish);
  if (patch->type == JBV_ARRAY) {
    rc = _jbl_create_patch(patch, &p, &cnt, pool);
    RCGO(rc, finish);
    rc = _jbl_patch(jbl, p, cnt, pool);
  } else if (patch->type == JBV_OBJECT) {
    // FIXME: Merge patch not implemented
    //_jbl_merge_patch_node()
    rc = IW_ERROR_NOT_IMPLEMENTED;
  } else {
    rc = JBL_ERROR_PATCH_INVALID;
  }

finish:
  iwpool_destroy(pool);
  return rc;
}

iwrc jbl_fill_from_node(struct jbl *jbl, struct jbl_node *node) {
  if (!jbl || !node) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (node->type == JBV_NONE) {
    memcpy(jbl, &(struct jbl) JBL_INITIALIZER, sizeof(*jbl));
    return 0;
  }
  struct binn bv = BINN_INITIALIZER;
  iwrc rc = _jbl_binn_from_node(&bv, node);
  RCRET(rc);

  binn_destroy(&jbl->bn);
  memcpy(&jbl->bn, &bv, sizeof(jbl->bn));
  return rc;
}

iwrc jbl_from_node(struct jbl **jblp, struct jbl_node *node) {
  if (!jblp || !node) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  if (node->type == JBV_OBJECT) {
    rc = jbl_create_empty_object(jblp);
  } else if (node->type == JBV_ARRAY) {
    rc = jbl_create_empty_array(jblp);
  } else {
    rc = IW_ERROR_INVALID_ARGS;
  }
  RCRET(rc);
  return jbl_fill_from_node(*jblp, node);
}

//--- Merge patch

iwrc jbl_merge_patch(struct jbl *jbl, const char *patchjson) {
  if (!jbl || !patchjson) {
    return IW_ERROR_INVALID_ARGS;
  }
  struct binn bv;
  struct jbl_node *target;
  struct iwpool *pool = iwpool_create(2UL * jbl->bn.size);
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  iwrc rc = _jbl_node_from_binn(&jbl->bn, &target, false, pool);
  RCGO(rc, finish);
  rc = jbn_merge_patch_from_json(target, patchjson, pool);
  RCGO(rc, finish);

  rc = _jbl_binn_from_node(&bv, target);
  RCGO(rc, finish);

  binn_destroy(&jbl->bn);
  memcpy(&jbl->bn, &bv, sizeof(jbl->bn));

finish:
  iwpool_destroy(pool);
  return 0;
}

iwrc jbl_merge_patch_jbl(struct jbl *jbl, struct jbl *patch) {
  struct iwxstr *xstr = iwxstr_create_empty();
  if (!xstr) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  iwrc rc = jbl_as_json(patch, jbl_xstr_json_printer, xstr, 0);
  RCGO(rc, finish);
  rc = jbl_merge_patch(jbl, iwxstr_ptr(xstr));
finish:
  iwxstr_destroy(xstr);
  return rc;
}
