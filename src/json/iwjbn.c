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
#include "iwjbn.h"
#include "iwconv.h"
#include "iwjson_internal.h"

#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define _STRX(x) #x
#define _STR(x)  _STRX(x)

/**
 * @brief Extended JSON Patch operation with pre-parsed JSON pointers.
 */
struct jbl_patch_ext {
  const struct jbl_patch *p;    /**< Original patch operation. */
  struct jbl_ptr *path;         /**< Pre-parsed target path. */
  struct jbl_ptr *from;         /**< Pre-parsed source path of `JBP_COPY`, `JBP_MOVE` and `JBP_SWAP`. */
};

IW_INLINE void _jbn_remove_item(struct jbl_node *parent, struct jbl_node *child);
static int _jbl_compare_nodes(struct jbl_node *n1, struct jbl_node *n2, iwrc *rcp);

//--- Values

void jbl_node_as_plain_value(const struct jbl_node *n, struct jbl_plain_value *v) {
  memset(v, 0, sizeof(*v));
  memcpy(v, (char*) n + offsetof(struct jbl_node, vsize), sizeof(*n) - offsetof(struct jbl_node, vsize));
}

void jbl_plain_value_set_node(const struct jbl_plain_value *v, struct jbl_node *n) {
  memcpy((char*) n + offsetof(struct jbl_node, vsize), v, sizeof(*v));
}

//--- Formatting

void iwjson_ftoa(long double val, char buf[static IWNUMBUF_SIZE], size_t *out_len) {
  int len = snprintf(buf, IWNUMBUF_SIZE, "%.8Lf", val);
  // FIXME: Dirt hack. I won't touch global locale.
  char *cp = strchr(buf, ',');
  if (cp) {
    *cp = '.';
  }
  if (len <= 0) {
    buf[0] = '\0';
    *out_len = 0;
    return;
  }
  while (len > 0 && buf[len - 1] == '0') { // trim zeroes from right
    buf[len - 1] = '\0';
    len--;
  }
  if ((len > 0) && (buf[len - 1] == '.')) {
    buf[len - 1] = '\0';
    len--;
  }
  *out_len = (size_t) len;
}

//--- Reading

iwrc jbn_from_json_printf_va(struct jbl_node **node, struct iwpool *pool, const char *format, va_list va) {
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
  rc = jbn_from_json(buf, node, pool);
finish:
  free(buf);
  return rc;
}

iwrc jbn_from_json_printf(struct jbl_node **node, struct iwpool *pool, const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  iwrc rc = jbn_from_json_printf_va(node, pool, format, ap);
  va_end(ap);
  return rc;
}

//--- JSON pointer (rfc6901)

iwrc _jbl_ptr_pool(const char *path, struct jbl_ptr **jpp, struct iwpool *pool) {
  iwrc rc = 0;
  int cnt = 0, len, sz, doff;
  int i = 0, j, k;
  struct jbl_ptr *jp;
  char *jpr; // raw pointer to jp
  *jpp = 0;

  if (!path) {
    path = "";
  }

  if (*path == '\0') {
    cnt = 0;
  } else {
    if ((path[0] != '/')) {
      return JBL_ERROR_JSON_POINTER;
    }
    for (i = 0; path[i]; ++i) {
      if (path[i] == '/') {
        ++cnt;
      } else if (path[i] == '~') {
        // RFC 6901: `~` inside a reference token must be escaped as `~0` or `~1`
        if ((path[i + 1] != '0') && (path[i + 1] != '1')) {
          return JBL_ERROR_JSON_POINTER;
        }
      }
    }
  }

  len = i;
  if ((len > 1) && (path[len - 1] == '/')) {
    return JBL_ERROR_JSON_POINTER;
  }
  sz = (int) (sizeof(struct jbl_ptr) + cnt * sizeof(char*) + len);
  if (pool) {
    jp = iwpool_alloc(sz, pool);
  } else {
    jp = malloc(sz);
  }
  if (!jp) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  jpr = (char*) jp;
  jp->cnt = cnt;
  jp->sz = sz;

  doff = offsetof(struct jbl_ptr, n) + cnt * sizeof(char*);
  assert(sz - doff >= len);

  for (i = 0, j = 0, cnt = 0; path[i] && cnt < jp->cnt; ++i, ++j) {
    if (path[i++] == '/') {
      jp->n[cnt] = jpr + doff + j;
      for (k = 0; ; ++i, ++k) {
        if (!path[i] || (path[i] == '/')) {
          --i;
          *(jp->n[cnt] + k) = '\0';
          break;
        }
        if (path[i] == '~') {
          if (path[i + 1] == '0') {
            *(jp->n[cnt] + k) = '~';
          } else if (path[i + 1] == '1') {
            *(jp->n[cnt] + k) = '/';
          }
          ++i;
        } else {
          *(jp->n[cnt] + k) = path[i];
        }
      }
      j += k;
      ++cnt;
    }
  }
  *jpp = jp;
  return rc;
}

iwrc jbl_ptr_alloc(const char *path, struct jbl_ptr **jpp) {
  return _jbl_ptr_pool(path, jpp, 0);
}

iwrc jbl_ptr_alloc_pool(const char *path, struct jbl_ptr **jpp, struct iwpool *pool) {
  return _jbl_ptr_pool(path, jpp, pool);
}

int jbl_ptr_cmp(struct jbl_ptr *p1, struct jbl_ptr *p2) {
  if (p1->sz != p2->sz) {
    return p1->sz - p2->sz;
  }
  if (p1->cnt != p2->cnt) {
    return p1->cnt - p2->cnt;
  }
  for (int i = 0; i < p1->cnt; ++i) {
    int r = strcmp(p1->n[i], p2->n[i]);
    if (r) {
      return r;
    }
  }
  return 0;
}

iwrc jbl_ptr_serialize(struct jbl_ptr *ptr, struct iwxstr *xstr) {
  for (int i = 0; i < ptr->cnt; ++i) {
    iwrc rc = iwxstr_cat(xstr, "/", 1);
    RCRET(rc);
    rc = iwxstr_cat(xstr, ptr->n[i], strlen(ptr->n[i]));
    RCRET(rc);
  }
  return 0;
}

//--- Traversal

iwrc jbn_visit(struct jbl_node *node, int lvl, struct jbn_vctx *vctx, JBN_VISITOR visitor) {
  iwrc rc = 0;
  if (lvl > JBL_MAX_NESTING_LEVEL) {
    return JBL_ERROR_MAX_NESTING_LEVEL_EXCEEDED;
  }
  if (!node) {
    node = vctx->root;
    lvl = 0;
    if (!node) {
      return IW_ERROR_INVALID_ARGS;
    }
  }
  struct jbl_node *n = node;
  switch (node->type) {
    case JBV_OBJECT:
    case JBV_ARRAY: {
      for (n = n->child; !vctx->terminate && n; n = n->next) {
        jbn_visitor_cmd_t cmd = visitor(lvl, n, n->key, n->klidx, vctx, &rc);
        RCRET(rc);
        if (cmd & JBL_VCMD_TERMINATE) {
          vctx->terminate = true;
        }
        if (cmd & JBN_VCMD_DELETE) {
          struct jbl_node *nn = n->next; // Keep pointer to next
          _jbn_remove_item(node, n);
          n->next = nn;
        } else if (!(cmd & JBL_VCMD_SKIP_NESTED) && (n->type >= JBV_OBJECT)) {
          rc = jbn_visit(n, lvl + 1, vctx, visitor);
          RCRET(rc);
        }
      }
      break;
    }
    default:
      break;
  }
  RCRET(rc);
  if (lvl == 0) {
    visitor(-1, node, 0, 0, vctx, &rc);
  }
  return rc;
}

iwrc jbn_visit2(struct jbl_node *node, int lvl, iwrc (*visitor)(int, struct jbl_node*)) {
  if (!node || !visitor) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (lvl > JBL_MAX_NESTING_LEVEL) {
    return JBL_ERROR_MAX_NESTING_LEVEL_EXCEEDED;
  }
  struct jbl_node *next = 0;
  switch (node->type) {
    case JBV_OBJECT:
    case JBV_ARRAY: {
      for (struct jbl_node *n = node->child; n; n = next) {
        next = n->next;
        iwrc rc = jbn_visit2(n, lvl + 1, visitor);
        RCRET(rc);
      }
      break;
    }
    default:
      break;
  }
  return visitor(lvl, node);
}

static inline bool _jbn_visitor_update_jptr_cursor(struct jbn_vctx *vctx, int lvl, const char *key, int idx) {
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
        idx = (int) strlen(keyptr);
      }
      int jplen = (int) strlen(jp->n[lvl]);
      if ((  (idx == jplen)
          && !strncmp(keyptr, jp->n[lvl], idx)) || ((jp->n[lvl][0] == '*') && (jp->n[lvl][1] == '\0'))) {
        vctx->pos = lvl;
        return (jp->cnt == lvl + 1);
      }
    }
  }
  return false;
}

//--- Lookup

static jbn_visitor_cmd_t _jbn_get_visitor(
  int              lvl,
  struct jbl_node *n,
  const char      *key,
  int              klidx,
  struct jbn_vctx *vctx,
  iwrc            *rc) {
  if (lvl < 0) { // EOF
    return JBL_VCMD_OK;
  }
  struct jbl_ptr *jp = vctx->op;
  assert(jp);
  if (_jbn_visitor_update_jptr_cursor(vctx, lvl, key, klidx)) { // Pointer matched
    vctx->result = n;
    return JBL_VCMD_TERMINATE;
  } else if (jp->cnt < lvl + 1) {
    return JBL_VCMD_SKIP_NESTED;
  }
  return JBL_VCMD_OK;
}

iwrc jbn_at2(struct jbl_node *node, struct jbl_ptr *jp, struct jbl_node **res) {
  if (jp->cnt == 0) {
    *res = node;
    return 0;
  }
  struct jbn_vctx vctx = {
    .root = node,
    .op = jp,
    .pos = -1
  };
  iwrc rc = jbn_visit(node, 0, &vctx, _jbn_get_visitor);
  if (rc) {
    *res = 0;
  } else {
    if (!vctx.result) {
      rc = JBL_ERROR_PATH_NOTFOUND;
      *res = 0;
    } else {
      *res = (struct jbl_node*) vctx.result;
    }
  }
  return rc;
}

iwrc jbn_at(struct jbl_node *node, const char *path, struct jbl_node **res) {
  struct jbl_ptr *jp;
  iwrc rc = _jbl_ptr_pool(path, &jp, 0);
  if (rc) {
    *res = 0;
    return rc;
  }
  rc = jbn_at2(node, jp, res);
  free(jp);
  return rc;
}

iwrc jbn_get(struct jbl_node *node, const char *key, int index, struct jbl_node **res) {
  if (!key || !res) {
    return IW_ERROR_INVALID_ARGS;
  }
  *res = 0;
  switch (node->type) {
    case JBV_OBJECT:
      if (key) {
        for (struct jbl_node *n = node->child; n; n = n->next) {
          if (n->key && strcmp(n->key, key) == 0) {
            *res = n;
            return 0;
          }
        }
      }
      break;
    case JBV_ARRAY: {
      int i = 0;
      for (struct jbl_node *n = node->child; n; n = n->next) {
        if (index == i++) {
          *res = n;
          return 0;
        }
      }
      break;
    }
    default:
      break;
  }
  return JBL_ERROR_PATH_NOTFOUND;
}

int jbn_paths_compare(
  struct jbl_node *n1,
  const char      *n1path,
  struct jbl_node *n2,
  const char      *n2path,
  jbl_type_t       vtype,
  iwrc            *rcp) {
  *rcp = 0;
  struct jbl_node *v1 = 0, *v2 = 0;
  iwrc rc = jbn_at(n1, n1path, &v1);
  if (rc && (rc != JBL_ERROR_PATH_NOTFOUND)) {
    *rcp = rc;
    return -2;
  }
  rc = jbn_at(n2, n2path, &v2);
  if (rc && (rc != JBL_ERROR_PATH_NOTFOUND)) {
    *rcp = rc;
    return -2;
  }
  if (vtype) {
    if (((v1 == 0) || (v1->type != vtype)) || ((v2 == 0) || (v2->type != vtype))) {
      *rcp = JBL_ERROR_TYPE_MISMATCHED;
      return -2;
    }
  }
  return _jbl_compare_nodes(v1, v2, rcp);
}

int jbn_path_compare(struct jbl_node *n1, struct jbl_node *n2, const char *path, jbl_type_t vtype, iwrc *rcp) {
  return jbn_paths_compare(n1, path, n2, path, vtype, rcp);
}

int jbn_path_compare_str(struct jbl_node *n, const char *path, const char *sv, iwrc *rcp) {
  *rcp = 0;
  struct jbl_node *v;
  iwrc rc = jbn_at(n, path, &v);
  if (rc) {
    *rcp = rc;
    return -2;
  }
  struct jbl_node cn = {
    .type = JBV_STR,
    .vptr = sv,
    .vsize = (int) strlen(sv)
  };
  return _jbl_compare_nodes(v, &cn, rcp);
}

int jbn_path_compare_i64(struct jbl_node *n, const char *path, int64_t iv, iwrc *rcp) {
  *rcp = 0;
  struct jbl_node *v;
  iwrc rc = jbn_at(n, path, &v);
  if (rc) {
    *rcp = rc;
    return -2;
  }
  struct jbl_node cn = {
    .type = JBV_I64,
    .vi64 = iv
  };
  return _jbl_compare_nodes(v, &cn, rcp);
}

int jbn_path_compare_f64(struct jbl_node *n, const char *path, double fv, iwrc *rcp) {
  *rcp = 0;
  struct jbl_node *v;
  iwrc rc = jbn_at(n, path, &v);
  if (rc) {
    *rcp = rc;
    return -2;
  }
  struct jbl_node cn = {
    .type = JBV_F64,
    .vf64 = fv
  };
  return _jbl_compare_nodes(v, &cn, rcp);
}

int jbn_path_compare_bool(struct jbl_node *n, const char *path, bool bv, iwrc *rcp) {
  *rcp = 0;
  struct jbl_node *v;
  iwrc rc = jbn_at(n, path, &v);
  if (rc) {
    *rcp = rc;
    return -2;
  }
  struct jbl_node cn = {
    .type = JBV_BOOL,
    .vbool = bv
  };
  return _jbl_compare_nodes(v, &cn, rcp);
}

//--- Value assignment

IW_INLINE void _jbl_node_reset_data(struct jbl_node *target) {
  jbl_type_t t = target->type;
  memset(((uint8_t*) target) + offsetof(struct jbl_node, child),
         0,
         sizeof(struct jbl_node) - offsetof(struct jbl_node, child));
  target->type = t;
}

IW_INLINE void _jbl_copy_node_data(struct jbl_node *target, struct jbl_node *value) {
  memcpy(((uint8_t*) target) + offsetof(struct jbl_node, child),
         ((uint8_t*) value) + offsetof(struct jbl_node, child),
         sizeof(struct jbl_node) - offsetof(struct jbl_node, child));
}

iwrc _jbl_increment_node_data(struct jbl_node *target, struct jbl_node *value) {
  if ((value->type != JBV_I64) && (value->type != JBV_F64)) {
    return JBL_ERROR_PATCH_INVALID_VALUE;
  }
  if (target->type == JBV_I64) {
    if (value->type == JBV_I64) {
      target->vi64 += value->vi64;
    } else {
      target->vi64 += (int64_t) value->vf64;
    }
    return 0;
  } else if (target->type == JBV_F64) {
    if (value->type == JBV_F64) {
      target->vf64 += value->vf64;
    } else {
      target->vf64 += (double) value->vi64;
    }
    return 0;
  } else {
    return JBL_ERROR_PATCH_TARGET_INVALID;
  }
}

//--- Modification

void jbn_data(struct jbl_node *node) {
  _jbl_node_reset_data(node);
}

int jbn_length(struct jbl_node *node) {
  int ret = 0;
  for (struct jbl_node *n = node->child; n; n = n->next) {
    ++ret;
  }
  return ret;
}

void _jbn_add_item(struct jbl_node *parent, struct jbl_node *node) {
  assert(parent && node);
  node->next = 0;
  node->prev = 0;
  node->parent = parent;
  if (parent->child) {
    struct jbl_node *prev = parent->child->prev;
    parent->child->prev = node;
    if (prev) { // -V1051
      prev->next = node;
      node->prev = prev;
    } else {
      parent->child->next = node;
      node->prev = parent->child;
    }
  } else {
    parent->child = node;
  }
  if (parent->type == JBV_ARRAY) {
    node->key = 0;
    if (node->prev) {
      node->klidx = node->prev->klidx + 1;
    } else {
      node->klidx = 0;
    }
  }
}

void jbn_add_item(struct jbl_node *parent, struct jbl_node *node) {
  _jbn_add_item(parent, node);
}

// Free a node allocated outside of an `iwpool` along with its dynamically
// allocated key/value strings.
static void _jbn_free_allocated_node(struct jbl_node *n) {
  if (n) {
    if (n->key) {
      free((void*) n->key);
    }
    if ((n->type == JBV_STR) && n->vptr) {
      free((void*) n->vptr);
    }
    free(n);
  }
}

iwrc jbn_add_item_str(
  struct jbl_node  *parent,
  const char       *key,
  const char       *val,
  int               vlen,
  struct jbl_node **node_out,
  struct iwpool    *pool) {
  if (!parent || parent->type < JBV_OBJECT) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  struct jbl_node *n;
  if (IW_LIKELY(pool)) {
    n = iwpool_calloc(sizeof(*n), pool);
  } else {
    n = calloc(1, sizeof(*n));
  }
  if (!n) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  if (parent->type == JBV_OBJECT) {
    if (!key) {
      rc = IW_ERROR_INVALID_ARGS;
      goto finish;
    }
    if (IW_LIKELY(pool)) {
      n->key = iwpool_strdup(pool, key, &rc);
      RCGO(rc, finish);
    } else {
      RCB(finish, n->key = strdup(key));
    }
    n->klidx = (int) strlen(n->key);
  }
  n->type = JBV_STR;
  if (val) {
    if (vlen < 0) {
      vlen = (int) strlen(val);
    }
    if (IW_LIKELY(pool)) {
      n->vptr = iwpool_strndup(pool, val, vlen, &rc);
      RCGO(rc, finish);
    } else {
      RCB(finish, n->vptr = strndup(val, vlen));
    }
    n->vsize = vlen;
  }
  jbn_add_item(parent, n);
  if (node_out) {
    *node_out = n;
  }
finish:
  if (!n->parent && !pool) {
    _jbn_free_allocated_node(n);
  }
  return rc;
}

iwrc jbn_add_item_null(struct jbl_node *parent, const char *key, struct iwpool *pool) {
  if (!parent || parent->type < JBV_OBJECT) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  struct jbl_node *n;
  if (IW_LIKELY(pool)) {
    n = iwpool_calloc(sizeof(*n), pool);
  } else {
    n = calloc(1, sizeof(*n));
  }
  if (!n) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  if (parent->type == JBV_OBJECT) {
    if (!key) {
      rc = IW_ERROR_INVALID_ARGS;
      goto finish;
    }
    if (IW_LIKELY(pool)) {
      n->key = iwpool_strdup(pool, key, &rc);
      RCGO(rc, finish);
    } else {
      RCB(finish, n->key = strdup(key));
    }

    n->klidx = (int) strlen(n->key);
  }
  n->type = JBV_NULL;
  jbn_add_item(parent, n);
finish:
  if (!n->parent && !pool) {
    _jbn_free_allocated_node(n);
  }
  return rc;
}

iwrc jbn_add_item_i64(
  struct jbl_node  *parent,
  const char       *key,
  int64_t           val,
  struct jbl_node **node_out,
  struct iwpool    *pool) {
  if (!parent || parent->type < JBV_OBJECT) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  struct jbl_node *n;
  if (IW_LIKELY(pool)) {
    n = iwpool_calloc(sizeof(*n), pool);
  } else {
    n = calloc(1, sizeof(*n));
  }
  if (!n) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  if (parent->type == JBV_OBJECT) {
    if (!key) {
      rc = IW_ERROR_INVALID_ARGS;
      goto finish;
    }
    if (IW_LIKELY(pool)) {
      n->key = iwpool_strdup(pool, key, &rc);
      RCGO(rc, finish);
    } else {
      RCB(finish, n->key = strdup(key));
    }
    n->klidx = (int) strlen(n->key);
  }
  n->type = JBV_I64;
  n->vi64 = val;
  jbn_add_item(parent, n);
  if (node_out) {
    *node_out = n;
  }
finish:
  if (!n->parent && !pool) {
    _jbn_free_allocated_node(n);
  }
  return rc;
}

iwrc jbn_add_item_f64(
  struct jbl_node  *parent,
  const char       *key,
  double            val,
  struct jbl_node **node_out,
  struct iwpool    *pool) {
  if (!parent || parent->type < JBV_OBJECT) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  struct jbl_node *n;
  if (IW_LIKELY(pool)) {
    n = iwpool_calloc(sizeof(*n), pool);
  } else {
    n = calloc(1, sizeof(*n));
  }
  if (!n) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  if (parent->type == JBV_OBJECT) {
    if (!key) {
      rc = IW_ERROR_INVALID_ARGS;
      goto finish;
    }
    if (IW_LIKELY(pool)) {
      n->key = iwpool_strdup(pool, key, &rc);
      RCGO(rc, finish);
    } else {
      RCB(finish, n->key = strdup(key));
    }
    n->klidx = (int) strlen(n->key);
  }
  n->type = JBV_F64;
  n->vf64 = val;
  jbn_add_item(parent, n);
  if (node_out) {
    *node_out = n;
  }
finish:
  if (!n->parent && !pool) {
    _jbn_free_allocated_node(n);
  }
  return rc;
}

iwrc jbn_add_item_bool(
  struct jbl_node  *parent,
  const char       *key,
  bool              val,
  struct jbl_node **node_out,
  struct iwpool    *pool) {
  if (!parent || parent->type < JBV_OBJECT) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  struct jbl_node *n;
  if (IW_LIKELY(pool)) {
    n = iwpool_calloc(sizeof(*n), pool);
  } else {
    n = calloc(1, sizeof(*n));
  }
  if (!n) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  if (parent->type == JBV_OBJECT) {
    if (!key) {
      rc = IW_ERROR_INVALID_ARGS;
      goto finish;
    }
    if (IW_LIKELY(pool)) {
      n->key = iwpool_strdup(pool, key, &rc);
      RCGO(rc, finish);
    } else {
      RCB(finish, n->key = strdup(key));
    }
    n->klidx = (int) strlen(n->key);
  }
  n->type = JBV_BOOL;
  n->vbool = val;
  jbn_add_item(parent, n);
  if (node_out) {
    *node_out = n;
  }
finish:
  if (!n->parent && !pool) {
    _jbn_free_allocated_node(n);
  }
  return rc;
}

iwrc jbn_add_item_obj(struct jbl_node *parent, const char *key, struct jbl_node **out, struct iwpool *pool) {
  if (!parent || parent->type < JBV_OBJECT) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  struct jbl_node *n;
  if (IW_LIKELY(pool)) {
    n = iwpool_calloc(sizeof(*n), pool);
  } else {
    n = calloc(1, sizeof(*n));
  }
  if (!n) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  if (parent->type == JBV_OBJECT) {
    if (!key) {
      rc = IW_ERROR_INVALID_ARGS;
      goto finish;
    }
    if (IW_LIKELY(pool)) {
      n->key = iwpool_strdup(pool, key, &rc);
      RCGO(rc, finish);
    } else {
      RCB(finish, n->key = strdup(key));
    }
    n->klidx = (int) strlen(n->key);
  }
  n->type = JBV_OBJECT;
  jbn_add_item(parent, n);
  if (out) {
    *out = n;
  }
finish:
  if (!n->parent && !pool) {
    _jbn_free_allocated_node(n);
  }
  return rc;
}

iwrc jbn_add_item_arr(struct jbl_node *parent, const char *key, struct jbl_node **out, struct iwpool *pool) {
  if (!parent || parent->type < JBV_OBJECT) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  struct jbl_node *n;
  if (IW_LIKELY(pool)) {
    n = iwpool_calloc(sizeof(*n), pool);
  } else {
    n = calloc(1, sizeof(*n));
  }
  if (!n) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  if (parent->type == JBV_OBJECT) {
    if (!key) {
      rc = IW_ERROR_INVALID_ARGS;
      goto finish;
    }
    if (IW_LIKELY(pool)) {
      n->key = iwpool_strdup(pool, key, &rc);
      RCGO(rc, finish);
    } else {
      RCB(finish, n->key = strdup(key));
    }
    n->klidx = (int) strlen(n->key);
  }
  n->type = JBV_ARRAY;
  jbn_add_item(parent, n);
  if (out) {
    *out = n;
  }
finish:
  if (!n->parent && !pool) {
    _jbn_free_allocated_node(n);
  }
  return rc;
}

iwrc jbn_copy_path(
  struct jbl_node *src,
  const char      *src_path,
  struct jbl_node *target,
  const char      *target_path,
  bool             overwrite_on_nulls,
  bool             no_src_clone,
  struct iwpool   *pool) {
  if (!src || !src_path || !target || !target_path || !pool) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  struct jbl_node *n1, *n2;
  jbp_patch_t op = JBP_REPLACE;

  if (strcmp("/", src_path) != 0) { // -V526
    rc = jbn_at(src, src_path, &n1);
    if (rc == JBL_ERROR_PATH_NOTFOUND) {
      return 0;
    }
    RCRET(rc);
  } else {
    n1 = src;
  }
  if (!overwrite_on_nulls && (n1->type <= JBV_NULL)) {
    return 0;
  }
  if (no_src_clone) {
    n2 = n1;
  } else {
    rc = jbn_clone(n1, &n2, pool);
    RCRET(rc);
  }

  rc = jbn_at(target, target_path, &n1);
  if (rc == JBL_ERROR_PATH_NOTFOUND) {
    rc = 0;
    op = JBP_ADD_CREATE;
  }
  struct jbl_patch p[] = {
    {
      .op = op,
      .path = target_path,
      .vnode = n2
    }
  };
  return jbn_patch(target, p, sizeof(p) / sizeof(p[0]), pool);
}

IW_EXPORT iwrc jbn_copy_paths(
  struct jbl_node *src,
  struct jbl_node *target,
  const char     **paths,
  bool             overwrite_on_nulls,
  bool             no_src_clone,
  struct iwpool   *pool) {
  if (!target || !src || !paths || !pool) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  for (const char **p = paths; *p; ++p) {
    const char *path = *p;
    rc = jbn_copy_path(src, path, target, path, overwrite_on_nulls, no_src_clone, pool);
    RCBREAK(rc);
  }
  return rc;
}

IW_INLINE void _jbn_remove_item(struct jbl_node *parent, struct jbl_node *child) {
  assert(parent->child);
  if (parent->child == child) {                 // First element
    if (child->next) {
      parent->child = child->next;
      parent->child->prev = child->prev;
      if (child->prev) {
        child->prev->next = 0;
      }
    } else {
      parent->child = 0;
    }
  } else if (parent->child->prev == child) {    // Last element
    parent->child->prev = child->prev;
    if (child->prev) {
      child->prev->next = 0;
    }
  } else { // Somewhere in middle
    if (child->next) {
      child->next->prev = child->prev;
    }
    if (child->prev) {
      child->prev->next = child->next;
    }
  }
  child->next = 0;
  child->prev = 0;
  child->parent = 0;
}

void jbn_remove_item(struct jbl_node *parent, struct jbl_node *child) {
  _jbn_remove_item(parent, child);
}

static struct jbl_node* _jbl_node_find(struct jbl_node *node, struct jbl_ptr *ptr, int from, int to) {
  if (!ptr || !node) {
    return 0;
  }
  struct jbl_node *n = node;

  for (int i = from; n && i < ptr->cnt && i < to; ++i) {
    if (n->type == JBV_OBJECT) {
      int ptrnlen = (int) strlen(ptr->n[i]);
      for (n = n->child; n; n = n->next) {
        if (!strncmp(n->key, ptr->n[i], n->klidx) && (ptrnlen == n->klidx)) {
          break;
        }
      }
    } else if (n->type == JBV_ARRAY) {
      if (*ptr->n[i] == '-' && *(ptr->n[i] + 1) == '\0') {
        for (n = n->child; n; n = n->next) {
          if (n->next == 0) {
            break;
          }
        }
      } else {
        int64_t idx = iwatoi(ptr->n[i]);
        for (n = n->child; n; n = n->next) {
          if (idx == n->klidx) {
            break;
          }
        }
      }
    } else {
      return 0;
    }
  }
  return n;
}

static struct jbl_node* _jbl_node_detach(struct jbl_node *target, struct jbl_ptr *path) {
  if (!path) {
    return 0;
  }
  struct jbl_node *parent = (path->cnt > 1) ? _jbl_node_find(target, path, 0, path->cnt - 1) : target;
  if (!parent) {
    return 0;
  }
  struct jbl_node *child = _jbl_node_find(parent, path, path->cnt - 1, path->cnt);
  if (!child) {
    return 0;
  }
  _jbn_remove_item(parent, child);
  return child;
}

struct jbl_node* jbn_detach2(struct jbl_node *target, struct jbl_ptr *path) {
  return _jbl_node_detach(target, path);
}

struct jbl_node* jbn_detach(struct jbl_node *target, const char *path) {
  struct jbl_ptr *jp;
  iwrc rc = _jbl_ptr_pool(path, &jp, 0);
  if (rc) {
    return 0;
  }
  struct jbl_node *res = jbn_detach2(target, jp);
  free(jp);
  return res;
}

//--- Comparison

static int _jbl_cmp_node_keys(const void *o1, const void *o2) {
  struct jbl_node *n1 = *((struct jbl_node**) o1);
  struct jbl_node *n2 = *((struct jbl_node**) o2);
  if (!n1 && !n2) {
    return 0;
  }
  if (!n2 || (n1->klidx > n2->klidx)) { // -V522
    return 1;
  } else if (!n1 || (n1->klidx < n2->klidx)) { // -V522
    return -1;
  }
  return strncmp(n1->key, n2->key, n1->klidx);
}

static uint32_t _jbl_node_count(struct jbl_node *n) {
  uint32_t ret = 0;
  n = n->child;
  while (n) {
    ret++;
    n = n->next;
  }
  return ret;
}

static int _jbl_compare_objects(struct jbl_node *n1, struct jbl_node *n2, iwrc *rcp) {
  int ret = 0;
  uint32_t cnt = _jbl_node_count(n1);
  uint32_t i = _jbl_node_count(n2);
  if (cnt > i) {
    return 1;
  } else if (cnt < i) {
    return -1;
  } else if (cnt == 0) {
    return 0;
  }
  struct jbl_node **s1 = (struct jbl_node**) malloc(2 * sizeof(struct jbl_node*) * cnt);
  if (!s1) {
    *rcp = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    return 0;
  }
  struct jbl_node **s2 = s1 + cnt;

  i = 0;
  n1 = n1->child;
  n2 = n2->child;
  while (n1 && n2) {
    s1[i] = n1;
    s2[i] = n2;
    n1 = n1->next;
    n2 = n2->next;
    ++i;
  }
  qsort((void*) s1, cnt, sizeof(struct jbl_node*), _jbl_cmp_node_keys);
  qsort((void*) s2, cnt, sizeof(struct jbl_node*), _jbl_cmp_node_keys);
  for (i = 0; i < cnt; ++i) {
    ret = _jbl_cmp_node_keys(s1 + i, s2 + i);
    if (ret) {
      goto finish;
    }
    ret = _jbl_compare_nodes(s1[i], s2[i], rcp);
    if (*rcp || ret) {
      goto finish;
    }
  }

finish:
  free((void*) s1);
  return ret;
}

static int _jbl_compare_nodes(struct jbl_node *n1, struct jbl_node *n2, iwrc *rcp) {
  if (!n1 && !n2) {
    return 0;
  } else if (!n1) {
    return -1;
  } else if (!n2) {
    return 1;
  } else if (n1->type != n2->type) {
    return (int) n1->type - (int) n2->type;
  }
  switch (n1->type) {
    case JBV_BOOL:
      return n1->vbool - n2->vbool;
    case JBV_I64:
      return n1->vi64 > n2->vi64 ? 1 : n1->vi64 < n2->vi64 ? -1 : 0;
    case JBV_F64: {
      size_t sz1, sz2;
      char b1[IWNUMBUF_SIZE];
      char b2[IWNUMBUF_SIZE];
      iwjson_ftoa(n1->vf64, b1, &sz1);
      iwjson_ftoa(n2->vf64, b2, &sz2);
      return iwafcmp(b1, sz1, b2, sz2);
    }
    case JBV_STR:
      if (n1->vsize != n2->vsize) {
        return n1->vsize - n2->vsize;
      }
      return strncmp(n1->vptr, n2->vptr, n1->vsize);
    case JBV_ARRAY:
      for (n1 = n1->child, n2 = n2->child; n1 && n2; n1 = n1->next, n2 = n2->next) {
        int res = _jbl_compare_nodes(n1, n2, rcp);
        if (res) {
          return res;
        }
      }
      if (n1) {
        return 1;
      } else if (n2) {
        return -1;
      } else {
        return 0;
      }
    case JBV_OBJECT:
      return _jbl_compare_objects(n1, n2, rcp);
    case JBV_NULL:
    case JBV_NONE:
      break;
  }
  return 0;
}

int jbn_compare_nodes(struct jbl_node *n1, struct jbl_node *n2, iwrc *rcp) {
  return _jbl_compare_nodes(n1, n2, rcp);
}

//--- Patching

static iwrc _jbl_target_apply_patch(struct jbl_node *target, const struct jbl_patch_ext *ex, struct iwpool *pool) {
  struct jbl_node *ntmp = 0;
  jbp_patch_t op = ex->p->op;
  struct jbl_ptr *path = ex->path;
  struct jbl_node *value = ex->p->vnode;
  bool oproot = ex->path->cnt == 1 && *ex->path->n[0] == '\0';

  if (op == JBP_TEST) {
    iwrc rc = 0;
    if (!value) {
      return JBL_ERROR_PATCH_NOVALUE;
    }
    if (_jbl_compare_nodes(oproot ? target : _jbl_node_find(target, path, 0, path->cnt), value, &rc)) {
      RCRET(rc);
      return JBL_ERROR_PATCH_TEST_FAILED;
    } else {
      return rc;
    }
  }
  if (oproot) { // Root operation
    if (op == JBP_REMOVE) {
      memset(target, 0, sizeof(*target));
    } else if ((op == JBP_REPLACE) || (op == JBP_ADD) || (op == JBP_ADD_CREATE)) {
      if (!value) {
        return JBL_ERROR_PATCH_NOVALUE;
      }
      memmove(target, value, sizeof(*value));
    }
  } else { // Not a root
    if ((op == JBP_REMOVE) || (op == JBP_REPLACE)) {
      _jbl_node_detach(target, ex->path);
    }
    if (op == JBP_REMOVE) {
      return 0;
    } else if ((op == JBP_MOVE) || (op == JBP_COPY) || (op == JBP_SWAP)) {
      if (op == JBP_MOVE) {
        value = _jbl_node_detach(target, ex->from);
      } else {
        value = _jbl_node_find(target, ex->from, 0, ex->from->cnt);
      }
      if (!value) {
        return JBL_ERROR_PATH_NOTFOUND;
      }
      if (op == JBP_SWAP) {
        ntmp = iwpool_calloc(sizeof(*ntmp), pool);
        if (!ntmp) {
          return iwrc_set_errno(IW_ERROR_ALLOC, errno);
        }
      }
    } else { // ADD/REPLACE/INCREMENT
      if (!value) {
        return JBL_ERROR_PATCH_NOVALUE;
      }
    }
    int lastidx = path->cnt - 1;
    struct jbl_node *parent = (path->cnt > 1) ? _jbl_node_find(target, path, 0, lastidx) : target;
    if (!parent) {
      if (op == JBP_ADD_CREATE) {
        parent = target;
        for (int i = 0; i < lastidx; ++i) {
          struct jbl_node *pn = _jbl_node_find(parent, path, i, i + 1);
          if (!pn) {
            pn = iwpool_calloc(sizeof(*pn), pool);
            if (!pn) {
              return iwrc_set_errno(IW_ERROR_ALLOC, errno);
            }
            pn->type = JBV_OBJECT;
            pn->key = path->n[i];
            pn->klidx = (int) strlen(pn->key);
            _jbn_add_item(parent, pn);
          } else if (pn->type != JBV_OBJECT) {
            return JBL_ERROR_PATCH_TARGET_INVALID;
          }
          parent = pn;
        }
      } else {
        return JBL_ERROR_PATCH_TARGET_INVALID;
      }
    }
    if (parent->type == JBV_ARRAY) {
      if ((path->n[lastidx][0] == '-') && (path->n[lastidx][1] == '\0')) {
        if (op == JBP_SWAP) {
          value = _jbl_node_detach(target, ex->from);
        }
        _jbn_add_item(parent, value); // Add to end of array
      } else {                        // Insert into the specified index
        int idx = iwatoi(path->n[lastidx]);
        int cnt = idx;
        struct jbl_node *child = parent->child;
        while (child && cnt > 0) {
          cnt--;
          child = child->next;
        }
        if (cnt > 0) {
          return JBL_ERROR_PATCH_INVALID_ARRAY_INDEX;
        }
        value->klidx = idx;
        if (child) {
          if (op == JBP_SWAP) {
            _jbl_copy_node_data(ntmp, value);
            _jbl_copy_node_data(value, child);
            _jbl_copy_node_data(child, ntmp);
          } else {
            value->parent = parent;
            value->next = child;
            value->prev = child->prev;
            child->prev = value;
            if (child == parent->child) {
              parent->child = value;
            } else {
              value->prev->next = value;
            }
            while (child) {
              child->klidx++;
              child = child->next;
            }
          }
        } else {
          if (op == JBP_SWAP) {
            value = _jbl_node_detach(target, ex->from);
          }
          _jbn_add_item(parent, value);
        }
      }
    } else if (parent->type == JBV_OBJECT) {
      struct jbl_node *child = _jbl_node_find(parent, path, path->cnt - 1, path->cnt);
      if (child) {
        if (op == JBP_INCREMENT) {
          return _jbl_increment_node_data(child, value);
        } else {
          if (op == JBP_SWAP) {
            _jbl_copy_node_data(ntmp, value);
            _jbl_copy_node_data(value, child);
            _jbl_copy_node_data(child, ntmp);
          } else {
            _jbl_copy_node_data(child, value);
          }
        }
      } else if (op != JBP_INCREMENT) {
        if (op == JBP_SWAP) {
          value = _jbl_node_detach(target, ex->from);
        }
        value->key = path->n[path->cnt - 1];
        value->klidx = (int) strlen(value->key);
        _jbn_add_item(parent, value);
      } else {
        return JBL_ERROR_PATCH_TARGET_INVALID;
      }
    } else {
      return JBL_ERROR_PATCH_TARGET_INVALID;
    }
  }
  return 0;
}

iwrc _jbl_patch_node(struct jbl_node *root, const struct jbl_patch *p, size_t cnt, struct iwpool *pool) {
  if (cnt < 1) {
    return 0;
  }
  if (!root || !p) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  size_t i = 0;
  struct jbl_patch_ext parr[cnt];
  memset(parr, 0, cnt * sizeof(struct jbl_patch_ext));
  for (i = 0; i < cnt; ++i) {
    struct jbl_patch_ext *ext = &parr[i];
    ext->p = &p[i];
    rc = _jbl_ptr_pool(p[i].path, &ext->path, pool);
    RCRET(rc);
    if (p[i].from) {
      rc = _jbl_ptr_pool(p[i].from, &ext->from, pool);
      RCRET(rc);
    }
  }
  for (i = 0; i < cnt; ++i) {
    rc = _jbl_target_apply_patch(root, &parr[i], pool);
    RCRET(rc);
  }
  return rc;
}

//--- Value assignment

void jbn_apply_from(struct jbl_node *target, struct jbl_node *from) {
  const int off = offsetof(struct jbl_node, child);
  memcpy((char*) target + off,
         (char*) from + off,
         sizeof(struct jbl_node) - off);
}

iwrc jbn_patch(struct jbl_node *root, const struct jbl_patch *p, size_t cnt, struct iwpool *pool) {
  return _jbl_patch_node(root, p, cnt, pool);
}

iwrc _jbl_create_patch(struct jbl_node *node, struct jbl_patch **pptr, int *cntp, struct iwpool *pool) {
  *pptr = 0;
  *cntp = 0;
  int i = 0;
  for (struct jbl_node *n = node->child; n; n = n->next) {
    if (n->type != JBV_OBJECT) {
      return JBL_ERROR_PATCH_INVALID;
    }
    ++i;
  }
  struct jbl_patch *p = iwpool_alloc(i * sizeof(*p), pool);
  if (!p) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  memset(p, 0, i * sizeof(*p));
  i = 0;
  for (struct jbl_node *n = node->child; n; n = n->next, ++i) {
    struct jbl_patch *pp = p + i;
    for (struct jbl_node *n2 = n->child; n2; n2 = n2->next) {
      if (!strncmp("op", n2->key, n2->klidx)) {
        if (n2->type != JBV_STR) {
          return JBL_ERROR_PATCH_INVALID;
        }
        if (!strncmp("add", n2->vptr, n2->vsize)) {
          pp->op = JBP_ADD;
        } else if (!strncmp("remove", n2->vptr, n2->vsize)) {
          pp->op = JBP_REMOVE;
        } else if (!strncmp("replace", n2->vptr, n2->vsize)) {
          pp->op = JBP_REPLACE;
        } else if (!strncmp("copy", n2->vptr, n2->vsize)) {
          pp->op = JBP_COPY;
        } else if (!strncmp("move", n2->vptr, n2->vsize)) {
          pp->op = JBP_MOVE;
        } else if (!strncmp("test", n2->vptr, n2->vsize)) {
          pp->op = JBP_TEST;
        } else if (!strncmp("increment", n2->vptr, n2->vsize)) {
          pp->op = JBP_INCREMENT;
        } else if (!strncmp("add_create", n2->vptr, n2->vsize)) {
          pp->op = JBP_ADD_CREATE;
        } else if (!strncmp("swap", n2->vptr, n2->vsize)) {
          pp->op = JBP_SWAP;
        } else {
          return JBL_ERROR_PATCH_INVALID_OP;
        }
      } else if (!strncmp("value", n2->key, n2->klidx)) {
        pp->vnode = n2;
      } else if (!strncmp("path", n2->key, n2->klidx)) {
        if (n2->type != JBV_STR) {
          return JBL_ERROR_PATCH_INVALID;
        }
        pp->path = n2->vptr;
      } else if (!strncmp("from", n2->key, n2->klidx)) {
        if (n2->type != JBV_STR) {
          return JBL_ERROR_PATCH_INVALID;
        }
        pp->from = n2->vptr;
      }
    }
  }
  *cntp = i;
  *pptr = p;
  return 0;
}

//--- Merge patch

static iwrc _jbn_allocated_destroy_visitor(int lvl, struct jbl_node *n) {
  if (n->key) {
    free((void*) n->key);
  }
  if (n->type == JBV_STR) {
    free((void*) n->vptr);
  }
  free(n);
  return 0;
}

static struct jbl_node* _jbl_merge_patch_node(
  struct jbl_node *target,
  struct jbl_node *patch,
  struct iwpool   *pool,
  iwrc            *rcp) {
  *rcp = 0;
  if (!patch) {
    return 0;
  }
  if (patch->type == JBV_OBJECT) {
    if (!target) {
      if (pool) {
        target = iwpool_alloc(sizeof(*target), pool);
        if (!target) {
          *rcp = iwrc_set_errno(IW_ERROR_ALLOC, errno);
          return 0;
        }
        memset(target, 0, sizeof(*target));
        target->key = patch->key;
      } else {
        target = malloc(sizeof(*target));
        if (!target) {
          *rcp = iwrc_set_errno(IW_ERROR_ALLOC, errno);
          return 0;
        }
        memset(target, 0, sizeof(*target));
        if (patch->key) {
          target->key = strdup(patch->key);
          if (!target->key) {
            free(target);
            *rcp = iwrc_set_errno(IW_ERROR_ALLOC, errno);
            return 0;
          }
        }
      }
      target->type = JBV_OBJECT;
      target->klidx = patch->klidx;
    } else if (target->type != JBV_OBJECT) {
      if (!pool && target->type == JBV_STR) {
        free((void*) target->vptr);
      }
      _jbl_node_reset_data(target);
      target->type = JBV_OBJECT;
    }

    patch = patch->child;
    while (patch) {
      struct jbl_node *patch_next = patch->next;
      if (patch->type == JBV_NULL) {
        struct jbl_node *next = 0;
        struct jbl_node *node = target->child;
        while (node) {
          next = node->next;
          if ((node->klidx == patch->klidx) && !strncmp(node->key, patch->key, node->klidx)) {
            _jbn_remove_item(target, node);
            if (!pool) {
              jbn_visit2(node, 0, _jbn_allocated_destroy_visitor);
            }
            break;
          }
          node = next;
        }
      } else {
        struct jbl_node *node = target->child;
        while (node) {
          if ((node->klidx == patch->klidx) && !strncmp(node->key, patch->key, node->klidx)) {
            if (pool) {
              struct jbl_node *src = _jbl_merge_patch_node(node, patch, pool, rcp);
              if (src != node) {
                _jbl_copy_node_data(node, src);
              }
            } else {
              if (node->type == JBV_STR) {
                free((void*) node->vptr);
              }
              struct jbl_node *src = _jbl_merge_patch_node(node, patch, 0, rcp);
              if (src != node) {
                _jbl_copy_node_data(node, src);
                if (node->type == JBV_STR) {
                  src->vptr = 0;
                }
                _jbn_allocated_destroy_visitor(0, src);
              }
            }
            break;
          }
          node = node->next;
        }
        if (!node) {
          _jbn_add_item(target, _jbl_merge_patch_node(0, patch, pool, rcp));
        }
      }
      patch = patch_next;
    }
    return target;
  } else if (pool) {
    return patch;
  } else {
    struct jbl_node *np;
    iwrc rc = jbn_clone(patch, &np, 0);
    if (rc) {
      *rcp = rc;
      return 0;
    }
    return np;
  }
}

iwrc jbn_merge_patch_from_json(struct jbl_node *root, const char *patchjson, struct iwpool *pool) {
  if (!root || !patchjson || !pool) {
    return IW_ERROR_INVALID_ARGS;
  }
  struct jbl_node *patch, *res;
  iwrc rc = jbn_from_json(patchjson, &patch, pool);
  RCRET(rc);
  res = _jbl_merge_patch_node(root, patch, pool, &rc);
  RCGO(rc, finish);
  if (res != root) {
    memcpy(root, res, sizeof(*root)); // -V575
  }

finish:
  return rc;
}

iwrc jbn_merge_patch_create(const char *path, struct jbl_node *val, struct iwpool *pool, struct jbl_node **out) {
  iwrc rc = 0;
  if (path == 0 || *path == '\0' || (*path == '/' && *(path + 1) == '\0')) {
    *out = val;
    return 0;
  }

  struct jbl_ptr *ptr = 0;
  rc = pool ? jbl_ptr_alloc_pool(path, &ptr, pool) : jbl_ptr_alloc(path, &ptr);
  RCGO(rc, finish);

  struct jbl_node *root, *p;
  RCB(finish, root = pool ? iwpool_calloc(sizeof(*root), pool) : calloc(1, sizeof(*root)));
  root->type = JBV_OBJECT;
  p = root;

  for (int i = 0; i < ptr->cnt; ++i) {
    struct jbl_node *n;
    const char *key = ptr->n[i];
    if (val && i == ptr->cnt - 1) {
      n = val;
    } else {
      RCB(finish, n = pool ? iwpool_calloc(sizeof(*n), pool) : calloc(1, sizeof(*root)));
      n->type = JBV_OBJECT;
    }
    p->child = n;
    n->parent = p;
    if (pool) {
      n->key = key;
    } else {
      RCB(finish, n->key = strdup(key));
    }
    n->klidx = strlen(key);
    p = n;
  }

  *out = root;

finish:
  if (!pool) {
    free(ptr);
  }
  return rc;
}

iwrc jbn_merge_patch_path(struct jbl_node *root, const char *path, struct jbl_node *val, struct iwpool *pool) {
  struct jbl_node *n = 0;
  struct iwpool *mpool = pool;
  if (!mpool) {
    RCRA(mpool = iwpool_create_empty());
  }
  iwrc rc = jbn_merge_patch_create(path, val, mpool, &n);
  if (!rc) {
    rc = jbn_merge_patch(root, n, pool);
  }
  if (mpool != pool) {
    iwpool_destroy(mpool);
  }
  return rc;
}

iwrc jbn_patch_auto(struct jbl_node *root, struct jbl_node *patch, struct iwpool *pool) {
  if (!root || !patch || !pool) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  if (patch->type == JBV_OBJECT) {
    _jbl_merge_patch_node(root, patch, pool, &rc);
  } else if (patch->type == JBV_ARRAY) {
    int cnt;
    struct jbl_patch *p;
    rc = _jbl_create_patch(patch, &p, &cnt, pool);
    RCRET(rc);
    rc = _jbl_patch_node(root, p, cnt, pool);
  } else {
    return IW_ERROR_INVALID_ARGS;
  }
  return rc;
}

iwrc jbn_merge_patch(struct jbl_node *root, struct jbl_node *patch, struct iwpool *pool) {
  if (!root || !patch || root->type != JBV_OBJECT) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  _jbl_merge_patch_node(root, patch, pool, &rc);
  return rc;
}

iwrc jbn_double_value(struct jbl_node *n, double *out) {
  if (n->type == JBV_F64) {
    *out = n->vf64;
    return 0;
  } else if (n->type == JBV_I64) {
    *out = n->vi64;
    return 0;
  } else {
    return IW_ERROR_INVALID_ARGS;
  }
}

iwrc jbn_int_value(struct jbl_node *n, int64_t *out) {
  if (n->type == JBV_I64) {
    *out = n->vi64;
    return 0;
  } else if (n->type == JBV_F64) {
    *out = n->vf64;
    return 0;
  } else {
    return IW_ERROR_INVALID_ARGS;
  }
}

//--- Error codes

static const char* _jbl_ecodefn(locale_t locale, uint32_t ecode) {
  if (!((ecode > _JBL_ERROR_START) && (ecode < _JBL_ERROR_END))) {
    return 0;
  }
  switch (ecode) {
    case JBL_ERROR_INVALID_BUFFER:
      return "Invalid struct jbl* buffer (JBL_ERROR_INVALID_BUFFER)";
    case JBL_ERROR_CREATION:
      return "Cannot create struct jbl* object (JBL_ERROR_CREATION)";
    case JBL_ERROR_INVALID:
      return "Invalid struct jbl* object (JBL_ERROR_INVALID)";
    case JBL_ERROR_PARSE_JSON:
      return "Failed to parse JSON string (JBL_ERROR_PARSE_JSON)";
    case JBL_ERROR_PARSE_UNQUOTED_STRING:
      return "Unquoted JSON string (JBL_ERROR_PARSE_UNQUOTED_STRING)";
    case JBL_ERROR_PARSE_INVALID_CODEPOINT:
      return "Invalid unicode codepoint/escape sequence (JBL_ERROR_PARSE_INVALID_CODEPOINT)";
    case JBL_ERROR_PARSE_INVALID_UTF8:
      return "Invalid utf8 string (JBL_ERROR_PARSE_INVALID_UTF8)";
    case JBL_ERROR_JSON_POINTER:
      return "Invalid JSON pointer (rfc6901) path (JBL_ERROR_JSON_POINTER)";
    case JBL_ERROR_PATH_NOTFOUND:
      return "JSON object not matched the path specified (JBL_ERROR_PATH_NOTFOUND)";
    case JBL_ERROR_PATCH_INVALID:
      return "Invalid JSON patch specified (JBL_ERROR_PATCH_INVALID)";
    case JBL_ERROR_PATCH_INVALID_OP:
      return "Invalid JSON patch operation specified (JBL_ERROR_PATCH_INVALID_OP)";
    case JBL_ERROR_PATCH_NOVALUE:
      return "No value specified in JSON patch (JBL_ERROR_PATCH_NOVALUE)";
    case JBL_ERROR_PATCH_TARGET_INVALID:
      return "Could not find target object to set value (JBL_ERROR_PATCH_TARGET_INVALID)";
    case JBL_ERROR_PATCH_INVALID_VALUE:
      return "Invalid value specified by patch (JBL_ERROR_PATCH_INVALID_VALUE)";
    case JBL_ERROR_PATCH_INVALID_ARRAY_INDEX:
      return "Invalid array index in JSON patch path (JBL_ERROR_PATCH_INVALID_ARRAY_INDEX)";
    case JBL_ERROR_PATCH_TEST_FAILED:
      return "JSON patch test operation failed (JBL_ERROR_PATCH_TEST_FAILED)";
    case JBL_ERROR_NOT_AN_OBJECT:
      return "JBL is not an object (JBL_ERROR_NOT_AN_OBJECT)";
    case JBL_ERROR_TYPE_MISMATCHED:
      return "Type of JBL object mismatched user type constraints (JBL_ERROR_TYPE_MISMATCHED)";
    case JBL_ERROR_MAX_NESTING_LEVEL_EXCEEDED:
      return "Exceeded the maximal object nesting level: " _STR(JBL_MAX_NESTING_LEVEL)
             " (JBL_ERROR_MAX_NESTING_LEVEL_EXCEEDED)";
  }
  return 0;
}

iwrc jbl_init(void) {
  static int _jbl_initialized = 0;
  if (!__sync_bool_compare_and_swap(&_jbl_initialized, 0, 1)) {
    return 0;
  }
  return iwlog_register_ecodefn(_jbl_ecodefn);
}
