#include "iwjson.h"
#include "iwjson_internal.h"
#include "iwconv.h"
#include "utf8proc.h"

#include <errno.h>
#include <stdlib.h>
#include <assert.h>

#define IS_WHITESPACE(c_) ((unsigned char) (c_) <= (unsigned char) ' ')

/** JSON parsing context */
typedef struct JCTX {
  IWPOOL *pool;
  struct jbl_node *root;
  const char      *buf;
  const char      *sp;
  bool js; /**< If true parser will treat keys as js symbols */
  iwrc rc;
} JCTX;

static void _jbn_add_item(struct jbl_node *parent, struct jbl_node *node) {
  assert(parent && node);
  node->next = 0;
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
    if (node->prev) {
      node->klidx = node->prev->klidx + 1;
    } else {
      node->klidx = 0;
    }
  }
}

static struct jbl_node* _jbl_json_create_node(
  jbl_type_t       type,
  const char      *key,
  int              klidx,
  struct jbl_node *parent,
  JCTX            *ctx) {
  struct jbl_node *node;
  if (IW_LIKELY(ctx->pool)) {
    node = iwpool_calloc(sizeof(*node), ctx->pool);
  } else {
    node = calloc(1, sizeof(*node));
  }
  if (!node) {
    ctx->rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    return 0;
  }
  node->type = type;
  node->key = key;
  node->klidx = klidx;
  if (parent) {
    _jbn_add_item(parent, node);
  }
  if (!ctx->root) {
    ctx->root = node;
  }
  return node;
}

IW_INLINE void _jbl_skip_bom(JCTX *ctx) {
  const char *p = ctx->buf;
  if ((p[0] == '\xEF') && (p[1] == '\xBB') && (p[2] == '\xBF')) {
    ctx->buf += 3;
  }
}

IW_INLINE int _jbl_hex(char c) {
  if ((c >= '0') && (c <= '9')) {
    return c - '0';
  }
  if ((c >= 'a') && (c <= 'f')) {
    return c - 'a' + 10;
  }
  if ((c >= 'A') && (c <= 'F')) {
    return c - 'A' + 10;
  }
  return -1;
}

static int _jbl_unescape_json_string(JCTX *ctx, const char q, const char *p, char *d, int dlen, const char **end) {
  char c;
  char *ds = d;
  char *de = d + dlen;

  while ((c = *p++)) {
    if (c == q) { // string closing quotes
      if (end) {
        *end = p;
      }
      return (int) (d - ds);
    } else if (c == '\\') {
      switch (*p) {
        case '\\':
        case '/':
        case '"':
          if (d < de) {
            *d = *p;
          }
          ++p, ++d;
          break;
        case 'b':
          if (d < de) {
            *d = '\b';
          }
          ++p, ++d;
          break;
        case 'f':
          if (d < de) {
            *d = '\f';
          }
          ++p, ++d;
          break;
        case 'n':
        case 'r':
          if (d < de) {
            *d = '\n';
          }
          ++p, ++d;
          break;
        case 't':
          if (d < de) {
            *d = '\t';
          }
          ++p, ++d;
          break;
        case 'u': {
          uint32_t cp, cp2;
          int h1, h2, h3, h4;
          if (  ((h1 = _jbl_hex(p[1])) < 0) || ((h2 = _jbl_hex(p[2])) < 0)
             || ((h3 = _jbl_hex(p[3])) < 0) || ((h4 = _jbl_hex(p[4])) < 0)) {
            ctx->rc = JBL_ERROR_PARSE_INVALID_CODEPOINT;
            return 0;
          }
          cp = h1 << 12 | h2 << 8 | h3 << 4 | h4;
          if ((cp & 0xfc00) == 0xd800) {
            p += 6;
            if (  (p[-1] != '\\') || (*p != 'u')
               || ((h1 = _jbl_hex(p[1])) < 0) || ((h2 = _jbl_hex(p[2])) < 0)
               || ((h3 = _jbl_hex(p[3])) < 0) || ((h4 = _jbl_hex(p[4])) < 0)) {
              ctx->rc = JBL_ERROR_PARSE_INVALID_CODEPOINT;
              return 0;
            }
            cp2 = h1 << 12 | h2 << 8 | h3 << 4 | h4;
            if ((cp2 & 0xfc00) != 0xdc00) {
              ctx->rc = JBL_ERROR_PARSE_INVALID_CODEPOINT;
              return 0;
            }
            cp = 0x10000 + ((cp - 0xd800) << 10) + (cp2 - 0xdc00);
          }
          if (!utf8proc_codepoint_valid(cp)) {
            ctx->rc = JBL_ERROR_PARSE_INVALID_CODEPOINT;
            return 0;
          }
          uint8_t uchars[4];
          utf8proc_ssize_t ulen = utf8proc_encode_char(cp, uchars);
          assert(ulen <= sizeof(uchars));
          for (int i = 0; i < ulen; ++i) {
            if (d < de) {
              *d = uchars[i];
            }
            ++d;
          }
          p += 5;
          break;
        }
        default:
          if (d < de) {
            *d = c;
          }
          ++d;
      }
    } else {
      if (d < de) {
        *d = c;
      }
      ++d;
    }
  }
  ctx->rc = JBL_ERROR_PARSE_UNQUOTED_STRING;
  return 0;
}

static const char* _jbl_parse_js_key(const char **key, const char *p, JCTX *ctx) {
  char c, q = 0;
  while ((c = *p++)) {
    if (!q && (c == '\'' || c == '"')) {
      q = c;
    }
    if (q || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
      if (!q) {
        p--;
      }
      const char *sp = p;
      while ((c = *p) && ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) {
        ++p;
      }
      if (q && c != q) {
        ctx->rc = JBL_ERROR_PARSE_JSON;
        return 0;
      }
      char *kptr = iwpool_alloc(p - sp + 1, ctx->pool);
      if (!kptr) {
        ctx->rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
        return 0;
      }
      memcpy(kptr, sp, p - sp);
      kptr[p - sp] = '\0';
      *key = kptr;

      if (q) {
        ++p;
      }
      while (*p && IS_WHITESPACE(*p)) p++;
      if (*p == ':') {
        return p + 1;
      }
      ctx->rc = JBL_ERROR_PARSE_JSON;
      return 0;
    } else if (c == '}') {
      return p - 1;
    } else if (IS_WHITESPACE(c) || (c == ',')) {
      continue;
    } else {
      ctx->rc = JBL_ERROR_PARSE_JSON;
      return 0;
    }
  }
  ctx->rc = JBL_ERROR_PARSE_JSON;
  return 0;
}

static const char* _jbl_parse_json_key(const char **key, const char *p, JCTX *ctx) {
  char c;
  while ((c = *p++)) {
    if (c == '"') {
      int len = _jbl_unescape_json_string(ctx, '"', p, 0, 0, 0);
      if (ctx->rc) {
        return 0;
      }
      {
        char *kptr;
        if (IW_LIKELY(ctx->pool)) {
          kptr = iwpool_alloc(len + 1, ctx->pool);
        } else {
          kptr = malloc(len + 1);
        }
        if (!kptr) {
          ctx->rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
          return 0;
        }
        if ((len != _jbl_unescape_json_string(ctx, '"', p, kptr, len, &p)) || ctx->rc) {
          if (!ctx->rc) {
            ctx->rc = JBL_ERROR_PARSE_JSON;
          }
          return 0;
        }
        kptr[len] = '\0';
        *key = kptr;
      }

      while (*p && IS_WHITESPACE(*p)) p++;
      if (*p == ':') {
        return p + 1;
      }
      ctx->rc = JBL_ERROR_PARSE_JSON;
      return 0;
    } else if (c == '}') {
      return p - 1;
    } else if (IS_WHITESPACE(c) || (c == ',')) {
      continue;
    } else {
      ctx->rc = JBL_ERROR_PARSE_JSON;
      return 0;
    }
  }
  ctx->rc = JBL_ERROR_PARSE_JSON;
  return 0;
}

static const char* _jbl_parse_value(
  JCTX *ctx,
  int lvl,
  struct jbl_node *parent,
  const char *key, int klidx,
  const char *p) {
  if (lvl > JBL_MAX_NESTING_LEVEL) {
    ctx->rc = JBL_ERROR_MAX_NESTING_LEVEL_EXCEEDED;
    return 0;
  }

  struct jbl_node *node;
  while (1) {
    switch (*p) {
      case '\0':
        ctx->rc = JBL_ERROR_PARSE_JSON;
        return 0;
      case ' ':
      case '\t':
      case '\n':
      case '\r':
      case ',':
        ++p;
        break;
      case 'n':
        if (!strncmp(p, "null", 4)) {
          _jbl_json_create_node(JBV_NULL, key, klidx, parent, ctx);
          if (ctx->rc) {
            return 0;
          }
          return p + 4;
        }
        ctx->rc = JBL_ERROR_PARSE_JSON;
        return 0;
      case 't':
        if (!strncmp(p, "true", 4)) {
          node = _jbl_json_create_node(JBV_BOOL, key, klidx, parent, ctx);
          if (ctx->rc) {
            return 0;
          }
          node->vbool = true; // -V522
          return p + 4;
        }
        ctx->rc = JBL_ERROR_PARSE_JSON;
        return 0;
      case 'f':
        if (!strncmp(p, "false", 5)) {
          node = _jbl_json_create_node(JBV_BOOL, key, klidx, parent, ctx);
          if (ctx->rc) {
            return 0;
          }
          node->vbool = false;
          return p + 5;
        }
        ctx->rc = JBL_ERROR_PARSE_JSON;
        return 0;
      case '\'':
      case '"': {
        const char q = *p++, *end;
        if (q == '\'' && !ctx->js) {
          ctx->rc = JBL_ERROR_PARSE_JSON;
          return 0;
        }
        int len = _jbl_unescape_json_string(ctx, q, p, 0, 0, &end);
        if (ctx->rc) {
          return 0;
        }
        node = _jbl_json_create_node(JBV_STR, key, klidx, parent, ctx);
        if (ctx->rc) {
          return 0;
        }
        if (len) {
          char *vptr;
          if (IW_LIKELY(ctx->pool)) {
            vptr = iwpool_alloc(len + 1, ctx->pool);
          } else {
            vptr = malloc(len + 1);
          }
          if (!vptr) {
            ctx->rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
            return 0;
          }
          if ((len != _jbl_unescape_json_string(ctx, q, p, vptr, len, &p)) || ctx->rc) {
            if (!ctx->rc) {
              ctx->rc = JBL_ERROR_PARSE_JSON;
            }
            return 0;
          }
          vptr[len] = '\0';
          node->vptr = vptr;
          node->vsize = len;
        } else {
          p = end;
          if (IW_LIKELY(ctx->pool)) {
            node->vptr = "";
          } else {
            node->vptr = malloc(1);
            if (!node->vptr) {
              ctx->rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
              return 0;
            }
          }
          node->vsize = 0;
        }
        return p;
      }
      case '{':
        node = _jbl_json_create_node(JBV_OBJECT, key, klidx, parent, ctx);
        if (ctx->rc) {
          return 0;
        }
        ++p;
        while (1) {
          const char *nkey = 0;
          if (!ctx->js) {
            p = _jbl_parse_json_key(&nkey, p, ctx);
          } else {
            p = _jbl_parse_js_key(&nkey, p, ctx);
          }
          if (ctx->rc) {
            return 0;
          }
          if (*p == '}') {
            return p + 1;              // -V522
          }
          p = _jbl_parse_value(ctx, lvl + 1, node, nkey, nkey ? (int) strlen(nkey) : 0, p);
          if (ctx->rc) {
            return 0;
          }
        }
        break;
      case '[':
        node = _jbl_json_create_node(JBV_ARRAY, key, klidx, parent, ctx);
        if (ctx->rc) {
          return 0;
        }
        ++p;
        for (int i = 0; ; ++i) {
          p = _jbl_parse_value(ctx, lvl + 1, node, 0, i, p);
          if (ctx->rc) {
            return 0;
          }
          if (*p == ']') {
            return p + 1;
          }
        }
        break;
      case ']':
        return p;
        break;
      case '.':
      case '-':
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9': {
        if (*p == '.' && !ctx->js) {
          ctx->rc = JBL_ERROR_PARSE_JSON;
          return 0;
        }
        node = _jbl_json_create_node(JBV_I64, key, klidx, parent, ctx);
        if (ctx->rc) {
          return 0;
        }
        char *pe;
        node->vi64 = strtoll(p, &pe, 0);
        if ((pe == p) || (errno == ERANGE)) {
          if (*p != '.' && !((*p == '-' || *p == '+') && *(p + 1) == '.')) {
            ctx->rc = JBL_ERROR_PARSE_JSON;
            return 0;
          }
        }
        if ((*pe == '.') || (*pe == 'e') || (*pe == 'E') || (*pe == '-') || (*pe == '+')) {
          node->type = JBV_F64;
          node->vf64 = iwstrtod(p, &pe);
          if ((pe == p) || (errno == ERANGE)) {
            ctx->rc = JBL_ERROR_PARSE_JSON;
            return 0;
          }
        }
        return pe;
      }
      default:
        ctx->rc = JBL_ERROR_PARSE_JSON;
        return 0;
    }
  }
  return p;
}

static iwrc _jbl_node_as_json(struct jbl_node *node, jbl_json_printer pt, void *op, int lvl, jbl_print_flags_t pf) {
  iwrc rc = 0;
  bool pretty = pf & JBL_PRINT_PRETTY;
  jbl_print_flags_t ppf = pf & ~JBL_PRINT_PRETTY;
  const int indent = (ppf & JBL_PRINT_PRETTY_INDENT2) ? 2 : (ppf & JBL_PRINT_PRETTY_INDENT4) ? 4 : 1;

#define PT(data_, size_, ch_, count_) do {        \
          rc = pt(data_, size_, ch_, count_, op); \
          RCRET(rc);                              \
} while (0)

  switch (node->type) {
    case JBV_ARRAY:
      PT(0, 0, '[', 1);
      if (node->child && pretty) {
        PT(0, 0, '\n', 1);
      }
      for (struct jbl_node *n = node->child; n; n = n->next) {
        if (n->type == JBV_NONE) {
          continue;
        }
        if (pretty) {
          PT(0, 0, ' ', lvl * indent + indent);
        }
        rc = _jbl_node_as_json(n, pt, op, lvl + 1, pf);
        RCRET(rc);
        if (n->next) {
          PT(0, 0, ',', 1);
        }
        if (pretty) {
          PT(0, 0, '\n', 1);
        }
      }
      if (node->child && pretty) {
        PT(0, 0, ' ', lvl * indent);
      }
      PT(0, 0, ']', 1);
      break;
    case JBV_OBJECT:
      PT(0, 0, '{', 1);
      if (node->child && pretty) {
        PT(0, 0, '\n', 1);
      }
      for (struct jbl_node *n = node->child; n; n = n->next) {
        if (n->type == JBV_NONE) {
          continue;
        }
        if (pretty) {
          PT(0, 0, ' ', lvl * indent + indent);
        }
        rc = _jbl_write_json_string(n->key, n->klidx, pt, op, pf);
        RCRET(rc);
        if (pretty) {
          PT(": ", -1, 0, 0);
        } else {
          PT(0, 0, ':', 1);
        }
        rc = _jbl_node_as_json(n, pt, op, lvl + 1, pf);
        RCRET(rc);
        if (n->next) {
          PT(0, 0, ',', 1);
        }
        if (pretty) {
          PT(0, 0, '\n', 1);
        }
      }
      if (node->child && pretty) {
        PT(0, 0, ' ', lvl * indent);
      }
      PT(0, 0, '}', 1);
      break;
    case JBV_STR:
      rc = _jbl_write_json_string(node->vptr, node->vsize, pt, op, pf);
      break;
    case JBV_I64:
      rc = _jbl_write_int(node->vi64, pt, op);
      break;
    case JBV_F64:
      rc = _jbl_write_double(node->vf64, pt, op);
      break;
    case JBV_BOOL:
      if (node->vbool) {
        PT("true", 4, 0, 1);
      } else {
        PT("false", 5, 0, 1);
      }
      break;
    case JBV_NULL:
      PT("null", 4, 0, 1);
      break;
    case JBV_NONE:
      break;
    default:
      iwlog_ecode_error3(IW_ERROR_ASSERTION);
      return IW_ERROR_ASSERTION;
  }
#undef PT
  return rc;
}

static struct jbl_node* _jbl_clone_node_struct(struct jbl_node *src, struct iwpool *pool) {
  struct jbl_node *n = pool ? iwpool_calloc(sizeof(*n), pool) : calloc(1, sizeof(*n));
  if (!n) {
    return 0;
  }

  n->vsize = src->vsize;
  n->type = src->type;
  n->klidx = src->klidx;
  n->flags = src->flags;

  if (src->key) {
    n->key = pool ? iwpool_strndup2(pool, src->key, src->klidx) : strndup(src->key, src->klidx);
    if (!n->key) {
      return 0;
    }
  }
  switch (src->type) {
    case JBV_STR: {
      n->vptr = pool ? iwpool_strndup2(pool, src->vptr, src->vsize) : strndup(src->vptr, src->vsize);
      if (!n->vptr) {
        return 0;
      }
      break;
    }
    case JBV_I64:
      n->vi64 = src->vi64;
      break;
    case JBV_BOOL:
      n->vbool = src->vbool;
      break;
    case JBV_F64:
      n->vf64 = src->vf64;
      break;
    default:
      break;
  }

  return n;
}

static jbn_visitor_cmd_t _jbl_clone_node_visit(
  int lvl, struct jbl_node *n, const char *key, int klidx, JBN_VCTX *vctx,
  iwrc *rc) {
  if (lvl < 0) {
    return JBL_VCMD_OK;
  }
  struct jbl_node *parent = vctx->root;
  if (lvl < vctx->pos) { // Pop
    for ( ; lvl < vctx->pos; --vctx->pos) {
      parent = parent->parent;
      assert(parent);
    }
    vctx->root = parent;
    assert(vctx->root);
  } else if (lvl > vctx->pos) { // Push
    vctx->pos = lvl;
    parent = vctx->op;
    vctx->root = parent;
    assert(parent);
  }
  struct jbl_node *nn = _jbl_clone_node_struct(n, vctx->pool);
  if (!nn) {
    *rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    return JBL_VCMD_TERMINATE;
  }
  _jbn_add_item(parent, nn);
  if (nn->type >= JBV_OBJECT) {
    vctx->op = nn; // Remeber the last container object
  }
  return JBL_VCMD_OK;
}

iwrc jbn_clone(struct jbl_node *src, struct jbl_node **targetp, struct iwpool *pool) {
  *targetp = 0;
  struct jbl_node *n = _jbl_clone_node_struct(src, pool);
  if (!n) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  JBN_VCTX vctx = {
    .pool = pool,
    .root = n,
    .op = n
  };
  iwrc rc = jbn_visit(src, 0, &vctx, _jbl_clone_node_visit);
  RCRET(rc);
  *targetp = n;
  return 0;
}

iwrc jbn_as_json(struct jbl_node *node, jbl_json_printer pt, void *op, jbl_print_flags_t pf) {
  return _jbl_node_as_json(node, pt, op, 0, pf);
}

iwrc jbn_as_json_alloc(struct jbl_node *node, jbl_print_flags_t pf, char **out) {
  iwrc rc = 0;
  struct iwxstr *xstr = iwxstr_create_empty();
  if (!xstr) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  rc = jbn_as_json(node, jbl_xstr_json_printer, xstr, pf);
  if (rc) {
    iwxstr_destroy(xstr);
    *out = 0;
  } else {
    *out = iwxstr_destroy_keep_ptr(xstr);
  }
  return rc;
}

iwrc jbl_as_json_alloc(struct jbl *jbl, jbl_print_flags_t pf, char **out) {
  iwrc rc = 0;
  struct iwxstr *xstr = iwxstr_create_empty();
  if (!xstr) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  rc = jbl_as_json(jbl, jbl_xstr_json_printer, xstr, pf);
  if (rc) {
    iwxstr_destroy(xstr);
    *out = 0;
  } else {
    *out = iwxstr_destroy_keep_ptr(xstr);
  }
  return rc;
}

iwrc jbn_from_json(const char *json, struct jbl_node **node, struct iwpool *pool) {
  *node = 0;
  JCTX ctx = {
    .pool = pool,
    .buf = json
  };
  _jbl_skip_bom(&ctx);
  _jbl_parse_value(&ctx, 0, 0, 0, 0, ctx.buf);
  *node = ctx.root;
  return ctx.rc;
}

iwrc jbn_from_js(const char *json, struct jbl_node **node, struct iwpool *pool) {
  *node = 0;
  JCTX ctx = {
    .pool = pool,
    .buf = json,
    .js = true
  };
  _jbl_skip_bom(&ctx);
  _jbl_parse_value(&ctx, 0, 0, 0, 0, ctx.buf);
  *node = ctx.root;
  return ctx.rc;
}

#define _TAG_ATTR 0x01U
#define _TAG_BODY 0x02U

static iwrc _jbn_write_xml_string(
  const struct jbn_as_xml_spec *spec, unsigned type,
  jbl_json_printer pt, void *op,
  const char *str, int len) {
  iwrc rc = 0;
#define PT(data_, size_, ch_, count_) do {                        \
          rc = pt((const char*) (data_), size_, ch_, count_, op); \
          RCRET(rc);                                              \
} while (0)

  // Simplified xml escaping rules
  static char *esc[63] = {
    [9] = "&#09;",  // tab  |  Tag attr
    [10] = "&#10;", // \n   |  Tag attr
    [13] = "&#13;", // \r   |  Tag attr
    [34] = "&#34;", // "    |  Tag attr
    [38] = "&#38;", // &    |  Tag attr | body
    [39] = "&#39;", // '    |  Tag attr
    [60] = "&#60;", // <    |  Tag body
    [62] = "&#62;"  // >    |  Tag body
  };

  if (len < 0) {
    len = (int) strlen(str);
  }

  for (size_t i = 0; i < len; ++i) {
    int ch = (unsigned char) str[i];
    if (ch >= 9 && ch <= 62) {
      const char *subst = esc[ch];
      if (subst) {
        if (type == _TAG_ATTR) {
          if (ch <= 39) {
            PT(subst, 5, 0, 0);
          } else {
            PT(0, 0, ch, 1);
          }
        } else if (type == _TAG_BODY) {
          if (ch > 39 || ch == 38) {
            PT(subst, 5, 0, 0);
          } else {
            PT(0, 0, ch, 1);
          }
        } else {
          PT(0, 0, ch, 1);
        }
      } else {
        PT(0, 0, ch, 1);
      }
    } else {
      PT(0, 0, ch, 1);
    }
  }

  return rc;
#undef PT
}

static iwrc _jbn_node_write_xml_string(
  const struct jbn_as_xml_spec *spec, unsigned type,
  jbl_json_printer pt, void *op, struct jbl_node *n) {
  switch (n->type) {
    case JBV_STR:
      return _jbn_write_xml_string(spec, type, pt, op, n->vptr, n->vsize);
    case JBV_I64:
      return _jbl_write_int(n->vi64, pt, op);
    case JBV_F64:
      return _jbl_write_double(n->vf64, pt, op);
    case JBV_BOOL:
      if (n->vbool) {
        return pt("true", 4, 0, 1, op);
      } else {
        return pt("false", 5, 0, 1, op);
      }
      break;
    default:
      break;
  }
  return 0;
}

static iwrc _jbn_as_xml(struct jbl_node *node, const struct jbn_as_xml_spec *spec, int lvl) {
  iwrc rc = 0;
  int pf = spec->flags;
  bool pretty = pf & JBL_PRINT_PRETTY;
  pf &= ~JBL_PRINT_PRETTY;
  const int indent = (pf & JBL_PRINT_PRETTY_INDENT2) ? 2 : (pf & JBL_PRINT_PRETTY_INDENT4) ? 4 : 1;
  jbl_json_printer pt = spec->printer_fn;
  void *op = spec->printer_fn_data;

#define PT(data_, size_, ch_, count_) do {        \
          rc = pt(data_, size_, ch_, count_, op); \
          RCRET(rc);                              \
} while (0)

  switch (node->type) {
    case JBV_ARRAY:
      if (pretty) {
        PT(0, 0, '\n', 1);
        PT(0, 0, ' ', lvl * indent);
      }
      const char *key = node->key;
      if (!key) {
        key = lvl ? spec->array_tag : spec->root_tag;
      }
      PT(0, 0, '<', 1);
      PT(key, -1, 0, 0);
      PT(0, 0, '>', 1);

      for (struct jbl_node *n = node->child; n; n = n->next) {
        if (pretty) {
          PT(0, 0, '\n', 1);
          PT(0, 0, ' ', lvl * indent + indent);
        }
        PT(0, 0, '<', 1);
        PT(spec->array_tag, -1, 0, 0);
        PT(0, 0, '>', 1);
        rc = _jbn_as_xml(n, spec, lvl + 1);
        RCRET(rc);
        if (pretty && n->child) {
          PT(0, 0, '\n', 1);
          PT(0, 0, ' ', lvl * indent + indent);
        }
        PT("</", 2, 0, 0);
        PT(spec->array_tag, -1, 0, 0);
        PT(0, 0, '>', 1);
      }

      if (pretty) {
        PT(0, 0, '\n', 1);
        PT(0, 0, ' ', lvl * indent);
      }
      PT("</", 2, 0, 0);
      PT(key, -1, 0, 0);
      PT(0, 0, '>', 1);
      break;

    case JBV_OBJECT: {
      bool inattrs = true;
      if (pretty) {
        PT(0, 0, '\n', 1);
        PT(0, 0, ' ', lvl * indent);
      }
      const char *key = node->key;
      if (!key) {
        key = lvl ? spec->array_tag : spec->root_tag;
      }
      PT(0, 0, '<', 1);
      PT(key, -1, 0, 0);
      if (!node->child) {
        PT(0, 0, '>', 1);
      } else {
        for (struct jbl_node *n = node->child; n; n = n->next) {
          if (inattrs) {
            if (n->key && n->klidx > 1 && *n->key == spec->attr_prefix && n->child == 0) {
              PT(0, 0, ' ', 1);
              PT(n->key + 1, n->klidx - 1, 0, 0);
              PT("=\"", 2, 0, 0);
              rc = _jbn_as_xml(n, spec, -1);
              RCRET(rc);
              PT(0, 0, '"', 1);
              continue;
            } else {
              inattrs = false;
              PT(0, 0, '>', 1);
            }
          }
          if (pretty && !n->child) {
            PT(0, 0, '\n', 1);
            PT(0, 0, ' ', lvl * indent + indent);
          }
          rc = _jbn_as_xml(n, spec, lvl + 1);
          RCRET(rc);
        }
      }
      if (pretty) {
        PT(0, 0, '\n', 1);
        PT(0, 0, ' ', lvl * indent);
      }
      PT("</", 2, 0, 0);
      PT(key, -1, 0, 0);
      PT(0, 0, '>', 1);
      break;
    }

    default:
      if (lvl == -1) {
        rc = _jbn_node_write_xml_string(spec, _TAG_ATTR, pt, op, node);
        RCRET(rc);
      } else {
        const char *key = node->key;
        if (!key || strcmp(key, spec->body_attr) == 0) {
          rc = _jbn_node_write_xml_string(spec, _TAG_BODY, pt, op, node);
          RCRET(rc);
        } else {
          PT(0, 0, '<', 1);
          PT(key, -1, 0, 0);
          PT(0, 0, '>', 1);
          rc = _jbn_node_write_xml_string(spec, _TAG_BODY, pt, op, node);
          RCRET(rc);
          PT("</", 2, 0, 0);
          PT(key, -1, 0, 0);
          PT(0, 0, '>', 1);
        }
      }
      break;
  }

  return rc;
#undef PT
}

iwrc jbn_as_xml(struct jbl_node *node, const struct jbn_as_xml_spec *spec_) {
  if (!node || !spec_ || !spec_->print_xml_header) {
    return IW_ERROR_INVALID_ARGS;
  }

  struct jbn_as_xml_spec spec;
  memcpy(&spec, spec_, sizeof(spec));

  if (!spec.attr_prefix) {
    spec.attr_prefix = '>';
  }

  if (!spec.array_tag) {
    spec.array_tag = "item";
  }

  if (!spec.root_tag) {
    spec.root_tag = "root";
  }

  if (!spec.body_attr) {
    spec.body_attr = "";
  }

  if (spec.print_xml_header) {
    iwrc rc = spec.printer_fn(
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
      IW_LLEN("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"),
      0,
      0,
      spec.printer_fn_data);
    RCRET(rc);
  }

  return _jbn_as_xml(node, &spec, 0);
}
