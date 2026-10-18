#include "iwlog.h"
#include "iwjbn.h"
#include "iwjbl.h"
#include "iwconv.h"
#include "iwjson_internal.h"
#include "utf8proc.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#define IS_WHITESPACE(c_) ((unsigned char) (c_) <= (unsigned char) ' ')

/** JSON parsing context */
typedef struct JCTX {
  struct iwpool   *pool;
  struct jbl_node *root;
  const char      *buf;
  const char      *sp;
  const char      *pending_key; /**< Key allocated for the value node not created yet */
  bool js;                      /**< If true parser will treat keys as js symbols */
  iwrc rc;
} JCTX;

static struct jbl_node* _jbl_json_create_node(
  jbl_type_t       type,
  const char      *key,
  int              klidx,
  struct jbl_node *parent,
  struct JCTX     *ctx) {
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
  ctx->pending_key = 0; // The key ownership is passed to the node
  if (parent) {
    _jbn_add_item(parent, node);
  }
  if (!ctx->root) {
    ctx->root = node;
  }
  return node;
}

IW_INLINE void _jbl_skip_bom(struct JCTX *ctx) {
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

/// Decodes the JSON string literal starting at `p` (right after the opening quote).
///
/// @param ctx  Parser context
/// @param q    String quote character: `"` for JSON, `'` or `"` for js-like literals
/// @param p    Points to the first character of the string body
/// @param d    Output buffer, or zero to only measure the decoded string length
/// @param dlen Size of the output buffer
/// @param end  Optional holder of the position right after the closing quote
/// @return Length in bytes of the decoded string
static int _jbl_unescape_json_string(
  struct JCTX *ctx, const char q, const char *p, char *d, int dlen,
  const char **end) {
  char c;
  int len = 0;

  while ((c = *p++)) {
    if (c == q) { // string closing quotes
      if (end) {
        *end = p;
      }
      return len;
    } else if (c == '\\') {
      switch (*p) {
        case '\\':
        case '/':
        case '"':
          if (d && (len < dlen)) {
            d[len] = *p;
          }
          ++p, ++len;
          break;
        case 'b':
          if (d && (len < dlen)) {
            d[len] = '\b';
          }
          ++p, ++len;
          break;
        case 'f':
          if (d && (len < dlen)) {
            d[len] = '\f';
          }
          ++p, ++len;
          break;
        case 'n':
          if (d && (len < dlen)) {
            d[len] = '\n';
          }
          ++p, ++len;
          break;
        case 'r':
          if (d && (len < dlen)) {
            d[len] = '\r';
          }
          ++p, ++len;
          break;
        case 't':
          if (d && (len < dlen)) {
            d[len] = '\t';
          }
          ++p, ++len;
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
            if (d && (len < dlen)) {
              d[len] = uchars[i];
            }
            ++len;
          }
          p += 5;
          break;
        }
        default:
          if (d && (len < dlen)) {
            d[len] = c;
          }
          ++len;
      }
    } else {
      if (d && (len < dlen)) {
        d[len] = c;
      }
      ++len;
    }
  }
  ctx->rc = JBL_ERROR_PARSE_UNQUOTED_STRING;
  return 0;
}

static const char* _jbl_parse_js_key(const char **key, const char *p, struct JCTX *ctx) {
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
      char *kptr;
      if (IW_LIKELY(ctx->pool)) {
        kptr = iwpool_alloc(p - sp + 1, ctx->pool);
      } else {
        kptr = malloc(p - sp + 1);
      }
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

static const char* _jbl_parse_json_key(const char **key, const char *p, struct JCTX *ctx) {
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
  struct JCTX *ctx,
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
            char *vptr = malloc(1);
            if (!vptr) {
              ctx->rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
              return 0;
            }
            vptr[0] = '\0';
            node->vptr = vptr;
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
            if (nkey) { // A key without a value
              if (!ctx->pool) {
                free((void*) nkey);
              }
              ctx->rc = JBL_ERROR_PARSE_JSON;
              return 0;
            }
            return p + 1;
          }
          ctx->pending_key = nkey;
          p = _jbl_parse_value(ctx, lvl + 1, node, nkey, nkey ? (int) strlen(nkey) : 0, p);
          if (ctx->pending_key) { // The value node was not created
            if (!ctx->pool) {
              free((void*) ctx->pending_key);
            }
            ctx->pending_key = 0;
          }
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

iwrc _jbl_write_double(double num, jbl_json_printer pt, void *op) {
  size_t sz;
  char buf[IWNUMBUF_SIZE];
  iwjson_ftoa(num, buf, &sz);
  return pt(buf, -1, 0, 0, op);
}

iwrc _jbl_write_int(int64_t num, jbl_json_printer pt, void *op) {
  char buf[IWNUMBUF_SIZE];
  int sz = iwitoa(num, buf, sizeof(buf));
  return pt(buf, sz, 0, 0, op);
}

iwrc _jbl_write_json_string(const char *str, int len, jbl_json_printer pt, void *op, jbl_print_flags_t pf) {
  iwrc rc = pt(0, 0, '"', 1, op);
  RCRET(rc);
  static const char *specials = "btnvfr";

#define PT(data_, size_, ch_, count_) do {                        \
          rc = pt((const char*) (data_), size_, ch_, count_, op); \
          RCRET(rc);                                              \
} while (0)

  if (len < 0) {
    len = (int) strlen(str);
  }
  for (int i = 0; i < len; ++i) {
    uint8_t ch = (uint8_t) str[i];
    if ((ch == '"') || (ch == '\\')) {
      PT(0, 0, '\\', 1);
      PT(0, 0, ch, 1);
    } else if ((ch >= '\b') && (ch <= '\r') && (ch != '\v')) {
      PT(0, 0, '\\', 1);
      PT(0, 0, specials[ch - '\b'], 1);
    } else if ((ch < ' ') || (ch == 0x7f)) {
      // JSON does not allow raw control characters, `\u` escape is the only option
      char sbuf[7];
      snprintf(sbuf, sizeof(sbuf), "\\u%04X", ch);
      PT(sbuf, 6, 0, 0);
    } else if (isprint(ch)) {
      PT(0, 0, ch, 1);
    } else if (pf & JBL_PRINT_CODEPOINTS) {
      char sbuf[7]; // escaped unicode seq
      utf8proc_int32_t cp;
      utf8proc_ssize_t sz = utf8proc_iterate((const utf8proc_uint8_t*) str + i, len - i, &cp);
      if (sz < 0) {
        return JBL_ERROR_PARSE_INVALID_UTF8;
      }
      if (cp >= 0x0010000UL) {
        uint32_t hs = 0xD800, ls = 0xDC00; // surrogates
        cp -= 0x0010000UL;
        hs |= ((cp >> 10) & 0x3FF);
        ls |= (cp & 0x3FF);
        snprintf(sbuf, 7, "\\u%04X", hs);
        PT(sbuf, 6, 0, 0);
        snprintf(sbuf, 7, "\\u%04X", ls);
        PT(sbuf, 6, 0, 0);
      } else {
        snprintf(sbuf, 7, "\\u%04X", cp);
        PT(sbuf, 6, 0, 0);
      }
      i += (int) sz - 1;
    } else {
      PT(0, 0, ch, 1);
    }
  }
  rc = pt(0, 0, '"', 1, op);
  return rc;
#undef PT
}

iwrc jbl_fstream_json_printer(const char *data, int size, char ch, int count, void *op) {
  FILE *file = op;
  if (!file) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (!data) {
    // Do not put a user defined count on the stack, write it in fixed chunks
    char cbuf[64];
    memset(cbuf, ch, sizeof(cbuf));
    for (int left = count; left > 0;) {
      int chunk = MIN(left, (int) sizeof(cbuf));
      if (fwrite(cbuf, 1, chunk, file) != (size_t) chunk) {
        return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
      }
      left -= chunk;
    }
  } else {
    if (size < 0) {
      size = (int) strlen(data);
    }
    if (!count) {
      count = 1;
    }
    for (int i = 0; i < count; ++i) {
      if (fprintf(file, "%.*s", size, data) < 0) {
        return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
      }
    }
  }
  return 0;
}

iwrc jbl_xstr_json_printer(const char *data, int size, char ch, int count, void *op) {
  struct iwxstr *xstr = op;
  if (!xstr) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (!data) {
    if (count) {
      for (int i = 0; i < count; ++i) {
        iwrc rc = iwxstr_cat(xstr, &ch, 1);
        RCRET(rc);
      }
    }
  } else {
    if (size < 0) {
      size = (int) strlen(data);
    }
    if (!count) {
      count = 1;
    }
    for (int i = 0; i < count; ++i) {
      iwrc rc = iwxstr_cat(xstr, data, size);
      RCRET(rc);
    }
  }
  return 0;
}

iwrc jbl_count_json_printer(const char *data, int size, char ch, int count, void *op) {
  int *cnt = op;
  if (!data) {
    *cnt = *cnt + count;
  } else {
    if (size < 0) {
      size = (int) strlen(data);
    }
    if (!count) {
      count = 1;
    }
    *cnt = *cnt + count * size;
  }
  return 0;
}

/** Returns `true` if the container node has at least one child with a value. */
static bool _jbl_node_has_value(struct jbl_node *node) {
  for (struct jbl_node *n = node->child; n; n = n->next) {
    if (n->type != JBV_NONE) {
      return true;
    }
  }
  return false;
}

static iwrc _jbl_node_as_json(struct jbl_node *node, jbl_json_printer pt, void *op, int lvl, jbl_print_flags_t pf) {
  iwrc rc = 0;
  bool pretty = pf & JBL_PRINT_PRETTY;
  bool first = true;
  jbl_print_flags_t ppf = pf & ~JBL_PRINT_PRETTY;
  const int indent = (ppf & JBL_PRINT_PRETTY_INDENT2) ? 2 : (ppf & JBL_PRINT_PRETTY_INDENT4) ? 4 : 1;

#define PT(data_, size_, ch_, count_) do {        \
          rc = pt(data_, size_, ch_, count_, op); \
          RCRET(rc);                              \
} while (0)

  switch (node->type) {
    case JBV_ARRAY:
      PT(0, 0, '[', 1);
      if (pretty && _jbl_node_has_value(node)) {
        PT(0, 0, '\n', 1);
      }
      for (struct jbl_node *n = node->child; n; n = n->next) {
        if (n->type == JBV_NONE) { // No value, no element
          continue;
        }
        if (!first) {
          PT(0, 0, ',', 1);
          if (pretty) {
            PT(0, 0, '\n', 1);
          }
        }
        first = false;
        if (pretty) {
          PT(0, 0, ' ', lvl * indent + indent);
        }
        rc = _jbl_node_as_json(n, pt, op, lvl + 1, pf);
        RCRET(rc);
      }
      if (pretty && !first) {
        PT(0, 0, '\n', 1);
        PT(0, 0, ' ', lvl * indent);
      }
      PT(0, 0, ']', 1);
      break;
    case JBV_OBJECT:
      PT(0, 0, '{', 1);
      if (pretty && _jbl_node_has_value(node)) {
        PT(0, 0, '\n', 1);
      }
      for (struct jbl_node *n = node->child; n; n = n->next) {
        if (n->type == JBV_NONE) { // No value, no member
          continue;
        }
        if (!first) {
          PT(0, 0, ',', 1);
          if (pretty) {
            PT(0, 0, '\n', 1);
          }
        }
        first = false;
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
      }
      if (pretty && !first) {
        PT(0, 0, '\n', 1);
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

// Free a `jbl_node` allocated outside of an `iwpool` along with its
// dynamically allocated key/value strings. Required by post-order
// `jbn_visit2()` based teardown of partially built trees.
static iwrc _jbl_free_node_visitor(int lvl, struct jbl_node *n) {
  if (n->key) {
    free((void*) n->key);
  }
  if ((n->type == JBV_STR) && n->vptr) {
    free((void*) n->vptr);
  }
  free(n);
  return 0;
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
      goto error;
    }
  }
  switch (src->type) {
    case JBV_STR: {
      n->vptr = pool ? iwpool_strndup2(pool, src->vptr, src->vsize) : strndup(src->vptr, src->vsize);
      if (!n->vptr) {
        goto error;
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

error:
  if (!pool) {
    _jbl_free_node_visitor(0, n);
  }
  return 0;
}

static jbn_visitor_cmd_t _jbl_clone_node_visit(
  int lvl, struct jbl_node *n, const char *key, int klidx, struct jbn_vctx *vctx,
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
  if (!src || !targetp) {
    return IW_ERROR_INVALID_ARGS;
  }
  *targetp = 0;
  struct jbl_node *n = _jbl_clone_node_struct(src, pool);
  if (!n) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  struct jbn_vctx vctx = {
    .pool = pool,
    .root = n,
    .op = n
  };
  iwrc rc = jbn_visit(src, 0, &vctx, _jbl_clone_node_visit);
  if (rc) {
    if (!pool) {
      jbn_visit2(n, 0, _jbl_free_node_visitor);
    }
    return rc;
  }
  *targetp = n;
  return 0;
}

iwrc jbn_as_json(struct jbl_node *node, jbl_json_printer pt, void *op, jbl_print_flags_t pf) {
  if (!node || !pt) {
    return IW_ERROR_INVALID_ARGS;
  }
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

static void _jbl_parse_result(struct JCTX *ctx, struct jbl_node **node) {
  if (ctx->rc) {
    if (!ctx->pool && ctx->root) { // Release the partially built tree
      jbn_visit2(ctx->root, 0, _jbl_free_node_visitor);
    }
    *node = 0;
  } else {
    *node = ctx->root;
  }
}

static iwrc _jbl_parse(const char *json, struct jbl_node **node, struct iwpool *pool, bool js) {
  *node = 0;
  struct JCTX ctx = {
    .pool = pool,
    .buf = json,
    .js = js
  };
  _jbl_skip_bom(&ctx);
  const char *end = _jbl_parse_value(&ctx, 0, 0, 0, 0, ctx.buf);
  if (!ctx.rc) {
    for ( ; *end && IS_WHITESPACE(*end); ++end) { }
    if (*end) { // Only whitespace is allowed after the document
      ctx.rc = JBL_ERROR_PARSE_JSON;
    }
  }
  _jbl_parse_result(&ctx, node);
  return ctx.rc;
}

iwrc jbn_from_json(const char *json, struct jbl_node **node, struct iwpool *pool) {
  return _jbl_parse(json, node, pool, false);
}

iwrc jbn_from_js(const char *json, struct jbl_node **node, struct iwpool *pool) {
  return _jbl_parse(json, node, pool, true);
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
  if (!node || !spec_ || !spec_->printer_fn) {
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
