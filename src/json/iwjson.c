#include "iwjson.h"
#include "iwconv.h"
#include "utf8proc.h"
#include "iwjson_internal.h"

#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>

#define _STRX(x) #x
#define _STR(x)  _STRX(x)

IW_INLINE int _jbl_printf_estimate_size(const char *format, va_list ap) {
  char buf[1];
  int ret = vsnprintf(buf, sizeof(buf), format, ap);
  if (ret < 0) {
    return ret;
  } else {
    return ret + 1;
  }
}

IW_INLINE void _jbn_remove_item(struct jbl_node *parent, struct jbl_node *child);
static void _jbn_add_item(struct jbl_node *parent, struct jbl_node *node);

void jbl_node_as_plain_value(const struct jbl_node *n, struct jbl_plain_value *v) {
  memset(v, 0, sizeof(*v));
  memcpy(v, (char*) n + offsetof(struct jbl_node, vsize), sizeof(*n) - offsetof(struct jbl_node, vsize));
}

void jbl_plain_value_set_node(const struct jbl_plain_value *v, struct jbl_node *n) {
  memcpy((char*) n + offsetof(struct jbl_node, vsize), v, sizeof(*v));
}

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

iwrc jbl_create_empty_object(struct jbl **jblp) {
  *jblp = calloc(1, sizeof(**jblp));
  if (!*jblp) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  binn_create(&(*jblp)->bn, BINN_OBJECT, 0, 0);
  return 0;
}

iwrc jbl_create_empty_array(struct jbl **jblp) {
  *jblp = calloc(1, sizeof(**jblp));
  if (!*jblp) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  binn_create(&(*jblp)->bn, BINN_LIST, 0, 0);
  return 0;
}

void jbl_set_user_data(struct jbl *jbl, void *user_data, void (*user_data_free_fn)(void*)) {
  binn_set_user_data(&jbl->bn, user_data, user_data_free_fn);
}

void* jbl_get_user_data(struct jbl *jbl) {
  return jbl->bn.user_data;
}

iwrc jbl_set_int64(struct jbl *jbl, const char *key, int64_t v) {
  jbl_type_t t = jbl_type(jbl);
  if (((t != JBV_OBJECT) && (t != JBV_ARRAY)) || !jbl->bn.writable) {
    return JBL_ERROR_CREATION;
  }
  binn *bv = &jbl->bn;
  if (key) {
    if (t == JBV_OBJECT) {
      if (!binn_object_set_int64(bv, key, v)) {
        return JBL_ERROR_CREATION;
      }
    } else {
      return JBL_ERROR_CREATION;
    }
    return 0;
  } else if (t == JBV_ARRAY) {
    if (!binn_list_add_int64(bv, v)) {
      return JBL_ERROR_CREATION;
    }
    return 0;
  }
  return JBL_ERROR_INVALID;
}

iwrc jbl_set_f64(struct jbl *jbl, const char *key, double v) {
  jbl_type_t t = jbl_type(jbl);
  if (((t != JBV_OBJECT) && (t != JBV_ARRAY)) || !jbl->bn.writable) {
    return JBL_ERROR_CREATION;
  }
  binn *bv = &jbl->bn;
  if (key) {
    if (t == JBV_OBJECT) {
      if (!binn_object_set_double(bv, key, v)) {
        return JBL_ERROR_CREATION;
      }
    } else {
      return JBL_ERROR_CREATION;
    }
    return 0;
  } else if (t == JBV_ARRAY) {
    if (!binn_list_add_double(bv, v)) {
      return JBL_ERROR_CREATION;
    }
    return 0;
  }
  return JBL_ERROR_INVALID;
}

iwrc jbl_set_string(struct jbl *jbl, const char *key, const char *v) {
  jbl_type_t t = jbl_type(jbl);
  if (((t != JBV_OBJECT) && (t != JBV_ARRAY)) || !jbl->bn.writable) {
    return JBL_ERROR_CREATION;
  }
  binn *bv = &jbl->bn;
  if (key) {
    if (t == JBV_OBJECT) {
      if (!binn_object_set_str(bv, key, v)) {
        return JBL_ERROR_CREATION;
      }
    } else {
      return JBL_ERROR_CREATION;
    }
    return 0;
  } else if (t == JBV_ARRAY) {
    if (!binn_list_add_const_str(bv, v)) {
      return JBL_ERROR_CREATION;
    }
    return 0;
  }
  return JBL_ERROR_INVALID;
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

iwrc jbl_set_bool(struct jbl *jbl, const char *key, bool v) {
  jbl_type_t t = jbl_type(jbl);
  if (((t != JBV_OBJECT) && (t != JBV_ARRAY)) || !jbl->bn.writable) {
    return JBL_ERROR_CREATION;
  }
  binn *bv = &jbl->bn;
  if (key) {
    if (t == JBV_OBJECT) {
      if (!binn_object_set_bool(bv, key, v)) {
        return JBL_ERROR_CREATION;
      }
    } else {
      return JBL_ERROR_CREATION;
    }
    return 0;
  } else if (t == JBV_ARRAY) {
    if (!binn_list_add_bool(bv, v)) {
      return JBL_ERROR_CREATION;
    }
    return 0;
  }
  return JBL_ERROR_INVALID;
}

iwrc jbl_set_null(struct jbl *jbl, const char *key) {
  jbl_type_t t = jbl_type(jbl);
  if (((t != JBV_OBJECT) && (t != JBV_ARRAY)) || !jbl->bn.writable) {
    return JBL_ERROR_CREATION;
  }
  binn *bv = &jbl->bn;
  if (key) {
    if (t == JBV_OBJECT) {
      if (!binn_object_set_null(bv, key)) {
        return JBL_ERROR_CREATION;
      }
    } else {
      return JBL_ERROR_CREATION;
    }
    return 0;
  } else if (t == JBV_ARRAY) {
    if (!binn_list_add_null(bv)) {
      return JBL_ERROR_CREATION;
    }
    return 0;
  }
  return JBL_ERROR_INVALID;
}

iwrc jbl_set_empty_array(struct jbl *jbl, const char *key) {
  struct jbl *v = 0;
  iwrc rc = jbl_create_empty_array(&v);
  RCGO(rc, finish);
  rc = jbl_set_nested(jbl, key, v);
finish:
  jbl_destroy(&v);
  return rc;
}

iwrc jbl_set_empty_object(struct jbl *jbl, const char *key) {
  struct jbl *v = 0;
  iwrc rc = jbl_create_empty_object(&v);
  RCGO(rc, finish);
  rc = jbl_set_nested(jbl, key, v);
finish:
  jbl_destroy(&v);
  return rc;
}

iwrc jbl_set_nested(struct jbl *jbl, const char *key, struct jbl *v) {
  jbl_type_t t = jbl_type(jbl);
  if (((t != JBV_OBJECT) && (t != JBV_ARRAY)) || !jbl->bn.writable) {
    return JBL_ERROR_CREATION;
  }
  binn *bv = &jbl->bn;
  if (key) {
    if (t == JBV_OBJECT) {
      if (!binn_object_set_value(bv, key, &v->bn)) {
        return JBL_ERROR_CREATION;
      }
    } else {
      return JBL_ERROR_CREATION;
    }
    return 0;
  } else if (t == JBV_ARRAY) {
    if (!binn_list_add_value(bv, &v->bn)) {
      return JBL_ERROR_CREATION;
    }
    return 0;
  }
  return JBL_ERROR_INVALID;
}

iwrc jbl_from_buf_keep(struct jbl **jblp, void *buf, size_t bufsz, bool keep_on_destroy) {
  int type, size = 0, count = 0;
  if ((bufsz < MIN_BINN_SIZE) || !binn_is_valid_header(buf, &type, &count, &size, NULL)) {
    return JBL_ERROR_INVALID_BUFFER;
  }
  if (size > bufsz) {
    return JBL_ERROR_INVALID_BUFFER;
  }
  *jblp = calloc(1, sizeof(**jblp));
  if (!*jblp) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  struct jbl *jbl = *jblp;
  jbl->bn.header = BINN_MAGIC;
  jbl->bn.type = type;
  jbl->bn.ptr = buf;
  jbl->bn.size = size;
  jbl->bn.count = count;
  jbl->bn.freefn = keep_on_destroy ? 0 : free;
  return 0;
}

iwrc jbl_clone(struct jbl *src, struct jbl **targetp) {
  *targetp = calloc(1, sizeof(**targetp));
  struct jbl *t = *targetp;
  if (!t) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  binn *bn = binn_copy(&src->bn);
  if (!bn) {
    return JBL_ERROR_CREATION;
  }
  t->node = 0;
  bn->allocated = 0;
  memcpy(&t->bn, bn, sizeof(*bn));
  free(bn);
  return 0;
}

IW_EXPORT iwrc jbl_object_copy_to(struct jbl *src, struct jbl *target) {
  iwrc rc = 0;
  // According to binn spec keys are not null terminated
  // and key length is not more than 255 bytes
  char *key, kbuf[256];
  int klen;
  struct jbl *holder = 0;
  struct jbl_iterator it;

  if ((jbl_type(src) != JBV_OBJECT) || (jbl_type(target) != JBV_OBJECT)) {
    return JBL_ERROR_NOT_AN_OBJECT;
  }
  RCC(rc, finish, jbl_create_iterator_holder(&holder));
  RCC(rc, finish, jbl_iterator_init(src, &it));
  while (jbl_iterator_next(&it, holder, &key, &klen)) {
    memcpy(kbuf, key, klen);
    kbuf[klen] = '\0';
    RCC(rc, finish, jbl_set_nested(target, kbuf, holder));
  }

finish:
  jbl_destroy(&holder);
  return rc;
}

iwrc jbl_clone_into_pool(struct jbl *src, struct jbl **targetp, struct iwpool *pool) {
  *targetp = 0;
  if (src->bn.writable && src->bn.dirty) {
    if (!binn_save_header(&src->bn)) {
      return JBL_ERROR_INVALID;
    }
  }
  struct jbl *jbl = iwpool_alloc(sizeof(*jbl) + src->bn.size, pool);
  if (!jbl) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  jbl->node = 0;
  memcpy(&jbl->bn, &src->bn, sizeof(jbl->bn));
  jbl->bn.ptr = (char*) jbl + sizeof(*jbl);
  memcpy(jbl->bn.ptr, src->bn.ptr, src->bn.size);
  jbl->bn.freefn = 0;
  *targetp = jbl;
  return 0;
}

iwrc jbl_from_buf_keep_onstack(struct jbl *jbl, void *buf, size_t bufsz) {
  int type, size = 0, count = 0;
  if ((bufsz < MIN_BINN_SIZE) || !binn_is_valid_header(buf, &type, &count, &size, NULL)) {
    return JBL_ERROR_INVALID_BUFFER;
  }
  if (size > bufsz) {
    return JBL_ERROR_INVALID_BUFFER;
  }
  memset(jbl, 0, sizeof(*jbl));
  jbl->bn.header = BINN_MAGIC;
  jbl->bn.type = type;
  jbl->bn.ptr = buf;
  jbl->bn.size = size;
  jbl->bn.count = count;
  return 0;
}

iwrc jbl_from_buf_keep_onstack2(struct jbl *jbl, void *buf) {
  int type, size = 0, count = 0;
  if (!binn_is_valid_header(buf, &type, &count, &size, NULL)) {
    return JBL_ERROR_INVALID_BUFFER;
  }
  memset(jbl, 0, sizeof(*jbl));
  jbl->bn.header = BINN_MAGIC;
  jbl->bn.type = type;
  jbl->bn.ptr = buf;
  jbl->bn.size = size;
  jbl->bn.count = count;
  return 0;
}

void jbl_destroy(struct jbl **jblp) {
  if (*jblp) {
    struct jbl *jbl = *jblp;
    binn_free(&jbl->bn);
    free(jbl);
    *jblp = 0;
  }
}

iwrc jbl_create_iterator_holder(struct jbl **jblp) {
  *jblp = calloc(1, sizeof(**jblp));
  if (!*jblp) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  return 0;
}

iwrc jbl_iterator_init(struct jbl *jbl, struct jbl_iterator *iter) {
  int btype = jbl->bn.type;
  if ((btype != BINN_OBJECT) && (btype != BINN_LIST) && (btype != BINN_MAP)) {
    memset(iter, 0, sizeof(*iter));
    return 0;
  }
  binn_iter *biter = (binn_iter*) iter;
  if (!binn_iter_init(biter, &jbl->bn, btype)) {
    return JBL_ERROR_CREATION;
  }
  return 0;
}

bool jbl_iterator_next(struct jbl_iterator *iter, struct jbl *holder, char **pkey, int *klen) {
  binn_iter *biter = (binn_iter*) iter;
  if (pkey) {
    *pkey = 0;
  }
  if (klen) {
    *klen = 0;
  }
  if (!iter || (iter->type == 0)) {
    return false;
  }
  if (iter->type == BINN_LIST) {
    if (klen) {
      *klen = iter->current;
    }
    return binn_list_next(biter, &holder->bn);
  } else {
    return binn_read_next_pair2(iter->type, biter, klen, pkey, &holder->bn);
  }
  return false;
}

IW_INLINE jbl_type_t _jbl_binn_type(int btype) {
  switch (btype) {
    case BINN_NULL:
      return JBV_NULL;
    case BINN_STRING:
      return JBV_STR;
    case BINN_OBJECT:
    case BINN_MAP:
      return JBV_OBJECT;
    case BINN_LIST:
      return JBV_ARRAY;
    case BINN_BOOL:
    case BINN_TRUE:
    case BINN_FALSE:
      return JBV_BOOL;
    case BINN_UINT8:
    case BINN_UINT16:
    case BINN_UINT32:
    case BINN_UINT64:
    case BINN_INT8:
    case BINN_INT16:
    case BINN_INT32:
    case BINN_INT64:
      return JBV_I64;
    case BINN_FLOAT32:
    case BINN_FLOAT64:
      return JBV_F64;
    default:
      return JBV_NONE;
  }
}

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
  return (size_t) jbl->bn.size;
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
  for (size_t i = 0; i < len; ++i) {
    uint8_t ch = (uint8_t) str[i];
    if ((ch == '"') || (ch == '\\')) {
      PT(0, 0, '\\', 1);
      PT(0, 0, ch, 1);
    } else if ((ch >= '\b') && (ch <= '\r')) {
      PT(0, 0, '\\', 1);
      PT(0, 0, specials[ch - '\b'], 1);
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
      i += sz - 1;
    } else {
      PT(0, 0, ch, 1);
    }
  }
  rc = pt(0, 0, '"', 1, op);
  return rc;
#undef PT
}

static iwrc _jbl_as_json(binn *bn, jbl_json_printer pt, void *op, int lvl, jbl_print_flags_t pf) {
  iwrc rc = 0;
  binn bv;
  binn_iter iter;
  int lv;
  int64_t llv;
  double dv;
  char key[MAX_BIN_KEY_LEN + 1];
  bool pretty = pf & JBL_PRINT_PRETTY;

#define PT(data_, size_, ch_, count_) do {        \
          rc = pt(data_, size_, ch_, count_, op); \
          RCGO(rc, finish);                       \
} while (0)

  switch (bn->type) {
    case BINN_LIST:
      if (!binn_iter_init(&iter, bn, bn->type)) {
        rc = JBL_ERROR_INVALID;
        goto finish;
      }
      PT(0, 0, '[', 1);
      if (bn->count && pretty) {
        PT(0, 0, '\n', 1);
      }
      for (int i = 0; binn_list_next(&iter, &bv); ++i) {
        if (pretty) {
          PT(0, 0, ' ', lvl + 1);
        }
        rc = _jbl_as_json(&bv, pt, op, lvl + 1, pf);
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

    case BINN_OBJECT:
    case BINN_MAP:
      if (!binn_iter_init(&iter, bn, bn->type)) {
        rc = JBL_ERROR_INVALID;
        goto finish;
      }
      PT(0, 0, '{', 1);
      if (bn->count && pretty) {
        PT(0, 0, '\n', 1);
      }
      if (bn->type == BINN_OBJECT) {
        for (int i = 0; binn_object_next(&iter, key, &bv); ++i) {
          if (pretty) {
            PT(0, 0, ' ', lvl + 1);
          }
          rc = _jbl_write_json_string(key, -1, pt, op, pf);
          RCGO(rc, finish);
          if (pretty) {
            PT(": ", -1, 0, 0);
          } else {
            PT(0, 0, ':', 1);
          }
          rc = _jbl_as_json(&bv, pt, op, lvl + 1, pf);
          RCGO(rc, finish);
          if (i < bn->count - 1) {
            PT(0, 0, ',', 1);
          }
          if (pretty) {
            PT(0, 0, '\n', 1);
          }
        }
      } else {
        for (int i = 0; binn_map_next(&iter, &lv, &bv); ++i) {
          if (pretty) {
            PT(0, 0, ' ', lvl + 1);
          }
          PT(0, 0, '"', 1);
          rc = _jbl_write_int(lv, pt, op);
          RCGO(rc, finish);
          PT(0, 0, '"', 1);
          if (pretty) {
            PT(": ", -1, 0, 0);
          } else {
            PT(0, 0, ':', 1);
          }
          rc = _jbl_as_json(&bv, pt, op, lvl + 1, pf);
          RCGO(rc, finish);
          if (i < bn->count - 1) {
            PT(0, 0, ',', 1);
          }
          if (pretty) {
            PT(0, 0, '\n', 1);
          }
        }
      }
      if (bn->count && pretty) {
        PT(0, 0, ' ', lvl);
      }
      PT(0, 0, '}', 1);
      break;

    case BINN_STRING:
      rc = _jbl_write_json_string(bn->ptr, -1, pt, op, pf);
      break;
    case BINN_UINT8:
      llv = bn->vuint8;
      goto loc_int;
    case BINN_UINT16:
      llv = bn->vuint16;
      goto loc_int;
    case BINN_UINT32:
      llv = bn->vuint32;
      goto loc_int;
    case BINN_INT8:
      llv = bn->vint8; // NOLINT(bugprone-signed-char-misuse)
      goto loc_int;
    case BINN_INT16:
      llv = bn->vint16;
      goto loc_int;
    case BINN_INT32:
      llv = bn->vint32;
      goto loc_int;
    case BINN_INT64:
      llv = bn->vint64;
      goto loc_int;
    case BINN_UINT64: // overflow?
      llv = (int64_t) bn->vuint64;
loc_int:
      rc = _jbl_write_int(llv, pt, op);
      break;

    case BINN_FLOAT32:
      dv = bn->vfloat;
      goto loc_float;
    case BINN_FLOAT64:
      dv = bn->vdouble;
loc_float:
      rc = _jbl_write_double(dv, pt, op);
      break;

    case BINN_TRUE:
      PT("true", 4, 0, 0);
      break;
    case BINN_FALSE:
      PT("false", 5, 0, 0);
      break;
    case BINN_BOOL:
      PT(bn->vbool ? "true" : "false", -1, 0, 1);
      break;
    case BINN_NULL:
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

iwrc jbl_fstream_json_printer(const char *data, int size, char ch, int count, void *op) {
  FILE *file = op;
  if (!file) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (!data) {
    if (count) {
      char cbuf[count]; // TODO: review overflow
      memset(cbuf, ch, sizeof(cbuf));
      size_t wc = fwrite(cbuf, 1, count, file);
      if (wc != sizeof(cbuf)) {
        return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
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

int64_t jbl_get_i64(struct jbl *jbl) {
  assert(jbl);
  switch (jbl->bn.type) {
    case BINN_UINT8:
      return jbl->bn.vuint8;
    case BINN_UINT16:
      return jbl->bn.vuint16;
    case BINN_UINT32:
      return jbl->bn.vuint32;
    case BINN_UINT64:
      return jbl->bn.vuint64;
    case BINN_INT8:
      return jbl->bn.vint8;
    case BINN_INT16:
      return jbl->bn.vint16;
    case BINN_INT32:
      return jbl->bn.vint32;
    case BINN_INT64:
      return jbl->bn.vint64;
    case BINN_BOOL:
      return jbl->bn.vbool;
    case BINN_FLOAT32:
      return (int64_t) jbl->bn.vfloat;
    case BINN_FLOAT64:
      return (int64_t) jbl->bn.vdouble;
    default:
      return 0;
  }
}

int32_t jbl_get_i32(struct jbl *jbl) {
  return (int32_t) jbl_get_i64(jbl);
}

double jbl_get_f64(struct jbl *jbl) {
  assert(jbl);
  switch (jbl->bn.type) {
    case BINN_FLOAT64:
      return jbl->bn.vdouble;
    case BINN_FLOAT32:
      return jbl->bn.vfloat;
    case BINN_UINT8:
      return jbl->bn.vuint8;
    case BINN_UINT16:
      return jbl->bn.vuint16;
    case BINN_UINT32:
      return jbl->bn.vuint32;
    case BINN_UINT64:
      return jbl->bn.vuint64;
    case BINN_INT8:
      return jbl->bn.vint8;
    case BINN_INT16:
      return jbl->bn.vint16;
    case BINN_INT32:
      return jbl->bn.vint32;
    case BINN_INT64:
      return jbl->bn.vint64;
    case BINN_BOOL:
      return jbl->bn.vbool;
    default:
      return 0.0;
  }
}

const char* jbl_get_str(struct jbl *jbl) {
  assert(jbl && jbl->bn.type == BINN_STRING);
  if (jbl->bn.type != BINN_STRING) {
    return 0;
  } else {
    return jbl->bn.ptr;
  }
}

size_t jbl_copy_strn(struct jbl *jbl, char *buf, size_t bufsz) {
  assert(jbl && buf && jbl->bn.type == BINN_STRING);
  if (jbl->bn.type != BINN_STRING) {
    return 0;
  }
  size_t slen = strlen(jbl->bn.ptr);
  size_t ret = MIN(slen, bufsz);
  memcpy(buf, jbl->bn.ptr, ret);
  return ret;
}

jbl_type_t jbl_object_get_type(struct jbl *jbl, const char *key) {
  if (jbl->bn.type != BINN_OBJECT) {
    return JBV_NONE;
  }
  binn bv;
  if (!binn_object_get_value(&jbl->bn, key, &bv)) {
    return JBV_NONE;
  }
  return _jbl_binn_type(bv.type);
}

iwrc jbl_object_get_i64(struct jbl *jbl, const char *key, int64_t *out) {
  *out = 0;
  if (jbl->bn.type != BINN_OBJECT) {
    return JBL_ERROR_NOT_AN_OBJECT;
  }
  int64 v;
  if (!binn_object_get_int64(&jbl->bn, key, &v)) {
    return JBL_ERROR_CREATION;
  }
  *out = v;
  return 0;
}

iwrc jbl_object_get_f64(struct jbl *jbl, const char *key, double *out) {
  *out = 0.0;
  if (jbl->bn.type != BINN_OBJECT) {
    return JBL_ERROR_NOT_AN_OBJECT;
  }
  if (!binn_object_get_double(&jbl->bn, key, out)) {
    return JBL_ERROR_CREATION;
  }
  return 0;
}

iwrc jbl_object_get_bool(struct jbl *jbl, const char *key, bool *out) {
  *out = false;
  if (jbl->bn.type != BINN_OBJECT) {
    return JBL_ERROR_NOT_AN_OBJECT;
  }
  BOOL v;
  if (!binn_object_get_bool(&jbl->bn, key, &v)) {
    return JBL_ERROR_CREATION;
  }
  *out = v;
  return 0;
}

iwrc jbl_object_get_str(struct jbl *jbl, const char *key, const char **out) {
  *out = 0;
  if (jbl->bn.type != BINN_OBJECT) {
    return JBL_ERROR_NOT_AN_OBJECT;
  }
  if (!binn_object_get_str(&jbl->bn, key, (char**) out)) {
    return JBL_ERROR_CREATION;
  }
  return 0;
}

iwrc jbl_object_get_fill_jbl(struct jbl *jbl, const char *key, struct jbl *out) {
  if (jbl->bn.type != BINN_OBJECT) {
    return JBL_ERROR_NOT_AN_OBJECT;
  }
  binn_free(&out->bn);
  if (!binn_object_get_value(&jbl->bn, key, &out->bn)) {
    return JBL_ERROR_CREATION;
  }
  return 0;
}

iwrc jbl_as_buf(struct jbl *jbl, void **buf, size_t *size) {
  assert(jbl && buf && size);
  if (jbl->bn.writable && jbl->bn.dirty) {
    if (!binn_save_header(&jbl->bn)) {
      return JBL_ERROR_INVALID;
    }
  }
  *buf = jbl->bn.ptr;
  *size = (size_t) jbl->bn.size;
  return 0;
}

//----------------------------------------------------------------------------------------------------------

static iwrc _jbl_ptr_pool(const char *path, struct jbl_ptr **jpp, struct iwpool *pool) {
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

iwrc _jbl_visit(binn_iter *iter, int lvl, struct jbl_vctx *vctx, jbl_visitor visitor) {
  iwrc rc = 0;
  binn *bn = vctx->bn;
  jbl_visitor_cmd_t cmd;
  int idx;
  binn bv;

  if (lvl > JBL_MAX_NESTING_LEVEL) {
    return JBL_ERROR_MAX_NESTING_LEVEL_EXCEEDED;
  }
  if (!iter) {
    binn_iter it;
    if (!BINN_IS_CONTAINER_TYPE(bn->type)) {
      return JBL_ERROR_INVALID;
    }
    if (!binn_iter_init(&it, bn, bn->type)) {
      return JBL_ERROR_INVALID;
    }
    rc = _jbl_visit(&it, 0, vctx, visitor);
    return rc;
  }

  switch (iter->type) {
    case BINN_OBJECT: {
      char key[MAX_BIN_KEY_LEN + 1];
      while (!vctx->terminate && binn_object_next(iter, key, &bv)) {
        cmd = visitor(lvl, &bv, key, -1, vctx, &rc);
        RCRET(rc);
        if (cmd & JBL_VCMD_TERMINATE) {
          vctx->terminate = true;
          break;
        }
        if (!(cmd & JBL_VCMD_SKIP_NESTED) && BINN_IS_CONTAINER_TYPE(bv.type)) {
          binn_iter it;
          if (!binn_iter_init(&it, &bv, bv.type)) {
            return JBL_ERROR_INVALID;
          }
          rc = _jbl_visit(&it, lvl + 1, vctx, visitor);
          RCRET(rc);
        }
      }
      break;
    }
    case BINN_MAP: {
      while (!vctx->terminate && binn_map_next(iter, &idx, &bv)) {
        cmd = visitor(lvl, &bv, 0, idx, vctx, &rc);
        RCRET(rc);
        if (cmd & JBL_VCMD_TERMINATE) {
          vctx->terminate = true;
          break;
        }
        if (!(cmd & JBL_VCMD_SKIP_NESTED) && BINN_IS_CONTAINER_TYPE(bv.type)) {
          binn_iter it;
          if (!binn_iter_init(&it, &bv, bv.type)) {
            return JBL_ERROR_INVALID;
          }
          rc = _jbl_visit(&it, lvl + 1, vctx, visitor);
          RCRET(rc);
        }
      }
      break;
    }
    case BINN_LIST: {
      for (idx = 0; !vctx->terminate && binn_list_next(iter, &bv); ++idx) {
        cmd = visitor(lvl, &bv, 0, idx, vctx, &rc);
        RCRET(rc);
        if (cmd & JBL_VCMD_TERMINATE) {
          vctx->terminate = true;
          break;
        }
        if (!(cmd & JBL_VCMD_SKIP_NESTED) && BINN_IS_CONTAINER_TYPE(bv.type)) {
          binn_iter it;
          if (!binn_iter_init(&it, &bv, bv.type)) {
            return JBL_ERROR_INVALID;
          }
          rc = _jbl_visit(&it, lvl + 1, vctx, visitor);
          RCRET(rc);
        }
      }
      break;
    }
  }
  return rc;
}

iwrc jbn_visit(struct jbl_node *node, int lvl, JBN_VCTX *vctx, JBN_VISITOR visitor) {
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

IW_INLINE bool _jbl_visitor_update_jptr_cursor(struct jbl_vctx *vctx, int lvl, const char *key, int idx) {
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

IW_INLINE bool _jbn_visitor_update_jptr_cursor(JBN_VCTX *vctx, int lvl, const char *key, int idx) {
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

static jbl_visitor_cmd_t _jbl_get_visitor2(
  int lvl, binn *bv, const char *key, int idx, struct jbl_vctx *vctx,
  iwrc *rc) {
  struct jbl_ptr *jp = vctx->op;
  assert(jp);
  if (_jbl_visitor_update_jptr_cursor(vctx, lvl, key, idx)) { // Pointer matched
    struct jbl *jbl = vctx->result;
    memcpy(&jbl->bn, bv, sizeof(*bv));
    jbl->node = 0;
    jbl->bn.freefn = 0;
    vctx->found = true;
    return JBL_VCMD_TERMINATE;
  } else if (jp->cnt < lvl + 1) {
    return JBL_VCMD_SKIP_NESTED;
  }
  return JBL_VCMD_OK;
}

static jbl_visitor_cmd_t _jbl_get_visitor(
  int lvl, binn *bv, const char *key, int idx, struct jbl_vctx *vctx,
  iwrc *rc) {
  struct jbl_ptr *jp = vctx->op;
  assert(jp);
  if (_jbl_visitor_update_jptr_cursor(vctx, lvl, key, idx)) { // Pointer matched
    struct jbl *jbl = malloc(sizeof(struct jbl));
    if (!jbl) {
      *rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
      return JBL_VCMD_TERMINATE;
    }
    memcpy(&jbl->bn, bv, sizeof(*bv));
    jbl->node = 0;
    jbl->bn.allocated = 0;
    jbl->bn.freefn = 0;
    vctx->result = jbl;
    return JBL_VCMD_TERMINATE;
  } else if (jp->cnt < lvl + 1) {
    return JBL_VCMD_SKIP_NESTED;
  }
  return JBL_VCMD_OK;
}

bool _jbl_at(struct jbl *jbl, struct jbl_ptr *jp, struct jbl *res) {
  if (jp->cnt == 0) {
    memcpy(&res->bn, &jbl->bn, sizeof(res->bn));
    res->node = 0;
    res->bn.allocated = 0;
    res->bn.freefn = 0;
    return true;
  }
  struct jbl_vctx vctx = {
    .bn = &jbl->bn,
    .op = jp,
    .pos = -1,
    .result = res
  };
  _jbl_visit(0, 0, &vctx, _jbl_get_visitor2);
  return vctx.found;
}

iwrc jbl_at2(struct jbl *jbl, struct jbl_ptr *jp, struct jbl **res) {
  if (jp->cnt == 0) {
    struct jbl *rv;
    RCRA(rv = malloc(sizeof(struct jbl)));
    memcpy(&rv->bn, &jbl->bn, sizeof(rv->bn));
    rv->node = 0;
    rv->bn.allocated = 0;
    rv->bn.freefn = 0;
    *res = rv;
    return 0;
  }
  struct jbl_vctx vctx = {
    .bn = &jbl->bn,
    .op = jp,
    .pos = -1
  };
  iwrc rc = _jbl_visit(0, 0, &vctx, _jbl_get_visitor);
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

static jbn_visitor_cmd_t _jbn_get_visitor(
  int              lvl,
  struct jbl_node *n,
  const char      *key,
  int              klidx,
  JBN_VCTX        *vctx,
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
  JBN_VCTX vctx = {
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

static void _jbn_add_item(struct jbl_node *parent, struct jbl_node *node) {
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
      return IW_ERROR_INVALID_ARGS;
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
      return IW_ERROR_INVALID_ARGS;
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
      return IW_ERROR_INVALID_ARGS;
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
      return IW_ERROR_INVALID_ARGS;
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
      return IW_ERROR_INVALID_ARGS;
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
      return IW_ERROR_INVALID_ARGS;
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
      return IW_ERROR_INVALID_ARGS;
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

static iwrc _jbl_create_node(
  JBLDRCTX         *ctx,
  const binn       *bv,
  struct jbl_node  *parent,
  const char       *key,
  int               klidx,
  struct jbl_node **node,
  bool              clone_strings) {
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
  if (key && clone_strings) {
    if (IW_LIKELY(ctx->pool)) {
      n->key = iwpool_strndup(ctx->pool, key, klidx, &rc);
      RCGO(rc, finish);
    } else {
      RCB(finish, n->key = strndup(key, klidx));
    }
  } else {
    n->key = key;
  }
  n->klidx = klidx;
  n->parent = parent;
  switch (bv->type) {
    case BINN_NULL:
      n->type = JBV_NULL;
      break;
    case BINN_STRING:
      n->type = JBV_STR;
      if (!clone_strings) {
        n->vptr = bv->ptr;
        n->vsize = bv->size;
      } else {
        if (IW_LIKELY(ctx->pool)) {
          n->vptr = iwpool_strndup(ctx->pool, bv->ptr, bv->size, &rc);
          RCGO(rc, finish);
        } else {
          RCB(finish, n->vptr = strndup(bv->ptr, bv->size));
        }
        n->vsize = bv->size;
      }
      break;
    case BINN_OBJECT:
    case BINN_MAP:
      n->type = JBV_OBJECT;
      break;
    case BINN_LIST:
      n->type = JBV_ARRAY;
      break;
    case BINN_TRUE:
      n->type = JBV_BOOL;
      n->vbool = true;
      break;
    case BINN_FALSE:
      n->type = JBV_BOOL;
      n->vbool = false;
      break;
    case BINN_BOOL:
      n->type = JBV_BOOL;
      n->vbool = bv->vbool;
      break;
    case BINN_UINT8:
      n->vi64 = bv->vuint8;
      n->type = JBV_I64;
      break;
    case BINN_UINT16:
      n->vi64 = bv->vuint16;
      n->type = JBV_I64;
      break;
    case BINN_UINT32:
      n->vi64 = bv->vuint32;
      n->type = JBV_I64;
      break;
    case BINN_UINT64:
      n->vi64 = bv->vuint64;
      n->type = JBV_I64;
      break;
    case BINN_INT8:
      n->vi64 = bv->vint8; // NOLINT(bugprone-signed-char-misuse)
      n->type = JBV_I64;
      break;
    case BINN_INT16:
      n->vi64 = bv->vint16;
      n->type = JBV_I64;
      break;
    case BINN_INT32:
      n->vi64 = bv->vint32;
      n->type = JBV_I64;
      break;
    case BINN_INT64:
      n->vi64 = bv->vint64;
      n->type = JBV_I64;
      break;
    case BINN_FLOAT32:
    case BINN_FLOAT64:
      n->vf64 = bv->vdouble;
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
  JBLDRCTX        *ctx,
  const binn      *bn,
  struct jbl_node *parent,
  char            *key,
  int              klidx,
  bool             clone_strings) {
  binn bv;
  binn_iter iter;
  iwrc rc = 0;

  switch (bn->type) {
    case BINN_OBJECT:
    case BINN_MAP:
      rc = _jbl_create_node(ctx, bn, parent, key, klidx, &parent, clone_strings);
      RCRET(rc);
      if (!ctx->root) {
        ctx->root = parent;
      }
      if (!binn_iter_init(&iter, (binn*) bn, bn->type)) {
        return JBL_ERROR_INVALID;
      }
      if (bn->type == BINN_OBJECT) {
        while (binn_object_next2(&iter, &key, &klidx, &bv)) {
          rc = _jbl_node_from_binn_impl(ctx, &bv, parent, key, klidx, clone_strings);
          RCRET(rc);
        }
      } else if (bn->type == BINN_MAP) {
        while (binn_map_next(&iter, &klidx, &bv)) {
          rc = _jbl_node_from_binn_impl(ctx, &bv, parent, 0, klidx, clone_strings);
          RCRET(rc);
        }
      }
      break;
    case BINN_LIST:
      rc = _jbl_create_node(ctx, bn, parent, key, klidx, &parent, clone_strings);
      RCRET(rc);
      if (!ctx->root) {
        ctx->root = parent;
      }
      if (!binn_iter_init(&iter, (binn*) bn, bn->type)) {
        return JBL_ERROR_INVALID;
      }
      for (int i = 0; binn_list_next(&iter, &bv); ++i) {
        rc = _jbl_node_from_binn_impl(ctx, &bv, parent, 0, i, clone_strings);
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

iwrc _jbl_node_from_binn(const binn *bn, struct jbl_node **node, bool clone_strings, struct iwpool *pool) {
  JBLDRCTX ctx = {
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

IW_INLINE struct jbl_node* _jbl_node_find2(struct jbl_node *node, struct jbl_ptr *ptr) {
  if (!node || !ptr || !ptr->cnt) {
    return 0;
  }
  return _jbl_node_find(node, ptr, 0, ptr->cnt - 1);
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
  struct jbl_node **s1 = malloc(2 * sizeof(struct jbl_node*) * cnt);
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
  qsort(s1, cnt, sizeof(struct jbl_node*), _jbl_cmp_node_keys);
  qsort(s2, cnt, sizeof(struct jbl_node*), _jbl_cmp_node_keys);
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
  free(s1);
  return ret;
}

int _jbl_compare_nodes(struct jbl_node *n1, struct jbl_node *n2, iwrc *rcp) {
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

static iwrc _jbl_from_node_impl(binn *res, struct jbl_node *node) {
  iwrc rc = 0;
  switch (node->type) {
    case JBV_OBJECT:
      if (!binn_create(res, BINN_OBJECT, 0, NULL)) {
        return JBL_ERROR_CREATION;
      }
      for (struct jbl_node *n = node->child; n; n = n->next) {
        binn bv;
        rc = _jbl_from_node_impl(&bv, n);
        RCRET(rc);
        if (!binn_object_set_value2(res, n->key, n->klidx, &bv)) {
          rc = JBL_ERROR_CREATION;
        }
        binn_free(&bv);
        RCRET(rc);
      }
      break;
    case JBV_ARRAY:
      if (!binn_create(res, BINN_LIST, 0, NULL)) {
        return JBL_ERROR_CREATION;
      }
      for (struct jbl_node *n = node->child; n; n = n->next) {
        binn bv;
        rc = _jbl_from_node_impl(&bv, n);
        RCRET(rc);
        if (!binn_list_add_value(res, &bv)) {
          rc = JBL_ERROR_CREATION;
        }
        binn_free(&bv);
        RCRET(rc);
      }
      break;
    case JBV_STR:
      binn_init_item(res);
      binn_set_string(res, node->vptr, node->vsize);
      break;
    case JBV_I64:
      binn_init_item(res);
      binn_set_int64(res, node->vi64);
      break;
    case JBV_F64:
      binn_init_item(res);
      binn_set_double(res, node->vf64);
      break;
    case JBV_BOOL:
      binn_init_item(res);
      binn_set_bool(res, node->vbool);
      break;
    case JBV_NULL:
      binn_init_item(res);
      binn_set_null(res);
      break;
    case JBV_NONE:
      rc = JBL_ERROR_CREATION;
      break;
  }
  return rc;
}

iwrc _jbl_binn_from_node(binn *res, struct jbl_node *node) {
  iwrc rc = _jbl_from_node_impl(res, node);
  if (!rc) {
    if (res->writable && res->dirty) {
      binn_save_header(res);
    }
  }
  return rc;
}

iwrc _jbl_from_node(struct jbl *jbl, struct jbl_node *node) {
  jbl->node = node;
  return _jbl_binn_from_node(&jbl->bn, node);
}

static iwrc _jbl_patch_node(struct jbl_node *root, const struct jbl_patch *p, size_t cnt, struct iwpool *pool) {
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

static iwrc _jbl_patch(struct jbl *jbl, const struct jbl_patch *p, size_t cnt, struct iwpool *pool) {
  if (cnt < 1) {
    return 0;
  }
  if (!jbl || !p) {
    return IW_ERROR_INVALID_ARGS;
  }
  binn bv;
  binn *bn;
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
  binn_free(&jbl->bn);
  if (bn) {
    if (bn->writable && bn->dirty) {
      binn_save_header(bn);
    }
    memcpy(&jbl->bn, bn, sizeof(jbl->bn));
    jbl->bn.allocated = 0;
  } else {
    memset(&jbl->bn, 0, sizeof(jbl->bn));
    root->type = JBV_NONE;
  }
  return rc;
}

int _jbl_cmp_atomic_values(struct jbl *v1, struct jbl *v2) {
  jbl_type_t t1 = jbl_type(v1);
  jbl_type_t t2 = jbl_type(v2);
  if (t1 != t2) {
    return (int) t1 - (int) t2;
  }
  switch (t1) {
    case JBV_BOOL:
    case JBV_I64: {
      int64_t vv1 = jbl_get_i64(v1);
      int64_t vv2 = jbl_get_i64(v2);
      return vv1 > vv2 ? 1 : vv1 < vv2 ? -1 : 0;
    }
    case JBV_STR:
      return strcmp(jbl_get_str(v1), jbl_get_str(v2)); // -V575
    case JBV_F64: {
      double vv1 = jbl_get_f64(v1);
      double vv2 = jbl_get_f64(v2);
      return vv1 > vv2 ? 1 : vv1 < vv2 ? -1 : 0;
    }
    default:
      return 0;
  }
}

bool _jbl_is_eq_atomic_values(struct jbl *v1, struct jbl *v2) {
  jbl_type_t t1 = jbl_type(v1);
  jbl_type_t t2 = jbl_type(v2);
  if (t1 != t2) {
    return false;
  }
  switch (t1) {
    case JBV_BOOL:
    case JBV_I64:
      return jbl_get_i64(v1) == jbl_get_i64(v2);
    case JBV_STR:
      return !strcmp(jbl_get_str(v1), jbl_get_str(v2)); // -V575
    case JBV_F64:
      return jbl_get_f64(v1) == jbl_get_f64(v2); // -V550
    case JBV_OBJECT:
    case JBV_ARRAY:
      return false;
    default:
      return true;
  }
}

// --------------------------- Public API

void jbn_apply_from(struct jbl_node *target, struct jbl_node *from) {
  const int off = offsetof(struct jbl_node, child);
  memcpy((char*) target + off,
         (char*) from + off,
         sizeof(struct jbl_node) - off);
}

iwrc jbl_to_node(struct jbl *jbl, struct jbl_node **node, bool clone_strings, struct iwpool *pool) {
  if (jbl->node) {
    *node = jbl->node;
    return 0;
  }
  return _jbl_node_from_binn(&jbl->bn, node, clone_strings, pool);
}

iwrc jbn_patch(struct jbl_node *root, const struct jbl_patch *p, size_t cnt, struct iwpool *pool) {
  return _jbl_patch_node(root, p, cnt, pool);
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

static iwrc _jbl_create_patch(struct jbl_node *node, struct jbl_patch **pptr, int *cntp, struct iwpool *pool) {
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
    memset(jbl, 0, sizeof(*jbl));
    return 0;
  }
  binn bv = { 0 };
  iwrc rc = _jbl_binn_from_node(&bv, node);
  RCRET(rc);
  binn_free(&jbl->bn);
  memcpy(&jbl->bn, &bv, sizeof(jbl->bn));
  jbl->bn.allocated = 0;
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
        target->key = strdup(patch->key);
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
    n->key = pool ? key : strdup(key);
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

iwrc jbl_merge_patch(struct jbl *jbl, const char *patchjson) {
  if (!jbl || !patchjson) {
    return IW_ERROR_INVALID_ARGS;
  }
  binn bv;
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

  binn_free(&jbl->bn);
  memcpy(&jbl->bn, &bv, sizeof(jbl->bn));
  jbl->bn.allocated = 0;

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
