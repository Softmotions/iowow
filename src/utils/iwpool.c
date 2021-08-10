#include "iwpool.h"
#include "iwutils.h"
#include "iwlog.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>

#define IWPOOL_UNIT_ALIGN_SIZE 8

/** Atomic heap unit */
typedef struct IWPOOL_UNIT {
  void *heap;
  struct IWPOOL_UNIT *next;
} IWPOOL_UNIT;

/** Memory pool */
struct _IWPOOL {
  size_t usiz;                       /**< Used size */
  size_t asiz;                       /**< Allocated size */
  char  *heap;                       /**< Current pool heap ptr */
  IWPOOL_UNIT *unit;                 /**< Current heap unit */
  void *user_data;                   /**< Associated user data */
  void  (*user_data_free_fn)(void*); /**< User data dispose function */
};

IWPOOL *iwpool_create(size_t siz) {
  IWPOOL *pool;
  siz = siz < 1 ? IWPOOL_POOL_SIZ : siz;
  siz = IW_ROUNDUP(siz, IWPOOL_UNIT_ALIGN_SIZE);
  pool = malloc(sizeof(*pool));
  if (!pool) {
    goto error;
  }
  pool->unit = malloc(sizeof(*pool->unit));
  if (!pool->unit) {
    goto error;
  }
  pool->unit->heap = malloc(siz);
  if (!pool->unit->heap) {
    goto error;
  }
  pool->asiz = siz;
  pool->heap = pool->unit->heap;
  pool->usiz = 0;
  pool->unit->next = 0;
  pool->user_data = 0;
  pool->user_data_free_fn = 0;
  return pool;

error:
  if (pool) {
    if (pool->unit && pool->unit->heap) {
      free(pool->unit->heap);
    }
    free(pool->unit);
    free(pool);
  }
  return 0;
}

IWPOOL *iwpool_create_empty(void) {
  return calloc(1, sizeof(struct _IWPOOL));
}

IW_INLINE int iwpool_extend(IWPOOL *pool, size_t siz) {
  IWPOOL_UNIT *nunit = malloc(sizeof(*nunit));
  if (!nunit) {
    return 0;
  }
  siz = IW_ROUNDUP(siz, IWPOOL_UNIT_ALIGN_SIZE);
  nunit->heap = malloc(siz);
  if (!nunit->heap) {
    free(nunit);
    return 0;
  }
  nunit->next = pool->unit;
  pool->heap = nunit->heap;
  pool->unit = nunit;
  pool->usiz = 0;
  pool->asiz = siz;
  return 1;
}

void *iwpool_alloc(size_t siz, IWPOOL *pool) {
  siz = IW_ROUNDUP(siz, IWPOOL_UNIT_ALIGN_SIZE);
  size_t usiz = pool->usiz + siz;
  if (SIZE_T_MAX - pool->usiz < siz) {
    return 0;
  }
  void *h = pool->heap;
  if (usiz > pool->asiz) {
    if (SIZE_T_MAX - pool->asiz < usiz) {
      return 0;
    }
    usiz = usiz + pool->asiz;
    if (!iwpool_extend(pool, usiz)) {
      return 0;
    }
    h = pool->heap;
  }
  pool->usiz += siz;
  pool->heap += siz;
  return h;
}

void *iwpool_calloc(size_t siz, IWPOOL *pool) {
  void *res = iwpool_alloc(siz, pool);
  if (!res) {
    return 0;
  }
  memset(res, 0, siz);
  return res;
}

char *iwpool_strndup(IWPOOL *pool, const char *str, size_t len, iwrc *rcp) {
  char *ret = iwpool_alloc(len + 1, pool);
  if (!ret) {
    *rcp = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    return 0;
  } else {
    *rcp = 0;
  }
  memcpy(ret, str, len);
  ret[len] = '\0';
  return ret;
}

char *iwpool_strdup(IWPOOL *pool, const char *str, iwrc *rcp) {
  return iwpool_strndup(pool, str, strlen(str), rcp);
}

char *iwpool_strdup2(IWPOOL *pool, const char *str) {
  iwrc rc;
  return iwpool_strndup(pool, str, strlen(str), &rc);
}

char *iwpool_strndup2(IWPOOL *pool, const char *str, size_t len) {
  iwrc rc;
  return iwpool_strndup(pool, str, len, &rc);
}

IW_INLINE int _iwpool_printf_estimate_size(const char *format, va_list ap) {
  char buf[1];
  return vsnprintf(buf, sizeof(buf), format, ap) + 1;
}

static char *_iwpool_printf_va(IWPOOL *pool, int size, const char *format, va_list ap) {
  char *wbuf = iwpool_alloc(size, pool);
  if (!wbuf) {
    return 0;
  }
  vsnprintf(wbuf, size, format, ap);
  return wbuf;
}

char *iwpool_printf(IWPOOL *pool, const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  int size = _iwpool_printf_estimate_size(format, ap);
  va_end(ap);
  va_start(ap, format);
  char *res = _iwpool_printf_va(pool, size, format, ap);
  va_end(ap);
  return res;
}

char **iwpool_split_string(
  IWPOOL *pool, const char *haystack, const char *split_chars,
  bool ignore_whitespace) {

  size_t hsz = strlen(haystack);
  char **ret = iwpool_alloc((hsz + 1) * sizeof(char*), pool);
  if (!ret) {
    return 0;
  }
  const char *sp = haystack;
  const char *ep = sp;
  int j = 0;
  for (int i = 0; *ep; ++i, ++ep) {
    const char ch = haystack[i];
    const char *sch = strchr(split_chars, ch);
    if ((ep >= sp) && (sch || (*(ep + 1) == '\0'))) {
      if (!sch && (*(ep + 1) == '\0')) {
        ++ep;
      }
      if (ignore_whitespace) {
        while (isspace(*sp)) ++sp;
        while (isspace(*(ep - 1))) --ep;
      }
      if (ep >= sp) {
        char *s = iwpool_alloc(ep - sp + 1, pool);
        if (!s) {
          return 0;
        }
        memcpy(s, sp, ep - sp);
        s[ep - sp] = '\0';
        ret[j++] = s;
        ep = haystack + i;
      }
      sp = haystack + i + 1;
    }
  }
  ret[j] = 0;
  return ret;
}

char **iwpool_printf_split(
  IWPOOL *pool,
  const char *split_chars, bool ignore_whitespace,
  const char *format, ...) {

  va_list ap;
  va_start(ap, format);
  int size = _iwpool_printf_estimate_size(format, ap);
  va_end(ap);
  char *buf = malloc(size);
  if (!buf) {
    return 0;
  }
  va_start(ap, format);
  vsnprintf(buf, size, format, ap);
  va_end(ap);
  char **ret = iwpool_split_string(pool, buf, split_chars, ignore_whitespace);
  free(buf);
  return ret;
}

void iwpool_free_fn(void *pool) {
  iwpool_destroy(pool);
}

void iwpool_user_data_set(IWPOOL *pool, void *data, void (*free_fn)(void*)) {
  if (pool->user_data_free_fn) {
    pool->user_data_free_fn(pool->user_data);
  }
  pool->user_data_free_fn = free_fn;
  pool->user_data = data;
}

void *iwpool_user_data_detach(IWPOOL *pool) {
  pool->user_data_free_fn = 0;
  return pool->user_data;
}

void *iwpool_user_data_get(IWPOOL *pool) {
  return pool->user_data;
}

size_t iwpool_allocated_size(IWPOOL *pool) {
  return pool->asiz;
}

size_t iwpool_used_size(IWPOOL *pool) {
  return pool->usiz;
}

void iwpool_destroy(IWPOOL *pool) {
  if (!pool) {
    return;
  }
  for (IWPOOL_UNIT *u = pool->unit, *next; u; u = next) {
    next = u->next;
    free(u->heap);
    free(u);
  }
  if (pool->user_data_free_fn) {
    pool->user_data_free_fn(pool->user_data);
  }
  free(pool);
}
