#include "iwpool.h"
#include "iwutils.h"
#include "iwlog.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define IWPOOL_UNIT_ALIGN_SIZE 8

/** Atomic heap unit */
typedef struct IWPOOL_UNIT {
  void               *heap;
  struct IWPOOL_UNIT *next;
} IWPOOL_UNIT;

/** Memory pool */
struct _IWPOOL {
  size_t       usiz;   /**< Used size */
  size_t       asiz;   /**< Allocated size */
  char        *heap;   /**< Current pool heap ptr */
  IWPOOL_UNIT *unit;   /**< Current heap unit */
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
  pool->unit->next = 0;
  pool->usiz = 0;
  pool->asiz = siz;
  pool->heap = pool->unit->heap;
  return pool;

error:
  if (pool) {
    if (pool->unit && pool->unit->heap) {
      free(pool->unit->heap);
    }
    if (pool->unit) {
      free(pool->unit);
    }
    free(pool);
  }
  return 0;
}

IW_INLINE int iwpool_extend(IWPOOL *pool, IWPOOL_UNIT *unit, size_t siz) {
  IWPOOL_UNIT *nunit =  malloc(sizeof(*nunit));
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
  IWPOOL_UNIT  *unit = pool->unit;
  siz = IW_ROUNDUP(siz, IWPOOL_UNIT_ALIGN_SIZE);
  size_t usiz = pool->usiz + siz;
  void *h = pool->heap;
  if (usiz > pool->asiz) {
    if (!iwpool_extend(pool, unit, usiz * 2)) {
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

size_t iwpool_allocated_size(IWPOOL *pool) {
  return pool->asiz;
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
  free(pool);
}
