#include "iwpool.h"
#include "iwutils.h"
#include <stdlib.h>

#define _IWPOOL_FREE(p)                     \
  do {                                      \
    if (p) {                                \
      free(p);                              \
      (p) = 0;                              \
    }                                       \
  } while(0)

/** Atomic heap unit */
typedef struct IWPOOL_UNIT {
  void               *heap;
  struct IWPOOL_UNIT *next;
} IWPOOL_UNIT;

/** Memory pool */
struct _IWPOOL {
  IWPOOL_UNIT *head;   /**< First heap unit */
  char        *heap;   /**< Heap of current heap unit */
  size_t       usiz;   /**< Used size */
  size_t       asiz;   /**< Allocated size */
  IWPOOL_UNIT *unit;   /**< Current heap unit */
};

IWPOOL *iwpool_create(size_t siz) {
  IWPOOL *pool;
  siz = siz < 1 ? IWPOOL_POOL_SIZ : siz;
  siz = IW_ROUNDUP(siz, IWPOOL_ALIGN_SIZE);
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
  pool->heap = pool->unit->heap;
  pool->head = pool->unit;
  pool->usiz = 0;
  pool->asiz = siz;
  return pool;
error:
  if (pool && pool->unit) {
    _IWPOOL_FREE(pool->unit->heap);
    _IWPOOL_FREE(pool->unit);
  }
  _IWPOOL_FREE(pool);
  return 0;
}

IW_INLINE int iwpool_extend(IWPOOL *pool, IWPOOL_UNIT *unit, size_t siz) {
  IWPOOL_UNIT *nunit =  malloc(sizeof(*nunit));
  if (!nunit) {
    return 0;
  }
  nunit->heap = calloc(1, siz);
  if (!nunit->heap) {
    _IWPOOL_FREE(nunit);
    return 0;
  }
  nunit->next = 0;
  unit->next = nunit;
  pool->heap = unit->heap;
  return 1;
}

void *iwpool_alloc(size_t siz, IWPOOL *pool) {
  siz = IW_ROUNDUP(siz, IWPOOL_ALIGN_SIZE);
  IWPOOL_UNIT  *unit = pool->unit;
  size_t usiz = pool->usiz + siz;
  size_t asiz = pool->asiz;
  void *d = pool->heap;
  if (usiz > asiz) {
    size_t nsiz = usiz << 1;
    if (!iwpool_extend(pool, unit, nsiz)) {
      return 0;
    }
    pool->usiz = 0;
    pool->asiz = nsiz;
    pool->unit = unit->next;
    d = pool->heap;
  } else {
    pool->usiz = usiz;
  }
  pool->heap += siz;
  return d;
}

void iwpool_destroy(IWPOOL *pool) {
  if (!pool) {
    return;
  }
  for (IWPOOL_UNIT *cur = pool->head, *next; cur; cur = next) {
    next = cur->next;
    _IWPOOL_FREE(cur->heap);
    _IWPOOL_FREE(cur);
  }
}
