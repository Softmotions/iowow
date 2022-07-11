#include "iwhmap.h"
#include "iwlog.h"
#include "murmur3.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#define MIN_BUCKETS 64
#define STEPS       4

struct lru_node;

typedef struct entry {
  void *key;
  void *val;
  struct lru_node *lru_node;
  uint32_t hash;
} entry_t;

typedef struct {
  entry_t *entries;
  uint32_t used;
  uint32_t total;
} bucket_t;

typedef struct lru_node {
  struct lru_node *next;
  struct lru_node *prev;
  void *key;
} lru_node_t;

typedef struct _IWHMAP {
  uint32_t  count;
  uint32_t  buckets_mask;
  bucket_t *buckets;

  int (*cmp_fn)(const void*, const void*);
  uint32_t (*hash_key_fn)(const void*);
  void (*kv_free_fn)(void*, void*);

  // LRU
  struct lru_node *lru_first;
  struct lru_node *lru_last;
  iwhmap_lru_eviction_needed lru_ev;
  void *lru_ev_user_data;

  bool int_key_as_pointer_value;
} hmap_t;

static void _noop_kv_free(void *key, void *val) {
}

void iwhmap_kv_free(void *key, void *val) {
  free(key);
  free(val);
}

IW_INLINE uint32_t _n_buckets(hmap_t *hm) {
  return hm->buckets_mask + 1;
}

static int _ptr_cmp(const void *v1, const void *v2) {
  return v1 > v2 ? 1 : v1 < v2 ? -1 : 0;
}

static int _int32_cmp(const void *v1, const void *v2) {
  intptr_t p1 = (intptr_t) v1;
  intptr_t p2 = (intptr_t) v2;
  return p1 > p2 ? 1 : p1 < p2 ? -1 : 0;
}

static int _int64_cmp(const void *v1, const void *v2) {
#ifdef IW_64
  intptr_t p1 = (intptr_t) v1;
  intptr_t p2 = (intptr_t) v2;
  return p1 > p2 ? 1 : p1 < p2 ? -1 : 0;
#else
  int64_t l1, l2;
  memcpy(&l1, v1, sizeof(l1));
  memcpy(&l2, v2, sizeof(l2));
  return l1 > l2 ? 1 : l1 < l2 ? -1 : 0;
#endif
}

// https://gist.github.com/badboy/6267743
// https://nullprogram.com/blog/2018/07/31

IW_INLINE uint32_t _hash_int32(uint32_t x) {
  x ^= x >> 17;
  x *= UINT32_C(0xed5ad4bb);
  x ^= x >> 11;
  x *= UINT32_C(0xac4c1b51);
  x ^= x >> 15;
  x *= UINT32_C(0x31848bab);
  x ^= x >> 14;
  return x;
}

IW_INLINE uint32_t _hash_int64(uint64_t x) {
  return _hash_int32(x) ^ _hash_int32(x >> 31);
}

IW_INLINE uint32_t _hash_int64_key(const void *key) {
#ifdef IW_64
  return _hash_int64((uint64_t) key);
#else
  uint64_t lv;
  memcpy(&lv, key, sizeof(lv));
  return _hash_int64(lv);
#endif
}

IW_INLINE uint32_t _hash_int32_key(const void *key) {
  return _hash_int32((uintptr_t) key);
}

IW_INLINE uint32_t _hash_buf_key(const void *key) {
  return murmur3(key, strlen(key));
}

IWHMAP* iwhmap_create(
  int (*cmp_fn)(const void*, const void*),
  uint32_t (*hash_key_fn)(const void*),
  void (*kv_free_fn)(void*, void*)
  ) {
  if (!hash_key_fn) {
    return 0;
  }
  if (!cmp_fn) {
    cmp_fn = _ptr_cmp;
  }
  if (!kv_free_fn) {
    kv_free_fn = _noop_kv_free;
  }

  hmap_t *hm = malloc(sizeof(*hm));
  if (!hm) {
    return 0;
  }
  hm->buckets = calloc(MIN_BUCKETS, sizeof(hm->buckets[0]));
  if (!hm->buckets) {
    free(hm);
    return 0;
  }
  hm->cmp_fn = cmp_fn;
  hm->hash_key_fn = hash_key_fn;
  hm->kv_free_fn = kv_free_fn;
  hm->buckets_mask = MIN_BUCKETS - 1;
  hm->count = 0;
  hm->lru_first = hm->lru_last = 0;
  hm->lru_ev = 0;
  hm->lru_ev_user_data = 0;
  hm->int_key_as_pointer_value = false;
  return hm;
}

IWHMAP* iwhmap_create_i64(void (*kv_free_fn)(void*, void*)) {
  hmap_t *hm = iwhmap_create(_int64_cmp, _hash_int64_key, kv_free_fn);
  if (hm) {
#ifdef IW_64
    hm->int_key_as_pointer_value = true;
#endif
  }
  return hm;
}

IWHMAP* iwhmap_create_i32(void (*kv_free_fn)(void*, void*)) {
  hmap_t *hm = iwhmap_create(_int32_cmp, _hash_int32_key, kv_free_fn);
  if (hm) {
    hm->int_key_as_pointer_value = true;
  }
  return hm;
}

IWHMAP* iwhmap_create_str(void (*kv_free_fn)(void*, void*)) {
  return iwhmap_create((int (*)(const void*, const void*)) strcmp, _hash_buf_key, kv_free_fn);
}

static entry_t* _entry_find(IWHMAP *hm, const void *key, uint32_t hash) {
  bucket_t *bucket = hm->buckets + (hash & hm->buckets_mask);
  entry_t *entry = bucket->entries;
  for (entry_t *end = entry + bucket->used; entry < end; ++entry) {
    if (hash == entry->hash && hm->cmp_fn(key, entry->key) == 0) {
      return entry;
    }
  }
  return 0;
}

static entry_t* _entry_add(IWHMAP *hm, void *key, uint32_t hash) {
  entry_t *entry;
  bucket_t *bucket = hm->buckets + (hash & hm->buckets_mask);

  if (bucket->used + 1 >= bucket->total) {
    if (UINT32_MAX - bucket->total < STEPS) {
      errno = EOVERFLOW;
      return 0;
    }
    uint32_t new_total = bucket->total + STEPS;
    entry_t *new_entries = realloc(bucket->entries, new_total * sizeof(new_entries[0]));
    if (!new_entries) {
      return 0;
    }
    bucket->entries = new_entries;
    bucket->total = new_total;
  }
  entry = bucket->entries;
  for (entry_t *end = entry + bucket->used; entry < end; ++entry) {
    // NOLINTNEXTLINE (clang-analyzer-core.UndefinedBinaryOperatorResult)
    if ((hash == entry->hash) && (hm->cmp_fn(key, entry->key) == 0)) {
      return entry;
    }
  }
  ++bucket->used;
  ++hm->count;

  entry->hash = hash;
  entry->key = 0;
  entry->val = 0;
  entry->lru_node = 0;

  return entry;
}

static void _rehash(hmap_t *hm, uint32_t num_buckets) {
  bucket_t *buckets = calloc(num_buckets, sizeof(*buckets));
  if (!buckets) {
    return;
  }
  assert(!(num_buckets & (num_buckets - 1)));
  assert(num_buckets != _n_buckets(hm));

  bucket_t *bucket,
           *bucket_end = hm->buckets + _n_buckets(hm);

  hmap_t hm_copy = *hm;
  hm_copy.count = 0;
  hm_copy.buckets_mask = num_buckets - 1;
  hm_copy.buckets = buckets;

  for (bucket = hm->buckets; bucket < bucket_end; ++bucket) {
    entry_t *entry_old = bucket->entries;
    entry_t *entry_old_end = entry_old + bucket->used;
    for ( ; entry_old < entry_old_end; ++entry_old) {
      entry_t *entry_new = _entry_add(&hm_copy, entry_old->key, entry_old->hash);
      if (!entry_new) {
        goto fail;
      }
      entry_new->key = entry_old->key;
      entry_new->val = entry_old->val;
      entry_new->lru_node = entry_old->lru_node;
    }
  }

  for (bucket = hm->buckets; bucket < bucket_end; ++bucket) {
    free(bucket->entries);
  }
  free(hm->buckets);

  hm->buckets = buckets;
  hm->buckets_mask = num_buckets - 1;

  assert(hm->count == hm_copy.count);
  return;

fail:
  for (bucket_end = bucket, bucket = hm->buckets; bucket < bucket_end; ++bucket) {
    free(bucket->entries);
  }
  free(buckets);
}

static void _lru_entry_update(IWHMAP *hm, entry_t *entry) {
  if (entry->lru_node) {
    entry->lru_node->key = entry->key;
    if (entry->lru_node->next) {
      struct lru_node *prev = entry->lru_node->prev;
      if (prev) {
        prev->next = entry->lru_node->next;
      } else {
        hm->lru_first = entry->lru_node->next;
      }
      entry->lru_node->next->prev = prev;
      hm->lru_last->next = entry->lru_node;
      entry->lru_node->next = 0;
      entry->lru_node->prev = hm->lru_last;
      hm->lru_last = entry->lru_node;
    }
  } else {
    entry->lru_node = malloc(sizeof(*entry->lru_node));
    if (entry->lru_node) {
      entry->lru_node->key = entry->key;
      if (hm->lru_last) {
        hm->lru_last->next = entry->lru_node;
        entry->lru_node->next = 0;
        entry->lru_node->prev = hm->lru_last;
        hm->lru_last = entry->lru_node;
      } else {
        hm->lru_first = hm->lru_last = entry->lru_node;
        entry->lru_node->next = entry->lru_node->prev = 0;
      }
    }
  }
}

static void _lru_entry_remove(IWHMAP *hm, entry_t *entry) {
  if (entry->lru_node->next) {
    struct lru_node *prev = entry->lru_node->prev;
    if (prev) {
      prev->next = entry->lru_node->next;
    } else {
      hm->lru_first = entry->lru_node->next;
    }
    entry->lru_node->next->prev = prev;
  } else if (entry->lru_node->prev) {
    entry->lru_node->prev->next = 0;
    hm->lru_last = entry->lru_node->prev;
  } else {
    hm->lru_last = hm->lru_first = 0;
  }
  free(entry->lru_node);
  entry->lru_node = 0;
}

void* iwhmap_get(IWHMAP *hm, const void *key) {
  uint32_t hash = hm->hash_key_fn(key);
  entry_t *entry = _entry_find(hm, key, hash);
  if (entry) {
    if (hm->lru_ev) {
      _lru_entry_update(hm, entry);
    }
    return entry->val;
  } else {
    return 0;
  }
}

static void _entry_remove(IWHMAP *hm, bucket_t *bucket, entry_t *entry) {
  if (entry->lru_node) {
    _lru_entry_remove(hm, entry);
  }

  hm->kv_free_fn(hm->int_key_as_pointer_value ? 0 : entry->key, entry->val);

  if (bucket->used > 1) {
    entry_t *entry_last = bucket->entries + bucket->used - 1;
    if (entry != entry_last) {
      memcpy(entry, entry_last, sizeof(*entry));
    }
  }
  --bucket->used;
  --hm->count;

  if ((hm->buckets_mask > MIN_BUCKETS - 1) && (hm->count < hm->buckets_mask / 2)) {
    _rehash(hm, _n_buckets(hm) / 2);
  } else {
    uint32_t steps_used = bucket->used / STEPS;
    uint32_t steps_total = bucket->total / STEPS;
    if (steps_used + 1 < steps_total) {
      entry_t *entries_new = realloc(bucket->entries, (steps_used + 1) * STEPS * sizeof(entries_new[0]));
      if (entries_new) {
        bucket->entries = entries_new;
        bucket->total = (steps_used + 1) * STEPS;
      }
    }
  }
}

void iwhmap_remove(IWHMAP *hm, const void *key) {
  uint32_t hash = hm->hash_key_fn(key);
  bucket_t *bucket = hm->buckets + (hash & hm->buckets_mask);
  entry_t *entry = _entry_find(hm, key, hash);
  if (entry) {
    _entry_remove(hm, bucket, entry);
  }
}

iwrc iwhmap_put(IWHMAP *hm, void *key, void *val) {
  uint32_t hash = hm->hash_key_fn(key);
  entry_t *entry = _entry_add(hm, key, hash);
  if (!entry) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }

  hm->kv_free_fn(hm->int_key_as_pointer_value ? 0 : entry->key, entry->val);

  entry->key = key;
  entry->val = val;

  if (hm->lru_ev) {
    _lru_entry_update(hm, entry);
  }

  if (hm->count > hm->buckets_mask) {
    _rehash(hm, _n_buckets(hm) * 2);
  }

  while (hm->lru_first && hm->lru_ev(hm, hm->lru_ev_user_data)) {
    hash = hm->hash_key_fn(hm->lru_first->key);
    bucket_t *bucket = hm->buckets + (hash & hm->buckets_mask);
    entry = _entry_find(hm, hm->lru_first->key, hash);
    assert(entry); // Should never be zero.
    _entry_remove(hm, bucket, entry);
  }

  return 0;
}

iwrc iwhmap_put_i32(IWHMAP *hm, int32_t key, void *val) {
  return iwhmap_put(hm, (void*) (intptr_t) key, val);
}

iwrc iwhmap_put_i64(IWHMAP *hm, int64_t key, void *val) {
  if (hm->int_key_as_pointer_value) {
    return iwhmap_put(hm, (void*) (intptr_t) key, val);
  } else {
    int64_t *kv = malloc(sizeof(*kv));
    if (!kv) {
      return iwrc_set_errno(IW_ERROR_ALLOC, errno);
    }
    memcpy(kv, &key, sizeof(*kv));
    iwrc rc = iwhmap_put(hm, kv, val);
    if (rc) {
      free(kv);
    }
    return rc;
  }
}

void* iwhmap_get_i64(IWHMAP *hm, int64_t key) {
  if (hm->int_key_as_pointer_value) {
    return iwhmap_get(hm, (void*) (intptr_t) key);
  } else {
    return iwhmap_get(hm, &key);
  }
}

uint32_t iwhmap_count(IWHMAP *hm) {
  return hm->count;
}

void iwhmap_iter_init(IWHMAP *hm, IWHMAP_ITER *iter) {
  iter->hm = hm;
  iter->entry = -1;
  iter->bucket = 0;
  iter->key = 0;
  iter->val = 0;
}

bool iwhmap_iter_next(IWHMAP_ITER *iter) {
  entry_t *entry;
  bucket_t *bucket = iter->hm->buckets + iter->bucket;

  ++iter->entry;
  if ((uint32_t) iter->entry >= bucket->used) {
    uint32_t n = _n_buckets(iter->hm);
    iter->entry = 0;
    for (++iter->bucket; iter->bucket < n; ++iter->bucket) {
      bucket = iter->hm->buckets + iter->bucket;
      if (bucket->used > 0) {
        break;
      }
    }
    if (iter->bucket >= n) {
      return false;
    }
  }
  entry = bucket->entries + iter->entry;
  iter->key = entry->key;
  iter->val = entry->val;
  return true;
}

void iwhmap_clear(IWHMAP *hm) {
  if (!hm) {
    return;
  }
  for (bucket_t *b = hm->buckets, *be = hm->buckets + _n_buckets(hm); b < be; ++b) {
    for (entry_t *e = b->entries, *ee = b->entries + b->used; e < ee; ++e) {
      hm->kv_free_fn(hm->int_key_as_pointer_value ? 0 : e->key, e->val);
    }
    free(b->entries);
    b->used = 0;
    b->total = 0;
    b->entries = 0;
  }
  if (_n_buckets(hm) > MIN_BUCKETS) {
    bucket_t *buckets_new = realloc(hm->buckets, sizeof(buckets_new[0]) * MIN_BUCKETS);
    if (buckets_new) {
      memset(buckets_new, 0, sizeof(buckets_new[0]) * MIN_BUCKETS);
      hm->buckets = buckets_new;
      hm->buckets_mask = MIN_BUCKETS - 1;
    }
  }
  hm->count = 0;
}

void iwhmap_destroy(IWHMAP *hm) {
  if (!hm) {
    return;
  }
  for (bucket_t *b = hm->buckets, *be = hm->buckets + _n_buckets(hm); b < be; ++b) {
    for (entry_t *e = b->entries, *ee = b->entries + b->used; e < ee; ++e) {
      hm->kv_free_fn(hm->int_key_as_pointer_value ? 0 : e->key, e->val);
    }
    free(b->entries);
  }
  for (lru_node_t *n = hm->lru_first; n; ) {
    lru_node_t *nn = n->next;
    free(n);
    n = nn;
  }
  free(hm->buckets);
  free(hm);
}

bool iwhmap_lru_eviction_max_count(IWHMAP *hm, void *max_count_val) {
  uint32_t max_count = (uintptr_t) max_count_val;
  return iwhmap_count(hm) > max_count;
}

void iwhmap_lru_init(IWHMAP *hm, iwhmap_lru_eviction_needed ev, void *ev_user_data) {
  hm->lru_ev = ev;
  hm->lru_ev_user_data = ev_user_data;
}
