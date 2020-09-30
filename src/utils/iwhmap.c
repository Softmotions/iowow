#include "iwhmap.h"
#include "iwlog.h"
#include "murmur3.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#define MIN_BUCKETS 64
#define STEPS 4

typedef struct {
  void *key;
  void *val;
  uint32_t hash;
} entry_t;

typedef struct {
  entry_t *entries;
  uint32_t used;
  uint32_t total;
} bucket_t;

typedef struct _IWHMAP {
  uint32_t count;
  uint32_t buckets_mask;
  bucket_t *buckets;

  int (*cmp_fn)(const void *, const void *);
  uint32_t (*hash_key_fn)(const void *);
  void (*kv_free_fn)(void *, void *);

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

IWHMAP *iwhmap_create(int (*cmp_fn)(const void *, const void *),
                      uint32_t (*hash_key_fn)(const void *),
                      void (*kv_free_fn)(void *, void *)) {

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
  hm->int_key_as_pointer_value = false;
  return hm;
}

IWHMAP *iwhmap_create_i64(void (*kv_free_fn)(void *, void *)) {
  hmap_t *hm = iwhmap_create(_int64_cmp, _hash_int64_key, kv_free_fn);
  if (hm) {
#ifdef IW_64
    hm->int_key_as_pointer_value = true;
#endif
  }
  return hm;
}

IWHMAP *iwhmap_create_i32(void (*kv_free_fn)(void *, void *)) {
  hmap_t *hm = iwhmap_create(_int32_cmp, _hash_int32_key, kv_free_fn);
  if (hm) {
    hm->int_key_as_pointer_value = true;
  }
  return hm;
}

IWHMAP *iwhmap_create_str(void (*kv_free_fn)(void *, void *)) {
  return iwhmap_create((int (*)(const void *, const void *)) strcmp, _hash_buf_key, kv_free_fn);
}

static entry_t *_entry_find(IWHMAP *hm, const void *key, uint32_t hash) {
  bucket_t *bucket = hm->buckets + (hash & hm->buckets_mask);
  entry_t *entry = bucket->entries;
  for (entry_t *end = entry + bucket->used; entry < end; ++entry) {
    if (hash == entry->hash && hm->cmp_fn(key, entry->key) == 0) {
      return entry;
    }
  }
  return 0;
}

static entry_t *_entry_add(IWHMAP *hm, void *key, uint32_t hash) {
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
    if (hash == entry->hash && hm->cmp_fn(key, entry->key) == 0) {
      return entry;
    }
  }
  ++bucket->used;
  ++hm->count;

  entry->hash = hash;
  entry->key = 0;
  entry->val = 0;

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
    for (; entry_old < entry_old_end; ++entry_old) {
      entry_t *entry_new = _entry_add(&hm_copy, entry_old->key, entry_old->hash);
      if (!entry_new) {
        goto fail;
      }
      entry_new->key = entry_old->key;
      entry_new->val = entry_old->val;
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

iwrc iwhmap_put(IWHMAP *hm, void *key, void *val) {
  uint32_t hash = hm->hash_key_fn(key);
  entry_t *entry = _entry_add(hm, key, hash);
  if (!entry) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }

  hm->kv_free_fn(hm->int_key_as_pointer_value ? 0 : entry->key, entry->val);

  entry->key = key;
  entry->val = val;

  if (hm->count > hm->buckets_mask) {
    _rehash(hm, _n_buckets(hm) * 2);
  }
  return 0;
}

void *iwhmap_get(IWHMAP *hm, const void *key) {
  uint32_t hash = hm->hash_key_fn(key);
  entry_t *entry = _entry_find(hm, key, hash);
  if (entry) {
    return entry->val;
  } else {
    return 0;
  }
}

void iwhmap_remove(IWHMAP *hm, const void *key) {
  uint32_t hash = hm->hash_key_fn(key);
  bucket_t *bucket = hm->buckets + (hash & hm->buckets_mask);

  entry_t *entry = _entry_find(hm, key, hash);
  if (!entry) {
    return;
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

  if (hm->buckets_mask > MIN_BUCKETS - 1 && hm->count < hm->buckets_mask / 2) {
    _rehash(hm, _n_buckets(hm) / 2);
  } else {
    uint32_t steps_used = bucket->used / STEPS;
    uint32_t steps_total = bucket->total / STEPS;

    if (steps_used + 1 < steps_total) {
      entry_t *entries_new = realloc(bucket->entries, (steps_used + 1) * STEPS * sizeof(entries_new[0]));
      if (entries_new) {
        bucket->entries = entries_new;
        bucket->total = (steps_used  + 1) * STEPS;
      }
    }
  }
}

int iwhmap_count(IWHMAP *hm) {
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
  free(hm->buckets);
  free(hm);
}
