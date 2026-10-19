#include "iwhmap.h"
#include "iwlog.h"
#include "wyhash32.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

/// Initial number of entry slots.
#define INITIAL_CAPACITY 64u

/// Maximal number of entry slots: keeps slot indices within the `int32_t` range
/// of `struct iwhmap_iter::entry` and prevents capacity arithmetic overflows.
#define MAX_CAPACITY (1u << 30)

/// The entries table is grown once the number of entries reaches `capacity * 3 / 4`.
#define LOAD_PERCENT 3u

/// The entries table is shrunk once the number of entries falls below `capacity / 8`.
#define SHRINK_DIVISOR 8u

/// Initial number of LRU list nodes allocated.
#define INITIAL_LRU_NODES 64u

/// LRU node reference: a node index plus one, zero means "no node".
#define LRU_NONE 0u

/// LRU list node. Nodes are kept in a slab and are referred by index,
/// so map entries stay compact (no pointer per entry) while the node slab
/// is allocated only when LRU mode is used.
struct lru_node {
  uint32_t next;  ///< Reference of the next (more recent) node.
  uint32_t prev;  ///< Reference of the previous (less recent) node.
  void    *key;
};

/// Hash map entry, also used as an entries table slot: an empty slot is
/// marked by `hash == 0` and terminates the probe sequence.
///
/// `hash` keeps a normalized key hash (see `_nhash()`), which allows to reject
/// most candidates without calling `cmp_fn`.
struct entry {
  void    *key;
  void    *val;
  uint32_t hash;
  uint32_t lru_idx;  ///< LRU node reference, `LRU_NONE` if the entry is not in the LRU list.
};

/// Entries are stored in a single flat, power of two sized table and are
/// resolved with linear probing. Removals shift the rest of the probe cluster
/// backwards, so the table holds no tombstones and any empty slot is a valid
/// probe terminator.
struct iwhmap {
  struct entry *entries;
  uint32_t      capacity;       ///< Number of slots: a power of two.
  uint32_t      capacity_mask;  ///< `capacity - 1`
  uint32_t      count;          ///< Number of entries stored.

  int (*cmp_fn)(const void*, const void*);
  uint32_t (*hash_key_fn)(const void*);
  void (*kv_free_fn)(void*, void*);

  // LRU
  struct lru_node *lru_nodes;
  uint32_t lru_nodes_capacity;
  uint32_t lru_nodes_count;  ///< Number of allocated LRU node slots.
  uint32_t lru_free;         ///< Head of the free LRU node list.
  uint32_t lru_first;        ///< Least recently used node.
  uint32_t lru_last;         ///< Most recently used node.
  iwhmap_lru_eviction_needed lru_ev;
  void *lru_ev_user_data;

  bool int_key_as_pointer_value;
};

static void _noop_kv_free(void *key, void *val) {
}

static void _noop_uint64_kv_free(void *key, void *val) {
  if (key) {
    free(key);
  }
}

void iwhmap_kv_free(void *key, void *val) {
  free(key);
  free(val);
}

/// Maximal number of entries the table of given capacity can hold.
IW_INLINE uint32_t _max_load(uint32_t capacity) {
  return capacity - capacity / (LOAD_PERCENT + 1);
}

/// Normalizes the key hash so that `0` is reserved to mark an empty slot.
IW_INLINE uint32_t _nhash(uint32_t hash) {
  hash += 1;
  return hash ? hash : 1;
}

static int _ptr_cmp(const void *v1, const void *v2) {
  return v1 > v2 ? 1 : v1 < v2 ? -1 : 0;
}

static int _uint32_cmp(const void *v1, const void *v2) {
  intptr_t p1 = (intptr_t) v1;
  intptr_t p2 = (intptr_t) v2;
  return p1 > p2 ? 1 : p1 < p2 ? -1 : 0;
}

static int _uint64_cmp(const void *v1, const void *v2) {
  if (sizeof(uintptr_t) >= sizeof(uint64_t)) {
    intptr_t p1 = (intptr_t) v1;
    intptr_t p2 = (intptr_t) v2;
    return p1 > p2 ? 1 : p1 < p2 ? -1 : 0;
  } else {
    uint64_t l1, l2;
    memcpy(&l1, v1, sizeof(l1));
    memcpy(&l2, v2, sizeof(l2));
    return l1 > l2 ? 1 : l1 < l2 ? -1 : 0;
  }
}

// https://gist.github.com/badboy/6267743
// https://nullprogram.com/blog/2018/07/31

IW_INLINE uint32_t _hash_uint32(uint32_t x) {
  x ^= x >> 17;
  x *= UINT32_C(0xed5ad4bb);
  x ^= x >> 11;
  x *= UINT32_C(0xac4c1b51);
  x ^= x >> 15;
  x *= UINT32_C(0x31848bab);
  x ^= x >> 14;
  return x;
}

IW_INLINE uint32_t _hash_uint64(uint64_t x) {
  return _hash_uint32(x) ^ _hash_uint32(x >> 31);
}

IW_INLINE uint32_t _hash_uint64_key(const void *key) {
  #ifdef IW_64
  return _hash_uint64((uint64_t) key);
  #else
  uint64_t lv = 0;
  memcpy(&lv, key, sizeof(key));
  return _hash_uint64(lv);
  #endif
}

IW_INLINE uint32_t _hash_uint32_key(const void *key) {
  return _hash_uint32((uintptr_t) key);
}

IW_INLINE uint32_t _hash_buf_key(const void *key) {
  return wyhash32(key, strlen(key), 0x3017f643);
}

static struct entry* _entries_alloc(uint32_t capacity) {
  return calloc(capacity, sizeof(struct entry));
}

struct iwhmap* iwhmap_create(
  int (*cmp_fn)(const void*, const void*),
  uint32_t (*hash_key_fn)(const void*),
  void (*kv_free_fn)(void*, void*)) {
  if (!hash_key_fn) {
    return 0;
  }
  if (!cmp_fn) {
    cmp_fn = _ptr_cmp;
  }
  if (!kv_free_fn) {
    kv_free_fn = _noop_kv_free;
  }

  struct iwhmap *hm = malloc(sizeof(*hm));
  if (!hm) {
    return 0;
  }
  hm->entries = _entries_alloc(INITIAL_CAPACITY);
  if (!hm->entries) {
    free(hm);
    return 0;
  }
  hm->capacity = INITIAL_CAPACITY;
  hm->capacity_mask = INITIAL_CAPACITY - 1;
  hm->count = 0;
  hm->cmp_fn = cmp_fn;
  hm->hash_key_fn = hash_key_fn;
  hm->kv_free_fn = kv_free_fn;
  hm->lru_nodes = 0;
  hm->lru_nodes_capacity = 0;
  hm->lru_nodes_count = 0;
  hm->lru_free = LRU_NONE;
  hm->lru_first = LRU_NONE;
  hm->lru_last = LRU_NONE;
  hm->lru_ev = 0;
  hm->lru_ev_user_data = 0;
  hm->int_key_as_pointer_value = false;
  return hm;
}

struct iwhmap* iwhmap_create_u64(void (*kv_free_fn)(void*, void*)) {
  if (!kv_free_fn) {
    kv_free_fn = _noop_uint64_kv_free;
  }
  struct iwhmap *hm = iwhmap_create(_uint64_cmp, _hash_uint64_key, kv_free_fn);
  if (hm) {
    if (sizeof(uintptr_t) >= sizeof(uint64_t)) {
      hm->int_key_as_pointer_value = true;
    }
  }
  return hm;
}

struct iwhmap* iwhmap_create_u32(void (*kv_free_fn)(void*, void*)) {
  struct iwhmap *hm = iwhmap_create(_uint32_cmp, _hash_uint32_key, kv_free_fn);
  if (hm) {
    hm->int_key_as_pointer_value = true;
  }
  return hm;
}

struct iwhmap* iwhmap_create_str(void (*kv_free_fn)(void*, void*)) {
  return iwhmap_create((int (*)(const void*, const void*)) strcmp, _hash_buf_key, kv_free_fn);
}

/// Looks up the entry with the given key.
/// @param nhash Normalized key hash, see `_nhash()`.
/// @return Entry pointer or zero if there is no such key.
static struct entry* _entry_find(struct iwhmap *hm, const void *key, uint32_t nhash) {
  struct entry *entries = hm->entries;
  uint32_t mask = hm->capacity_mask;
  for (uint32_t i = nhash & mask; ; i = (i + 1) & mask) {
    struct entry *entry = entries + i;
    // An empty slot terminates the probe sequence: removals never leave holes.
    if (!entry->hash) {
      return 0;
    }
    if ((entry->hash == nhash) && (hm->cmp_fn(key, entry->key) == 0)) {
      return entry;
    }
  }
}

/// Returns an entry for the given key: either an existing one, or a newly
/// claimed (zeroed) slot. Increments `hm->count` when a new slot is claimed.
///
/// The caller is responsible for keeping at least one empty slot in the table.
/// @param nhash Normalized key hash, see `_nhash()`.
/// @param created Set to `true` if a new slot has been claimed.
static struct entry* _entry_put(struct iwhmap *hm, void *key, uint32_t nhash, bool *created) {
  struct entry *entries = hm->entries;
  uint32_t mask = hm->capacity_mask;
  for (uint32_t i = nhash & mask; ; i = (i + 1) & mask) {
    struct entry *entry = entries + i;
    if (!entry->hash) {
      entry->hash = nhash;
      entry->key = 0;
      entry->val = 0;
      entry->lru_idx = LRU_NONE;
      ++hm->count;
      *created = true;
      return entry;
    }
    if ((entry->hash == nhash) && (hm->cmp_fn(key, entry->key) == 0)) {
      *created = false;
      return entry;
    }
  }
}

/// Reallocates the entries table to the given capacity and re-places all entries.
/// Existing entries are moved as is: `kv_free_fn` is not called.
static iwrc _resize(struct iwhmap *hm, uint32_t capacity) {
  assert(!(capacity & (capacity - 1)));
  assert(capacity != hm->capacity);
  assert((capacity >= INITIAL_CAPACITY) && (capacity <= MAX_CAPACITY));

  struct entry *entries_new = _entries_alloc(capacity);
  if (!entries_new) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  struct entry *entries_old = hm->entries;
  uint32_t mask_new = capacity - 1;
  uint32_t count = 0;

  for (struct entry *entry = entries_old, *end = entries_old + hm->capacity; entry < end; ++entry) {
    if (!entry->hash) {
      continue;
    }
    uint32_t i = entry->hash & mask_new;
    while (entries_new[i].hash) {
      i = (i + 1) & mask_new;
    }
    entries_new[i] = *entry;
    ++count;
  }

  assert(count == hm->count);
  (void) count;
  hm->entries = entries_new;
  hm->capacity = capacity;
  hm->capacity_mask = mask_new;
  free(entries_old);
  return 0;
}

/// Makes sure the table can hold one more entry.
static iwrc _reserve_entry(struct iwhmap *hm) {
  if (hm->count + 1 <= _max_load(hm->capacity)) {
    return 0;
  }
  if (hm->capacity >= MAX_CAPACITY) {
    errno = EOVERFLOW;
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
  return _resize(hm, hm->capacity * 2);
}

/// Allocates an LRU node and returns its reference or `LRU_NONE` on OOM.
static uint32_t _lru_node_alloc(struct iwhmap *hm) {
  if (hm->lru_free != LRU_NONE) {
    uint32_t ref = hm->lru_free;
    hm->lru_free = hm->lru_nodes[ref - 1].next;
    return ref;
  }
  if (hm->lru_nodes_count >= hm->lru_nodes_capacity) {
    assert(hm->lru_nodes_count == hm->lru_nodes_capacity);
    uint32_t capacity = hm->lru_nodes_capacity ? hm->lru_nodes_capacity * 2 : INITIAL_LRU_NODES;
    // LRU nodes never outnumber entries, so `MAX_CAPACITY` bounds the slab as well;
    // the check also prevents the doubling from wrapping around.
    if ((capacity < hm->lru_nodes_capacity) || (capacity > MAX_CAPACITY)) {
      return LRU_NONE;
    }
    struct lru_node *nodes = realloc(hm->lru_nodes, (size_t) capacity * sizeof(nodes[0]));
    if (!nodes) {
      return LRU_NONE;
    }
    hm->lru_nodes = nodes;
    hm->lru_nodes_capacity = capacity;
  }
  return ++hm->lru_nodes_count;
}

/// Releases the given LRU node reference.
static void _lru_node_free(struct iwhmap *hm, uint32_t ref) {
  struct lru_node *node = hm->lru_nodes + (ref - 1);
  node->next = hm->lru_free;
  node->prev = LRU_NONE;
  node->key = 0;
  hm->lru_free = ref;
}

/// Marks the entry as the most recently used one.
static void _lru_entry_update(struct iwhmap *hm, struct entry *entry) {
  if (entry->lru_idx != LRU_NONE) {
    struct lru_node *node = hm->lru_nodes + (entry->lru_idx - 1);
    node->key = entry->key;
    if (node->next != LRU_NONE) {
      if (node->prev != LRU_NONE) {
        hm->lru_nodes[node->prev - 1].next = node->next;
      } else {
        hm->lru_first = node->next;
      }
      hm->lru_nodes[node->next - 1].prev = node->prev;
      hm->lru_nodes[hm->lru_last - 1].next = entry->lru_idx;
      node->next = LRU_NONE;
      node->prev = hm->lru_last;
      hm->lru_last = entry->lru_idx;
    }
  } else {
    uint32_t ref = _lru_node_alloc(hm);
    if (ref != LRU_NONE) {
      struct lru_node *node = hm->lru_nodes + (ref - 1);
      node->key = entry->key;
      entry->lru_idx = ref;
      if (hm->lru_last != LRU_NONE) {
        hm->lru_nodes[hm->lru_last - 1].next = ref;
        node->next = LRU_NONE;
        node->prev = hm->lru_last;
        hm->lru_last = ref;
      } else {
        hm->lru_first = hm->lru_last = ref;
        node->next = node->prev = LRU_NONE;
      }
    }
  }
}

/// Removes the entry from the LRU list.
static void _lru_entry_remove(struct iwhmap *hm, struct entry *entry) {
  struct lru_node *node = hm->lru_nodes + (entry->lru_idx - 1);
  if (node->next != LRU_NONE) {
    if (node->prev != LRU_NONE) {
      hm->lru_nodes[node->prev - 1].next = node->next;
    } else {
      hm->lru_first = node->next;
    }
    hm->lru_nodes[node->next - 1].prev = node->prev;
  } else if (node->prev != LRU_NONE) {
    hm->lru_nodes[node->prev - 1].next = LRU_NONE;
    hm->lru_last = node->prev;
  } else {
    hm->lru_last = hm->lru_first = LRU_NONE;
  }
  _lru_node_free(hm, entry->lru_idx);
  entry->lru_idx = LRU_NONE;
}

void* iwhmap_get(struct iwhmap *hm, const void *key) {
  struct entry *entry = _entry_find(hm, key, _nhash(hm->hash_key_fn(key)));
  if (entry) {
    if (hm->lru_ev) {
      _lru_entry_update(hm, entry);
    }
    return entry->val;
  } else {
    return 0;
  }
}

/// Removes the entry from the table and shifts the rest of its probe cluster
/// backwards, so the table keeps no tombstones.
/// @note Invalidates all entry pointers, including the given one.
static void _entry_remove(struct iwhmap *hm, struct entry *entry) {
  if (entry->lru_idx != LRU_NONE) {
    _lru_entry_remove(hm, entry);
  }

  hm->kv_free_fn(hm->int_key_as_pointer_value ? 0 : entry->key, entry->val);
  --hm->count;

  struct entry *entries = hm->entries;
  uint32_t mask = hm->capacity_mask;
  uint32_t hole = (uint32_t)(entry - entries);

  for (uint32_t i = (hole + 1) & mask; entries[i].hash; i = (i + 1) & mask) {
    uint32_t home = entries[i].hash & mask;
    // The entry can be moved back only if the hole is located on its probe path,
    // otherwise moving it would make the entry unreachable for lookups.
    if (((hole - home) & mask) <= ((i - home) & mask)) {
      entries[hole] = entries[i];
      hole = i;
    }
  }
  entry = entries + hole;
  entry->hash = 0;
  entry->key = 0;
  entry->val = 0;
  entry->lru_idx = LRU_NONE;

  if ((hm->capacity > INITIAL_CAPACITY) && (hm->count < hm->capacity / SHRINK_DIVISOR)) {
    iwrc rc = _resize(hm, hm->capacity / 2);
    (void) rc; // Failure is not critical: the table stays functional as is.
  }
}

bool iwhmap_remove(struct iwhmap *hm, const void *key) {
  struct entry *entry = _entry_find(hm, key, _nhash(hm->hash_key_fn(key)));
  if (entry) {
    _entry_remove(hm, entry);
    return true;
  } else {
    return false;
  }
}

bool iwhmap_remove_u64(struct iwhmap *hm, uint64_t key) {
  if (hm->int_key_as_pointer_value) {
    return iwhmap_remove(hm, (void*) (uintptr_t) key);
  } else {
    return iwhmap_remove(hm, &key);
  }
}

bool iwhmap_remove_u32(struct iwhmap *hm, uint32_t key) {
  return iwhmap_remove(hm, (void*) (uintptr_t) key);
}

iwrc iwhmap_put(struct iwhmap *hm, void *key, void *val) {
  uint32_t nhash = _nhash(hm->hash_key_fn(key));
  // Reserve space before the lookup: a `put` of an already existing key may grow
  // the table one step earlier than strictly needed, but it keeps the insertion
  // path to a single probe sequence.
  iwrc rc = _reserve_entry(hm);
  if (rc) {
    return rc;
  }
  bool created;
  struct entry *entry = _entry_put(hm, key, nhash, &created);
  if (!created) {
    hm->kv_free_fn(hm->int_key_as_pointer_value ? 0 : entry->key, entry->val);
  }
  entry->key = key;
  entry->val = val;

  if (hm->lru_ev) {
    _lru_entry_update(hm, entry);
  }

  while ((hm->lru_first != LRU_NONE) && hm->lru_ev(hm, hm->lru_ev_user_data)) {
    void *lru_key = hm->lru_nodes[hm->lru_first - 1].key;
    entry = _entry_find(hm, lru_key, _nhash(hm->hash_key_fn(lru_key)));
    assert(entry); // Should never be zero.
    _entry_remove(hm, entry);
  }

  return 0;
}

iwrc iwhmap_put_str(struct iwhmap *hm, const char *key_, void *val) {
  char *key = strdup(key_);
  if (!key) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  iwrc rc = iwhmap_put(hm, key, val);
  if (rc) {
    free(key);
  }
  return rc;
}

iwrc iwhmap_rename(struct iwhmap *hm, const void *key_old, void *key_new) {
  uint32_t nhash_old = _nhash(hm->hash_key_fn(key_old));
  struct entry *entry = _entry_find(hm, key_old, nhash_old);
  if (!entry) {
    return 0;
  }
  // Reserve space before the old entry is removed, so a failed resize leaves
  // both the map and the renamed value intact.
  iwrc rc = _reserve_entry(hm);
  if (rc) {
    return rc;
  }
  entry = _entry_find(hm, key_old, nhash_old);

  void *val = entry->val;
  entry->val = 0;
  _entry_remove(hm, entry);

  uint32_t nhash_new = _nhash(hm->hash_key_fn(key_new));
  bool created;
  entry = _entry_put(hm, key_new, nhash_new, &created);
  if (!created) {
    hm->kv_free_fn(hm->int_key_as_pointer_value ? 0 : entry->key, entry->val);
  }

  entry->key = key_new;
  entry->val = val;

  if (hm->lru_ev) {
    _lru_entry_update(hm, entry);
  }
  return 0;
}

iwrc iwhmap_put_u32(struct iwhmap *hm, uint32_t key, void *val) {
  return iwhmap_put(hm, (void*) (uintptr_t) key, val);
}

iwrc iwhmap_put_u64(struct iwhmap *hm, uint64_t key, void *val) {
  if (hm->int_key_as_pointer_value) {
    return iwhmap_put(hm, (void*) (uintptr_t) key, val);
  } else {
    uint64_t *kv = malloc(sizeof(*kv));
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

void* iwhmap_get_u64(struct iwhmap *hm, uint64_t key) {
  if (hm->int_key_as_pointer_value) {
    return iwhmap_get(hm, (void*) (intptr_t) key);
  } else {
    return iwhmap_get(hm, &key);
  }
}

void* iwhmap_get_u32(struct iwhmap *hm, uint32_t key) {
  return iwhmap_get(hm, (void*) (intptr_t) key);
}

uint32_t iwhmap_count(const struct iwhmap *hm) {
  return hm->count;
}

void iwhmap_iter_init(struct iwhmap *hm, struct iwhmap_iter *iter) {
  iter->hm = hm;
  iter->entry = -1;
  iter->bucket = 0;
  iter->key = 0;
  iter->val = 0;
}

bool iwhmap_iter_next(struct iwhmap_iter *iter) {
  struct iwhmap *hm = iter->hm;
  if (!hm) {
    return false;
  }
  struct entry *entries = hm->entries;
  uint32_t capacity = hm->capacity;

  if ((iter->entry >= 0) && ((uint32_t) iter->entry < capacity)) {
    // Removals shift the rest of the probe cluster backwards, so the slot
    // returned by the previous call may hold another entry now (this is the case
    // when the caller removes the entry it has just received). Return that entry
    // as well, otherwise it would be silently skipped by the iteration.
    struct entry *entry = entries + iter->entry;
    if (entry->hash && ((entry->hash != iter->bucket) || (entry->key != iter->key))) {
      iter->bucket = entry->hash;
      iter->key = entry->key;
      iter->val = entry->val;
      return true;
    }
  }

  uint32_t i = (iter->entry < 0) ? 0 : (uint32_t) iter->entry + 1;
  for ( ; (i < capacity) && !entries[i].hash; ++i) {}
  if (i >= capacity) {
    iter->entry = (int32_t) capacity;
    return false;
  }
  struct entry *entry = entries + i;
  iter->entry = (int32_t) i;
  iter->bucket = entry->hash;
  iter->key = entry->key;
  iter->val = entry->val;
  return true;
}

/// Releases all LRU list nodes.
static void _lru_nodes_free(struct iwhmap *hm) {
  free(hm->lru_nodes);
  hm->lru_nodes = 0;
  hm->lru_nodes_capacity = 0;
  hm->lru_nodes_count = 0;
  hm->lru_free = LRU_NONE;
  hm->lru_first = LRU_NONE;
  hm->lru_last = LRU_NONE;
}

void iwhmap_clear(struct iwhmap *hm) {
  if (!hm) {
    return;
  }
  for (struct entry *entry = hm->entries, *end = hm->entries + hm->capacity; entry < end; ++entry) {
    if (entry->hash) {
      hm->kv_free_fn(hm->int_key_as_pointer_value ? 0 : entry->key, entry->val);
    }
  }
  struct entry *entries_new = 0;
  if (hm->capacity > INITIAL_CAPACITY) {
    entries_new = _entries_alloc(INITIAL_CAPACITY);
  }
  if (entries_new) {
    free(hm->entries);
    hm->entries = entries_new;
    hm->capacity = INITIAL_CAPACITY;
    hm->capacity_mask = INITIAL_CAPACITY - 1;
  } else {
    memset(hm->entries, 0, (size_t) hm->capacity * sizeof(hm->entries[0]));
  }
  _lru_nodes_free(hm);
  hm->count = 0;
}

void iwhmap_destroy(struct iwhmap *hm) {
  if (!hm) {
    return;
  }
  for (struct entry *entry = hm->entries, *end = hm->entries + hm->capacity; entry < end; ++entry) {
    if (entry->hash) {
      hm->kv_free_fn(hm->int_key_as_pointer_value ? 0 : entry->key, entry->val);
    }
  }
  free(hm->lru_nodes);
  free(hm->entries);
  free(hm);
}

bool iwhmap_lru_eviction_max_count(struct iwhmap *hm, void *max_count_val) {
  uint32_t max_count = (uintptr_t) max_count_val;
  return iwhmap_count(hm) > max_count;
}

void iwhmap_lru_init(struct iwhmap *hm, iwhmap_lru_eviction_needed ev, void *ev_user_data) {
  hm->lru_ev = ev;
  hm->lru_ev_user_data = ev_user_data;
}
