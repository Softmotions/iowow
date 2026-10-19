#include "iowow.h"
#include "iwhmap.h"
#include "iwtests.h"

static int init_suite(void) {
  return iw_init();
}

/// Counts the number of `kv_free_fn` invocations, used by the memory ownership tests.
static int kv_free_calls;

static void kv_free_count(void *key, void *val) {
  ++kv_free_calls;
  free(key);
  free(val);
}

static void hex32(uint32_t *hash, char *buf) {
  sprintf(buf, "%08x", *hash);
}

static void hex128(uint32_t hash[4], char *buf) {
  sprintf(buf, "%08x%08x%08x%08x", hash[0], hash[1], hash[2], hash[3]);
}

void murmur3_x86_32(const void *key, size_t len, uint32_t seed, void *out);
void murmur3_x86_128(const void *key, const size_t len, uint32_t seed, void *out);
void murmur3_x64_128(const void *key, const size_t len, const uint32_t seed, void *out);

static void test_murmur_hash(void) {
#define TESTHASH(arch, nbytes, seed, str, expected) {                          \
          char *input = str;                                                   \
          uint32_t hash[4];                                                    \
          char buf[33];                                                        \
          murmur3_ ## arch ## _ ## nbytes(input, strlen(input), (seed), hash); \
          hex ## nbytes(hash, buf);                                            \
          IW_TEST_ASSERT_STR_EQUAL(buf, expected);                               \
}

  TESTHASH(x86, 32, 1234, "Hello, world!", "faf6cdb3");
  TESTHASH(x86, 32, 4321, "Hello, world!", "bf505788");
  TESTHASH(x86, 32, 1234, "xxxxxxxxxxxxxxxxxxxxxxxxxxxx", "8905ac28");
  TESTHASH(x86, 32, 1234, "", "0f2cc00b");

  TESTHASH(x86, 128, 123, "Hello, world!", "61c9129e5a1aacd7a41621629e37c886");
  TESTHASH(x86, 128, 321, "Hello, world!", "d5fbdcb3c26c4193045880c5a7170f0f");
  TESTHASH(x86, 128, 123, "xxxxxxxxxxxxxxxxxxxxxxxxxxxx", "5e40bab278825a164cf929d31fec6047");
  TESTHASH(x86, 128, 123, "", "fedc524526f3e79926f3e79926f3e799");

  TESTHASH(x64, 128, 123, "Hello, world!", "8743acad421c8c73d373c3f5f19732fd");
  TESTHASH(x64, 128, 321, "Hello, world!", "f86d4004ca47f42bb9546c7979200aee");
  TESTHASH(x64, 128, 123, "xxxxxxxxxxxxxxxxxxxxxxxxxxxx", "becf7e04dbcf74637751664ef66e73e0");
  TESTHASH(x64, 128, 123, "", "4cd9597081679d1abd92f8784bace33d");
}

static void test_basic_crud_str(void) {
  char kbuf[64];
  char vbuf[64];
  struct iwhmap *hm = iwhmap_create_str(iwhmap_kv_free);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(hm);
  for (int i = 0; i < 10000; ++i) {
    snprintf(kbuf, sizeof(kbuf), "key%d", i);
    snprintf(vbuf, sizeof(vbuf), "value%d", i);
    iwrc rc = iwhmap_put(hm, strdup(kbuf), strdup(vbuf));
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  }
  for (int i = 0; i < 10000; ++i) {
    snprintf(kbuf, sizeof(kbuf), "key%d", i);
    snprintf(vbuf, sizeof(vbuf), "value%d", i);
    const char *vp = iwhmap_get(hm, kbuf);
    IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(vp);
    IW_TEST_ASSERT_STR_EQUAL(vbuf, vp);
    if (i % 2 == 0) {
      iwhmap_remove(hm, kbuf);
    }
  }
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 5000);
  for (int i = 0; i < 10000; ++i) {
    if ((i % 2) == 0) {
      continue;
    }
    snprintf(kbuf, sizeof(kbuf), "key%d", i);
    snprintf(vbuf, sizeof(vbuf), "value%d", i);
    const char *vp = iwhmap_get(hm, kbuf);
    IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(vp);
    IW_TEST_ASSERT_STR_EQUAL(vbuf, vp);
    if (i % 3 == 0) {
      iwhmap_remove(hm, kbuf);
    }
  }
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 3333);

  // A missing key has to be reported as absent.
  IW_TEST_ASSERT_PTR_NULL(iwhmap_get(hm, "key0"));
  IW_TEST_ASSERT_PTR_NULL(iwhmap_get(hm, "no-such-key"));
  IW_TEST_ASSERT_FALSE(iwhmap_remove(hm, "no-such-key"));

  // Replacing a value keeps a single entry.
  snprintf(kbuf, sizeof(kbuf), "key1");
  IW_TEST_ASSERT_EQUAL(iwhmap_put(hm, strdup(kbuf), strdup("replaced")), 0);
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 3333);
  IW_TEST_ASSERT_STR_EQUAL(iwhmap_get(hm, kbuf), "replaced");

  iwhmap_destroy(hm);
}

static void test_put_str(void) {
  char kbuf[64];
  snprintf(kbuf, sizeof(kbuf), "mutable-key");
  struct iwhmap *hm = iwhmap_create_str(iwhmap_kv_free);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(hm);
  IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_str(hm, kbuf, strdup("v")), 0);
  // The key is copied, mutating the source buffer must not affect the map.
  memset(kbuf, 'x', strlen(kbuf));
  IW_TEST_ASSERT_STR_EQUAL(iwhmap_get(hm, "mutable-key"), "v");
  IW_TEST_ASSERT_PTR_NULL(iwhmap_get(hm, "xxxxxxxxxxx"));
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 1);
  iwhmap_destroy(hm);
}

static void test_u32_ops(void) {
  struct iwhmap *hm = iwhmap_create_u32(0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(hm);
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 0);
  IW_TEST_ASSERT_PTR_NULL(iwhmap_get_u32(hm, 1));
  IW_TEST_ASSERT_FALSE(iwhmap_remove_u32(hm, 1));

  // Boundary keys must survive the "key as pointer" representation.
  IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_u32(hm, 0, (void*) (uintptr_t) 0xA0), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_u32(hm, 1, (void*) (uintptr_t) 0xA1), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_u32(hm, UINT32_MAX, (void*) (uintptr_t) 0xA2), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_u32(hm, UINT32_MAX - 1, (void*) (uintptr_t) 0xA3), 0);
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 4);
  IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get_u32(hm, 0), 0xA0);
  IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get_u32(hm, UINT32_MAX), 0xA2);
  IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get_u32(hm, UINT32_MAX - 1), 0xA3);

  // Replacement keeps the entry count.
  IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_u32(hm, 1, (void*) (uintptr_t) 0xB1), 0);
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 4);
  IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get_u32(hm, 1), 0xB1);

  IW_TEST_ASSERT_TRUE(iwhmap_remove_u32(hm, 1));
  IW_TEST_ASSERT_FALSE(iwhmap_remove_u32(hm, 1));
  IW_TEST_ASSERT_PTR_NULL(iwhmap_get_u32(hm, 1));
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 3);
  // The remaining keys must be reachable after the removal that shifted the probe cluster.
  IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get_u32(hm, 0), 0xA0);
  IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get_u32(hm, UINT32_MAX), 0xA2);
  IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get_u32(hm, UINT32_MAX - 1), 0xA3);
  iwhmap_destroy(hm);
}

static void test_u64_ops(void) {
  struct iwhmap *hm = iwhmap_create_u64(0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(hm);
  const uint64_t keys[] = { 0, 1, 2, UINT32_MAX, UINT64_C(0x100000001), UINT64_MAX };
  const size_t nkeys = sizeof(keys) / sizeof(keys[0]);
  for (size_t i = 0; i < nkeys; ++i) {
    IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_u64(hm, keys[i], (void*) (uintptr_t) (i + 1)), 0);
  }
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), nkeys);
  for (size_t i = 0; i < nkeys; ++i) {
    IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get_u64(hm, keys[i]), i + 1);
  }
  for (size_t i = 0; i < nkeys; i += 2) {
    IW_TEST_ASSERT_TRUE(iwhmap_remove_u64(hm, keys[i]));
  }
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), nkeys / 2);
  for (size_t i = 0; i < nkeys; ++i) {
    if (i % 2) {
      IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get_u64(hm, keys[i]), i + 1);
    } else {
      IW_TEST_ASSERT_PTR_NULL(iwhmap_get_u64(hm, keys[i]));
    }
  }
  iwhmap_destroy(hm);
}

/// Covers table growth and the shrink performed when the map is drained.
static void test_growth_shrink(void) {
  const uint32_t n = 100000;
  struct iwhmap *hm = iwhmap_create_u32(0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(hm);
  for (uint32_t i = 0; i < n; ++i) {
    IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_u32(hm, i * 2, (void*) (uintptr_t) (i + 1)), 0);
  }
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), n);
  for (uint32_t i = 0; i < n; ++i) {
    IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get_u32(hm, i * 2), i + 1);
  }
  for (uint32_t i = 0; i < n; ++i) {
    if (i % 4 == 0) {
      IW_TEST_ASSERT_TRUE(iwhmap_remove_u32(hm, i * 2));
    }
  }
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), n - n / 4);
  for (uint32_t i = 0; i < n; ++i) {
    if (i % 4 == 0) {
      IW_TEST_ASSERT_PTR_NULL(iwhmap_get_u32(hm, i * 2));
    } else {
      IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get_u32(hm, i * 2), i + 1);
    }
  }
  for (uint32_t i = 0; i < n; ++i) {
    if (i % 4 != 0) {
      iwhmap_remove_u32(hm, i * 2);
    }
  }
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 0);
  for (uint32_t i = 0; i < n; ++i) {
    IW_TEST_ASSERT_PTR_NULL(iwhmap_get_u32(hm, i * 2));
  }

  // The map has to stay usable after it has been fully drained.
  for (uint32_t i = 0; i < 1000; ++i) {
    IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_u32(hm, i, (void*) (uintptr_t) (i + 1)), 0);
  }
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 1000);
  for (uint32_t i = 0; i < 1000; ++i) {
    IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get_u32(hm, i), i + 1);
  }
  iwhmap_destroy(hm);
}

/// Randomized differential test against a plain shadow model.
/// Covers probe cluster shifting after removals and the entry count bookkeeping.
static void test_random_model(void) {
#define MODEL_KEYS 4096
  uint8_t present[MODEL_KEYS];
  memset(present, 0, sizeof(present));
  uint64_t rng = UINT64_C(0x243F6A8885A308D3);
  struct iwhmap *hm = iwhmap_create_u32(0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(hm);

  for (int step = 0; step < 200000; ++step) {
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    const uint32_t key = (uint32_t) (rng % MODEL_KEYS);
    const uint32_t op = (uint32_t) ((rng >> 32) % 100);

    if (op < 50) {
      IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_u32(hm, key, (void*) (uintptr_t) (key + 1)), 0);
      present[key] = 1;
    } else if (op < 85) {
      IW_TEST_ASSERT_EQUAL(iwhmap_remove_u32(hm, key), present[key]);
      present[key] = 0;
    } else {
      void *val = iwhmap_get_u32(hm, key);
      if (present[key]) {
        IW_TEST_ASSERT_EQUAL((uintptr_t) val, key + 1);
      } else {
        IW_TEST_ASSERT_PTR_NULL(val);
      }
    }

    if ((step % 8192) == 0) {
      uint32_t count = 0;
      for (uint32_t k = 0; k < MODEL_KEYS; ++k) {
        void *val = iwhmap_get_u32(hm, k);
        if (present[k]) {
          IW_TEST_ASSERT_EQUAL((uintptr_t) val, k + 1);
          ++count;
        } else {
          IW_TEST_ASSERT_PTR_NULL(val);
        }
      }
      IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), count);
    }
  }
  iwhmap_destroy(hm);
#undef MODEL_KEYS
}

static void test_iteration(void) {
  const uint32_t n = 10000;
  uint8_t visited[20000];
  memset(visited, 0, sizeof(visited));
  struct iwhmap *hm = iwhmap_create_u32(0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(hm);
  for (uint32_t i = 0; i < n; ++i) {
    IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_u32(hm, i * 2, (void*) (uintptr_t) (i + 1)), 0);
  }
  struct iwhmap_iter iter;
  iwhmap_iter_init(hm, &iter);
  uint32_t seen = 0;
  while (iwhmap_iter_next(&iter)) {
    const uintptr_t key = (uintptr_t) iter.key;
    const uintptr_t val = (uintptr_t) iter.val;
    IW_TEST_ASSERT_TRUE(key < 2 * n);
    IW_TEST_ASSERT_EQUAL(key % 2, 0);
    IW_TEST_ASSERT_EQUAL(val, key / 2 + 1);
    IW_TEST_ASSERT_EQUAL(visited[key], 0);
    visited[key] = 1;
    ++seen;
  }
  IW_TEST_ASSERT_EQUAL(seen, n);
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), n);
  // The iterator has to stay exhausted.
  IW_TEST_ASSERT_FALSE(iwhmap_iter_next(&iter));

  // Iteration over an empty map yields nothing.
  struct iwhmap *empty = iwhmap_create_u32(0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(empty);
  struct iwhmap_iter empty_iter;
  iwhmap_iter_init(empty, &empty_iter);
  IW_TEST_ASSERT_FALSE(iwhmap_iter_next(&empty_iter));
  IW_TEST_ASSERT_FALSE(iwhmap_iter_next(&empty_iter));
  iwhmap_destroy(empty);

  // Null map iteration yields nothing.
  struct iwhmap_iter null_iter;
  iwhmap_iter_init(0, &null_iter);
  IW_TEST_ASSERT_FALSE(iwhmap_iter_next(&null_iter));

  iwhmap_destroy(hm);
}

/// Removals shift the rest of the probe cluster backwards, so the iterator has to
/// keep going when the caller removes the entry it has just received.
static void test_remove_during_iteration(void) {
  const uint32_t n = 1000;
  const uint32_t to_remove = 700;
  struct iwhmap *hm = iwhmap_create_u32(0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(hm);
  for (uint32_t i = 0; i < n; ++i) {
    IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_u32(hm, i, (void*) (uintptr_t) (i + 1)), 0);
  }

  uint8_t removed[1000];
  memset(removed, 0, sizeof(removed));
  struct iwhmap_iter iter;
  iwhmap_iter_init(hm, &iter);
  uint32_t seen = 0;
  while (iwhmap_iter_next(&iter)) {
    ++seen;
    if (seen <= to_remove) {
      const uintptr_t key = (uintptr_t) iter.key;
      IW_TEST_ASSERT_TRUE(key < n);
      IW_TEST_ASSERT_EQUAL(removed[key], 0);
      IW_TEST_ASSERT_TRUE(iwhmap_remove_u32(hm, (uint32_t) key));
      removed[key] = 1;
    }
  }
  // Every entry has to be visited exactly once, no entry may be skipped.
  IW_TEST_ASSERT_EQUAL(seen, n);
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), n - to_remove);
  for (uint32_t i = 0; i < n; ++i) {
    void *val = iwhmap_get_u32(hm, i);
    if (removed[i]) {
      IW_TEST_ASSERT_PTR_NULL(val);
    } else {
      IW_TEST_ASSERT_EQUAL((uintptr_t) val, i + 1);
    }
  }
  iwhmap_destroy(hm);
}

/// Full drain driven by iteration: the map must stay consistent even though the
/// table is rehashed while it is being iterated.
static void test_drain_during_iteration(void) {
  const uint32_t n = 5000;
  struct iwhmap *hm = iwhmap_create_u32(0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(hm);
  for (uint32_t i = 0; i < n; ++i) {
    IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_u32(hm, i, (void*) (uintptr_t) (i + 1)), 0);
  }
  uint8_t *removed = calloc(n, 1);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(removed);

  struct iwhmap_iter iter;
  iwhmap_iter_init(hm, &iter);
  while (iwhmap_iter_next(&iter)) {
    const uintptr_t key = (uintptr_t) iter.key;
    IW_TEST_ASSERT_TRUE(key < n);
    iwhmap_remove_u32(hm, (uint32_t) key);
    removed[key] = 1;
  }
  uint32_t count = 0;
  for (uint32_t i = 0; i < n; ++i) {
    void *val = iwhmap_get_u32(hm, i);
    if (removed[i]) {
      IW_TEST_ASSERT_PTR_NULL(val);
    } else {
      IW_TEST_ASSERT_EQUAL((uintptr_t) val, i + 1);
      ++count;
    }
  }
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), count);
  free(removed);
  iwhmap_destroy(hm);
}

//------------------------------------------------------------------------------------ collisions

static uint32_t hash_const(const void *key) {
  return 0x2a2a2a2aU;
}

/// All keys land in the same probe cluster: the worst case for the probe
/// cluster shifting performed by removals.
static void test_collisions(void) {
  const uint32_t n = 500;
  struct iwhmap *hm = iwhmap_create(0, hash_const, 0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(hm);
  for (uint32_t i = 0; i < n; ++i) {
    IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_u32(hm, i, (void*) (uintptr_t) (i + 1)), 0);
  }
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), n);
  for (uint32_t i = 0; i < n; ++i) {
    IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get_u32(hm, i), i + 1);
  }
  for (uint32_t i = 0; i < n; i += 2) {
    IW_TEST_ASSERT_TRUE(iwhmap_remove_u32(hm, i));
  }
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), n / 2);
  for (uint32_t i = 0; i < n; ++i) {
    if (i % 2) {
      IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get_u32(hm, i), i + 1);
    } else {
      IW_TEST_ASSERT_PTR_NULL(iwhmap_get_u32(hm, i));
    }
  }
  iwhmap_destroy(hm);
}

//------------------------------------------------------------------------------------------ lru

static void test_lru1(void) {
  struct iwhmap *hm = iwhmap_create_u32(0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(hm);

  // Init LRU mode max 2 records in map
  iwhmap_lru_init(hm, iwhmap_lru_eviction_max_count, (void*) (uintptr_t) 2UL);

  iwrc rc = iwhmap_put_u32(hm, 1, (void*) 1L);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  long val = (intptr_t) iwhmap_get_u64(hm, 1);
  IW_TEST_ASSERT_EQUAL(val, 1L);

  rc -= iwhmap_put_u32(hm, 2, (void*) 2L);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  val = (intptr_t) iwhmap_get_u64(hm, 1);
  IW_TEST_ASSERT_EQUAL(val, 1L);
  val = (intptr_t) iwhmap_get_u64(hm, 2);
  IW_TEST_ASSERT_EQUAL(val, 2L);

  rc = iwhmap_put_u32(hm, 3, (void*) 3L);
  IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  val = (intptr_t) iwhmap_get_u64(hm, 1);
  IW_TEST_ASSERT_EQUAL(val, 0L);
  val = (intptr_t) iwhmap_get_u64(hm, 3);
  IW_TEST_ASSERT_EQUAL(val, 3L);
  val = (intptr_t) iwhmap_get_u64(hm, 2);
  IW_TEST_ASSERT_EQUAL(val, 2L);

  rc = iwhmap_put_u32(hm, 4, (void*) 4L);
  val = (intptr_t) iwhmap_get_u64(hm, 3);
  IW_TEST_ASSERT_EQUAL(val, 0);
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 2);

  iwhmap_destroy(hm);
}

static void test_lru2(void) {
  iwrc rc = 0;
  struct iwhmap *hm = iwhmap_create_u32(0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(hm);
  iwhmap_lru_init(hm, iwhmap_lru_eviction_max_count, (void*) (uintptr_t) 1024UL);
  for (int i = 0; i < 2048; ++i) {
    rc = iwhmap_put_u32(hm, i + 1, (void*) (intptr_t) i);
    IW_TEST_ASSERT_EQUAL_FATAL(rc, 0);
  }
  uint32_t val = iwhmap_count(hm);
  IW_TEST_ASSERT_EQUAL(val, 1024);

  iwhmap_destroy(hm);
}

/// LRU eviction has to keep working across LRU node slab growth and node reuse.
static void test_lru3(void) {
  const uint32_t max_count = 100;
  struct iwhmap *hm = iwhmap_create_u32(0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(hm);
  iwhmap_lru_init(hm, iwhmap_lru_eviction_max_count, (void*) (uintptr_t) max_count);

  for (uint32_t i = 1; i <= 1000; ++i) {
    IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_u32(hm, i, (void*) (uintptr_t) i), 0);
    IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), i < max_count ? i : max_count);
  }
  for (uint32_t i = 1; i <= 1000 - max_count; ++i) {
    IW_TEST_ASSERT_PTR_NULL(iwhmap_get_u32(hm, i));
  }
  for (uint32_t i = 1000 - max_count + 1; i <= 1000; ++i) {
    IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get_u32(hm, i), i);
  }
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), max_count);

  // Freed LRU nodes have to be reused by the subsequent inserts.
  for (uint32_t i = 901; i <= 1000; i += 2) {
    IW_TEST_ASSERT_TRUE(iwhmap_remove_u32(hm, i));
  }
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), max_count / 2);
  for (uint32_t i = 1001; i <= 1100; ++i) {
    IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_u32(hm, i, (void*) (uintptr_t) i), 0);
    // The map is filled up to `max_count` again, the oldest entries are evicted.
    IW_TEST_ASSERT_TRUE(iwhmap_count(hm) <= max_count);
  }
  for (uint32_t i = 1001; i <= 1100; ++i) {
    IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get_u32(hm, i), i);
  }
  iwhmap_destroy(hm);
}

/// Explicit removals must keep the LRU list consistent: the eviction order has to
/// skip the removed entries and continue with the next least recently used one.
static void test_lru_remove(void) {
  struct iwhmap *hm = iwhmap_create_u32(0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(hm);
  iwhmap_lru_init(hm, iwhmap_lru_eviction_max_count, (void*) (uintptr_t) 3UL);

  IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_u32(hm, 1, (void*) 1L), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_u32(hm, 2, (void*) 2L), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_u32(hm, 3, (void*) 3L), 0);
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 3);

  // Remove the least recently used entry: the list head has to move to `2`.
  IW_TEST_ASSERT_TRUE(iwhmap_remove_u32(hm, 1));
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 2);
  IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_u32(hm, 4, (void*) 4L), 0);
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 3);
  IW_TEST_ASSERT_PTR_NULL(iwhmap_get_u32(hm, 1));
  IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get_u32(hm, 2), 2);
  IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get_u32(hm, 3), 3);
  IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get_u32(hm, 4), 4);

  // One more insert evicts `2`, which is the least recently used entry now.
  IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_u32(hm, 5, (void*) 5L), 0);
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 3);
  IW_TEST_ASSERT_PTR_NULL(iwhmap_get_u32(hm, 2));
  IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get_u32(hm, 5), 5);

  // Removing the most recently used entry and the list tail keeps the list valid.
  IW_TEST_ASSERT_TRUE(iwhmap_remove_u32(hm, 5));
  IW_TEST_ASSERT_TRUE(iwhmap_remove_u32(hm, 4));
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 1);  // only `3` is left
  IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_u32(hm, 6, (void*) 6L), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_u32(hm, 7, (void*) 7L), 0);
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 3);
  // `3` is the least recently used entry now: the next insert evicts it.
  IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_u32(hm, 8, (void*) 8L), 0);
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 3);
  IW_TEST_ASSERT_PTR_NULL(iwhmap_get_u32(hm, 3));
  IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get_u32(hm, 6), 6);
  IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get_u32(hm, 7), 7);
  IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get_u32(hm, 8), 8);
  iwhmap_destroy(hm);
}

//----------------------------------------------------------------------------------------- misc

static void test_rename(void) {
  struct iwhmap *hm = iwhmap_create_str(iwhmap_kv_free);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(hm);
  IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_str(hm, "key_a", strdup("value_a")), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_str(hm, "key_b", strdup("value_b")), 0);
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 2);

  // Renaming a missing key is a no-op.
  char *unused = strdup("unused");
  IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_rename(hm, "key_x", unused), 0);
  free(unused);
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 2);

  // Plain rename keeps the value.
  IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_rename(hm, "key_a", strdup("key_c")), 0);
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 2);
  IW_TEST_ASSERT_PTR_NULL(iwhmap_get(hm, "key_a"));
  IW_TEST_ASSERT_STR_EQUAL(iwhmap_get(hm, "key_c"), "value_a");

  // Rename onto an existing key replaces its value.
  IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_rename(hm, "key_c", strdup("key_b")), 0);
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 1);
  IW_TEST_ASSERT_PTR_NULL(iwhmap_get(hm, "key_c"));
  IW_TEST_ASSERT_STR_EQUAL(iwhmap_get(hm, "key_b"), "value_a");

  iwhmap_destroy(hm);
}

static void test_kv_free_accounting(void) {
  kv_free_calls = 0;
  struct iwhmap *hm = iwhmap_create_str(kv_free_count);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(hm);
  IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_str(hm, "k", strdup("v1")), 0);
  IW_TEST_ASSERT_EQUAL(kv_free_calls, 0);

  // Replacing a value frees the stored key and value exactly once.
  IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_str(hm, "k", strdup("v2")), 0);
  IW_TEST_ASSERT_EQUAL(kv_free_calls, 1);
  IW_TEST_ASSERT_STR_EQUAL(iwhmap_get(hm, "k"), "v2");

  IW_TEST_ASSERT_TRUE(iwhmap_remove(hm, "k"));
  IW_TEST_ASSERT_EQUAL(kv_free_calls, 2);
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 0);

  // `clear` releases everything the map still holds.
  for (int i = 0; i < 100; ++i) {
    char kbuf[32];
    snprintf(kbuf, sizeof(kbuf), "key%d", i);
    IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_str(hm, kbuf, strdup("v")), 0);
  }
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 100);
  iwhmap_clear(hm);
  IW_TEST_ASSERT_EQUAL(kv_free_calls, 102);
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 0);
  IW_TEST_ASSERT_PTR_NULL(iwhmap_get(hm, "key0"));

  // The map has to stay usable after `clear`.
  IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put_str(hm, "again", strdup("v")), 0);
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 1);
  IW_TEST_ASSERT_STR_EQUAL(iwhmap_get(hm, "again"), "v");

  // `destroy` releases the remaining entries.
  iwhmap_destroy(hm);
  IW_TEST_ASSERT_EQUAL(kv_free_calls, 103);
}

static void test_null_arguments(void) {
  // The hash function is mandatory.
  IW_TEST_ASSERT_PTR_NULL(iwhmap_create(0, 0, 0));
  // `clear` and `destroy` tolerate a null map.
  iwhmap_clear(0);
  iwhmap_destroy(0);

  // A map created without `kv_free_fn` must not fail on destroy.
  struct iwhmap *hm = iwhmap_create_str(0);
  IW_TEST_ASSERT_PTR_NOT_NULL_FATAL(hm);
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 0);
  IW_TEST_ASSERT_EQUAL_FATAL(iwhmap_put(hm, "k", (void*) 1L), 0);
  IW_TEST_ASSERT_EQUAL((uintptr_t) iwhmap_get(hm, "k"), 1);
  IW_TEST_ASSERT_EQUAL(iwhmap_count(hm), 1);
  iwhmap_destroy(hm);
}

static const struct iw_test_case cases[] = {
  IW_TEST_CASE(test_murmur_hash),
  IW_TEST_CASE(test_basic_crud_str),
  IW_TEST_CASE(test_put_str),
  IW_TEST_CASE(test_u32_ops),
  IW_TEST_CASE(test_u64_ops),
  IW_TEST_CASE(test_growth_shrink),
  IW_TEST_CASE(test_random_model),
  IW_TEST_CASE(test_iteration),
  IW_TEST_CASE(test_remove_during_iteration),
  IW_TEST_CASE(test_drain_during_iteration),
  IW_TEST_CASE(test_collisions),
  IW_TEST_CASE(test_lru1),
  IW_TEST_CASE(test_lru2),
  IW_TEST_CASE(test_lru3),
  IW_TEST_CASE(test_lru_remove),
  IW_TEST_CASE(test_rename),
  IW_TEST_CASE(test_kv_free_accounting),
  IW_TEST_CASE(test_null_arguments),
};

int main(int argc, char *argv[]) {
  return iw_test_run(argc, argv, IW_TEST_SUITE("iwhmap_test1", cases, init_suite, 0));
}
