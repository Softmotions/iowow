#include "iwkv_internal.h"
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>

#ifdef _WIN32
#include "win32/mman/mman.h"
#else
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#include <sys/mman.h>
#endif

#ifdef IW_TESTS
extern atomic_uint_fast64_t g_trigger;
static atomic_int _test_crash_rollforward_after = -1;
#endif

#define BKP_STARTED     0x1       /**< Backup started */
#define BKP_WAL_CLEANUP 0x2       /**< Do checkpoint and truncate WAL file */
#define BKP_MAIN_COPY   0x3       /**< Copy main database file */
#define BKP_WAL_COPY1   0x4       /**< Copy most of WAL file content */
#define BKP_WAL_COPY2   0x5       /**< Copy rest of WAL file in exclusive locked mode */

/// Minimum size of the pending-write hash table.
#define IWAL_PHASH_MIN 256

#ifndef IWAL_COALESCE_MAXLEN
/// Maximum write length eligible for the write-coalescing set. Larger writes are
/// logged directly (an ordering barrier for pending writes). Selected from
/// measurements: 32 KiB reaches the WAL-size knee for all tested datasets while
/// keeping the create-phase CPU overhead within ~5% of the non-coalescing build.
#define IWAL_COALESCE_MAXLEN 32768U
#endif

/// Maximum region length handled by the compact changed-byte patch path.
#define IWAL_DIFF_MAXLEN 512U

/// A pending (coalesced) WAL write. Entries are kept in last-write order via
/// the intrusive doubly linked list (see `pents_head`/`pents_tail`), so that
/// serialization emits each dirty region exactly once at the position of its
/// most recent write.
struct iwal_pentry {
  off_t    off;
  uint32_t len;
  uint32_t arena_off;               /**< Offset of the latest data in the arena */
  uint32_t arena_base_off;          /**< Offset of the window-start data in the arena */
  uint32_t fill_val;                /**< Value for a `WOP_SET` fill entry */
  int32_t  prev;
  int32_t  next;
  uint8_t  is_fill;                 /**< Entry is a `WOP_SET` fill, not data */
  uint8_t  has_base;                /**< Entry keeps window-start bytes for diffing */
};

struct iwal {
  struct iwdlsnr lsnr;
  atomic_bool    applying;          /**< WAL applying */
  atomic_bool    open;              /**< Is WAL in use */
  atomic_bool    force_cp;          /**< Next checkpoint scheduled */
  atomic_bool    synched;           /**< WAL is synched or WBFIXPOINT is the last write operation */
  bool force_sp;                    /**< Next savepoint scheduled */
  bool check_cp_crc;                /**< Check CRC32 sum of data blocks during checkpoint. Default: false  */
  iwkv_openflags oflags;            /**< File open flags */
  atomic_int     bkp_stage;         /**< Online backup stage */

  size_t wal_buffer_sz;           /**< WAL file intermediate buffer size. */
  size_t pending_cap;             /**< Max bytes kept by the coalescing set */
  size_t checkpoint_buffer_sz;    /**< Checkpoint buffer size in bytes. */

  size_t   dirty_page_sz;           /**< Page size used for dirty-page accounting */
  uint8_t *dirty_bitmap;            /**< Bitmap of dirty main-file pages */
  size_t   dirty_bitmap_cap;        /**< Bytes allocated for `dirty_bitmap` */

  atomic_size_t dirty_pages;        /**< Number of set bits in `dirty_bitmap` */
  uint32_t      bufpos;             /**< Current position in buffer */
  uint32_t      bufsz;              /**< Size of buffer */
  HANDLE   fh;                      /**< File handle */
  uint8_t *buf;                     /**< File buffer */
  char    *path;                    /**< WAL file path */
  pthread_mutex_t *mtxp;            /**< Global WAL mutex */
  pthread_cond_t  *cpt_condp;       /**< Checkpoint thread cond variable */
  pthread_cond_t  *bkp_condp;       /**< Online backup stage cond variable */
  pthread_t       *cptp;            /**< Checkpoint thread */
  iwrc (*wal_lock_interceptor)(bool, void*);
  /**< Optional function called
       - before acquiring
       - after releasing
       exclusive database lock by WAL checkpoint thread.
       In the case of `before lock` first argument will be set to true */
  void    *wal_lock_interceptor_opaque;  /**< Opaque data for `wal_lock_interceptor` */
  uint32_t savepoint_timeout_sec;        /**< Savepoint timeout seconds */
  uint32_t checkpoint_timeout_sec;       /**< Checkpoint timeout seconds */
  atomic_size_t mbytes;                  /**< Cumulative logged write volume since the last checkpoint */
  off_t    rollforward_offset;           /**< Rollforward offset during online backup */
  uint64_t checkpoint_ts;                /**< Last checkpoint timestamp milliseconds */
  pthread_mutex_t mtx;                   /**< Global WAL mutex */
  pthread_cond_t  cpt_cond;              /**< Checkpoint thread cond variable */
  pthread_cond_t  bkp_cond;              /**< Online backup stage cond variable */
  pthread_t       cpt;                   /**< Checkpoint thread */
  struct iwkv    *iwkv;

  struct iwal_pentry *pents;             /**< Coalescing pending writes */
  size_t   pents_cap;                    /**< Capacity of `pents` */
  uint32_t pents_num;                    /**< Number of pending writes */
  int32_t  pents_head;                   /**< Oldest pending write (list head) */
  int32_t  pents_tail;                   /**< Newest pending write (list tail) */
  int32_t *phash;                        /**< (off,len) -> pents index + 1, 0 empty */
  size_t   phash_sz;                     /**< Power of two hash table size */
  uint8_t *parena;                       /**< Pending write data arena */
  size_t   parena_cap;                   /**< Arena capacity in bytes */
  size_t   parena_pos;                   /**< Arena used bytes */
  uint32_t coalesce_maxlen;              /**< Max write length eligible for coalescing */
};

typedef struct iwal IWAL;

static iwrc _checkpoint_exl(struct iwal *wal, uint64_t *tsp, bool no_fixpoint);
static iwrc _resize_rollforward_exl(struct iwal *wal, IWFS_EXT *extf, off_t target);
static void _account_write(struct iwal *wal, off_t off, off_t len);

IW_INLINE iwrc _lock(struct iwal *wal) {
  int rci = pthread_mutex_lock(wal->mtxp);
  return (rci ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci) : 0);
}

IW_INLINE iwrc _unlock(struct iwal *wal) {
  int rci = pthread_mutex_unlock(wal->mtxp);
  return (rci ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci) : 0);
}

/// Set the online-backup stage and wake threads waiting for it to change.
/// Must be called with `wal->mtx` held.
IW_INLINE void _bkp_stage_set(struct iwal *wal, int stage) {
  if (wal->bkp_stage != stage) {
    wal->bkp_stage = stage;
    if (wal->bkp_condp) {
      pthread_cond_broadcast(wal->bkp_condp);
    }
  }
}

static iwrc _excl_lock(struct iwal *wal) {
  iwrc rc = 0;
  if (wal->wal_lock_interceptor) {
    rc = wal->wal_lock_interceptor(true, wal->wal_lock_interceptor_opaque);
    RCRET(rc);
  }
  rc = iwkv_exclusive_lock(wal->iwkv);
  if (rc) {
    if (wal->wal_lock_interceptor) {
      IWRC(wal->wal_lock_interceptor(false, wal->wal_lock_interceptor_opaque), rc);
    }
    return rc;
  }
  rc = _lock(wal);
  if (rc) {
    IWRC(iwkv_exclusive_unlock(wal->iwkv), rc);
    if (wal->wal_lock_interceptor) {
      IWRC(wal->wal_lock_interceptor(false, wal->wal_lock_interceptor_opaque), rc);
    }
  }
  return rc;
}

static iwrc _excl_unlock(struct iwal *wal) {
  iwrc rc = _unlock(wal);
  IWRC(iwkv_exclusive_unlock(wal->iwkv), rc);
  if (wal->wal_lock_interceptor) {
    IWRC(wal->wal_lock_interceptor(false, wal->wal_lock_interceptor_opaque), rc);
  }
  return rc;
}

static iwrc _init_locks(struct iwal *wal) {
  int rci = pthread_mutex_init(&wal->mtx, 0);
  if (rci) {
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  wal->mtxp = &wal->mtx;
  rci = pthread_cond_init(&wal->bkp_cond, 0);
  if (rci) {
    pthread_mutex_destroy(&wal->mtx);
    wal->mtxp = 0;
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  wal->bkp_condp = &wal->bkp_cond;
  return 0;
}

static void _wal_shutdown(struct iwal *wal) {
  while (wal->bkp_stage) { // todo: review
    iwp_sleep(50);
  }
  wal->open = false;
  if (wal->mtxp && wal->cpt_condp) {
    pthread_mutex_lock(wal->mtxp);
    pthread_cond_broadcast(wal->cpt_condp);
    if (wal->bkp_condp) {
      pthread_cond_broadcast(wal->bkp_condp);
    }
    pthread_mutex_unlock(wal->mtxp);
  }
  if (wal->cptp) {
    pthread_join(wal->cpt, 0);
    wal->cptp = 0;
  }
}

static void _destroy(struct iwal *wal) {
  if (wal) {
    _wal_shutdown(wal);
    if (!INVALIDHANDLE(wal->fh)) {
      iwp_unlock(wal->fh);
      iwp_closefh(wal->fh);
    }
    if (wal->bkp_condp) {
      pthread_cond_destroy(wal->bkp_condp);
      wal->bkp_condp = 0;
    }
    if (wal->cpt_condp) {
      pthread_cond_destroy(wal->cpt_condp);
      wal->cpt_condp = 0;
    }
    if (wal->mtxp) {
      pthread_mutex_destroy(wal->mtxp);
      wal->mtxp = 0;
    }
    free(wal->path);
    free(wal->pents);
    free(wal->phash);
    free(wal->parena);
    free(wal->dirty_bitmap);
    if (wal->buf) {
      wal->buf -= sizeof(WBSEP);
      free(wal->buf);
    }
    free(wal);
  }
}

static iwrc _flush_buf(struct iwal *wal, bool sync) {
  iwrc rc = 0;
  if (wal->bufpos) {
    uint32_t crc = wal->check_cp_crc ? iwu_crc32(wal->buf, wal->bufpos, 0) : 0;
    WBSEP sep = {
      .id = WOP_SEP,
      .crc = crc,
      .len = wal->bufpos
    };
    size_t wz = wal->bufpos + sizeof(WBSEP);
    uint8_t *wp = wal->buf - sizeof(WBSEP);
    memcpy(wp, &sep, sizeof(WBSEP));
    rc = iwp_write(wal->fh, wp, wz);
    RCRET(rc);
    wal->bufpos = 0;
  }
  if (sync) {
    rc = iwp_fsync(wal->fh);
  }
  return rc;
}

IW_INLINE iwrc _truncate_wl(struct iwal *wal) {
  iwrc rc = iwp_ftruncate(wal->fh, 0);
  RCRET(rc);
  wal->rollforward_offset = 0;
  rc = iwp_lseek(wal->fh, 0, IWP_SEEK_SET, 0);
  RCRET(rc);
  rc = iwp_fsync(wal->fh);
  return rc;
}

/// Append a raw WAL record (and optional payload) to the intermediate buffer.
/// Does not touch the coalescing pending set; callers that must preserve WAL
/// ordering have to flush pending writes first (see `_write_wl`).
static iwrc _append_wl(struct iwal *wal, const void *op, off_t oplen, const uint8_t *data, off_t len) {
  iwrc rc = 0;
  const off_t bufsz = wal->bufsz;
  wal->synched = false;
  if (bufsz - wal->bufpos < oplen) {
    RCC(rc, finish, _flush_buf(wal, false));
  }
  assert(bufsz - wal->bufpos >= oplen);
  memcpy(wal->buf + wal->bufpos, op, (size_t) oplen);
  wal->bufpos += oplen;
  if (bufsz - wal->bufpos < len) {
    RCC(rc, finish, _flush_buf(wal, false));
    RCC(rc, finish, iwp_write(wal->fh, data, (size_t) len));
  } else if (len > 0) {
    assert(bufsz - wal->bufpos >= len);
    memcpy(wal->buf + wal->bufpos, data, (size_t) len);
    wal->bufpos += len;
  }
finish:
  return rc;
}

//-------------------------- Pending write coalescing

static uint32_t _pending_hash(off_t off, uint32_t len) {
  uint64_t h = (uint64_t) off ^ ((uint64_t) len * 0x9E3779B97F4A7C15ULL);
  h ^= h >> 33;
  h *= 0xFF51AFD7ED558CCDULL;
  h ^= h >> 33;
  return (uint32_t) h;
}

static int32_t _pending_lookup(struct iwal *wal, off_t off, uint32_t len) {
  if (!wal->phash_sz) {
    return -1;
  }
  const uint32_t mask = (uint32_t) (wal->phash_sz - 1);
  uint32_t i = _pending_hash(off, len) & mask;
  for ( ; ; ) {
    int32_t v = wal->phash[i];
    if (!v) {
      return -1;
    }
    struct iwal_pentry *e = &wal->pents[v - 1];
    if (e->off == off && e->len == len) {
      return v - 1;
    }
    i = (i + 1) & mask;
  }
}

static iwrc _pending_hash_resize(struct iwal *wal, size_t nsz) {
  int32_t *nt = malloc(nsz * sizeof(*nt));
  if (!nt) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  memset(nt, 0, nsz * sizeof(*nt));
  const uint32_t mask = (uint32_t) (nsz - 1);
  for (int32_t e = wal->pents_head; e != -1; e = wal->pents[e].next) {
    uint32_t i = _pending_hash(wal->pents[e].off, wal->pents[e].len) & mask;
    while (nt[i]) {
      i = (i + 1) & mask;
    }
    nt[i] = e + 1;
  }
  free(wal->phash);
  wal->phash = nt;
  wal->phash_sz = nsz;
  return 0;
}

static void _pending_hash_put(struct iwal *wal, int32_t e) {
  const uint32_t mask = (uint32_t) (wal->phash_sz - 1);
  uint32_t i = _pending_hash(wal->pents[e].off, wal->pents[e].len) & mask;
  while (wal->phash[i]) {
    i = (i + 1) & mask;
  }
  wal->phash[i] = e + 1;
}

static iwrc _pending_hash_ensure(struct iwal *wal) {
  if (!wal->phash_sz) {
    return _pending_hash_resize(wal, IWAL_PHASH_MIN);
  }
  if (((size_t) wal->pents_num + 1) * 10 >= wal->phash_sz * 7) { // load factor 0.7
    return _pending_hash_resize(wal, wal->phash_sz << 1);
  }
  return 0;
}

static iwrc _pending_ensure(struct iwal *wal, size_t n) {
  if (n <= wal->pents_cap) {
    return 0;
  }
  size_t cap = wal->pents_cap ? wal->pents_cap : 64;
  while (cap < n) {
    cap <<= 1;
  }
  struct iwal_pentry *np = realloc(wal->pents, cap * sizeof(*np));
  if (!np) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  wal->pents = np;
  wal->pents_cap = cap;
  return 0;
}

static iwrc _pending_arena_ensure(struct iwal *wal, size_t need) {
  if (wal->parena_pos + need <= wal->parena_cap) {
    return 0;
  }
  size_t cap = wal->parena_cap ? wal->parena_cap : 65536;
  while (cap < wal->parena_pos + need) {
    cap <<= 1;
  }
  uint8_t *na = realloc(wal->parena, cap);
  if (!na) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  wal->parena = na;
  wal->parena_cap = cap;
  return 0;
}

static void _pending_reset(struct iwal *wal) {
  wal->pents_head = -1;
  wal->pents_tail = -1;
  wal->pents_num = 0;
  wal->parena_pos = 0;
  if (wal->phash_sz) {
    memset(wal->phash, 0, wal->phash_sz * sizeof(*wal->phash));
  }
}

/// Serialize the coalesced pending set into the WAL buffer.
///
/// Entries are emitted in last-write order. For pure writes this is equivalent
/// to replaying them in the original order: for every byte the entry with the
/// greatest write time is emitted last, and thus wins. `SET`, `COPY` and
/// `RESIZE` records are emitted through `_write_wl`, which flushes this set
/// first, so they can never be reordered against plain writes.
static iwrc _flush_pending(struct iwal *wal) {
  iwrc rc = 0;
  for (int32_t e = wal->pents_head; e != -1; e = wal->pents[e].next) {
    struct iwal_pentry *pe = &wal->pents[e];
    if (pe->is_fill) {
      WBSET wb = {
        .id = WOP_SET,
        .val = pe->fill_val,
        .off = pe->off,
        .len = pe->len
      };
      rc = _append_wl(wal, &wb, sizeof(wb), 0, 0);
    } else if (pe->has_base) {
      // Emit only the net change since the first write of this region in the
      // current flushing window, as a single compact patch record. The union
      // keeps `hdr` properly aligned while `blob` is the serialized record.
      union {
        WBPATCH hdr;
        uint8_t blob[sizeof(WBPATCH) + IWAL_DIFF_MAXLEN * (size_t) 4 + 16];
      } patch;
      WBPATCH *wb = &patch.hdr;
      const uint8_t *base = wal->parena + pe->arena_base_off;
      const uint8_t *cur = wal->parena + pe->arena_off;
      wb->id = WOP_PATCH;
      wb->off = pe->off;
      uint8_t *p = patch.blob + sizeof(*wb);
      for (uint32_t i = 0; i < pe->len; ) {
        if (base[i] == cur[i]) {
          ++i;
          continue;
        }
        const uint32_t start = i;
        while (i < pe->len && base[i] != cur[i]) {
          ++i;
        }
        const uint32_t slen = i - start;
        int step;
        IW_SETVNUMBUF(step, p, start);
        p += step;
        IW_SETVNUMBUF(step, p, slen);
        p += step;
        memcpy(p, cur + start, slen);
        p += slen;
      }
      wb->len = (uint32_t) (p - (patch.blob + sizeof(*wb)));
      if (wb->len) {
        rc = _append_wl(wal, patch.blob, (off_t) (p - patch.blob), 0, 0);
      }
    } else {
      WBWRITE wb = {
        .id = WOP_WRITE,
        .crc = wal->check_cp_crc ? iwu_crc32(wal->parena + pe->arena_off, pe->len, 0) : 0,
        .len = pe->len,
        .off = pe->off
      };
      rc = _append_wl(wal, &wb, sizeof(wb), wal->parena + pe->arena_off, pe->len);
    }
    RCRET(rc);
  }
  _pending_reset(wal);
  return 0;
}

/// Flush all pending coalesced writes and then the intermediate WAL buffer.
static iwrc _flush_wl(struct iwal *wal, bool sync) {
  iwrc rc = _flush_pending(wal);
  RCRET(rc);
  return _flush_buf(wal, sync);
}

/// Emit a WAL record, making sure all preceding coalesced writes are on the
/// log before it (ordering barrier).
static iwrc _write_wl(struct iwal *wal, const void *op, off_t oplen, const uint8_t *data, off_t len) {
  iwrc rc = _flush_pending(wal);
  RCRET(rc);
  return _append_wl(wal, op, oplen, data, len);
}

/// Invalidate the retained window-start bytes of any diffed entry that a `SET`
/// fill partially overlaps. Such a fill changes bytes behind the entry's back,
/// so a later diff against the old base would be wrong; the entry falls back to
/// emitting its full current content. `SET` records are rare, so the linear
/// scan is acceptable.
static void _pending_invalidate_overlap(struct iwal *wal, off_t off, uint32_t len) {
  const off_t end = off + (off_t) len;
  for (int32_t e = wal->pents_head; e != -1; e = wal->pents[e].next) {
    struct iwal_pentry *pe = &wal->pents[e];
    if (pe->has_base && (pe->off < end) && (off < pe->off + (off_t) pe->len)) {
      pe->has_base = 0;
    }
  }
}

/// Coalesce a plain file write, a `SET` fill, or a diff-capable write.
///
/// Repeated operations on the same region (same offset and length) replace the
/// previous pending value instead of appending a new record. When @a old is not
/// NULL the window-start bytes are also kept, so that only the net changed
/// bytes are emitted at flush time as a compact patch.
static iwrc _write_pending_wl(
  struct iwal   *wal,
  off_t          off,
  const uint8_t *old,
  const uint8_t *data,
  uint32_t       len,
  uint8_t        fill,
  uint32_t       fill_val) {
  iwrc rc = 0;
  wal->synched = false;
  if (!len) {
    return 0;
  }
  _account_write(wal, off, len);
  const bool diff = old && (len <= IWAL_DIFF_MAXLEN);
  if (!fill && !diff && len > wal->coalesce_maxlen && (_pending_lookup(wal, off, len) < 0)) {
    // Large one-shot write: bypass the coalescing set to avoid its extra copy
    // and hash bookkeeping. This is an ordering barrier for pending writes.
    WBWRITE wb = {
      .id = WOP_WRITE,
      .crc = wal->check_cp_crc ? iwu_crc32(data, len, 0) : 0,
      .len = len,
      .off = off
    };
    rc = _flush_pending(wal);
    RCRET(rc);
    return _append_wl(wal, &wb, sizeof(wb), data, len);
  }
  if (!fill && wal->parena_pos + len + (diff ? len : 0) > wal->pending_cap) {
    // Bound the memory used by the coalescing set.
    rc = _flush_wl(wal, false);
    RCRET(rc);
  }
  int32_t e = _pending_lookup(wal, off, len);
  if (e >= 0) {
    struct iwal_pentry *pe = &wal->pents[e];
    const bool was_fill = pe->is_fill;
    pe->is_fill = fill;
    pe->fill_val = fill_val;
    if (fill) {
      pe->has_base = 0;
    }
    if (!fill) {
      if (was_fill) { // entry was a `SET` fill, no arena storage allocated yet
        RCC(rc, finish, _pending_arena_ensure(wal, len));
        pe->arena_off = (uint32_t) wal->parena_pos;
        wal->parena_pos += len;
      }
      memcpy(wal->parena + pe->arena_off, data, len);
    }
    if (e != wal->pents_tail) { // keep entries ordered by last operation time
      if (pe->prev >= 0) {
        wal->pents[pe->prev].next = pe->next;
      } else {
        wal->pents_head = pe->next;
      }
      if (pe->next >= 0) {
        wal->pents[pe->next].prev = pe->prev;
      }
      pe->prev = wal->pents_tail;
      pe->next = -1;
      wal->pents[wal->pents_tail].next = e;
      wal->pents_tail = e;
    }
    if (fill) {
      _pending_invalidate_overlap(wal, off, len);
    }
    return 0;
  }
  RCC(rc, finish, _pending_ensure(wal, (size_t) wal->pents_num + 1));
  RCC(rc, finish, _pending_hash_ensure(wal));
  if (!fill) {
    RCC(rc, finish, _pending_arena_ensure(wal, len + (diff ? len : 0)));
  }
  int32_t ni = (int32_t) wal->pents_num++;
  struct iwal_pentry *pe = &wal->pents[ni];
  pe->off = off;
  pe->len = len;
  pe->is_fill = fill;
  pe->has_base = diff ? 1 : 0;
  pe->fill_val = fill_val;
  pe->arena_off = 0;
  pe->arena_base_off = 0;
  pe->prev = wal->pents_tail;
  pe->next = -1;
  if (!fill) {
    if (diff) {
      pe->arena_base_off = (uint32_t) wal->parena_pos;
      memcpy(wal->parena + wal->parena_pos, old, len);
      wal->parena_pos += len;
    }
    pe->arena_off = (uint32_t) wal->parena_pos;
    memcpy(wal->parena + wal->parena_pos, data, len);
    wal->parena_pos += len;
  }
  if (wal->pents_tail >= 0) {
    wal->pents[wal->pents_tail].next = ni;
  } else {
    wal->pents_head = ni;
  }
  wal->pents_tail = ni;
  _pending_hash_put(wal, ni);
  if (fill) {
    _pending_invalidate_overlap(wal, off, len);
  }
finish:
  return rc;
}

/// Log only the bytes that changed in a region. The window-start bytes are kept
/// in the coalescing set and the change is materialized as a compact patch when
/// the set is flushed.
static iwrc _onwrite_diff(
  struct iwdlsnr *self, off_t off, const uint8_t *old, const uint8_t *new, off_t len,
  int flags) {
  struct iwal *wal = (struct iwal*) self;
  if (wal->applying) {
    return 0;
  }
  if (len <= 0) {
    return 0;
  }
  iwrc rc = _lock(wal);
  RCRET(rc);
  rc = _write_pending_wl(wal, off, old, new, (uint32_t) len, 0, 0);
  IWRC(_unlock(wal), rc);
  return rc;
}

IW_INLINE iwrc _write_write_op(
  struct iwal   *wal,
  off_t          off,
  const uint8_t *data,
  uint32_t       len,
  uint8_t        fill,
  uint32_t       fill_val) {
  iwrc rc = _lock(wal);
  RCRET(rc);
  rc = _write_pending_wl(wal, off, 0, data, len, fill, fill_val);
  IWRC(_unlock(wal), rc);
  return rc;
}

iwrc iwal_sync(struct iwkv *iwkv) {
  struct iwal *wal = (struct iwal*) iwkv->dlsnr;
  iwrc rc = _lock(wal);
  RCRET(rc);
  rc = _flush_wl(wal, true);
  IWRC(_unlock(wal), rc);
  return rc;
}

static iwrc _onopen(struct iwdlsnr *self, const char *path, int mode) {
  return 0;
}

static iwrc _onclosing(struct iwdlsnr *self) {
  struct iwal *wal = (struct iwal*) self;
  struct iwkv *iwkv = wal->iwkv;
#ifdef IW_TESTS
  uint64_t tv = g_trigger;
  if (tv & IWKVD_WAL_NO_CHECKPOINT_ON_CLOSE) {
    iwkv->dlsnr = 0;
    _destroy(wal);
    return 0;
  }
#endif
  iwrc rc = _checkpoint_exl(wal, 0, false);
  iwkv->dlsnr = 0;
  _destroy(wal);
  return rc;
}

//-------------------------- Dirty-page accounting

/// Ensure the dirty-page bitmap can cover at least @a npages pages.
static bool _dirty_reserve(struct iwal *wal, size_t npages) {
  const size_t need = (npages + 7) >> 3;
  if (need <= wal->dirty_bitmap_cap) {
    return true;
  }
  size_t cap = wal->dirty_bitmap_cap ? wal->dirty_bitmap_cap : 4096;
  while (cap < need) {
    cap <<= 1;
  }
  uint8_t *nb = realloc(wal->dirty_bitmap, cap);
  if (!nb) {
    return false;
  }
  memset(nb + wal->dirty_bitmap_cap, 0, cap - wal->dirty_bitmap_cap);
  wal->dirty_bitmap = nb;
  wal->dirty_bitmap_cap = cap;
  return true;
}

/// Mark [off, off + len) dirty at page granularity.
static bool _dirty_mark(struct iwal *wal, off_t off, off_t len) {
  if (len <= 0) {
    return true;
  }
  const size_t ps = wal->dirty_page_sz;
  const uint64_t first = (uint64_t) off / ps;
  const uint64_t last = ((uint64_t) off + (uint64_t) len - 1) / ps;
  if (!_dirty_reserve(wal, (size_t) last + 1)) {
    return false;
  }
  for (uint64_t p = first; p <= last; ++p) {
    uint8_t *b = &wal->dirty_bitmap[p >> 3];
    const uint8_t m = (uint8_t) (1U << (p & 7));
    if (!(*b & m)) {
      *b |= m;
      ++wal->dirty_pages;
    }
  }
  return true;
}

static void _dirty_reset(struct iwal *wal) {
  if (wal->dirty_pages && wal->dirty_bitmap) {
    memset(wal->dirty_bitmap, 0, wal->dirty_bitmap_cap);
  }
  wal->dirty_pages = 0;
}

/// Account one logged private-mmap mutation. `mbytes` bounds the WAL size and
/// recovery cost; the dirty-page set bounds the private copy-on-write memory.
static void _account_write(struct iwal *wal, off_t off, off_t len) {
  if (len <= 0) {
    return;
  }
  wal->mbytes += (size_t) len;
  if (!_dirty_mark(wal, off, len)) {
    // Could not grow the dirty set: fall back to forcing a checkpoint.
    wal->force_cp = true;
  }
}

static iwrc _onset(struct iwdlsnr *self, off_t off, uint8_t val, off_t len, int flags) {
  struct iwal *wal = (struct iwal*) self;
  if (wal->applying) {
    return 0;
  }
  return _write_write_op(wal, off, 0, (uint32_t) len, 1, val);
}

static iwrc _oncopy(struct iwdlsnr *self, off_t off, off_t len, off_t noff, int flags) {
  struct iwal *wal = (struct iwal*) self;
  if (wal->applying) {
    return 0;
  }
  WBCOPY wb = {
    .id = WOP_COPY,
    .off = off,
    .len = len,
    .noff = noff
  };
  iwrc rc = _lock(wal);
  RCRET(rc);
  _account_write(wal, noff, len);
  rc = _write_wl(wal, &wb, sizeof(wb), 0, 0);
  IWRC(_unlock(wal), rc);
  return rc;
}

static iwrc _onwrite(struct iwdlsnr *self, off_t off, const void *buf, off_t len, int flags) {
  assert(len <= (size_t) (-1));
  struct iwal *wal = (struct iwal*) self;
  if (wal->applying) {
    return 0;
  }
  return _write_write_op(wal, off, buf, (uint32_t) len, 0, 0);
}

static iwrc _onresize(struct iwdlsnr *self, off_t osize, off_t nsize, int flags, bool *handled) {
  struct iwal *wal = (struct iwal*) self;
  if (wal->applying) {
    *handled = false;
    return 0;
  }
  *handled = true;
  WBRESIZE wb = {
    .id = WOP_RESIZE,
    .osize = osize,
    .nsize = nsize
  };
  iwrc rc = _lock(wal);
  RCRET(rc);
  // The main database file is being copied for an online backup and must not grow.
  // Wait until the copy is complete; `bkp_stage` changes are broadcast under `wal->mtx`.
  while (wal->bkp_condp && wal->bkp_stage == BKP_MAIN_COPY) {
    int rci = pthread_cond_wait(wal->bkp_condp, wal->mtxp);
    if (rci) {
      _unlock(wal);
      return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
    }
  }
  RCC(rc, finish, _write_wl(wal, &wb, sizeof(wb), 0, 0));
  if ((wal->bkp_stage == 0) && (wal->rollforward_offset == 0)) {
    IWFS_EXT *extf;
    RCC(rc, finish, _flush_wl(wal, true));
    RCC(rc, finish, wal->iwkv->fsm.extfile(&wal->iwkv->fsm, &extf));
    off_t target = (nsize > osize) ? nsize : osize;
    rc = _resize_rollforward_exl(wal, extf, target);
  } else {
    // Online backup or an active rollforward offset: use the regular fixpoint checkpoint path.
    rc = _checkpoint_exl(wal, 0, false);
  }

finish:
  IWRC(_unlock(wal), rc);
  return rc;
}

static iwrc _onsynced(struct iwdlsnr *self, int flags) {
  struct iwal *wal = (struct iwal*) self;
  if (wal->applying) {
    return 0;
  }
  iwrc rc = _lock(wal);
  RCRET(rc);
  rc = _flush_wl(wal, true);
  IWRC(_unlock(wal), rc);
  return rc;
}

static void _last_fix_and_reset_points(struct iwal *wal, uint8_t *wmm, off_t fsz, off_t *fpos, off_t *rpos) {
  uint8_t *rp = wmm;
  *fpos = 0;
  *rpos = 0;

  for (uint32_t i = 0; rp - wmm < fsz; ++i) {
    uint8_t opid;
    off_t avail = fsz - (rp - wmm);
    memcpy(&opid, rp, 1);
    if ((i == 0) && (opid != WOP_SEP)) {
      return;
    }
    switch (opid) {
      case WOP_SEP: {
        WBSEP wb;
        if (avail < sizeof(wb)) {
          return;
        }
        memcpy(&wb, rp, sizeof(wb));
        rp += sizeof(wb);
        if (wb.len > avail - (off_t) sizeof(wb)) {
          return;
        }
        break;
      }
      case WOP_SET: {
        if (avail < sizeof(WBSET)) {
          return;
        }
        rp += sizeof(WBSET);
        break;
      }
      case WOP_COPY: {
        if (avail < sizeof(WBCOPY)) {
          return;
        }
        rp += sizeof(WBCOPY);
        break;
      }
      case WOP_WRITE: {
        WBWRITE wb;
        if (avail < sizeof(wb)) {
          return;
        }
        memcpy(&wb, rp, sizeof(wb));
        rp += sizeof(wb);
        if (wb.len > avail - (off_t) sizeof(wb)) {
          return;
        }
        rp += wb.len;
        break;
      }
      case WOP_PATCH: {
        WBPATCH wb;
        if (avail < sizeof(wb)) {
          return;
        }
        memcpy(&wb, rp, sizeof(wb));
        rp += sizeof(wb);
        if (wb.len > avail - (off_t) sizeof(wb)) {
          return;
        }
        rp += wb.len;
        break;
      }
      case WOP_RESIZE: {
        if (avail < sizeof(WBRESIZE)) {
          return;
        }
        rp += sizeof(WBRESIZE);
        break;
      }
      case WOP_SAVEPOINT: {
        if (avail < sizeof(WBSAVEPOINT)) {
          return;
        }
        *fpos = (rp - wmm);
        rp += sizeof(WBSAVEPOINT);
        break;
      }
      case WOP_RESET: {
        if (avail < sizeof(WBRESET)) {
          return;
        }
        *rpos = (rp - wmm);
        rp += sizeof(WBRESET);
        break;
      }
      default: {
        return;
        break;
      }
    }
  }
}

/// Bounded decode of a 32-bit WAL varint. Returns 0 on success, -1 when the
/// value would extend past @a end (a malformed or torn WAL).
static int _wal_read_vnum32(uint8_t **pp, const uint8_t *end, uint32_t *out) {
  const uint8_t *p = *pp;
  int cont = 0;
  while (p < end && (*p >= 0x80U) && cont < 4) {
    ++p;
    ++cont;
  }
  if (p >= end || (*p >= 0x80U)) {
    return -1;
  }
  int step = 0;
  *out = iw_readvnumbuf32(*pp, &step);
  *pp = *pp + step;
  return 0;
}

/// Applies the WAL records in [wmm, wmm + fsz) to the current exfile mapping.
///
/// `min_apply_off` allows an already committed prefix to be parsed and validated
/// without being re-applied. A non-zero `stop_off` stops the application right
/// before the WOP_SAVEPOINT located at that offset (used by recovery). When
/// `apply_resize` is false WOP_RESIZE records are validated but not applied,
/// which is required when re-applying into a private mapping whose COW pages
/// would otherwise be discarded by a remap.
///
/// Returns IWKV_ERROR_CORRUPTED_WAL_FILE on a malformed WAL.
static iwrc _apply_wl_records(
  struct iwal *wal, IWFS_EXT *extf, uint8_t *wmm, off_t fsz,
  off_t stop_off, off_t min_apply_off, bool apply_resize, bool notify_fixpoint) {
  assert(wal->bufpos == 0);
  iwrc rc = 0;
  size_t sp;
  uint8_t *mm = 0;
  const bool ccrc = wal->check_cp_crc;
  uint8_t *rp = wmm;

#define _WAL_CORRUPTED(msg_) do {             \
          rc = IWKV_ERROR_CORRUPTED_WAL_FILE; \
          iwlog_ecode_error2(rc, msg_);       \
          goto finish;                        \
} while (0);

  for (uint32_t i = 0; rp - wmm < fsz; ++i) {
    uint8_t opid;
    off_t avail = fsz - (rp - wmm);
    off_t roff = rp - wmm;
    memcpy(&opid, rp, 1);
    if ((i == 0) && (opid != WOP_SEP)) {
      rc = IWKV_ERROR_CORRUPTED_WAL_FILE;
      goto finish;
    }
    switch (opid) {
      case WOP_SEP: {
        WBSEP wb;
        if (avail < sizeof(wb)) {
          _WAL_CORRUPTED("Premature end of WAL (WBSEP)");
        }
        memcpy(&wb, rp, sizeof(wb));
        rp += sizeof(wb);
        if (wb.len > avail - (off_t) sizeof(wb)) {
          _WAL_CORRUPTED("Premature end of WAL (WBSEP)");
        }
        if (ccrc && wb.crc) {
          uint32_t crc = iwu_crc32(rp, wb.len, 0);
          if (crc != wb.crc) {
            _WAL_CORRUPTED("Invalid CRC32 checksum of WAL segment (WBSEP)");
          }
        }
        break;
      }
      case WOP_SET: {
        WBSET wb;
        if (avail < sizeof(wb)) {
          _WAL_CORRUPTED("Premature end of WAL (WBSET)");
        }
        memcpy(&wb, rp, sizeof(wb));
        rp += sizeof(wb);
        if (roff < min_apply_off) {
          break;
        }
        RCC(rc, finish, extf->probe_mmap_unsafe(extf, 0, &mm, &sp));

        if (  (wb.off < 0) || (wb.len < 0)
           || ((uint64_t) wb.len > (uint64_t) sp)
           || ((uint64_t) wb.off > (uint64_t) sp - (uint64_t) wb.len)) {
          _WAL_CORRUPTED("WAL WBSET range is out of bounds");
        }
        memset(mm + wb.off, wb.val, (size_t) wb.len);
        break;
      }
      case WOP_COPY: {
        WBCOPY wb;
        if (avail < sizeof(wb)) {
          _WAL_CORRUPTED("Premature end of WAL (WBCOPY)");
        }
        memcpy(&wb, rp, sizeof(wb));
        rp += sizeof(wb);
        if (roff < min_apply_off) {
          break;
        }
        RCC(rc, finish, extf->probe_mmap_unsafe(extf, 0, &mm, &sp));

        if (  (wb.off < 0) || (wb.len < 0) || (wb.noff < 0)
           || ((uint64_t) wb.len > (uint64_t) sp)
           || ((uint64_t) wb.off > (uint64_t) sp - (uint64_t) wb.len)
           || ((uint64_t) wb.noff > (uint64_t) sp - (uint64_t) wb.len)) {
          _WAL_CORRUPTED("WAL WBCOPY range is out of bounds");
        }
        memmove(mm + wb.noff, mm + wb.off, (size_t) wb.len);
        break;
      }
      case WOP_WRITE: {
        WBWRITE wb;
        if (avail < sizeof(wb)) {
          _WAL_CORRUPTED("Premature end of WAL (WBWRITE)");
        }
        memcpy(&wb, rp, sizeof(wb));
        rp += sizeof(wb);
        if (wb.len > avail - (off_t) sizeof(wb)) {
          _WAL_CORRUPTED("Premature end of WAL (WBWRITE)");
        }
        if (ccrc && wb.crc) {
          uint32_t crc = iwu_crc32(rp, wb.len, 0);
          if (crc != wb.crc) {
            _WAL_CORRUPTED("Invalid CRC32 checksum of WAL segment (WBWRITE)");
          }
        }
        if (roff < min_apply_off) {
          rp += wb.len;
          break;
        }
        RCC(rc, finish, extf->probe_mmap_unsafe(extf, 0, &mm, &sp));

        if (  (wb.off < 0)
           || ((uint64_t) wb.len > (uint64_t) sp)
           || ((uint64_t) wb.off > (uint64_t) sp - (uint64_t) wb.len)) {
          _WAL_CORRUPTED("WAL WBWRITE range is out of bounds");
        }
        memmove(mm + wb.off, rp, wb.len);
        rp += wb.len;
        break;
      }
      case WOP_PATCH: {
        WBPATCH wb;
        if (avail < sizeof(wb)) {
          _WAL_CORRUPTED("Premature end of WAL (WBPATCH)");
        }
        memcpy(&wb, rp, sizeof(wb));
        rp += sizeof(wb);
        if (wb.len > avail - (off_t) sizeof(wb)) {
          _WAL_CORRUPTED("Premature end of WAL (WBPATCH)");
        }
        if (roff < min_apply_off) {
          rp += wb.len;
          break;
        }
        if (wb.len) {
          RCC(rc, finish, extf->probe_mmap_unsafe(extf, 0, &mm, &sp));
          uint8_t *end = rp + wb.len;
          while (rp < end) {
            uint32_t soff, slen;
            if (_wal_read_vnum32(&rp, end, &soff) || _wal_read_vnum32(&rp, end, &slen)) {
              _WAL_CORRUPTED("Invalid WAL WBPATCH span");
            }
            if ((uint64_t) (end - rp) < (uint64_t) slen) {
              _WAL_CORRUPTED("Premature end of WAL (WBPATCH span data)");
            }
            if (  (wb.off < 0)
               || ((uint64_t) wb.off + soff > (uint64_t) sp)
               || ((uint64_t) slen > (uint64_t) sp - ((uint64_t) wb.off + soff))) {
              _WAL_CORRUPTED("WAL WBPATCH range is out of bounds");
            }
            memmove(mm + wb.off + soff, rp, slen);
            rp += slen;
          }
        }
        break;
      }
      case WOP_RESIZE: {
        WBRESIZE wb;
        if (avail < sizeof(wb)) {
          _WAL_CORRUPTED("Premature end of WAL (WBRESIZE)");
        }
        memcpy(&wb, rp, sizeof(wb));
        rp += sizeof(wb);
        if (wb.nsize < 0) {
          _WAL_CORRUPTED("Invalid WAL resize size");
        }
        if (!apply_resize || (roff < min_apply_off)) {
          break;
        }
        RCC(rc, finish, extf->truncate_unsafe(extf, wb.nsize));
        break;
      }
      case WOP_SAVEPOINT:
        if (avail < sizeof(WBSAVEPOINT)) {
          _WAL_CORRUPTED("Premature end of WAL (WBSAVEPOINT)");
        }
        if (stop_off && (stop_off == roff)) { // last fixpoint to
          if (notify_fixpoint) {
            WBSAVEPOINT wb;
            memcpy(&wb, rp, sizeof(wb));
            iwlog_warn("Database recovered at point of time: %"
                       PRIu64
                       " ms since epoch\n", wb.ts);
          }
          goto finish;
        }
        rp += sizeof(WBSAVEPOINT);
        break;
      case WOP_RESET: {
        if (avail < sizeof(WBRESET)) {
          _WAL_CORRUPTED("Premature end of WAL (WBRESET)");
        }
        rp += sizeof(WBRESET);
        break;
      }
      default: {
        _WAL_CORRUPTED("Invalid WAL command");
        break;
      }
    }
#ifdef IW_TESTS
    if (atomic_load(&_test_crash_rollforward_after) > 0
        && atomic_fetch_sub(&_test_crash_rollforward_after, 1) == 1) {
      // Simulate a hard process crash in the middle of WAL rollforward.
      // Dirty MAP_SHARED pages of the main file survive the process, so the
      // next open has to recover from the WAL exactly as after a real crash.
      _exit(99);
    }
#endif
  }

finish:
#undef _WAL_CORRUPTED
  return rc;
}

// Maps the WAL file for reading. On failure returns MAP_FAILED.
static uint8_t* _wal_mmap(struct iwal *wal, off_t fsz, off_t *pfsz) {
#ifndef _WIN32
  *pfsz = IW_ROUNDUP(fsz, iwp_page_size());
  uint8_t *wmm = mmap(0, (size_t) *pfsz, PROT_READ, MAP_PRIVATE, wal->fh, 0);
  #if defined(MADV_SEQUENTIAL) || defined(MADV_DONTFORK)
  int adv = 0;
  #ifdef MADV_SEQUENTIAL
  adv |= MADV_SEQUENTIAL;
  #endif
  #ifdef MADV_DONTFORK
  adv |= MADV_DONTFORK;
  #endif
  madvise(wmm, (size_t) fsz, adv);
  #endif
  return wmm;
#else
  *pfsz = fsz;
  return mmap(0, 0, PROT_READ, MAP_PRIVATE, wal->fh, 0);
#endif
}

/// Computes the effective WAL window and the offset of the last savepoint.
/// In recovery modes the window may be advanced to the last reset point, in
/// checkpoint mode to `wal->rollforward_offset`. When no savepoint is found
/// `*fpos` is left at 0 and the caller must not apply anything in recovery mode.
static iwrc _wal_window(
  struct iwal *wal, uint8_t *wmm_base, off_t fsz, int recover_mode,
  uint8_t **wmm, off_t *wfsz, off_t *fpos) {
  *wmm = wmm_base;
  *wfsz = fsz;
  *fpos = 0;
  if (recover_mode) {
    off_t rpos; // reset point
    _last_fix_and_reset_points(wal, wmm_base, fsz, fpos, &rpos);
    if (!*fpos) {
      return 0;
    }
    if ((rpos > 0) && (recover_mode == 1)) {
      // Recover from last known reset point
      if (*fpos < rpos) {
        *fpos = 0;
        return 0;
      }
      // WBSEP__WBRESET
      //        \_rpos
      rpos -= sizeof(WBSEP);
      // WBSEP__WBRESET
      // \_rpos
      *wmm += rpos;
      *wfsz -= rpos;
      *fpos -= rpos;
    }
  } else if (wal->rollforward_offset > 0) {
    if (wal->rollforward_offset >= fsz) {
      return IWKV_ERROR_CORRUPTED_WAL_FILE;
    }
    *wmm += wal->rollforward_offset;
    *wfsz -= wal->rollforward_offset;
  }
  return 0;
}

static iwrc _rollforward_exl(struct iwal *wal, IWFS_EXT *extf, int recover_mode) {
  assert(wal->bufpos == 0);
  off_t fsz = 0;
  iwrc rc = iwp_lseek(wal->fh, 0, IWP_SEEK_END, &fsz);
  RCRET(rc);
  if (!fsz) { // empty wal log
    return 0;
  }
  off_t pfsz = 0;
  uint8_t *wmm_base = _wal_mmap(wal, fsz, &pfsz);
  if (wmm_base == MAP_FAILED) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
  uint8_t *wmm = 0;
  off_t wfsz = 0, fpos = 0;
  rc = _wal_window(wal, wmm_base, fsz, recover_mode, &wmm, &wfsz, &fpos);
  if (rc) {
    munmap(wmm_base, (size_t) pfsz);
    return rc;
  }
  // Temporary turn off extf locking
  wal->applying = true;

  // Remap fsm in MAP_SHARED mode
  extf->remove_mmap_unsafe(extf, 0);
  rc = extf->add_mmap_unsafe(extf, 0, SIZE_T_MAX, IWFS_MMAP_SHARED);
  if (rc) {
    munmap(wmm_base, (size_t) pfsz);
    wal->iwkv->fatalrc = rc;
    wal->applying = false;
    return rc;
  }

  if (!recover_mode || fpos) {
    rc = _apply_wl_records(wal, extf, wmm, wfsz, fpos, 0, true, recover_mode != 0);
  }
  if (!rc) {
    rc = extf->sync_mmap_unsafe(extf, 0, IWFS_SYNCDEFAULT);
  }
  munmap(wmm_base, (size_t) pfsz);
  IWRC(extf->remove_mmap_unsafe(extf, 0), rc);
  IWRC(extf->add_mmap_unsafe(extf, 0, SIZE_T_MAX, IWFS_MMAP_PRIVATE), rc);
  if (!rc) {
    int stage = wal->bkp_stage;
    if ((stage == 0) || (stage == BKP_WAL_CLEANUP)) {
      rc = _truncate_wl(wal);
    } else {
      // Don't truncate WAL during online backup.
      // Just append the WBRESET mark
      WBRESET wb = {
        .id = WOP_RESET
      };
      IWRC(_flush_wl(wal, false), rc);
      // Write: WBSEP + WBRESET
      IWRC(_write_wl(wal, &wb, sizeof(wb), 0, 0), rc);
      IWRC(_flush_wl(wal, true), rc);
      IWRC(iwp_lseek(wal->fh, 0, IWP_SEEK_END, &fsz), rc);
      if (!rc) {
        // rollforward_offset points here --> WBSEP __ WBRESET __ EOF
        wal->rollforward_offset = fsz - (sizeof(WBSEP) + sizeof(WBRESET));
      }
    }
  }
  if (rc && !wal->iwkv->fatalrc) {
    wal->iwkv->fatalrc = rc;
  }
  wal->synched = true;
  wal->applying = false;
  return rc;
}

/// Mid-operation growth/shrink.
///
/// A growth/shrink is requested from inside an in-progress logical operation, so
/// the WAL tail after the last savepoint is not a consistent database state. The
/// main file must never advance past a savepoint, therefore:
///
///  1. only the committed prefix (up to the last savepoint) is applied to the
///     shared main file and made durable;
///  2. the file is resized to the pending `target` size;
///  3. the uncommitted tail is re-applied into the freshly remapped private
///     mapping, restoring the in-progress state.
///
/// The WAL is left untouched, so recovery still stops at the last savepoint and
/// the in-progress operation is discarded on a crash.
static iwrc _resize_rollforward_exl(struct iwal *wal, IWFS_EXT *extf, off_t target) {
  assert(wal->bufpos == 0);
  off_t fsz = 0;
  iwrc rc = iwp_lseek(wal->fh, 0, IWP_SEEK_END, &fsz);
  RCRET(rc);
  if (!fsz) { // empty wal log
    return 0;
  }
  off_t pfsz = 0;
  uint8_t *wmm_base = _wal_mmap(wal, fsz, &pfsz);
  if (wmm_base == MAP_FAILED) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }
  uint8_t *wmm = 0;
  off_t wfsz = 0, fpos = 0;
  rc = _wal_window(wal, wmm_base, fsz, 1, &wmm, &wfsz, &fpos);
  if (rc) {
    munmap(wmm_base, (size_t) pfsz);
    return rc;
  }
  wal->applying = true;

  // Phase 1: commit the prefix up to the last savepoint into the shared file.
  extf->remove_mmap_unsafe(extf, 0);
  rc = extf->add_mmap_unsafe(extf, 0, SIZE_T_MAX, IWFS_MMAP_SHARED);
  if (rc) {
    munmap(wmm_base, (size_t) pfsz);
    wal->iwkv->fatalrc = rc;
    wal->applying = false;
    return rc;
  }
  if (fpos) {
    rc = _apply_wl_records(wal, extf, wmm, wfsz, fpos, 0, true, false);
    if (!rc) {
      // Nothing is applied without a savepoint, so there is nothing to sync
      // (and an empty file has a zero-length mapping).
      rc = extf->sync_mmap_unsafe(extf, 0, IWFS_SYNCDEFAULT);
    }
  }
  IWRC(extf->remove_mmap_unsafe(extf, 0), rc);
  IWRC(extf->add_mmap_unsafe(extf, 0, SIZE_T_MAX, IWFS_MMAP_PRIVATE), rc);

  // Phase 2: resize first (a remap would discard restored COW pages), then
  // restore the uncommitted tail into the private mapping. The committed prefix
  // is skipped and trailing WOP_RESIZE records are no-ops at this point.
  if (!rc) {
    rc = extf->truncate_unsafe(extf, target);
  }
  if (!rc) {
    rc = _apply_wl_records(wal, extf, wmm, wfsz, 0, fpos, false, false);
  }

  munmap(wmm_base, (size_t) pfsz);
  if (rc && !wal->iwkv->fatalrc) {
    wal->iwkv->fatalrc = rc;
  }
  wal->applying = false;
  return rc;
}

static iwrc _recover_wl(struct iwkv *iwkv, struct iwal *wal, IWFS_FSM_OPTS *fsmopts, bool recover_backup) {
  off_t fsz = 0;
  iwrc rc = iwp_lseek(wal->fh, 0, IWP_SEEK_END, &fsz);
  RCRET(rc);
  if (!fsz) { // empty wal log
    return 0;
  }
  IWFS_EXT extf;
  IWFS_EXT_OPTS extopts;
  memcpy(&extopts, &fsmopts->exfile, sizeof(extopts));
  extopts.use_locks = false;
  extopts.file.omode = IWFS_OCREATE | IWFS_OWRITE;
  extopts.file.dlsnr = 0;
  rc = iwfs_exfile_open(&extf, &extopts);
  RCRET(rc);
  rc = _rollforward_exl(wal, &extf, recover_backup ? 2 : 1);
  IWRC(extf.close(&extf), rc);
  return rc;
}

IW_INLINE bool _need_checkpoint(struct iwal *wal) {
  if (wal->force_cp) {
    return true;
  }
  // Bound the private copy-on-write footprint: the number of distinct pages
  // dirtied since the last checkpoint.
  if (wal->dirty_pages * wal->dirty_page_sz >= wal->checkpoint_buffer_sz) {
    return true;
  }
  // Bound the WAL size and recovery cost. A workload that rewrites a small set
  // of pages keeps the dirty-page count low while still appending WAL records.
  return wal->mbytes >= wal->checkpoint_buffer_sz;
}

static iwrc _checkpoint_exl(struct iwal *wal, uint64_t *tsp, bool no_fixpoint) {
  if (tsp) {
    *tsp = 0;
  }
  int stage = wal->bkp_stage;
  if (stage == BKP_MAIN_COPY) {
    // No checkpoints during main file copying
    return 0;
  }
  iwrc rc = 0;
  IWFS_EXT *extf;
  struct iwkv *iwkv = wal->iwkv;
  if (!no_fixpoint) {
    wal->force_cp = false;
    wal->force_sp = false;
    WBSAVEPOINT wb = {
      .id = WOP_SAVEPOINT
    };
    RCC(rc, finish, iwp_current_time_ms(&wb.ts, false));
    RCC(rc, finish, _write_wl(wal, &wb, sizeof(wb), 0, 0));
  }
  RCC(rc, finish, _flush_wl(wal, true));
  RCC(rc, finish, iwkv->fsm.extfile(&iwkv->fsm, &extf));

  rc = _rollforward_exl(wal, extf, 0);
  wal->mbytes = 0;
  _dirty_reset(wal);
  wal->synched = true;
  iwp_current_time_ms(&wal->checkpoint_ts, true);
  if (tsp) {
    *tsp = wal->checkpoint_ts;
  }

finish:
  if (rc) {
    if (iwkv->fatalrc) {
      iwlog_ecode_error3(rc);
    } else {
      iwkv->fatalrc = rc;
    }
  }
  return rc;
}

#ifdef IW_TESTS

void iwal_test_crash_on_rollforward(int nops) {
  atomic_store(&_test_crash_rollforward_after, nops);
}

iwrc iwal_test_checkpoint(struct iwkv *iwkv) {
  if (!iwkv->dlsnr) {
    return IWKV_ERROR_WAL_MODE_REQUIRED;
  }
  struct iwal *wal = (struct iwal*) iwkv->dlsnr;
  iwrc rc = _excl_lock(wal);
  RCRET(rc);
  rc = _checkpoint_exl(wal, 0, false);
  IWRC(_excl_unlock(wal), rc);
  return rc;
}

void iwal_test_set_bkp_main_copy(struct iwkv *iwkv, bool active) {
  struct iwal *wal = (struct iwal*) iwkv->dlsnr;
  if (wal && !_lock(wal)) {
    _bkp_stage_set(wal, active ? BKP_MAIN_COPY : 0);
    _unlock(wal);
  }
}

#endif

//--------------------------------------- Public API

WUR iwrc iwal_poke_checkpoint(struct iwkv *iwkv, bool force) {
  struct iwal *wal = (struct iwal*) iwkv->dlsnr;
  if (!wal || !(force || _need_checkpoint(wal))) {
    return 0;
  }
  iwrc rc = _lock(wal);
  RCRET(rc);
  bool cforce = wal->force_cp;
  if (cforce) { // Forced already
    _unlock(wal);
    return 0;
  } else if (force) {
    wal->force_cp = true;
  } else if (!_need_checkpoint(wal)) {
    _unlock(wal);
    return 0;
  }
  int rci = pthread_cond_broadcast(wal->cpt_condp);
  if (rci) {
    rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  _unlock(wal);
  return rc;
}

iwrc iwal_poke_savepoint(struct iwkv *iwkv) {
  struct iwal *wal = (struct iwal*) iwkv->dlsnr;
  if (!wal) {
    return 0;
  }
  iwrc rc = _lock(wal);
  RCRET(rc);
  bool fsp = wal->force_sp;
  if (!fsp) {
    wal->force_sp = true;
    int rci = pthread_cond_broadcast(wal->cpt_condp);
    if (rci) {
      rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
    }
  }
  _unlock(wal);
  return rc;
}

iwrc _savepoint_exl(struct iwal *wal, uint64_t *tsp, bool sync) {
  if (tsp) {
    *tsp = 0;
  }
  wal->force_sp = false;
  WBSAVEPOINT wbfp = {
    .id = WOP_SAVEPOINT
  };
  iwrc rc = iwp_current_time_ms(&wbfp.ts, false);
  RCRET(rc);
  rc = _write_wl(wal, &wbfp, sizeof(wbfp), 0, 0);
  RCRET(rc);
  rc = _flush_wl(wal, sync);
  RCRET(rc);
  if (sync) {
    wal->synched = true;
  }
  if (tsp) {
    *tsp = wbfp.ts;
  }
  return 0;
}

bool iwal_synched(struct iwkv *iwkv) {
  struct iwal *wal = (struct iwal*) iwkv->dlsnr;
  if (!wal) {
    return false;
  }
  return wal->synched;
}

iwrc iwal_savepoint_exl(struct iwkv *iwkv, bool sync) {
  struct iwal *wal = (struct iwal*) iwkv->dlsnr;
  if (!wal) {
    return 0;
  }
  return _savepoint_exl(wal, 0, sync);
}

void iwal_shutdown(struct iwkv *iwkv) {
  struct iwal *wal = (struct iwal*) iwkv->dlsnr;
  if (wal) {
    _wal_shutdown(wal);
  }
}

static void* _cpt_worker_fn(void *op) {
  iwp_set_current_thread_name("iwal::CPT");

  int rci;
  iwrc rc = 0;
  struct iwal *wal = op;
  struct iwkv *iwkv = wal->iwkv;
  uint64_t savepoint_ts = 0;

  while (wal->open) {
    struct timespec tp;
    uint64_t tick_ts;
    bool sp = false, cp = false;
    rc = _lock(wal);
    RCBREAK(rc);

    if (_need_checkpoint(wal)) {
      cp = true;
      _unlock(wal);
      goto cprun;
    } else if (wal->force_sp) {
      sp = true;
      _unlock(wal);
      goto cprun;
    }

#if defined(IW_HAVE_CLOCK_MONOTONIC) && defined(IW_HAVE_PTHREAD_CONDATTR_SETCLOCK)
    rc = iwp_clock_get_time(CLOCK_MONOTONIC, &tp);
#else
    rc = iwp_clock_get_time(CLOCK_REALTIME, &tp);
#endif
    if (rc) {
      _unlock(wal);
      break;
    }
    tp.tv_sec += 1; // one sec tick
    tick_ts = tp.tv_sec * 1000 + (uint64_t) round(tp.tv_nsec / 1.0e6);
    do {
      rci = pthread_cond_timedwait(wal->cpt_condp, wal->mtxp, &tp);
    } while (rci == EINTR && !wal->open);
    if (rci && (rci != ETIMEDOUT)) {
      rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
      _unlock(wal);
      break;
    }
    if (!wal->open || iwkv->fatalrc) {
      _unlock(wal);
      break;
    }
    bool synched = wal->synched;
    size_t mbytes = wal->mbytes;
    cp = _need_checkpoint(wal) || ((mbytes && (tick_ts - wal->checkpoint_ts) >= 1000LL * wal->checkpoint_timeout_sec));
    if (!cp) {
      sp = !synched && (wal->force_sp || ((tick_ts - savepoint_ts) >= 1000LL * wal->savepoint_timeout_sec));
    }
    _unlock(wal);

cprun:
    if (cp || sp) {
      rc = _excl_lock(wal);
      RCBREAK(rc);
      if (iwkv->open) {
        if (cp) {
          rc = _checkpoint_exl(wal, &savepoint_ts, false);
        } else {
          rc = _savepoint_exl(wal, &savepoint_ts, true);
        }
      }
      _excl_unlock(wal);
      if (rc) {
        iwlog_ecode_error2(rc, "WAL worker savepoint/checkpoint error\n");
        rc = 0;
      }
    }
  }
  if (rc) {
    iwkv->fatalrc = iwkv->fatalrc ? iwkv->fatalrc : rc;
    iwlog_ecode_error2(rc, "WAL worker exited with error\n");
  }
  return 0;
}

iwrc iwal_online_backup(struct iwkv *iwkv, uint64_t *ts, const char *target_file) {
  iwrc rc;
  size_t sp;
  uint32_t lv;
  uint64_t llv;
  char buf[16384];
  off_t off = 0, fsize = 0;
  *ts = 0;

  if (!target_file) {
    return IW_ERROR_INVALID_ARGS;
  }
  struct iwal *wal = (struct iwal*) iwkv->dlsnr;
  if (!wal) {
    return IWKV_ERROR_WAL_MODE_REQUIRED;
  }

  rc = _lock(wal);
  RCRET(rc);
  if (wal->bkp_stage) {
    rc = IWKV_ERROR_BACKUP_IN_PROGRESS;
  } else {
    _bkp_stage_set(wal, BKP_STARTED);
  }
  _unlock(wal);

#ifndef _WIN32
  HANDLE fh = open(target_file, O_CREAT | O_WRONLY | O_TRUNC, 00600);
  if (INVALIDHANDLE(fh)) {
    rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    goto finish;
  }
#else
  HANDLE fh = CreateFile(target_file, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (INVALIDHANDLE(fh)) {
    rc = iwrc_set_werror(IW_ERROR_IO_ERRNO, GetLastError());
    goto finish;
  }
#endif

  // Flush all pending WAL changes.
  RCC(rc, finish, _excl_lock(wal));

  _bkp_stage_set(wal, BKP_WAL_CLEANUP);
  RCC(rc, unlock_excl, _checkpoint_exl(wal, 0, false));

  // Capture the main file handle while still holding the exclusive lock.
  // The main copy below must not take any exfile lock: `_onresize()` waits
  // for `BKP_MAIN_COPY` to finish while holding the exfile write lock, so
  // taking that lock here would deadlock the backup.
  IWFS_FSM_STATE fstate = { 0 };
  RCC(rc, unlock_excl, iwkv->fsm.state(&iwkv->fsm, &fstate));
  _bkp_stage_set(wal, BKP_MAIN_COPY);
  RCC(rc, finish, _excl_unlock(wal));

  // Copy the main database file.
  // Concurrent writers only modify the private mmap and append to the WAL;
  // a required file growth is deferred by `_onresize()` until this copy is
  // complete, so the copied main file image stays stable.
  do {
    rc = iwp_pread(fstate.exfile.file.fh, off, buf, sizeof(buf), &sp);
    RCGO(rc, finish);
    if (sp > 0) {
      rc = iwp_write(fh, buf, sp);
      RCGO(rc, finish);
      off += sp;
    }
  } while (sp > 0);

  // Copy most of WAL file content
  RCC(rc, finish, _lock(wal));
  _bkp_stage_set(wal, BKP_WAL_COPY1);
  rc = _flush_wl(wal, false);
  _unlock(wal);
  RCGO(rc, finish);

  fsize = off;
  off = 0;
  do {
    RCC(rc, finish, iwp_pread(wal->fh, off, buf, sizeof(buf), &sp));
    if (sp > 0) {
      rc = iwp_write(fh, buf, sp);
      RCGO(rc, finish);
      off += sp;
    }
  } while (sp > 0);

  // Copy rest of WAL file in exclusive locked mode
  RCC(rc, finish, _excl_lock(wal));
  _bkp_stage_set(wal, BKP_WAL_COPY2);
  RCC(rc, unlock_excl, _savepoint_exl(wal, ts, true));
  do {
    RCC(rc, unlock_excl, iwp_pread(wal->fh, off, buf, sizeof(buf), &sp));
    if (sp > 0) {
      RCC(rc, unlock_excl, iwp_write(fh, buf, sp));
      off += sp;
    }
  } while (sp > 0);

  llv = IW_HTOILL(fsize);
  RCC(rc, unlock_excl, iwp_write(fh, &llv, sizeof(llv)));

  lv = IW_HTOIL(IWKV_BACKUP_MAGIC);
  RCC(rc, unlock_excl, iwp_write(fh, &lv, sizeof(lv)));

unlock_excl:
  _bkp_stage_set(wal, 0);
  IWRC(_excl_unlock(wal), rc);

finish:
  if (rc) {
    _lock(wal);
    _bkp_stage_set(wal, 0);
    _unlock(wal);
  } else {
    rc = iwal_poke_checkpoint(iwkv, true);
  }
  if (!INVALIDHANDLE(fh)) {
    IWRC(iwp_fdatasync(fh), rc);
    IWRC(iwp_closefh(fh), rc);
  }
  return rc;
}

iwrc _init_cpt(struct iwal *wal) {
  if (  (wal->savepoint_timeout_sec == UINT32_MAX)
     && (wal->checkpoint_timeout_sec == UINT32_MAX)) {
    // do not start checkpoint thread
    return 0;
  }
  iwrc rc = 0;
  pthread_attr_t pattr;
  pthread_condattr_t cattr;
  int rci = pthread_condattr_init(&cattr);
  if (rci) {
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
#if defined(IW_HAVE_CLOCK_MONOTONIC) && defined(IW_HAVE_PTHREAD_CONDATTR_SETCLOCK)
  rci = pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
  if (rci) {
    rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
    goto finish;
  }
#endif
  rci = pthread_cond_init(&wal->cpt_cond, &cattr);
  if (rci) {
    rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
    goto finish;
  }
  wal->cpt_condp = &wal->cpt_cond;
  rci = pthread_attr_init(&pattr);
  if (rci) {
    rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
    goto finish;
  }
  pthread_attr_setdetachstate(&pattr, PTHREAD_CREATE_JOINABLE);
  rci = pthread_create(&wal->cpt, &pattr, _cpt_worker_fn, wal);
  if (rci) {
    rc = iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  } else {
    wal->cptp = &wal->cpt;
  }
  pthread_attr_destroy(&pattr);
finish:
  pthread_condattr_destroy(&cattr);
  return rc;
}

iwrc iwal_create(struct iwkv *iwkv, const struct iwkv_opts *opts, struct iwfs_fsm_opts *fsmopts, bool recover_backup) {
  assert(!iwkv->dlsnr && opts && fsmopts);
  if (!opts) {
    return IW_ERROR_INVALID_ARGS;
  }
  if ((opts->oflags & IWKV_RDONLY) || !opts->wal.enabled) {
    return 0;
  }
  iwrc rc = 0;
  struct iwal *wal = calloc(1, sizeof(*wal));
  if (!wal) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  wal->pents_head = -1;
  wal->pents_tail = -1;

  wal->wal_lock_interceptor = opts->wal.wal_lock_interceptor;
  wal->wal_lock_interceptor_opaque = opts->wal.wal_lock_interceptor_opaque;

  size_t sz = strlen(opts->path);
  char *wpath = malloc(sz + 4 /*-wal*/ + 1 /*\0*/);
  if (!wpath) {
    free(wal);
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  memcpy(wpath, opts->path, sz);
  memcpy(wpath + sz, "-wal", 4);
  wpath[sz + 4] = '\0';

  wal->fh = INVALID_HANDLE_VALUE;
  wal->path = wpath;
  wal->oflags = opts->oflags;
  wal->iwkv = iwkv;
  iwp_current_time_ms(&wal->checkpoint_ts, true);

  rc = _init_locks(wal);
  RCGO(rc, finish);

  struct iwdlsnr *dlsnr = &wal->lsnr;
  dlsnr->onopen = _onopen;
  dlsnr->onclosing = _onclosing;
  dlsnr->onset = _onset;
  dlsnr->oncopy = _oncopy;
  dlsnr->onwrite = _onwrite;
  dlsnr->onwrite_diff = _onwrite_diff;
  dlsnr->onresize = _onresize;
  dlsnr->onsynced = _onsynced;
  iwkv->dlsnr = (struct iwdlsnr*) wal;

  wal->wal_buffer_sz
    = opts->wal.wal_buffer_sz > 0
      ? opts->wal.wal_buffer_sz :
#if defined __ANDROID__ || defined TARGET_OS_IPHONE
      2UL * 1024 * 1024; // 2M
#else
      8UL * 1024 * 1024; // 8M
#endif
  if (wal->wal_buffer_sz < 4096) {
    wal->wal_buffer_sz = 4096;
  }

  // Bound the memory held by the coalescing set. Measurements show that the
  // create-phase CPU cost tracks this footprint, so it is kept well below the
  // WAL buffer size.
  wal->pending_cap = wal->wal_buffer_sz / 16;
  if (wal->pending_cap < 65536) {
    wal->pending_cap = 65536;
  }

  wal->checkpoint_buffer_sz
    = opts->wal.checkpoint_buffer_sz > 0
      ? opts->wal.checkpoint_buffer_sz :
#if defined __ANDROID__ || defined TARGET_OS_IPHONE
      64ULL * 1024 * 1024; // 64M
#else
      1024ULL * 1024 * 1024; // 1G
#endif
  if (wal->checkpoint_buffer_sz < 1024UL * 1024) { // 1M minimal
    wal->checkpoint_buffer_sz = 1024UL * 1024;
  }

  wal->savepoint_timeout_sec
    = opts->wal.savepoint_timeout_sec > 0
      ? opts->wal.savepoint_timeout_sec : 10; // 10 sec

  wal->checkpoint_timeout_sec
    = opts->wal.checkpoint_timeout_sec > 0 ?
#if defined __ANDROID__ || defined TARGET_OS_IPHONE
      opts->wal.checkpoint_timeout_sec : 60; // 1 min
#else
      opts->wal.checkpoint_timeout_sec : 300; // 5 min
#endif

  if (wal->checkpoint_timeout_sec < 10) { // 10 sec minimal
    wal->checkpoint_timeout_sec = 10;
  }
  if (wal->savepoint_timeout_sec >= wal->checkpoint_timeout_sec) {
    wal->savepoint_timeout_sec = wal->checkpoint_timeout_sec / 2;
  }

  wal->check_cp_crc = opts->wal.check_crc_on_checkpoint;

  wal->dirty_page_sz = iwp_page_size();
  if (!wal->dirty_page_sz) {
    wal->dirty_page_sz = 4096;
  }

  wal->coalesce_maxlen = IWAL_COALESCE_MAXLEN;

  wal->buf = malloc(wal->wal_buffer_sz);
  if (!wal->buf) {
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    goto finish;
  }
  wal->buf += sizeof(WBSEP);
  wal->bufsz = wal->wal_buffer_sz - sizeof(WBSEP);

  // Now open WAL file

#ifndef _WIN32
  HANDLE fh = open(wal->path, O_CREAT | O_RDWR | O_CLOEXEC, IWFS_DEFAULT_FILEMODE);
  if (INVALIDHANDLE(fh)) {
    rc = iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    goto finish;
  }
#else
  HANDLE fh = CreateFile(wal->path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                         NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (INVALIDHANDLE(fh)) {
    rc = iwrc_set_werror(IW_ERROR_IO_ERRNO, GetLastError());
    goto finish;
  }
#endif

  wal->fh = fh;
  rc = iwp_flock(wal->fh, IWP_WLOCK);
  RCGO(rc, finish);

  // Now force all fsm data to be privately mmaped.
  // We will apply wal log to main database file
  // then re-read our private mmaps
  fsmopts->mmap_opts = IWFS_MMAP_PRIVATE;
  fsmopts->exfile.file.dlsnr = iwkv->dlsnr;

  if (wal->oflags & IWKV_TRUNC) {
    rc = _truncate_wl(wal);
    RCGO(rc, finish);
  } else {
    rc = _recover_wl(iwkv, wal, fsmopts, recover_backup);
    RCGO(rc, finish);
  }

  wal->open = true;
  // Start checkpoint thread
  rc = _init_cpt(wal);

finish:
  if (rc) {
    iwkv->dlsnr = 0;
    iwkv->fatalrc = iwkv->fatalrc ? iwkv->fatalrc : rc;
    iwal_shutdown(iwkv);
    _destroy(wal);
  }
  return rc;
}
