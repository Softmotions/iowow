#include "iwrdb.h"
#include "iwp.h"
#include "iwlog.h"
#include "iwfile.h"

#include <sys/types.h>
#include <fcntl.h>
#include <pthread.h>

#ifdef _WIN32
#include "win32/mman/mman.h"
#else
#include <sys/mman.h>
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#include "iwcfg.h"

#define _ENSURE_OPEN(db_) \
        if (!(db_) || INVALIDHANDLE((db_)->fh)) return IW_ERROR_INVALID_STATE

struct iwrdb {
  HANDLE fh;
  iwrdb_oflags_t    oflags;
  pthread_rwlock_t *cwl;
  char    *path;
  uint8_t *buf;
  uint8_t *mm;
  size_t   bufsz;
  size_t   msiz;
  off_t    bp;
  off_t    end;
};

IW_INLINE iwrc _wlock(IWRDB db) {
  _ENSURE_OPEN(db);
  int rci = db->cwl ? pthread_rwlock_wrlock(db->cwl) : 0;
  return (rci ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci) : 0);
}

IW_INLINE iwrc _rlock(IWRDB db) {
  _ENSURE_OPEN(db);
  int rci = db->cwl ? pthread_rwlock_rdlock(db->cwl) : 0;
  return (rci ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci) : 0);
}

IW_INLINE iwrc _unlock(IWRDB db) {
  int rci = db->cwl ? pthread_rwlock_unlock(db->cwl) : 0;
  return (rci ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci) : 0);
}

static iwrc _initlocks(IWRDB db) {
  if (db->oflags & IWRDB_NOLOCKS) {
    db->cwl = 0;
    return 0;
  }
  db->cwl = malloc(sizeof(*db->cwl));
  if (!db->cwl) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  pthread_rwlockattr_t attr;
  pthread_rwlockattr_init(&attr);
#if defined __linux__ && (defined __USE_UNIX98 || defined __USE_XOPEN2K)
  pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif
  int rci = pthread_rwlock_init(db->cwl, &attr);
  if (rci) {
    free(db->cwl);
    db->cwl = 0;
    return iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci);
  }
  return 0;
}

static iwrc _destroy_locks(IWRDB db) {
  iwrc rc = 0;
  if (db->cwl) {
    pthread_rwlock_destroy(db->cwl);
    free(db->cwl);
    db->cwl = 0;
  }
  return rc;
}

static iwrc _flush_lw(IWRDB db) {
  if (db->bp) {
    iwrc rc = iwp_write(db->fh, db->buf, db->bp);
    RCRET(rc);
    db->end += db->bp;
    db->bp = 0;
  }
  return 0;
}

static iwrc _append_lw(IWRDB db, const void *data, int len, uint64_t *oref) {
  iwrc rc = 0;
  *oref = 0;

  if (db->bufsz && db->bp + len > db->bufsz) {
    rc = _flush_lw(db);
    RCRET(rc);
  }
  if (!db->bufsz || db->bp + len > db->bufsz) {
    *oref = db->end + 1;
    rc = iwp_write(db->fh, data, len);
    RCRET(rc);
    db->end += len;
  } else {
    memcpy(db->buf + db->bp, data, len);
    *oref = db->end + db->bp + 1;
    db->bp += len;
    assert(db->bp <= db->bufsz);
  }

  return rc;
}

iwrc iwrdb_open(const char *path, iwrdb_oflags_t oflags, size_t bufsz, IWRDB *odb) {
  assert(path && odb);
  iwrc rc = 0;
  IWRDB db = 0;
  *odb = 0;

#ifndef _WIN32
  HANDLE fh = open(path, O_CREAT | O_RDWR | O_CLOEXEC, IWFS_DEFAULT_FILEMODE);
  if (INVALIDHANDLE(fh)) {
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
#else
  HANDLE fh = CreateFile(path, GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (INVALIDHANDLE(fh)) {
    return iwrc_set_werror(IW_ERROR_IO_ERRNO, GetLastError());
  }
#endif

  db = calloc(1, sizeof(*db));
  if (!db) {
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    goto finish;
  }
  *odb = db;
  db->oflags = oflags;
  db->path = strdup(path);
  db->fh = fh;
  if (bufsz) {
    db->buf = malloc(bufsz);
    if (!db->buf) {
      rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
      goto finish;
    }
    db->bufsz = bufsz;
  }
  RCC(rc, finish, iwp_lseek(db->fh, 0, IWP_SEEK_END, &db->end));
  rc = _initlocks(db);

finish:
  if (rc && db) {
    iwrdb_close(&db, false);
  }
  return rc;
}

iwrc iwrdb_sync(IWRDB db) {
  iwrc rc;
  rc = _wlock(db);
  RCRET(rc);

  RCC(rc, finish, _flush_lw(db));
  RCC(rc, finish, iwp_ftruncate(db->fh, db->end));
  RCC(rc, finish, iwp_fsync(db->fh));

finish:
  _unlock(db);
  return rc;
}

iwrc iwrdb_close(IWRDB *rdb, bool no_sync) {
  iwrc rc = 0;
  IWRDB db;
  if (!rdb || !*rdb) {
    return 0;
  }
  db = *rdb;
  *rdb = 0;
  if (db->mm) {
    munmap(db->mm, db->msiz);
  }
  if (!INVALIDHANDLE(db->fh)) {
    if (!no_sync) {
      iwrdb_sync(db);
    }
    iwp_closefh(db->fh);
  }
  _destroy_locks(db);
  free(db->path);
  free(db->buf);
  free(db);
  return rc;
}

iwrc iwrdb_append(IWRDB db, const void *data, int len, uint64_t *oref) {
  iwrc rc = _wlock(db);
  RCRET(rc);
  rc = _append_lw(db, data, len, oref);
  _unlock(db);
  return rc;
}

iwrc iwrdb_patch(IWRDB db, uint64_t ref, off_t skip, const void *data, int len) {
  iwrc rc;
  size_t sz;
  off_t sz2;
  off_t tw = len;
  off_t off = ref - 1 + skip;
  uint8_t *rp = (uint8_t*) data;

  if (!ref || off < 0 || skip < 0) {
    return IW_ERROR_INVALID_ARGS;
  }

  rc = _wlock(db);
  RCRET(rc);

  if (off + len > db->end + db->bp) {
    rc = IW_ERROR_OUT_OF_BOUNDS;
    goto finish;
  }
  if (off < db->end) {
    sz2 = MIN(len, db->end - off);
    RCC(rc, finish, iwp_pwrite(db->fh, off, rp, sz2, &sz));
    tw -= sz;
    rp += sz;
    off += sz;
  }
  if (tw > 0) {
    sz = off - db->end;
    memcpy(db->buf + sz, rp, tw);
  }

finish:
  _unlock(db);
  return rc;
}

iwrc iwrdb_read(IWRDB db, uint64_t ref, off_t skip, void *buf, int len) {
  iwrc rc;
  uint8_t *wp = buf;
  off_t to_read = len;
  off_t off = ref - 1 + skip;

  if (!ref || skip < 0 || len < 0) {
    return IW_ERROR_INVALID_ARGS;
  }

  rc = _rlock(db);
  RCRET(rc);

  if (off + len > db->end + db->bp) {
    rc = IW_ERROR_OUT_OF_BOUNDS;
    goto finish;
  }

  if (off < db->end) {
    size_t sz, sz2;
    sz2 = MIN(len, db->end - off);
    if (db->mm && off + sz2 <= db->msiz) {
      memcpy(wp, db->mm + off, sz2);
      sz = sz2;
    } else {
      RCC(rc, finish, iwp_pread(db->fh, off, wp, sz2, &sz));
      if (sz != sz2) {
        rc = IW_ERROR_OUT_OF_BOUNDS;
        goto finish;
      }
    }
    wp += sz;
    off += sz;
    to_read -= sz;
  }

  if (to_read) {
    off_t sz = off - db->end;
    if (sz + to_read > db->bp) {
      rc = IW_ERROR_OUT_OF_BOUNDS;
      goto finish;
    }
    memcpy(wp, db->buf + sz, to_read);
  }

finish:
  _unlock(db);
  return rc;
}

HANDLE iwrdb_file_handle(IWRDB db) {
  if (!_rlock(db)) {
    HANDLE h = db->fh;
    _unlock(db);
    return h;
  }
  return INVALID_HANDLE_VALUE;
}

off_t iwrdb_offset_end(IWRDB db) {
  if (!_rlock(db)) {
    off_t ret = db->end + db->bp;
    _unlock(db);
    return ret;
  }
  return -1;
}

uint8_t* iwrdb_mmap(IWRDB db, bool readonly, int madv, size_t *msiz) {
  *msiz = 0;
  if (_rlock(db)) {
    return MAP_FAILED;
  }
  if (db->mm) {
    goto finish;
  } else {
    _unlock(db);
    if (_wlock(db)) {
      return MAP_FAILED;
    }
    if (db->mm) {
      goto finish;
    }
  }

  db->msiz = 0;
  const size_t msize = IW_ROUNDUP(db->end, iwp_page_size());

  int flags = MAP_SHARED;
#ifdef MAP_NORESERVE
  flags |= MAP_NORESERVE;
#endif

  uint8_t *mm = mmap(0, msize, (readonly ? PROT_READ : (PROT_READ | PROT_WRITE)), flags, db->fh, 0);
  if (mm == MAP_FAILED) {
    goto finish;
  }

  db->mm = mm;
  db->msiz = msize;

#ifndef _WIN32
#ifdef MADV_DONTFORK
  madv |= MADV_DONTFORK;
#endif
  if (madv) {
    madvise(mm, msize, madv);
  }
#endif

finish:
  mm = db->mm;
  *msiz = db->end;
  _unlock(db);
  return mm;
}

void iwrdb_munmap(IWRDB db) {
  if (!_wlock(db)) {
    if (db->mm) {
      munmap(db->mm, db->msiz);
      db->mm = 0;
      db->msiz = 0;
    }
  }
}
