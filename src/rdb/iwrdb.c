#include "iwrdb.h"
#include "iwp.h"
#include "iwlog.h"
#include "iwfile.h"

#include <sys/types.h>
#include <fcntl.h>
#include <pthread.h>

#include "iwcfg.h"

#define _ENSURE_OPEN(db_) \
  if (!(db_) || INVALIDHANDLE((db_)->fh)) return IW_ERROR_INVALID_STATE

struct _IWRDB {
  HANDLE fh;
  iwrdb_oflags_t    oflags;
  pthread_rwlock_t *cwl;
  char    *path;
  uint8_t *buf;
  size_t   bufsz;
  off_t    bp;
  off_t    end;
};

IW_INLINE iwrc _wlock(IWRDB db) {
  int rci = db->cwl ? pthread_rwlock_wrlock(db->cwl) : 0;
  return (rci ? iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci) : 0);
}

IW_INLINE iwrc _rlock(IWRDB db) {
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
  if (!db->cwl) {
    return 0;
  }
  int rci = pthread_rwlock_destroy(db->cwl);
  if (rci) {
    IWRC(iwrc_set_errno(IW_ERROR_THREADING_ERRNO, rci), rc);
  }
  free(db->cwl);
  db->cwl = 0;
  return rc;
}

static iwrc _flush_lw(IWRDB db) {
  if (db->bp < 1) {
    return 0;
  }
  iwrc rc = iwp_write(db->fh, db->buf, db->bp);
  RCRET(rc);
  db->end += db->bp;
  db->bp = 0;
  return 0;
}

static iwrc _append_lw(IWRDB db, const void *data, int len, uint64_t *oref) {
  iwrc rc = 0;
  *oref = 0;

  if (db->bufsz && (db->bp + len > db->bufsz)) {
    rc = _flush_lw(db);
    if (rc) {
      return rc;
    }
  }
  if (!db->bufsz || (db->bp + len > db->bufsz)) {
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
  if (db->bufsz && (db->bp == db->bufsz)) {
    return _flush_lw(db);
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
  rc = iwp_lseek(db->fh, 0, IWP_SEEK_END, &db->end);
  RCGO(rc, finish);
  rc = _initlocks(db);

finish:
  if (rc && db) {
    IWRC(iwrdb_close(&db), rc);
  }
  return rc;
}

iwrc iwrdb_sync(IWRDB db) {
  iwrc rc;
  _ENSURE_OPEN(db);
  rc = _wlock(db);
  RCRET(rc);
  rc = _flush_lw(db);
  RCGO(rc, finish);
  rc = iwp_fsync(db->fh);
  RCGO(rc, finish);

finish:
  IWRC(_unlock(db), rc);
  return rc;
}

iwrc iwrdb_close(IWRDB *rdb) {
  iwrc rc = 0;
  IWRDB db;
  if (!rdb || !*rdb) {
    return 0;
  }
  db = *rdb;
  if (!INVALIDHANDLE(db->fh)) {
    IWRC(iwrdb_sync(db), rc);
    IWRC(iwp_closefh(db->fh), rc);
  }
  db->fh = INVALID_HANDLE_VALUE;
  IWRC(_destroy_locks(db), rc);
  free(db->path);
  free(db->buf);
  free(db);
  *rdb = 0;
  return rc;
}

iwrc iwrdb_append(IWRDB db, const void *data, int len, uint64_t *oref) {
  _ENSURE_OPEN(db);
  iwrc rc = _wlock(db);
  if (rc) {
    return rc;
  }
  rc = _append_lw(db, data, len, oref);
  IWRC(_unlock(db), rc);
  return rc;
}

iwrc iwrdb_patch(IWRDB db, uint64_t ref, off_t skip, const void *data, int len) {
  iwrc rc;
  size_t sz;
  ssize_t sz2;
  ssize_t tw = len;
  uint8_t *rp = (uint8_t*) data;
  ssize_t off = ref - 1 + skip;

  _ENSURE_OPEN(db);
  if (!ref || (off < 0) || (skip < 0)) {
    return IW_ERROR_INVALID_ARGS;
  }
  rc = _wlock(db);
  if (rc) {
    return rc;
  }
  if (off + len > db->end + db->bp) {
    rc = IW_ERROR_OUT_OF_BOUNDS;
    goto finish;
  }
  if (off < db->end) {
    sz2 = MIN(len, db->end - off);
    rc = iwp_pwrite(db->fh, off, rp, sz2, &sz);
    RCGO(rc, finish);
    tw -= sz;
    rp += sz;
    off += sz;
  }
  if (tw > 0) {
    sz = off - db->end;
    memcpy(db->buf + sz, rp, tw);
  }
finish:
  IWRC(_unlock(db), rc);
  return rc;
}

iwrc iwrdb_read(IWRDB db, uint64_t ref, off_t skip, void *buf, int len, size_t *sp) {
  iwrc rc;
  size_t sz;
  ssize_t sz2;
  ssize_t tr = len;
  uint8_t *wp = buf;
  ssize_t off = ref - 1 + skip;

  *sp = 0;
  _ENSURE_OPEN(db);
  if (!ref || (skip < 0) || (len < 0)) {
    return IW_ERROR_INVALID_ARGS;
  }
  rc = _rlock(db);
  if (rc) {
    return rc;
  }
  if (off + len > db->end + db->bp) {
    off_t l = db->end + db->bp - off;
    if (l < 0) {
      rc = IW_ERROR_OUT_OF_BOUNDS;
      goto finish;
    }
  }
  if (off < db->end) {
    sz2 = MIN(len, db->end - off);
    rc = iwp_pread(db->fh, off, wp, sz2, &sz);
    RCGO(rc, finish);
    tr -= sz;
    wp += sz;
    off += sz;
  }
  if ((tr > 0) && (db->bp > 0)) {
    sz = off - db->end;
    memcpy(wp, db->buf + sz, tr);
  }
  *sp = len;

finish:
  IWRC(_unlock(db), rc);
  return rc;
}
