#include "platform/iwp.h"
#include "log/iwlog.h"
#include "iwcfg.h"

#include <time.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#define _IW_TIMESPEC2MS(IW_ts) \
    ((IW_ts).tv_sec * 1000) + (uint64_t) round((IW_ts).tv_nsec / 1.0e6)

iwrc iwp_current_time_ms(int64_t *time) {
    struct timespec spec;
    if (clock_gettime(CLOCK_REALTIME, &spec) < 0) {
        *time = 0;
        return IW_ERROR_ERRNO;
    }
    *time = _IW_TIMESPEC2MS(spec);
    return 0;
}

IW_EXPORT iwrc iwp_fstat(const char *path, IWP_FILE_STAT *fstat) {
    assert(path);
    assert(fstat);
    iwrc rc = 0;
    struct stat st = {0};

    if (stat(path, &st)) {
        return (errno == ENOENT) ? IW_ERROR_NOT_EXISTS : IW_ERROR_IO_ERRNO;
    }
    memset(fstat, 0, sizeof(*fstat));
    fstat->atime = _IW_TIMESPEC2MS(st.st_atim);
    fstat->mtime = _IW_TIMESPEC2MS(st.st_mtim);
    fstat->ctime = _IW_TIMESPEC2MS(st.st_ctim);
    fstat->size = st.st_size;

    if (S_ISREG(st.st_mode)) {
        fstat->ftype = IWP_TYPE_FILE;
    } else if (S_ISDIR(st.st_mode)) {
        fstat->ftype = IWP_TYPE_DIR;
    } else if (S_ISLNK(st.st_mode)) {
        fstat->ftype = IWP_LINK;
    } else {
        fstat->ftype = IWP_OTHER;
    }

    return rc;
}

iwrc iwp_flock(HANDLE fd, iwp_lockmode lmode) {
    struct flock lock;
    assert(!INVALIDHANDLE(fd));
    if (lmode == IWP_NOLOCK) {
        return 0;
    }
    memset(&lock, 0, sizeof(struct flock));
    lock.l_type = (lmode & IWP_WLOCK) ? F_WRLCK : F_RDLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    lock.l_pid = 0;
    while (fcntl(fd, (lmode & IWP_NBLOCK) ? F_SETLK : F_SETLKW, &lock) == -1) {
        if (errno != EINTR) {
            return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
        }
    }
    return 0;
}

iwrc iwp_unlock(HANDLE fd) {
    assert(!INVALIDHANDLE(fd));
    struct flock lock;
    memset(&lock, 0, sizeof(struct flock));
    lock.l_type = F_UNLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    lock.l_pid = 0;
    while (fcntl(fd, F_SETLKW, &lock) == -1) {
        if (errno != EINTR) {
            return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
        }
    }
    return 0;
}


iwrc iwp_closefh(HANDLE fh) {
    if (INVALIDHANDLE(fh)) {
        return 0;
    }
    if (close(fh) == -1) {
        return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    }
    return 0;
}

iwrc iwp_read(HANDLE fh, off_t off, void *buf,
              size_t siz, size_t *sp) {

    assert(buf && sp);
    ssize_t rs = pread(fh, buf, siz, off);
    if (rs == -1) {
        *sp = 0;
        return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    } else {
        *sp = rs;
        return 0;
    }
}

iwrc iwp_write(HANDLE fh, off_t off, const void *buf,
               size_t siz, size_t *sp) {

    assert(buf && sp);
    ssize_t ws = pwrite(fh, buf, siz, off);
    if (ws == -1) {
        *sp = 0;
        return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
    } else {
        *sp = ws;
        return 0;
    }
}

size_t iwp_page_size(void) {
    static off_t _iwp_pagesize = 0;
    if (!_iwp_pagesize) {
        _iwp_pagesize = sysconf(_SC_PAGESIZE);
    }
    return _iwp_pagesize;
}

iwrc iwp_ftruncate(HANDLE fh, off_t len) {
    int rv = ftruncate(fh, len);
    return !rv ? 0 : iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
}
