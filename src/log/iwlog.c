#include "iwlog.h"
#include "iwcfg.h"
#include "platform/iwp.h"

#include <time.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <math.h>
#include <stdlib.h>

static iwrc _default_logfn(locale_t locale,
                           iwlog_lvl lvl,
                           iwrc ecode,
                           int errno_code,
                           int werror_code,
                           const char* file, int line,
                           uint64_t ts,
                           void *opts,
                           const char *fmt,
                           va_list argp);

static const char* _ecode_explained(locale_t locale, uint32_t ecode);
static const char* _default_ecodefn(locale_t locale, uint32_t ecode);

static IWLOG_FN _current_logfn;
static pthread_mutex_t _mtx  = PTHREAD_MUTEX_INITIALIZER;
static IWLOG_FN _current_logfn = _default_logfn;
static void *_current_logfn_options = 0;
#define _IWLOG_MAX_ECODE_FUN 256
static IWLOG_ECODE_FN _ecode_functions[_IWLOG_MAX_ECODE_FUN] = {0};

iwrc iwlog(iwlog_lvl lvl,
           iwrc ecode,
           const char *file,
           int line,
           const char *fmt, ...) {
    va_list argp;
    int rv;
    va_start(argp, fmt);
    rv = iwlog_va(lvl, ecode, file, line, fmt, argp);
    va_end(argp);
    return rv;
}

void iwlog2(iwlog_lvl lvl,
            iwrc ecode,
            const char *file,
            int line,
            const char *fmt, ...) {
    va_list argp;
    va_start(argp, fmt);
    iwlog_va(lvl, ecode, file, line, fmt, argp);
    va_end(argp);
}

iwrc iwlog_va(iwlog_lvl lvl,
              iwrc ecode,
              const char *file,
              int line,
              const char *fmt,
              va_list argp) {

    assert(_current_logfn);

#ifdef _WIN32
    werror_code = iwrc_strip_werror(&ecode);
#else
    int werror_code = 0;
#endif
    int errno_code = iwrc_strip_errno(&ecode);
    iwrc rc;
    locale_t locale = uselocale(0);
    int64_t ts;

    if (iwp_current_time_ms(&ts)) {
        return -1;
    }

    pthread_mutex_lock(&_mtx);
    IWLOG_FN logfn = _current_logfn;
    void *opts = _current_logfn_options;
    pthread_mutex_unlock(&_mtx);

    rc = logfn(locale, lvl, ecode, errno_code, werror_code,
               file, line,
               ts, opts, fmt, argp);

    if (rc) {
        fprintf(stderr, "Logging function returned with error: %" PRIu64 IW_LINE_SEP, rc);
    }
    return rc;
}

#define _IWLOG_ERRNO_RC_MASK    0x01U
#define _IWLOG_WERR_EC_MASK     0x02U

iwrc iwrc_set_errno(iwrc rc, uint32_t errno_code) {
    if (!errno_code) {
        return rc;
    }
    uint64_t ret = _IWLOG_ERRNO_RC_MASK;
    ret <<= 30;
    ret |= (uint32_t) errno_code & 0x3fffffffU;
    ret <<= 32;
    ret |= (uint32_t) rc;
    return ret;
}

uint32_t iwrc_strip_errno(iwrc *rc) {
    uint64_t rcv = *rc;
    if (((rcv >> 62) & 0x03U) != _IWLOG_ERRNO_RC_MASK) {
        return 0;
    }
    *rc = rcv & 0x00000000ffffffffULL;
    return (uint32_t)(rcv >> 32) & 0x3fffffffU;
}

#ifdef _WIN32

iwrc iwrc_set_werror(iwrc rc, uint32_t werror) {
    if (!werror) {
        return rc;
    }
    uint64_t ret = _IWLOG_WERR_EC_MASK;
    ret <<= 30;
    ret |= (uint32_t) werror & 0x3fffffffU;
    ret <<= 32;
    ret |= (uint32_t) rc;
    return ret;
}

uint32_t iwrc_strip_werror(iwrc *rc) {
    uint64_t rcv = *rc;
    if (((rcv >> 62) & 0x03U) != _IWLOG_WERR_EC_MASK) {
        return 0;
    }
    *rc = rcv & 0x00000000ffffffffULL;
    return (uint32_t)(rcv >> 32) & 0x3fffffffU;
}
#endif

void iwrc_strip_code(iwrc *rc) {
    *rc = *rc & 0x00000000ffffffffULL;
}

void iwlog_set_logfn(IWLOG_FN fp) {
    pthread_mutex_lock(&_mtx);

    if (!fp) {
        _current_logfn = _default_logfn;
    } else {
        _current_logfn = fp;
    }

    pthread_mutex_unlock(&_mtx);
}

IWLOG_FN iwlog_get_logfn(void) {
    IWLOG_FN res;
    pthread_mutex_lock(&_mtx);
    res = _current_logfn;
    pthread_mutex_unlock(&_mtx);
    return res;
}

void iwlog_set_logfn_opts(void *opts) {
    pthread_mutex_lock(&_mtx);
    _current_logfn_options = opts;
    pthread_mutex_unlock(&_mtx);
}

const char* iwlog_ecode_explained(iwrc ecode) {
    const char *res;
    pthread_mutex_lock(&_mtx);
    res = _ecode_explained(0, ecode);
    pthread_mutex_unlock(&_mtx);
    return res;
}

iwrc iwlog_register_ecodefn(IWLOG_ECODE_FN fp) {
    assert(fp);
    int success = 0;
    pthread_mutex_lock(&_mtx);
    for (int i = 0; i < _IWLOG_MAX_ECODE_FUN; ++i) {
        if (_ecode_functions[i] == 0) {
            _ecode_functions[i] = fp;
            success = 1;
            break;
        }
    }
    pthread_mutex_unlock(&_mtx);
    return success ? 0 : IW_ERROR_FAIL;
}

iwrc iwlog_init(void) {
    static int _iwlog_initialized = 0;
    iwrc rc;
    if (!__sync_bool_compare_and_swap(&_iwlog_initialized, 0, 1)) {
        return 0; //initialized already
    }
    rc = iwlog_register_ecodefn(_default_ecodefn);
    return rc;
}

////////////////////////////////////////////////////////////////////////////////////////////////////


// Assumed:
//   1. `_mtx` is locked.
static const char* _ecode_explained(locale_t locale, uint32_t ecode) {
    const char *ret = 0;
    for (int i = 0; i < _IWLOG_MAX_ECODE_FUN; ++i) {
        if (_ecode_functions[i] == 0) {
            break;
        } else {
            ret = _ecode_functions[i](locale, ecode);
            if (ret) {
                break;
            }
        }
    }
    return ret;
}

static const char* _default_ecodefn(locale_t locale, uint32_t ecode) {

    switch (ecode) {
        case IW_ERROR_FAIL:
            return "Unspecified error. (IW_ERROR_FAIL)";
        case IW_ERROR_ERRNO:
            return "Error with expected errno status set. (IW_ERROR_ERRNO)";
        case IW_ERROR_IO_ERRNO:
            return "IO error with expected errno status set. (IW_ERROR_IO_ERRNO)";
        case IW_ERROR_NOT_EXISTS:
            return "Resource is not exists. (IW_ERROR_NOT_EXISTS)";
        case IW_ERROR_READONLY:
            return "Resource is readonly. (IW_ERROR_READONLY)";
        case IW_ERROR_ALREADY_OPENED:
            return "Resource is already opened. (IW_ERROR_ALREADY_OPENED)";
        case IW_ERROR_THREADING:
            return "Threading error. (IW_ERROR_THREADING)";
        case IW_ERROR_THREADING_ERRNO:
            return "Threading error with errno status set. (IW_ERROR_THREADING_ERRNO)";
        case IW_ERROR_ASSERTION:
            return "Generic assertion error. (IW_ERROR_ASSERTION)";
        case IW_ERROR_INVALID_HANDLE:
            return "Invalid HANDLE value. (IW_ERROR_INVALID_HANDLE)";
        case IW_ERROR_OUT_OF_BOUNDS:
            return "Argument/parameter/value is out of bounds. (IW_ERROR_OUT_OF_BOUNDS)";
        case IW_ERROR_NOT_IMPLEMENTED:
            return "Method is not implemented. (IW_ERROR_NOT_IMPLEMENTED)";
        case IW_ERROR_ALLOC:
            return "Memory allocation failed. (IW_ERROR_ALLOC)";
        case IW_ERROR_INVALID_STATE:
            return "Illegal state error. (IW_ERROR_INVALID_STATE)";
        case IW_ERROR_NOT_ALIGNED:
            return "Argument is not aligned properly. (IW_ERROR_NOT_ALIGNED)";
        case IW_OK:
        default:
            return 0;
    }
    return 0;
}


static iwrc _default_logfn(locale_t locale,
                           iwlog_lvl lvl,
                           iwrc ecode,
                           int errno_code,
                           int werror_code,
                           const char* file, int line,
                           uint64_t ts,
                           void *opts,
                           const char *fmt,
                           va_list argp) {

#define TBUF_SZ 96
#define EBUF_SZ 128

    iwrc rc = 0;
    IWLOG_DEFAULT_OPTS myopts = {0};
    FILE *out = stderr;
    time_t ts_sec = ((long double) ts / 1000);
    struct tm timeinfo;
    size_t sz, sz2;
    char tbuf[TBUF_SZ], ebuf[EBUF_SZ];
    char *errno_msg = 0, *werror_msg = 0;
    const char *ecode_msg = 0, *cat;

    if (errno_code) {
        errno_msg = strerror_r(errno_code, ebuf, EBUF_SZ);
    }

#ifdef _WIN32

    if (werror_code) {
        LPTSTR out = NULL;
        DWORD ret = FormatMessage(
                        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                        NULL,
                        werror_code,
                        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                        (LPTSTR) &out,
                        0,
                        NULL);

        if (ret == 0) {
            if (out) {
                LocalFree(out);
                out = NULL;
            }
        }

        werror_msg = out;
    }

#endif

    // cppcheck-suppress portability
    localtime_r(&ts_sec, &timeinfo);

    if (opts) {
        myopts = * (IWLOG_DEFAULT_OPTS*) opts;

        if (myopts.out) {
            out = myopts.out;
        }
    }
    sz = strftime(tbuf, TBUF_SZ, "%d %b %H:%M:%S", &timeinfo);
    if (sz == 0) {
        tbuf[0] = '\0';
    } else if (TBUF_SZ - sz > 4) { // .000 suffix
        tbuf[sz] = '.';
        sz2 = snprintf((char*) tbuf + sz + 1, 4, "%03d", (int)(ts % 1000));

        if (sz2 > 3) {
            tbuf[sz] = '\0';
        }
    }

    switch (lvl) {
        case IWLOG_DEBUG:
            cat = "DEBUG";
            break;
        case IWLOG_INFO:
            cat = "INFO";
            break;
        case IWLOG_WARN:
            cat = "WARN";
            break;
        case IWLOG_ERROR:
            cat = "ERROR";
            break;
        default:
            cat = "UNKNOW";
            assert(0);
            break;
    }

    if (pthread_mutex_lock(&_mtx)) {
        rc = IW_ERROR_THREADING_ERRNO;
        goto finish;
    }
    if (ecode) {
        ecode_msg = _ecode_explained(locale, ecode);
    }
    if (ecode || errno_code || werror_code) {
        if (file && line > 0) {
            file = basename(file);
            fprintf(out, "%s %s %s:%d %" PRIu64 "|%d|%d|%s|%s|%s: ", tbuf, cat, file, line,
                    ecode, errno_code, werror_code,
                    (ecode_msg ? ecode_msg : ""),
                    (errno_msg ? errno_msg : ""),
                    (werror_msg ? werror_msg : ""));
        } else {
            fprintf(out, "%s %s %" PRIu64 "|%d|%d|%s|%s|%s: ", tbuf, cat,
                    ecode, errno_code, werror_code,
                    (ecode_msg ? ecode_msg : ""),
                    (errno_msg ? errno_msg : ""),
                    (werror_msg ? werror_msg : ""));
        }
    } else {
        if (file && line > 0) {
            file = basename(file);
            fprintf(out, "%s %s %s:%d: ", tbuf, cat, file, line);
        } else {
            fprintf(out, "%s %s: ", tbuf, cat);
        }
    }

    if (fmt) {
        vfprintf(out, fmt, argp);
    }

    fprintf(out, IW_LINE_SEP);
    pthread_mutex_unlock(&_mtx);
    fflush(out);

finish:

#ifdef _WIN32

    if (werror_msg) {
        LocalFree(werror_msg);
    }

#endif

#undef TBUF_SZ
#undef EBUF_SZ
    return rc;
}
