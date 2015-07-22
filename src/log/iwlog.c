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

static IWLOG_ECODE_FN current_ecodefn;
static IWLOG_FN current_logfn;
static pthread_mutex_t iwlog_mtx  = PTHREAD_MUTEX_INITIALIZER;

static int default_logfn(locale_t locale,
                         IWLOG_LEVEL lvl,
                         int64_t ecode,
                         int errno_code,
                         int werror_code,
                         const char* file, int line,
                         uint64_t ts,
                         void *opts,
                         const char *fmt,
                         va_list argp) {

#define TBUF_SZ 96
#define EBUF_SZ 128

    int rv = 0;
    IWLOG_DEFAULT_OPTS myopts = {0};
    FILE *out = stderr;
    time_t ts_sec = ((long double) ts / 1000);
    struct tm* timeinfo;
    size_t sz, sz2;
    char tbuf[TBUF_SZ], ebuf[EBUF_SZ];
    char *errno_msg = NULL, *werror_msg = NULL;
    const char *ecode_msg = NULL, *cat;

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

    timeinfo = localtime(&ts_sec);

    if (opts) {
        myopts = * (IWLOG_DEFAULT_OPTS*) opts;

        if (myopts.out) {
            out = myopts.out;
        }
    }

    sz = strftime(tbuf, TBUF_SZ, "%d %b %H:%M:%S", timeinfo);

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

    if (pthread_mutex_lock(&iwlog_mtx)) {
        rv = -1;
        goto finish;
    }

    if (ecode) {
        assert(current_ecodefn);
        ecode_msg = current_ecodefn(locale, ecode);
    }

    if (ecode || errno_code || werror_code) {
        if (file != NULL && line > 0) {
            file = basename(file);
            fprintf(out, "%s %s %s:%d %" PRIu64 "|%d|%d|%s|%s|%s: ", tbuf, cat, file, line,
                    ecode, errno_code, werror_code,
                    (ecode_msg != NULL ? ecode_msg : ""),
                    (errno_msg != NULL ? errno_msg : ""),
                    (werror_msg != NULL ? werror_msg : ""));
        } else {
            fprintf(out, "%s %s %" PRIu64 "|%d|%d|%s|%s|%s: ", tbuf, cat,
                    ecode, errno_code, werror_code,
                    (ecode_msg != NULL ? ecode_msg : ""),
                    (errno_msg != NULL ? errno_msg : ""),
                    (werror_msg != NULL ? werror_msg : ""));
        }
    } else {
        if (file != NULL && line > 0) {
            file = basename(file);
            fprintf(out, "%s %s %s:%d: ", tbuf, cat, file, line);
        } else {
            fprintf(out, "%s %s: ", tbuf, cat);
        }
    }

    if (fmt != NULL) {
        vfprintf(out, fmt, argp);
    }

    fprintf(out, IW_LINE_SEP);
    pthread_mutex_unlock(&iwlog_mtx);
    fflush(out);

finish:

#ifdef _WIN32

    if (werror_msg) {
        LocalFree(werror_msg);
    }

#endif


#undef TBUF_SZ
#undef EBUF_SZ
    return rv;
}

const char* default_ecodefn(locale_t locale, int64_t ecode) {
    return NULL;
}

static IWLOG_FN current_logfn = default_logfn;
static void *current_logfn_options = NULL;
static IWLOG_ECODE_FN current_ecodefn = default_ecodefn;


int iwlog(IWLOG_LEVEL lvl,
          int64_t ecode,
          const char *file,
          int line,
          const char *fmt, ...
         ) {
    va_list argp;
    int rv;
    va_start(argp, fmt);
    rv = iwlog_va(lvl, ecode, file, line, fmt, argp);
    va_end(argp);
    return rv;
}

void iwlog2(IWLOG_LEVEL lvl,
            int64_t ecode,
            const char *file,
            int line,
            const char *fmt, ...) {
    va_list argp;
    va_start(argp, fmt);
    iwlog_va(lvl, ecode, file, line, fmt, argp);
    va_end(argp);
}

int iwlog_va(IWLOG_LEVEL lvl,
             int64_t ecode,
             const char *file,
             int line,
             const char *fmt,
             va_list argp) {

    assert(current_logfn);
    assert(current_ecodefn);

#ifdef _WIN32
    int werror_code = GetLastError();
#else
    int werror_code = 0;
#endif
    int errno_code = errno;
    int rv;
    locale_t locale = uselocale(NULL);
    int64_t ts;

    if (iwp_current_time_ms(&ts)) {
        return -1;
    }

    pthread_mutex_lock(&iwlog_mtx);
    IWLOG_FN logfn = current_logfn;
    void *opts = current_logfn_options;
    pthread_mutex_unlock(&iwlog_mtx);

    rv = logfn(locale, lvl, ecode, errno_code, werror_code,
               file, line,
               ts, opts, fmt, argp);

    if (rv) {
        fprintf(stderr, "Logging function returned with error: %d" IW_LINE_SEP, rv);
    }

    return rv;
}

void iwlog_set_logfn(IWLOG_FN fp) {
    pthread_mutex_lock(&iwlog_mtx);

    if (fp == NULL) {
        current_logfn = default_logfn;
    } else {
        current_logfn = fp;
    }

    pthread_mutex_unlock(&iwlog_mtx);
}

IWLOG_FN iwlog_get_logfn(void) {
    IWLOG_FN res;
    pthread_mutex_lock(&iwlog_mtx);
    res = current_logfn;
    pthread_mutex_unlock(&iwlog_mtx);
    return res;
}

void iwlog_set_logfn_opts(void *opts) {
    pthread_mutex_lock(&iwlog_mtx);
    current_logfn_options = opts;
    pthread_mutex_unlock(&iwlog_mtx);
}

const char* iwlog_ecode_explained(int64_t ecode) {
    IWLOG_ECODE_FN ecf = iwlog_get_ecodefn();
    assert(ecf);
    return ecf(NULL, ecode);
}

IWLOG_ECODE_FN iwlog_get_ecodefn(void) {
    IWLOG_ECODE_FN res;
    pthread_mutex_lock(&iwlog_mtx);
    res = current_ecodefn;
    pthread_mutex_unlock(&iwlog_mtx);
    return res;
}

void iwlog_set_ecodefn(IWLOG_ECODE_FN fp) {
    pthread_mutex_lock(&iwlog_mtx);

    if (fp == NULL) {
        current_ecodefn = fp;
    } else {
        current_ecodefn = fp;
    }

    pthread_mutex_unlock(&iwlog_mtx);
}
