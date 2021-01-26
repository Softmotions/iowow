//
/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2021 Softmotions Ltd <info@softmotions.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *************************************************************************************************/


#include "iwcfg.h"
#include "iwp.h"
#include "iwlog.h"
#include "iwutils.h"

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__ANDROID__) || !_GNU_SOURCE
#include <libgen.h>
#elif defined(_WIN32)
#include <libiberty/libiberty.h>
#else
#include <string.h>
#endif


#ifdef __ANDROID__
#define IW_ANDROID_LOG
#include <android/log.h>
#endif // __ANDROID__

static iwrc _default_logfn(
  FILE *out, locale_t locale, iwlog_lvl lvl, iwrc ecode, int errno_code, int werror_code,
  const char *file, int line, uint64_t ts, void *opts, const char *fmt,
  va_list argp);

static const char *_ecode_explained(locale_t locale, uint32_t ecode);
static const char *_default_ecodefn(locale_t locale, uint32_t ecode);

static IWLOG_FN _current_logfn;
static pthread_mutex_t _mtx = PTHREAD_MUTEX_INITIALIZER;
static IWLOG_FN _current_logfn = _default_logfn;
static void *_current_logfn_options = 0;
#define _IWLOG_MAX_ECODE_FUN 256
static IWLOG_ECODE_FN _ecode_functions[_IWLOG_MAX_ECODE_FUN] = { 0 };

iwrc iwlog(iwlog_lvl lvl, iwrc ecode, const char *file, int line, const char *fmt, ...) {
  va_list argp;
  iwrc rc;
  va_start(argp, fmt);
  rc = iwlog_va(stderr, lvl, ecode, file, line, fmt, argp);
  va_end(argp);
  return rc;
}

void iwlog2(iwlog_lvl lvl, iwrc ecode, const char *file, int line, const char *fmt, ...) {
  va_list argp;
  va_start(argp, fmt);
  iwlog_va(stderr, lvl, ecode, file, line, fmt, argp);
  va_end(argp);
}

iwrc iwlog_va(FILE *out, iwlog_lvl lvl, iwrc ecode, const char *file, int line, const char *fmt, va_list argp) {
  assert(_current_logfn);

#ifdef _WIN32
  int werror_code = iwrc_strip_werror(&ecode);
  locale_t locale = NULL;
#else
  int werror_code = 0;
  locale_t locale = uselocale(0);
#endif
  int errno_code = iwrc_strip_errno(&ecode);
  uint64_t ts;
  iwrc rc = iwp_current_time_ms(&ts, false);
  RCRET(rc);

  pthread_mutex_lock(&_mtx);
  IWLOG_FN logfn = _current_logfn;
  void *opts = _current_logfn_options;
  pthread_mutex_unlock(&_mtx);

  rc = logfn(out, locale, lvl, ecode, errno_code, werror_code, file, line, ts, opts, fmt, argp);
  if (rc) {
    fprintf(stderr, "Logging function returned with error: %" PRIu64 IW_LINE_SEP, rc);
  }
  return rc;
}

#define _IWLOG_ERRNO_RC_MASK 0x01U
#define _IWLOG_WERR_EC_MASK  0x02U

iwrc iwrc_set_errno(iwrc rc, int errno_code) {
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
  return (uint32_t) (rcv >> 32) & 0x3fffffffU;
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
  return (uint32_t) (rcv >> 32) & 0x3fffffffU;
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

const char *iwlog_ecode_explained(iwrc ecode) {
  iwrc_strip_errno(&ecode);
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
    return 0;  // initialized already
  }
  rc = iwlog_register_ecodefn(_default_ecodefn);
  return rc;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

// Assumed:
//   1. `_mtx` is locked.
static const char *_ecode_explained(locale_t locale, uint32_t ecode) {
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

static const char *_default_ecodefn(locale_t locale, uint32_t ecode) {
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
      return "Threading error with errno status set. "
             "(IW_ERROR_THREADING_ERRNO)";
    case IW_ERROR_ASSERTION:
      return "Generic assertion error. (IW_ERROR_ASSERTION)";
    case IW_ERROR_INVALID_HANDLE:
      return "Invalid HANDLE value. (IW_ERROR_INVALID_HANDLE)";
    case IW_ERROR_OUT_OF_BOUNDS:
      return "Argument/parameter/value is out of bounds. "
             "(IW_ERROR_OUT_OF_BOUNDS)";
    case IW_ERROR_NOT_IMPLEMENTED:
      return "Method is not implemented. (IW_ERROR_NOT_IMPLEMENTED)";
    case IW_ERROR_ALLOC:
      return "Memory allocation failed. (IW_ERROR_ALLOC)";
    case IW_ERROR_INVALID_STATE:
      return "Illegal state error. (IW_ERROR_INVALID_STATE)";
    case IW_ERROR_NOT_ALIGNED:
      return "Argument is not aligned properly. (IW_ERROR_NOT_ALIGNED)";
    case IW_ERROR_FALSE:
      return "False response/rejection. (IW_ERROR_FALSE)";
    case IW_ERROR_INVALID_ARGS:
      return "Invalid function arguments. (IW_ERROR_INVALID_ARGS)";
    case IW_ERROR_OVERFLOW:
      return "Overflow. (IW_ERROR_OVERFLOW)";
    case IW_ERROR_INVALID_VALUE:
      return " Invalid value. (IW_ERROR_INVALID_VALUE)";
    case IW_ERROR_UNEXPECTED_RESPONSE:
      return "Unexpected response (IW_ERROR_UNEXPECTED_RESPONSE)";
    case IW_OK:
    default:
      return 0;
  }
  return 0;
}

static iwrc _default_logfn(
  FILE       *out,
  locale_t    locale,
  iwlog_lvl   lvl,
  iwrc        ecode,
  int         errno_code,
  int         werror_code,
  const char *file,
  int         line,
  uint64_t    ts,
  void       *opts,
  const char *fmt,
  va_list     argp) {
#define TBUF_SZ 96
#define EBUF_SZ 128

  iwrc rc = 0;
  IWLOG_DEFAULT_OPTS myopts = { 0 };

#ifndef IW_ANDROID_LOG
  time_t ts_sec = ((long double) ts / 1000);
  struct tm timeinfo;
  size_t sz, sz2;
  char tbuf[TBUF_SZ];
  char *cat;
#endif

  char ebuf[EBUF_SZ];
  char *errno_msg = 0, *werror_msg = 0;
  const char *ecode_msg = 0;
  char fnamebuf[MAXPATHLEN];
  char *fnameptr = fnamebuf;
  char *fname = 0;

  if (errno_code) {

#if defined(_WIN32)
    int rci = strerror_s(ebuf, EBUF_SZ, errno_code);
    if (!rci) {
      errno_msg = ebuf;
    }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__ANDROID__) || ((  _POSIX_C_SOURCE >= 200112L \
                                                                             || _XOPEN_SOURCE >= 600) && !_GNU_SOURCE)
    int rci = strerror_r(errno_code, ebuf, EBUF_SZ);
    if (!rci) {
      errno_msg = ebuf;
    }
#else
    errno_msg = strerror_r(errno_code, ebuf, EBUF_SZ); // NOLINT
#endif
  }

#ifdef _WIN32
  if (werror_code) {
    LPTSTR msg = NULL;
    DWORD ret = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, werror_code,
                              MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), (LPTSTR) &msg, 0, NULL);

    if (ret == 0) {
      if (msg) {
        LocalFree(msg);
        msg = NULL;
      }
    }
    werror_msg = msg;
  }
#endif

  if (opts) {
    myopts = *(IWLOG_DEFAULT_OPTS*) opts;
    if (myopts.out) {
      out = myopts.out;
    }
  }

#ifndef IW_ANDROID_LOG
  // cppcheck-suppress portability
  localtime_r(&ts_sec, &timeinfo);

  sz = strftime(tbuf, TBUF_SZ, "%d %b %H:%M:%S", &timeinfo);
  if (sz == 0) {
    tbuf[0] = '\0';
  } else if (TBUF_SZ - sz > 4) {  // .000 suffix
    tbuf[sz] = '.';
    sz2 = snprintf((char*) tbuf + sz + 1, 4, "%03d", (int) (ts % 1000));
    if (sz2 > 3) {
      tbuf[sz] = '\0';
    }
  }
#else
  android_LogPriority alp = ANDROID_LOG_INFO;
#endif // IW_ANDROID_LOG

  switch (lvl) {
    case IWLOG_DEBUG:
#ifdef IW_ANDROID_LOG
      alp = ANDROID_LOG_DEBUG;
#else
      cat = "DEBUG";
#endif
      break;
    case IWLOG_INFO:
#ifdef IW_ANDROID_LOG
      alp = ANDROID_LOG_INFO;
#else
      cat = "INFO";
#endif
      file = 0;
      break;
    case IWLOG_WARN:
#ifdef IW_ANDROID_LOG
      alp = ANDROID_LOG_WARN;
#else
      cat = "WARN";
#endif
      break;
    case IWLOG_ERROR:
#ifdef IW_ANDROID_LOG
      alp = ANDROID_LOG_ERROR;
#else
      cat = "ERROR";
#endif
      break;
    default:
#ifndef IW_ANDROID_LOG
      cat = "UNKNOW";
#endif
      assert(0);
      break;
  }
  if (ecode) {
    ecode_msg = _ecode_explained(locale, ecode);
  }
  if (file && (line > 0)) {
    size_t len = strlen(file);
    if (len < sizeof(fnamebuf)) {
      memcpy(fnameptr, file, len);
      fnameptr[len] = '\0';
    } else {
      fnameptr = strdup(file);
      RCA(fnameptr, finish);
    }
#ifdef IW_HAVE_BASENAME_R
    fname = basename_r(file, fnameptr);
#else
    fname = basename(fnameptr); // NOLINT
#endif
  }

  if (pthread_mutex_lock(&_mtx)) {
    rc = IW_ERROR_THREADING_ERRNO;
    goto finish;
  }

#ifndef IW_ANDROID_LOG

  if (ecode || errno_code || werror_code) {
    if (fname && (line > 0)) {
      fprintf(out, "%s %s %s:%d %" PRIu64 "|%d|%d|%s|%s|%s: ", tbuf, cat, fname, line, ecode, errno_code,
              werror_code, (ecode_msg ? ecode_msg : ""), (errno_msg ? errno_msg : ""),
              (werror_msg ? werror_msg : "")); // -V547
    } else {
      fprintf(out, "%s %s %" PRIu64 "|%d|%d|%s|%s|%s: ", tbuf, cat, ecode, errno_code, werror_code,
              (ecode_msg ? ecode_msg : ""), (errno_msg ? errno_msg : ""), (werror_msg ? werror_msg : "")); // -V547
    }
  } else {
    if (fname && (line > 0)) {
      fprintf(out, "%s %s %s:%d: ", tbuf, cat, fname, line);
    } else {
      fprintf(out, "%s %s: ", tbuf, cat);
    }
  }
  if (fmt) {
    vfprintf(out, fmt, argp);
  }
  fprintf(out, IW_LINE_SEP);
  fflush(out);

#else

  if (ecode || errno_code || werror_code) {
    if (fname && (line > 0)) {
      __android_log_print(alp, "IWLOG", "%s:%d %" PRIu64 "|%d|%d|%s|%s|%s: ", fname, line, ecode, errno_code,
                          werror_code, (ecode_msg ? ecode_msg : ""), (errno_msg ? errno_msg : ""),
                          (werror_msg ? werror_msg : ""));
    } else {
      __android_log_print(alp, "IWLOG", "%" PRIu64 "|%d|%d|%s|%s|%s: ", ecode, errno_code, werror_code,
                          (ecode_msg ? ecode_msg : ""), (errno_msg ? errno_msg : ""), (werror_msg ? werror_msg : ""));
    }
  } else {
    if (fname && (line > 0)) {
      __android_log_print(alp, "IWLOG", "%s:%d: ", fname, line);
    }
  }
  if (fmt) {
    __android_log_vprint(alp, "IWLOG", fmt, argp);
  }

#endif

  pthread_mutex_unlock(&_mtx);

finish:
  if (fnameptr != fnamebuf) {
    free(fnameptr);
  }

#ifdef _WIN32
  if (werror_msg) {
    LocalFree(werror_msg);
  }
#endif

#undef TBUF_SZ
#undef EBUF_SZ
  return rc;
}
