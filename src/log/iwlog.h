#pragma once
#ifndef IWLOG_H
#define IWLOG_H

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

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif

/**
 * @file
 * @brief Error logging/reporting routines.
 * @author Anton Adamansky (adamansky@softmotions.com)
 *
 * Before using API of this module you should call
 * `iw_init(void)` iowow module initialization routine.
 *
 * By default all logging output redirected to the `stderr`
 * you can owerride it by passing  instance of `IWLOG_DEFAULT_OPTS`
 * to the `iwlog_set_logfn_opts(void*)`
 *
 * A custom error logging function may be implemented with `IWLOG_FN` signature
 * and registered by `void iwlog_set_logfn(IWLOG_FN fp)`
 *
 * The following methods normally used for logging:
 * @verbatim
    iwlog_{debug,info,warn,error}
    iwlog_ecode_{debug,info,warn,error} @endverbatim
 */

#include "iowow.h"

#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>

#ifdef __APPLE__
#include <xlocale.h>
#else
#include <locale.h>
#endif

IW_EXTERN_C_START

#ifndef IW_ERROR_START
#define IW_ERROR_START 70000
#endif

/**
 * @enum iw_ecode
 * @brief Common used error codes.
 */
typedef enum {
  IW_OK         = 0,              /**< No error. */
  IW_ERROR_FAIL = IW_ERROR_START, /**< Unspecified error. */
  IW_ERROR_ERRNO,                 /**< Error with expected errno status set. */
  IW_ERROR_IO_ERRNO,              /**< IO error with expected errno status set. */
  IW_ERROR_AGAIN,
  IW_ERROR_NOT_EXISTS,            /**< Resource is not exists. */
  IW_ERROR_READONLY,              /**< Resource is readonly. */
  IW_ERROR_ALREADY_OPENED,        /**< Resource is already opened. */
  IW_ERROR_THREADING,             /**< Threading error. */
  IW_ERROR_THREADING_ERRNO,       /**< Threading error with errno status set. */
  IW_ERROR_ASSERTION,             /**< Generic assertion error. */
  IW_ERROR_INVALID_HANDLE,        /**< Invalid HANDLE value. */
  IW_ERROR_OUT_OF_BOUNDS,         /**< Invalid bounds specified. */
  IW_ERROR_NOT_IMPLEMENTED,       /**< Method is not implemented. */
  IW_ERROR_ALLOC,                 /**< Memory allocation failed. */
  IW_ERROR_INVALID_STATE,         /**< Illegal state error. */
  IW_ERROR_NOT_ALIGNED,           /**< Argument is not aligned properly. */
  IW_ERROR_FALSE,                 /**< Request rejection/false response. */
  IW_ERROR_INVALID_ARGS,          /**< Invalid function arguments. */
  IW_ERROR_OVERFLOW,              /**< Overflow. */
  IW_ERROR_INVALID_VALUE,         /**< Invalid value. */
  IW_ERROR_UNEXPECTED_RESPONSE,   /**< Unexpected response (IW_ERROR_UNEXPECTED_RESPONSE) */
  IW_ERROR_NOT_ALLOWED,           /**< Action is not allowed. (IW_ERROR_NOT_ALLOWED) */
  IW_ERROR_UNSUPPORTED,           /**< Unsupported opration. (IW_ERROR_UNSUPPORTED) */
} iw_ecode;

/**
 * @enum iwlog_lvl
 * @brief Available logging vebosity levels.
 */
typedef enum {
  IWLOG_ERROR = 0,
  IWLOG_WARN  = 1,
  IWLOG_INFO  = 2,
  IWLOG_DEBUG = 3,
} iwlog_lvl;

/**
 * @brief Options for the default logging function.
 * @see iwlog_set_logfn_opts(void*)
 */
typedef struct {
  FILE *out; /**< Output file stream. Default: `stderr`  */
} IWLOG_DEFAULT_OPTS;

/**
 * @brief Logging function pointer.
 *
 * @param locale Locale used to print error message.
 * @param lvl Log level.
 * @param ecode Error code specified.
 * @param errno_code Optional errno code. Set it to 0 if errno not used.
 * @param file File name. Can be `NULL`
 * @param line Line number in the file.
 * @param ts Message time-stamp
 * @param fmt `printf` style message format
 * @return Not zero error code in the case of error.
 *
 * @see iwlog_set_logfn(IWLOG_FN)
 */
typedef iwrc (*IWLOG_FN)(
  FILE *out, locale_t locale, iwlog_lvl lvl, iwrc ecode,
  int errno_code, int werror_code, const char *file,
  int line, uint64_t ts, void *opts, const char *fmt,
  va_list argp);

/**
 * @brief Return the locale aware error code explanation message.
 *
 * @param locale Locale used. Can be `NULL`
 * @param ecode Error code
 * @return Message string describes a given error code or `NULL` if
 *         no message found.
 */
typedef const char* (*IWLOG_ECODE_FN)(locale_t locale, uint32_t ecode);

/**
 * @brief Attach the specified @a errno_code code into @a rc code
 * @param rc IOWOW error code
 * @param errno_code Error code will be embedded into.
 * @return Updated rc code
 */
IW_EXPORT iwrc iwrc_set_errno(iwrc rc, int errno_code);

/**
 * @brief Strip the attached `errno` code from the specified @a rc and
 * return errno code.
 *
 * @param rc `errno` code or `0`
 */
IW_EXPORT uint32_t iwrc_strip_errno(iwrc *rc);

#ifdef _WIN32

/**
 * @brief Attach the specified windows @a werror code into @a rc code
 * @param rc IOWOW error code
 * @param errno_code Error code will be embedded into.
 * @return Updated rc code
 */
IW_EXPORT iwrc iwrc_set_werror(iwrc rc, uint32_t werror);

/**
 * @brief Strip the attached windows `werror` code from the specified @a rc and
 * return this errno code.
 *
 * @param rc `errno` code or `0`
 */
IW_EXPORT uint32_t iwrc_strip_werror(iwrc *rc);

#endif

/**
 * @brief Remove embedded @a errno code from the passed @a rc
 * @param [in,out] rc
 */
IW_EXPORT void iwrc_strip_code(iwrc *rc);

/**
 * @brief Sets current logging function.
 * @warning Not thread safe.
 *
 * @param fp Logging function pointer.
 * @return Not zero if error occured.
 */
IW_EXPORT void iwlog_set_logfn(IWLOG_FN fp, void *opts);

/**
 * @brief Get a default logging function.
 *
 */
IW_EXPORT IWLOG_FN iwlog_get_logfn(void);

/**
 * @brief Returns string representation of a given error code.
 * @param ecode Error code
 * @return
 */
IW_EXPORT const char *iwlog_ecode_explained(iwrc ecode);

/**
 * @brief Register error code explanation function.
 * @note Up to `128` @a fp functions can be registered.
 * @param fp
 * @return `0` on success or error code.
 */
IW_EXPORT iwrc iwlog_register_ecodefn(IWLOG_ECODE_FN fp);

/**
 * @brief Logs a message.
 * @param lvl       Logging level.
 * @param ecode     Error code or zero.
 * @param file      Module file, can be `NULL`
 * @param line      Line in module.
 * @param fmt       Printf like message format.
 * @return
 */
IW_EXPORT iwrc iwlog(
  iwlog_lvl lvl, iwrc ecode, const char *file, int line,
  const char *fmt, ...);

IW_EXPORT void iwlog2(
  iwlog_lvl lvl, iwrc ecode, const char *file, int line,
  const char *fmt, ...);

IW_EXPORT iwrc iwlog_va(
  FILE *out, iwlog_lvl lvl, iwrc ecode, const char *file, int line,
  const char *fmt, va_list argp);

#ifdef _DEBUG
#define iwlog_debug(IW_fmt, ...) \
  iwlog2(IWLOG_DEBUG, 0, __FILE__, __LINE__, (IW_fmt), ## __VA_ARGS__)
#else
#define iwlog_debug(IW_fmt, ...)
#endif
#define iwlog_info(IW_fmt, ...) \
  iwlog2(IWLOG_INFO, 0, __FILE__, __LINE__, (IW_fmt), ## __VA_ARGS__)
#define iwlog_warn(IW_fmt, ...) \
  iwlog2(IWLOG_WARN, 0, __FILE__, __LINE__, (IW_fmt), ## __VA_ARGS__)
#define iwlog_error(IW_fmt, ...) \
  iwlog2(IWLOG_ERROR, 0, __FILE__, __LINE__, (IW_fmt), ## __VA_ARGS__)

#ifdef _DEBUG
#define iwlog_debug2(IW_fmt) \
  iwlog2(IWLOG_DEBUG, 0, __FILE__, __LINE__, (IW_fmt))
#else
#define iwlog_debug2(IW_fmt)
#endif
#define iwlog_info2(IW_fmt) iwlog2(IWLOG_INFO, 0, __FILE__, __LINE__, (IW_fmt))
#define iwlog_warn2(IW_fmt) iwlog2(IWLOG_WARN, 0, __FILE__, __LINE__, (IW_fmt))
#define iwlog_error2(IW_fmt) \
  iwlog2(IWLOG_ERROR, 0, __FILE__, __LINE__, (IW_fmt))

#ifdef _DEBUG
#define iwlog_ecode_debug(IW_ecode, IW_fmt, ...) \
  iwlog2(IWLOG_DEBUG, (IW_ecode), __FILE__, __LINE__, (IW_fmt), ## __VA_ARGS__)
#else
#define iwlog_ecode_debug(IW_ecode, IW_fmt, ...)
#endif
#define iwlog_ecode_info(IW_ecode, IW_fmt, ...) \
  iwlog2(IWLOG_INFO, (IW_ecode), __FILE__, __LINE__, (IW_fmt), ## __VA_ARGS__)
#define iwlog_ecode_warn(IW_ecode, IW_fmt, ...) \
  iwlog2(IWLOG_WARN, (IW_ecode), __FILE__, __LINE__, (IW_fmt), ## __VA_ARGS__)
#define iwlog_ecode_error(IW_ecode, IW_fmt, ...) \
  iwlog2(IWLOG_ERROR, (IW_ecode), __FILE__, __LINE__, (IW_fmt), ## __VA_ARGS__)

#ifdef _DEBUG
#define iwlog_ecode_debug2(IW_ecode, IW_fmt) \
  iwlog2(IWLOG_DEBUG, (IW_ecode), __FILE__, __LINE__, (IW_fmt))
#else
#define iwlog_ecode_debug2(IW_ecode, IW_fmt)
#endif
#define iwlog_ecode_info2(IW_ecode, IW_fmt) \
  iwlog2(IWLOG_INFO, (IW_ecode), __FILE__, __LINE__, (IW_fmt))
#define iwlog_ecode_warn2(IW_ecode, IW_fmt) \
  iwlog2(IWLOG_WARN, (IW_ecode), __FILE__, __LINE__, (IW_fmt))
#define iwlog_ecode_error2(IW_ecode, IW_fmt) \
  iwlog2(IWLOG_ERROR, (IW_ecode), __FILE__, __LINE__, (IW_fmt))

#ifdef _DEBUG
#define iwlog_ecode_debug3(IW_ecode) \
  iwlog2(IWLOG_DEBUG, (IW_ecode), __FILE__, __LINE__, "")
#else
#define iwlog_ecode_debug3(IW_ecode)
#endif
#define iwlog_ecode_info3(IW_ecode) iwlog2(IWLOG_INFO, (IW_ecode), __FILE__, __LINE__, ""))
#define iwlog_ecode_warn3(IW_ecode) \
  iwlog2(IWLOG_WARN, (IW_ecode), __FILE__, __LINE__, "")
#define iwlog_ecode_error3(IW_ecode) \
  iwlog2(IWLOG_ERROR, (IW_ecode), __FILE__, __LINE__, "")

#define IWRC(IW_act, IW_rc)                                   \
  {                                                           \
    iwrc __iwrc = (IW_act);                                   \
    if (__iwrc) {                                             \
      if (!(IW_rc))                                           \
      (IW_rc) = __iwrc;                                       \
      else                                                    \
      iwlog2(IWLOG_ERROR, __iwrc, __FILE__, __LINE__, "");    \
    }                                                         \
  }

#define IWRC2(IW_act, IW_lvl)                                   \
  {                                                             \
    iwrc __iwrc = (IW_act);                                     \
    if (__iwrc) {                                               \
      iwlog2(IWLOG_ ## IW_lvl, __iwrc, __FILE__, __LINE__, ""); \
    }                                                           \
  }

#define IWRC3(IW_act, IW_rc, IW_lvl)                            \
  {                                                             \
    iwrc __iwrc = (IW_act);                                     \
    if (__iwrc) {                                               \
      if (!(IW_rc))                                             \
      (IW_rc) = __iwrc;                                         \
      else                                                      \
      iwlog2(IWLOG_ ## IW_lvl, __iwrc, __FILE__, __LINE__, ""); \
    }                                                           \
  }

/**
 * @brief Initiate this submodule.
 * @return `0` on success or error code.
 */
IW_EXPORT iwrc iwlog_init(void);

#ifdef __clang__
#pragma clang diagnostic pop
#endif

IW_EXTERN_C_END
#endif
