
/**
 *  @file
 *  @brief Error logging/reporting rputines.
 */

#ifndef IWLOG
#define IWLOG

#include "basedefs.h"
#include <stdint.h>
#include <locale.h>
#include <stdarg.h>
#include <stdio.h>

IW_EXTERN_C_START


/**
 * @enum
 * Logging vebosity levels.
 */
typedef enum {
    IWLOG_ERROR = 0,
    IWLOG_WARN = 1,
    IWLOG_INFO = 2,
    IWLOG_DEBUG = 3
} IWLOG_LEVEL;


/**
 * @struct
 * @brief Options for the default logging function.
 * @see iwlog_set_logfn_opts(void*)
 */
typedef struct {
    FILE *out; /**< Output file stream. Default: @em stderr  */
} IWLOG_DEFAULT_OPTS;

/**
 * @brief Logging function pointer.
 *
 * @param locale Locale used to print error message.
 * @param lvl Log level.
 * @param ecode Error code specified.
 * @param errno_code Optional errno code. Set it to 0 if errno not used.
 * @param file File name. Can be @em NULL
 * @param line Line number in the file.
 * @param ts Message time-stamp
 * @param fmt @em printf style message format
 * @return Not zero error code in the case of error.
 *
 * @see iwlog_set_logfn(IWLOG_FN)
 */
typedef int (*IWLOG_FN)(locale_t locale,
                        IWLOG_LEVEL lvl,
                        int64_t ecode,
                        int errno_code,
                        int werror_code,
                        const char *file, int line, uint64_t ts,
                        void *opts,
                        const char *fmt,
                        va_list argp);

/**
 * @brief Return the locale aware error code explanation message.
 *
 * @param locale Locale used. Can be @em NULL
 * @param ecode Error code
 * @return Message string describes a given error code or @em NULL if
 *         no message found.
 */
typedef const char* (*IWLOG_ECODE_FN)(locale_t locale, int64_t ecode);

/**
 * @brief Sets default logging function.
 * @warning Not thread safe.
 *
 * @param fp Logging function pointer.
 * @return Not zero if error occured.
 */
IW_EXPORT void iwlog_set_logfn(IWLOG_FN fp);

/**
 * @brief Get a default logging function.
 */
IW_EXPORT IWLOG_FN iwlog_get_logfn(void);

/**
 * @brief Set opaque options structure for the
 * @param opts
 */
IW_EXPORT void iwlog_set_logfn_opts(void *opts);

/**
 * @brief Returns string representation of given error code.
 * @param ecode Error code
 * @return
 */
IW_EXPORT const char* iwlog_ecode_explained(int64_t ecode);

/**
 * @brief Get an error code explanation function.
 */
IW_EXPORT IWLOG_ECODE_FN iwlog_get_ecodefn(void);

/**
 * @brief Set default error code explanation function.
 * @param fp
 */
IW_EXPORT void iwlog_set_ecodefn(IWLOG_ECODE_FN fp);


int iwlog(IWLOG_LEVEL lvl,
          int64_t ecode,
          const char *file,
          int line,
          const char *fmt, ...);


void iwlog2(IWLOG_LEVEL lvl,
            int64_t ecode,
            const char *file,
            int line,
            const char *fmt, ...);


int iwlog_va(IWLOG_LEVEL lvl,
             int64_t ecode,
             const char *file,
             int line,
             const char *fmt,
             va_list argp);

#ifdef _DEBUG
#define iwlog_debug(IW_fmt,...) iwlog2(IWLOG_DEBUG, 0, __FILE__, __LINE__, (IW_fmt),##__VA_ARGS__)
#else
#define iwlog_debug(IW_fmt,...)
#endif
#define iwlog_info(IW_fmt,...) iwlog2(IWLOG_INFO, 0, __FILE__, __LINE__, (IW_fmt),##__VA_ARGS__)
#define iwlog_warn(IW_fmt,...) iwlog2(IWLOG_WARN, 0, __FILE__, __LINE__, (IW_fmt),##__VA_ARGS__)
#define iwlog_error(IW_fmt,...) iwlog2(IWLOG_ERROR, 0, __FILE__, __LINE__, (IW_fmt),##__VA_ARGS__)


#ifdef _DEBUG
#define iwlog_debug2(IW_fmt) iwlog2(IWLOG_DEBUG, 0, __FILE__, __LINE__, (IW_fmt))
#else
#define iwlog_debug2(IW_fmt)
#endif
#define iwlog_info2(IW_fmt) iwlog2(IWLOG_INFO, 0, __FILE__, __LINE__, (IW_fmt))
#define iwlog_warn2(IW_fmt) iwlog2(IWLOG_WARN, 0, __FILE__, __LINE__, (IW_fmt))
#define iwlog_error2(IW_fmt) iwlog2(IWLOG_ERROR, 0, __FILE__, __LINE__, (IW_fmt))

#ifdef _DEBUG
#define iwlog_ecode_debug(IW_ecode, IW_fmt,...) iwlog2(IWLOG_DEBUG, (IW_ecode), __FILE__, __LINE__, (IW_fmt),##__VA_ARGS__)
#else
#define iwlog_ecode_debug(IW_ecode, IW_fmt,...)
#endif
#define iwlog_ecode_info(IW_ecode, IW_fmt,...) iwlog2(IWLOG_INFO, (IW_ecode), __FILE__, __LINE__, (IW_fmt),##__VA_ARGS__)
#define iwlog_ecode_warn(IW_ecode, IW_fmt,...) iwlog2(IWLOG_WARN, (IW_ecode), __FILE__, __LINE__, (IW_fmt),##__VA_ARGS__)
#define iwlog_ecode_error(IW_ecode, IW_fmt,...) iwlog2(IWLOG_ERROR, (IW_ecode), __FILE__, __LINE__, (IW_fmt),##__VA_ARGS__)


#ifdef _DEBUG
#define iwlog_ecode_debug2(IW_ecode, IW_fmt) iwlog2(IWLOG_DEBUG, (IW_ecode), __FILE__, __LINE__, (IW_fmt))
#else
#define iwlog_ecode_debug2(IW_ecode, IW_fmt)
#endif
#define iwlog_ecode_info2(IW_ecode, IW_fmt) iwlog2(IWLOG_INFO, (IW_ecode), __FILE__, __LINE__, (IW_fmt))
#define iwlog_ecode_warn2(IW_ecode, IW_fmt) iwlog2(IWLOG_WARN, (IW_ecode), __FILE__, __LINE__, (IW_fmt))
#define iwlog_ecode_error2(IW_ecode, IW_fmt) iwlog2(IWLOG_ERROR, (IW_ecode), __FILE__, __LINE__, (IW_fmt))

IW_EXTERN_C_END
#endif
