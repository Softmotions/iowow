
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

#ifndef IW_ERROR_START
#define IW_ERROR_START 70000
#endif

/**
 * @brief Common error codes.
 */
typedef enum {
    IW_OK           = 0,                /**< No error. */
    IW_ERROR_FAIL   = IW_ERROR_START,   /**< Unspecified error. */
    IW_ERROR_ERRNO,                     /**< Error with expected errno status set. */
    IW_ERROR_IO_ERRNO,                  /**< IO error with expected errno status set. */
    IW_ERROR_NOT_EXISTS,                /**< Resource is not exists. */
    IW_ERROR_READONLY,                  /**< Resource is readonly. */
    IW_ERROR_ALREADY_OPENED,            /**< Resource is already opened. */
    IW_ERROR_THREADING,                 /**< Threading error. */
    IW_ERROR_THREADING_ERRNO,           /**< Threading error with errno status set. */
    IW_ERROR_ASSERTION,                 /**< Generic assertion error. */
    IW_ERROR_INVALID_HANDLE,            /**< Invalid HANDLE value. */
    IW_ERROR_OUT_OF_BOUNDS,             /**< Invalid bounds specified. */
    IW_ERROR_NOT_IMPLEMENTED            /**< Method is not implemented */
} iw_ecode;

/**
 * @enum
 * Logging vebosity levels.
 */
typedef enum {
    IWLOG_ERROR = 0,
    IWLOG_WARN = 1,
    IWLOG_INFO = 2,
    IWLOG_DEBUG = 3
} iwlog_lvl;

/**
 * @struct
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
typedef iwrc(*IWLOG_FN)(locale_t locale,
                        iwlog_lvl lvl,
                        iwrc ecode,
                        int errno_code,
                        int werror_code,
                        const char *file, int line, uint64_t ts,
                        void *opts,
                        const char *fmt,
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
IW_EXPORT iwrc iwrc_set_errno(iwrc rc, uint32_t errno_code);

/**
 * @brief Strip the attached `errno` code from the specified @a rc and
 * return this errno code.
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


IW_EXPORT void iwrc_strip_code(iwrc *rc);

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
IW_EXPORT const char* iwlog_ecode_explained(iwrc ecode);

/**
 * @brief Register error code explanation function.
 *
 * Up to `128` @a fp function can be registered.
 *
 * @param fp
 * @return `0` on success or error code.
 */
IW_EXPORT iwrc iwlog_register_ecodefn(IWLOG_ECODE_FN fp);


iwrc iwlog(iwlog_lvl lvl,
           iwrc ecode,
           const char *file,
           int line,
           const char *fmt, ...);


void iwlog2(iwlog_lvl lvl,
            iwrc ecode,
            const char *file,
            int line,
            const char *fmt, ...);


iwrc iwlog_va(iwlog_lvl lvl,
              iwrc ecode,
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

/**
 * @brief Init logging submodule.
 * @return `0` on success or error code.
 */
IW_EXPORT iwrc iwlog_init(void);


IW_EXTERN_C_END
#endif
