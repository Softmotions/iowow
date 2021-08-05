#pragma once
#ifndef IWP_H
#define IWP_H

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


/** @file
 *  @author Anton Adamansky (adamansky@softmotions.com)
 **/

#include "basedefs.h"
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/time.h>

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 0
#endif

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

#define IWCPU_SSE     0x1
#define IWCPU_SSE2    0x2
#define IWCPU_SSE3    0x4
#define IWCPU_SSE4_1  0x8
#define IWCPU_SSE4_2  0x10
#define IWCPU_AVX     0x20
#define IWCPU_AVX2    0x40
#define IWCPU_AVX512F 0x80

/**
 * Flags supported by current CPU.
 * `iwp_init()` must be called.
 *  Zero on non `x86` platforms.
 */
extern unsigned int iwcpuflags;

/**
 * @enum iwp_ecode
 * @brief Error codes.
 */
typedef enum {
  _IWP_ERROR_FS_START = (IW_ERROR_START + 2000UL),
  _IWP_ERROR_FS_END,
} iwp_ecode;

/** File locking mode acquired by process opened this file. */
typedef uint8_t iwp_lockmode;
/** Do not acquire lock on file. */
#define IWP_NOLOCK ((iwp_lockmode) 0x00U)
/** Acquire read lock on file. */
#define IWP_RLOCK ((iwp_lockmode) 0x01U)
/** Acquire write lock on file. */
#define IWP_WLOCK ((iwp_lockmode) 0x02U)
/** Do not block current thread if file have been locked by another process.
 *  In this case error will be raised. */
#define IWP_NBLOCK ((iwp_lockmode) 0x04U)

/**
 * @enum iwp_file_type
 * @brief File type.
 */
typedef enum {
  IWP_TYPE_FILE, /**< Ordinary file. */
  IWP_TYPE_DIR,  /**< Directory. */
  IWP_LINK,      /**< Symlink. */
  IWP_OTHER,     /**< Other file types, eg soc, block, pipe.. */
} iwp_file_type;

typedef enum {
  IWP_SEEK_SET = 1,
  IWP_SEEK_CUR,
  IWP_SEEK_END,
} iwp_seek_origin;

/**
 * Portable version of `int clock_gettime(clockid_t clk_id, struct timespec *tp)`
 */
IW_EXPORT iwrc iwp_clock_get_time(int clock_id, struct timespec *t);

/**
 * @brief Get current time in milliseconds.
 *
 * @param [out] time Time returned
 * @return `0` for success, or error code
 */
IW_EXPORT iwrc iwp_current_time_ms(uint64_t *time, bool monotonic);

/**
 * @brief File info.
 */
typedef struct IWP_FILE_STAT {
  uint64_t      size;  /**< File size. */
  uint64_t      atime; /**< Time of last access. */
  uint64_t      ctime; /**< Time of last status change. */
  uint64_t      mtime; /**< Time of last modification. */
  iwp_file_type ftype; /**< File type. */
} IWP_FILE_STAT;

/**
 * @brief Stat the file specified by @a path.
 *
 * @param path File path
 * @param [out] stat File stat info placeholder.
 * @return `0` on sucess or error code.
 */
IW_EXPORT iwrc iwp_fstat(const char *path, IWP_FILE_STAT *stat);

IW_EXPORT iwrc iwp_fstath(HANDLE fh, IWP_FILE_STAT *stat);

/**
 * @brief Lock the file.
 *
 * @param fh File handle.
 * @param lmode Lock mode specified.
 * @return `0` on sucess or error code.
 */
IW_EXPORT iwrc iwp_flock(HANDLE fh, iwp_lockmode lmode);

/**
 * @brief Unlock the file specified by @a fh
 * @param fh File handle
 * @return `0` on sucess or error code.
 */
IW_EXPORT iwrc iwp_unlock(HANDLE fh);

/**
 * @brief Close the specified file handle (File descriptor).
 * @param fh File handle.
 */
IW_EXPORT iwrc iwp_closefh(HANDLE fh);

/**
 * @brief Read @a siz bytes from file @a fh
 *        into @a buf at the specified offset @a off.
 *
 * @param fh        File handle.
 * @param off       Offset from start of the file.
 * @param [out] buf       Buffer into which bytes will read.
 * @param siz       Number of bytes to read.
 * @param [out] sp  Number of bytes read actually
 * @return `0` on sucess or error code.
 */
IW_EXPORT iwrc iwp_pread(HANDLE fh, off_t off, void *buf, size_t siz, size_t *sp);

/**
 * @brief Write @a siz bytes into file @a fh
 *        at the specified offset @a off
 *        from buffer @a buf.
 *
 * @param fh    File handle.
 * @param off   Offset from start of the file.
 * @param buf   Data buffer to write.
 * @param siz   Number of bytes to write.
 * @param [out] sp   Number of bytes written.
 * @return `0` on sucess or error code.
 */
IW_EXPORT iwrc iwp_pwrite(HANDLE fh, off_t off, const void *buf, size_t siz, size_t *sp);

IW_EXPORT iwrc iwp_write(HANDLE fh, const void *buf, size_t count);

IW_EXPORT iwrc iwp_read(HANDLE fh, void *buf, size_t count, size_t *sp);

IW_EXPORT iwrc iwp_lseek(HANDLE fh, off_t offset, iwp_seek_origin origin, off_t *pos);

/**
 * @brief Copy data within a file
 * @param off Data offset
 * @param siz Data size
 * @param noff New data offset
 */
IW_EXPORT iwrc iwp_copy_bytes(
  HANDLE fh,
  off_t off, size_t siz,
  off_t noff);

/**
 * @brief Get system page size.
 */
IW_EXPORT size_t iwp_page_size(void);


/**
 * @brief Minimal address space aligment for memory mapping.
 */
IW_EXPORT size_t iwp_alloc_unit(void);

/**
 * @brief Truncate a file specified by @a fh to a size of @a len bytes
 * @param fh File handle
 * @param len File size
 * @return `0` on sucess or error code.
 */
IW_EXPORT iwrc iwp_ftruncate(HANDLE fh, off_t len);

/**
 * @brief Allocate extra space for a file.
 * @param fh File handle
 * @param len New file size
 * @return `0` on sucess or error code.
 */
IW_EXPORT iwrc iwp_fallocate(HANDLE fh, off_t len);

/**
 * @brief Pause execution of current thread
 *        to the specified @a ms time in milliseconds.
 * @param ms Thread pause time
 */
IW_EXPORT iwrc iwp_sleep(uint64_t ms);

/**
 * @brief Recursive directory removal specified by @a path.
 * @param path Directory path
 */
IW_EXPORT iwrc iwp_removedir(const char *path);

/**
 * @brief Make directory specified by `path`
 * as well as all parent directories.
 *
 * @param path Path to directory.
 */
IW_EXPORT iwrc iwp_mkdirs(const char *path);

/**
 * @brief Get executable path for the current process.
 * It will be writein into @a opath
 * @param opath Allocated buffer at least `PATH_MAX` length
 */
IW_EXPORT iwrc iwp_exec_path(char *opath);

/**
 * @brief Return number of CPU cores.
 */
IW_EXPORT uint16_t iwp_num_cpu_cores(void);

/**
 * @brief Init iwp module.
 * @return `0` on success or error code.
 */
IW_EXPORT WUR iwrc iwp_init(void);

IW_EXPORT iwrc iwp_fsync(HANDLE fh);

IW_EXPORT iwrc iwp_fdatasync(HANDLE fh);

/**
 * Write system tmp directory path into provided `out` buffer.
 * Write at most `len` bytes not including terminating `NULL` char.
 * @return Number of bytes writen. Zero on error.
 */
IW_EXPORT size_t iwp_tmpdir(char *out, size_t len);

/**
 * Allocates unique temp file path. Caller should use `free()`
 * to release path buffer.
 * @return Zero on error.
 */
IW_EXPORT char* iwp_allocate_tmpfile_path(const char *prefix);

/**
 * Set name of the current thread. On some platforms
 * thread name canot be longer than 16 bytes including zero terminator.
 */
IW_EXPORT void iwp_set_current_thread_name(const char *name);

#endif
