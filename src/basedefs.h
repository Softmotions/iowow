#ifndef BASEDEFS_H
#define BASEDEFS_H

/**************************************************************************************************
 *  IOWOW library
 *  Copyright (C) 2012-2015 Softmotions Ltd <info@softmotions.com>
 *
 *  This file is part of IOWOW.
 *  IOWOW is free software; you can redistribute it and/or modify it under the terms of
 *  the GNU Lesser General Public License as published by the Free Software Foundation; either
 *  version 2.1 of the License or any later version. IOWOW is distributed in the hope
 *  that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 *  License for more details.
 *  You should have received a copy of the GNU Lesser General Public License along with IOWOW;
 *  if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 *  Boston, MA 02111-1307 USA.
 *************************************************************************************************/

/**
 * @file
 * @brief Very basic definitions.
 * @author Anton Adamansky (adamansky@gmail.com)
 */

#ifdef __cplusplus
#define IW_EXTERN_C_START extern "C" {
#define IW_EXTERN_C_END }
#else
#define IW_EXTERN_C_START
#define IW_EXTERN_C_END
#endif

#if (defined(_WIN32) || defined(_WIN64))
#	if (defined(IW_NODLL) || defined(IW_STATIC))
#		define IW_EXPORT
#	else
#		ifdef IW_API_EXPORTS
#			define IW_EXPORT __declspec(dllexport)
#		else
#			define IW_EXPORT __declspec(dllimport)
#		endif
#	endif
#else
#   if __GNUC__ >= 4
#       define IW_EXPORT __attribute__ ((visibility("default")))
#   else
#       define IW_EXPORT
#   endif
#endif

#if defined(__GNUC__) || defined(__clang__)
#define IW_INLINE static __inline__
#else
#define IW_INLINE static inline
#endif

#define IW_ARR_STATIC static
#define IW_ARR_CONST const

#ifdef _WIN32
#include <windows.h>
#define INVALIDHANDLE(_HNDL) (((_HNDL) == INVALID_HANDLE_VALUE) || (_HNDL) == NULL)
#else
typedef int HANDLE;
#define INVALID_HANDLE_VALUE (-1)
#define INVALIDHANDLE(_HNDL) ((_HNDL) < 0 || (_HNDL) == UINT16_MAX)
#endif

#define IW_ERROR_START 70000

#include<stdint.h>

/**
 * @brief The operation result status code.
 *
 * Zero status code `0` indicates <em>operation success</em>
 *
 * Status code can embed an `errno` code as operation result.
 * In this case `uint32_t iwrc_strip_errno(iwrc *rc)` used
 * to fetch embedded errno.
 *
 * @sa iwlog.h
 */
typedef uint64_t iwrc;

/**
 * @brief A rational number.
 */
typedef struct IW_RNUM {
    int32_t n;  /**< Numerator */
    int32_t dn; /**< Denometator */
} IW_RNUM;


#endif
