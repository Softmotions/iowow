#ifndef IWUTILS_H
#define IWUTILS_H

/**************************************************************************************************
 *  IOWOW library
 *  Copyright (C) 2012-2017 Softmotions Ltd <info@softmotions.com>
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
 * @author Anton Adamansky (adamansky@softmotions.com)
 */
 
#include "basedefs.h"
#include <math.h>

IW_EXTERN_C_START

#ifdef _WIN32
#define IW_PATH_CHR       '\\'
#define IW_PATH_STR       "\\"
#define IW_LINE_SEP       "\r\n"
#else
#define IW_PATH_CHR       '/'
#define IW_PATH_STR       "/"
#define IW_LINE_SEP       "\n"
#endif

#ifndef MIN
#define MIN(a_, b_) ((a_) < (b_) ? (a_) : (b_))
#endif

#ifndef MAX
#define MAX(a_, b_) ((a_) > (b_) ? (a_) : (b_))
#endif

/* Align IW_x_ with IW_v_. IW_v_ must be simple power of 2 value. */
#define IW_ROUNDUP(IW_x_, IW_v_) (((IW_x_) + (IW_v_) - 1) & ~((IW_v_) - 1))

/* Round down align IW_x_ with IW_v_. IW_v_ must be simple power of 2 value. */
#define IW_ROUNDOWN(IW_x_, IW_v_) ((IW_x_) - ((IW_x_) & ((IW_v_) - 1)))

#if defined(NDEBUG)
#define IW_DODEBUG(IW_expr_) \
    do { \
    } while(false)
#else
#define IW_DODEBUG(IW_expr_) \
    { \
        IW_expr_; \
    }
#endif

#define IW_SWAB16(IW_num_) \
    ( \
      ((IW_num_ & 0x00ffU) << 8) | \
      ((IW_num_ & 0xff00U) >> 8) \
    )

#define IW_SWAB32(IW_num_) \
    ( \
      ((IW_num_ & 0x000000ffUL) << 24) | \
      ((IW_num_ & 0x0000ff00UL) << 8) | \
      ((IW_num_ & 0x00ff0000UL) >> 8) | \
      ((IW_num_ & 0xff000000UL) >> 24) \
    )

#define IW_SWAB64(IW_num_) \
    ( \
      ((IW_num_ & 0x00000000000000ffULL) << 56) | \
      ((IW_num_ & 0x000000000000ff00ULL) << 40) | \
      ((IW_num_ & 0x0000000000ff0000ULL) << 24) | \
      ((IW_num_ & 0x00000000ff000000ULL) << 8) | \
      ((IW_num_ & 0x000000ff00000000ULL) >> 8) | \
      ((IW_num_ & 0x0000ff0000000000ULL) >> 24) | \
      ((IW_num_ & 0x00ff000000000000ULL) >> 40) | \
      ((IW_num_ & 0xff00000000000000ULL) >> 56) \
    )

#if (IW_BIGENDIAN == 1) || defined(IW_FORCE_BIGENDIAN)
#define IW_HTOIS(IW_num_)   IW_SWAB16(IW_num_)
#define IW_HTOIL(IW_num_)   IW_SWAB32(IW_num_)
#define IW_HTOILL(IW_num_)  IW_SWAB64(IW_num_)
#define IW_ITOHS(IW_num_)   IW_SWAB16(IW_num_)
#define IW_ITOHL(IW_num_)   IW_SWAB32(IW_num_)
#define IW_ITOHLL(IW_num_)  IW_SWAB64(IW_num_)
#else
#undef IW_BIGENDIAN
#define IW_BIGENDIAN       0
#define IW_HTOIS(IW_num_)   (IW_num_)
#define IW_HTOIL(IW_num_)   (IW_num_)
#define IW_HTOILL(IW_num_)  (IW_num_)
#define IW_ITOHS(IW_num_)   (IW_num_)
#define IW_ITOHL(IW_num_)   (IW_num_)
#define IW_ITOHLL(IW_num_)  (IW_num_)
#endif

#ifndef SIZE_T_MAX
# define SIZE_T_MAX ((size_t) -1)
#endif

#ifndef OFF_T_MIN
# define OFF_T_MIN ((off_t) (((uint64_t) 1) << (8 * sizeof(off_t) - 1)))
#endif
#ifndef OFF_T_MAX
# define OFF_T_MAX ((off_t) ~(((uint64_t) 1) << (8 * sizeof(off_t) - 1)))
#endif

#ifdef __GNUC__
#define IW_LIKELY(x_) __builtin_expect((x_), 1)
#define IW_UNLIKELY(x_) __builtin_expect((x_), 0)
#else
#define IW_LIKELY(x_)
#define IW_UNLIKELY(x_)
#endif

#define IW_RANGES_OVERLAP(IW_s1_, IW_e1_, IW_s2_, IW_e2_) \
    (((IW_e1_) > (IW_s2_) && (IW_e1_) <= (IW_e2_)) || \
     ((IW_s1_) >= (IW_s2_) && (IW_s1_) < (IW_e2_)) || \
     ((IW_s1_) <= (IW_s2_) && (IW_e1_) >= (IW_e2_)))

/**
 * @brief Create uniform distributed random number.
 * @param avg Distribution pivot
 * @param sd Avg square deviation
 */
IW_EXPORT double_t iwu_rand_dnorm(double_t avg, double_t sd);

/**
 * @brief Create uniform distributed integer random number in: `[0, range)`
 */
IW_EXPORT int iwu_rand(int range);

/**
 * @brief Create normal distributed integer random number.
 */
IW_EXPORT int iwu_rand_inorm(int range);

IW_EXTERN_C_END

#endif
