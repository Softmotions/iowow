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

#ifndef IW_CFG_H
#define IW_CFG_H

#include "basedefs.h"

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#if defined(__GNUC__) || defined(__clang__)
#define IW_INLINE static __inline__
#else
#define IW_INLINE static inline
#endif

#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>


#ifdef _WIN32
#define IW_PATH_CHR       '\\'
#define IW_PATH_STR       "\\"
#define IW_LINE_SEP       "\r\n"
#else
#define IW_PATH_CHR       '/'
#define IW_PATH_STR       "/"
#define IW_LINE_SEP       "\n"
#endif

/* Align IW_x with IW_v. IW_v must be simple power of 2 value. */
#define IW_ROUNDUP(IW_x, IW_v) (((IW_x) + (IW_v) - 1) & ~((IW_v) - 1))

/* Round down align IW_x with IW_v. IW_v must be simple power of 2 value. */
#define IW_ROUNDOWN(IW_x, IW_v) ((IW_x) - ((IW_x) & ((IW_v) - 1)))

#if defined(NDEBUG)
#define IW_DODEBUG(IW_expr) \
    do { \
    } while(false)
#else
#define IW_DODEBUG(IW_expr) \
    { \
        IW_expr; \
    }
#endif

#define IW_SWAB16(IW_num) \
    ( \
      ((IW_num & 0x00ffU) << 8) | \
      ((IW_num & 0xff00U) >> 8) \
    )

#define IW_SWAB32(IW_num) \
    ( \
      ((IW_num & 0x000000ffUL) << 24) | \
      ((IW_num & 0x0000ff00UL) << 8) | \
      ((IW_num & 0x00ff0000UL) >> 8) | \
      ((IW_num & 0xff000000UL) >> 24) \
    )

#define IW_SWAB64(IW_num) \
    ( \
      ((IW_num & 0x00000000000000ffULL) << 56) | \
      ((IW_num & 0x000000000000ff00ULL) << 40) | \
      ((IW_num & 0x0000000000ff0000ULL) << 24) | \
      ((IW_num & 0x00000000ff000000ULL) << 8) | \
      ((IW_num & 0x000000ff00000000ULL) >> 8) | \
      ((IW_num & 0x0000ff0000000000ULL) >> 24) | \
      ((IW_num & 0x00ff000000000000ULL) >> 40) | \
      ((IW_num & 0xff00000000000000ULL) >> 56) \
    )

#if (IW_BIGENDIAN == 1) || defined(IW_FORCE_BIGENDIAN)
#define IW_HTOIS(IW_num)   IW_SWAB16(IW_num)
#define IW_HTOIL(IW_num)   IW_SWAB32(IW_num)
#define IW_HTOILL(IW_num)  IW_SWAB64(IW_num)
#define IW_ITOHS(IW_num)   IW_SWAB16(IW_num)
#define IW_ITOHL(IW_num)   IW_SWAB32(IW_num)
#define IW_ITOHLL(IW_num)  IW_SWAB64(IW_num)
#else
#undef IW_BIGENDIAN
#define IW_BIGENDIAN       0
#define IW_HTOIS(IW_num)   (IW_num)
#define IW_HTOIL(IW_num)   (IW_num)
#define IW_HTOILL(IW_num)  (IW_num)
#define IW_ITOHS(IW_num)   (IW_num)
#define IW_ITOHL(IW_num)   (IW_num)
#define IW_ITOHLL(IW_num)  (IW_num)
#endif


#endif
