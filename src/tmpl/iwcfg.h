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


#ifdef _WIN32
#define IW_PATH_CHR       '\\'
#define IW_PATH_STR       "\\"
#define IW_LINE_SEP       "\r\n"
#else
#define IW_PATH_CHR       '/'
#define IW_PATH_STR       "/"
#define IW_LINE_SEP       "\n"
#endif



#endif
