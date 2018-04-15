#pragma once
#ifndef IW_CFG_H
#define IW_CFG_H

//
/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2018 Softmotions Ltd <info@softmotions.com>
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


#include "basedefs.h"

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#ifndef MAXPATHLEN
#ifdef PATH_MAX
# define MAXPATHLEN PATH_MAX
#else
# define MAXPATHLEN 4096
#endif
#endif

#if !defined(IW_32) && !defined(IW_64)
#error Unknown CPU bits
#endif

#define IOWOW_VERSION "@iowow_VERSION@"
#define IOWOW_VERSION_MAJOR @iowow_VERSION_MAJOR@
#define IOWOW_VERSION_MINOR @iowow_VERSION_MINOR@
#define IOWOW_VERSION_PATCH @iowow_VERSION_PATCH@


#endif
