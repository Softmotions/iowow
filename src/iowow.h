#pragma once
#ifndef IOWOW_H
#define IOWOW_H

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

#include "basedefs.h"
IW_EXTERN_C_START

/**
 * @brief Init iowow subsystem.
 * @return `0` on success or error code.
 */
IW_EXPORT WUR iwrc iw_init(void);

IW_EXPORT const char *iowow_version_full(void);

IW_EXPORT unsigned int iowow_version_major(void);

IW_EXPORT unsigned int iowow_version_minor(void);

IW_EXPORT unsigned int iowow_version_patch(void);


IW_EXTERN_C_END
#endif
