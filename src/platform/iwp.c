//
/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2017 Softmotions Ltd <info@softmotions.com>
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


#include "log/iwlog.h"
#include "platform/iwp.h"
#include <stdio.h>

unsigned int iwcpuflags = 0;

#if defined(__linux) || defined(__unix)
#include "linux/linux.c"
#else
#error Unsupported platform
#endif

// Thanks to https://attractivechaos.wordpress.com/2017/09/04/on-cpu-dispatch
static unsigned int x86_simd(void) {
  unsigned int eax, ebx, ecx, edx, flag = 0;
#ifdef _MSC_VER
  int cpuid[4];
  __cpuid(cpuid, 1);
  eax = cpuid[0], ebx = cpuid[1], ecx = cpuid[2], edx = cpuid[3];
#else
  __asm volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1));
#endif
  if (edx >> 25 & 1) flag |= IWCPU_SSE;
  if (edx >> 26 & 1) flag |= IWCPU_SSE2;
  if (ecx >> 0 & 1) flag |= IWCPU_SSE3;
  if (ecx >> 19 & 1) flag |= IWCPU_SSE4_1;
  if (ecx >> 20 & 1) flag |= IWCPU_SSE4_2;
  if (ecx >> 28 & 1) flag |= IWCPU_AVX;
  if (ebx >> 5 & 1) flag |= IWCPU_AVX2;
  if (ebx >> 16 & 1) flag |= IWCPU_AVX512F;
  return flag;
}

iwrc iwp_init(void) {
  iwcpuflags = x86_simd();
  return 0;
}
