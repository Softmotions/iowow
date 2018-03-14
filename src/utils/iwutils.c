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


#include "iwcfg.h"
#include "iwutils.h"
#include <limits.h>
#include <stdint.h>
#include "mt19937ar.h"

#define IWU_RAND_MAX 0xffffffff

void iwu_rand_seed(uint32_t seed) {
  init_genrand(seed);
}

IW_EXPORT uint32_t iwu_rand_u32() {
  return genrand_int32();
}

double_t iwu_rand_dnorm(double_t avg, double_t sd) {
  assert(sd >= 0.0);
  return sqrt(-2.0 * log((genrand_int31() / (double_t) INT_MAX))) *
         cos(2 * 3.141592653589793 * (genrand_int31() / (double_t) INT_MAX)) * sd + avg;
}

uint32_t iwu_rand_range(uint32_t range) {
  return genrand_int32() % range;
}

uint32_t iwu_rand_inorm(int range) {
  int num = (int) iwu_rand_dnorm(range >> 1, range / 10);
  return (num < 0 || num >= range) ? 0 : num;
}

int iwlog2_32(uint32_t val) {
  static const int tab32[32] = {
    0,  9,  1, 10, 13, 21,  2, 29,
    11, 14, 16, 18, 22, 25,  3, 30,
    8, 12, 20, 28, 15, 17, 24,  7,
    19, 27, 23,  6, 26,  5,  4, 31
  };
  val |= val >> 1;
  val |= val >> 2;
  val |= val >> 4;
  val |= val >> 8;
  val |= val >> 16;
  return tab32[(val * 0x07C4ACDD) >> 27];
}

int iwlog2_64(uint64_t val) {
  static const int table[64] = {
    0, 58, 1, 59, 47, 53, 2, 60, 39, 48, 27, 54, 33, 42, 3, 61,
    51, 37, 40, 49, 18, 28, 20, 55, 30, 34, 11, 43, 14, 22, 4, 62,
    57, 46, 52, 38, 26, 32, 41, 50, 36, 17, 19, 29, 10, 13, 21, 56,
    45, 25, 31, 35, 16, 9, 12, 44, 24, 15, 8, 23, 7, 6, 5, 63
  };
  val |= val >> 1;
  val |= val >> 2;
  val |= val >> 4;
  val |= val >> 8;
  val |= val >> 16;
  val |= val >> 32;
  return table[(val * 0x03f6eaf2cd271461) >> 58];
}
