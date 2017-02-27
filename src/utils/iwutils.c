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


#include "iwcfg.h"
#include "iwutils.h"

#include <limits.h>

double_t iwu_rand_dnorm(double_t avg, double_t sd) {
  assert(sd >= 0.0);
  return sqrt(-2.0 * log((rand() / (double_t) RAND_MAX))) *
         cos(2 * 3.141592653589793 * (rand() / (double_t) RAND_MAX)) * sd +
         avg;
}

int iwu_rand(int range) {
  int high, low;
  if (range < 2)
    return 0;
  high = (unsigned int) rand() >> 4;
  low = range * (rand() / (RAND_MAX + 1.0));
  low &= (unsigned int) INT_MAX >> 4;
  return (high + low) % range;
}

int iwu_rand_inorm(int range) {
  int num = (int) iwu_rand_dnorm(range >> 1, range / 10);
  return (num < 0 || num >= range) ? 0 : num;
}
