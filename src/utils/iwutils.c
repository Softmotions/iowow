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

#include "iwcfg.h"
#include "iwutils.h"

#include <limits.h>

double_t iwu_rand_dnorm(double_t avg, double_t sd) {
    assert(sd >= 0.0);
    return sqrt(-2.0 * log((rand() / (double_t) RAND_MAX))) * cos(2 * 3.141592653589793 * (rand() / (double_t) RAND_MAX)) * sd + avg;
}

int iwu_rand(int range) {
    int high, low;
    if (range < 2) return 0;
    high = (unsigned int) rand() >> 4;
    low = range * (rand() / (RAND_MAX + 1.0));
    low &= (unsigned int) INT_MAX >> 4;
    return (high + low) % range;
}

int iwu_rand_inorm(int range) {
    int num = (int) iwu_rand_dnorm(range >> 1, range / 10);
    return (num < 0 || num >= range) ? 0 : num;
}






