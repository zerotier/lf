/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * --
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial closed-source software that incorporates or links
 * directly against ZeroTier software without disclosing the source code
 * of your own application.
 */

#ifndef ZTLF_WHARRGARBL_H
#define ZTLF_WHARRGARBL_H

#include "common.h"

#define ZTLF_WHARRGARBL_SIZE_BYTES 24

void ZTLF_wharrgarbl(uint64_t wresult[3],const void *in,const unsigned long inlen,const uint64_t difficulty,const unsigned long memory);
uint64_t ZTLF_wharrgarblVerify2(const uint64_t wresult[2],const void *in,const unsigned long inlen,const uint64_t difficulty);
static inline ZTLF_wharrgarblVerify(const uint64_t wresult[3],const void *in,const unsigned long inlen) { return ZTLF_wharrgarblVerify2(wresult,in,inlen,ZTLF_ntohll(wresult[2])); }

#endif
