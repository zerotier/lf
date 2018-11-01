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

#ifndef ZT_LF_SCORE_H
#define ZT_LF_SCORE_H

#include "common.h"

static inline uint32_t score(const uint8_t h[32])
{
	uint64_t rem = 0;
	uint32_t zb = 0;
	unsigned int k,i = 0;

	while (i < 32) {
		if (h[i++])
			break;
		zb += 8;
	}

	for(k=0;k<8;++k) {
		rem <<= 8;
		if (i < 32)
			rem |= (uint64_t)h[i++];
	}

	while ((rem >> 63) == 0) {
		rem <<= 1;
		++zb;
	}

	return ((zb >= 256) ? 0xffffffff : ((zb << 24) | ((~((uint32_t)rem)) >> 8)));
}

#endif
