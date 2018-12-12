/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#ifndef ZT_LF_SCORE_H
#define ZT_LF_SCORE_H

#include "common.h"

/**
 * Computes a 32-bit discrete approximation of log2(h) where h is a 256-bit big-endian integer
 * 
 * @param h 32-byte/256-bit input to score
 * @return Leading zero bits in most significant 8 bytes, followed by two's compliment of the first 24 non-zero bits
 */
static inline uint32_t ZTLF_score(const uint8_t h[32])
{
	uint64_t rem = 0;
	uint32_t zb = 0;
	unsigned int k,i = 0;

	while (i < 32) {
		if (h[i])
			break;
		zb += 8;
		++i;
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

	return ( (zb >= 256) ? 0xffffffff : ((zb << 24) | (((uint32_t)(rem >> 40)) ^ 0x00ffffff)) );
}

#endif
