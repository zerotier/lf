/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#ifndef ZTLF_WHARRGARBL_H
#define ZTLF_WHARRGARBL_H

#include "common.h"

#define ZTLF_WHARRGARBL_POW_BYTES 20

/**
 * @param pow 20-byte buffer to receive proof of work results
 * @param in Input data to hash
 * @param inlen Length of input
 * @param difficulty Difficulty determining number of bits that must collide
 * @param memory Memory to use (does not need to be zeroed)
 * @param memorySize Memory size in bytes (must be at least 16)
 * @param threads Number of threads or 0 to use hardware thread count
 * @return Approximate number of iterations required
 */
uint64_t ZTLF_wharrgarbl(void *pow,const void *in,const unsigned long inlen,const uint32_t difficulty,void *memory,const unsigned long memorySize,unsigned int threads);

uint32_t ZTLF_wharrgarblVerify(const void *pow,const void *in,const unsigned long inlen);

static inline uint32_t ZTLF_wharrgarblGetDifficulty(const void *pow)
{
	const uint8_t *p = ((const uint8_t *)pow) + 16;
	uint32_t d = *p++;
	d <<= 8;
	d |= *p++;
	d <<= 8;
	d |= *p++;
	d <<= 8;
	d |= *p;
	return d;
}

#endif
