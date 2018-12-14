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
 * This is a simple Davies-Meyer construction hash function built from the Speck block cipher.
 * 
 * It should not be considered secure for authentication or encryption purposes. Its purpose
 * is to act as a cryptographic PRNG for use in Wharrgarbl's momentum-style collision search
 * proof of work function.
 * 
 * It's exposed here so it can be tested.
 * 
 * @param out Output to receive 128-bit digest
 * @param in Input to hash
 * @param len Length of input
 */
void ZTLF_SpeckHash(uint64_t out[2],const void *in,const unsigned long len);

/**
 * Compute a memory-hard proof of work from an input.
 * 
 * @param pow 20-byte buffer to receive proof of work results
 * @param in Input data to hash
 * @param inlen Length of input
 * @param difficulty Difficulty determining number of bits that must collide
 * @param memory Memory to use (does not need to be zeroed, if NULL will be allocated based on memorySize and then freed)
 * @param memorySize Memory size in bytes
 * @param threads Number of threads or 0 to use hardware thread count
 * @return Approximate number of iterations required or 0 if there was a problem (right now can only be memory size < 12)
 */
uint64_t ZTLF_Wharrgarbl(void *pow,const void *in,const unsigned long inlen,const uint32_t difficulty,void *memory,const unsigned long memorySize,unsigned int threads);

/**
 * Verify this proof of work
 * 
 * @param pow 20-byte PoW
 * @param in Original input used to generate work
 * @param inlen Length of original input
 * @return Difficulty or 0 if work was not valid
 */
uint32_t ZTLF_WharrgarblVerify(const void *pow,const void *in,const unsigned long inlen);

#endif
