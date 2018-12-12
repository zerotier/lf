/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#ifndef ZT_LF_SHA384_H
#define ZT_LF_SHA384_H

#include "common.h"
#include "sha3.h"

#ifdef __APPLE__

#include <CommonCrypto/CommonDigest.h>

#define ZTLF_HAVE_SHA_IMPL 1

static inline void ZTLF_SHA384(void *d,const void *b,const unsigned long s)
{
	CC_SHA512_CTX s384;
	CC_SHA384_Init(&s384);
	CC_SHA384_Update(&s384,b,(CC_LONG)s);
	CC_SHA384_Final((unsigned char *)d,&s384);
}

static inline void ZTLF_SHA512(void *d,const void *b,const unsigned long s)
{
	CC_SHA512_CTX s512;
	CC_SHA512_Init(&s512);
	CC_SHA512_Update(&s512,b,(CC_LONG)s);
	CC_SHA512_Final((unsigned char *)d,&s512);
}

#define ZTLF_SHA384_CTX CC_SHA512_CTX
#define ZTLF_SHA384_init(ctx) CC_SHA384_Init(ctx)
#define ZTLF_SHA384_update(ctx,b,l) CC_SHA384_Update(ctx,(const void *)(b),(CC_LONG)(l))
#define ZTLF_SHA384_final(ctx,d) CC_SHA384_Final((unsigned char *)(d),ctx)

#define ZTLF_SHA512_CTX CC_SHA512_CTX
#define ZTLF_SHA512_init(ctx) CC_SHA512_Init(ctx)
#define ZTLF_SHA512_update(ctx,b,l) CC_SHA512_Update(ctx,(const void *)(b),(CC_LONG)(l))
#define ZTLF_SHA512_final(ctx,d) CC_SHA512_Final((unsigned char *)(d),ctx)

#endif /* __APPLE__ */

#endif

#ifndef ZTLF_HAVE_SHA_IMPL

#include <openssl/sha.h>

static inline void ZTLF_SHA384(void *d,const void *b,const unsigned long s)
{
	SHA512_CTX h;
	SHA384_Init(&h);
	SHA384_Update(&h,b,(size_t)s);
	SHA384_Final((unsigned char *)d,&h);
}

static inline void ZTLF_SHA512(void *d,const void *b,const unsigned long s)
{
	SHA512_CTX h;
	SHA512_Init(&h);
	SHA512_Update(&h,b,(size_t)s);
	SHA512_Final((unsigned char *)d,&h);
}

#define ZTLF_SHA384_CTX SHA512_CTX
#define ZTLF_SHA384_init(ctx) SHA384_Init(ctx)
#define ZTLF_SHA384_update(ctx,b,l) SHA384_Update(ctx,(const void *)(b),(size_t)(l))
#define ZTLF_SHA384_final(ctx,d) SHA384_Final((unsigned char *)(d),ctx)

#define ZTLF_SHA512_CTX SHA512_CTX
#define ZTLF_SHA512_init(ctx) SHA512_Init(ctx)
#define ZTLF_SHA512_update(ctx,b,l) SHA512_Update(ctx,(const void *)(b),(size_t)(l))
#define ZTLF_SHA512_final(ctx,d) SHA512_Final((unsigned char *)(d),ctx)

#endif

/**
 * Computes SHA384(SHA3-512(message)) and fills d[] with the first 32 bytes of the result.
 * 
 * This is intended to provide an extremely future-proof 256-bit hash that will remain secure
 * if either SHA-2 or SHA-3 are significantly weakened.
 * 
 * @param d 32-byte buffer to receive digest
 * @param b Message to hash
 * @param s Size of message in bytes
 */
static inline void ZTLF_ShaSha256(void *d,const void *b,const unsigned long s)
{
	sha3_context sha3;
	uint8_t s384[48];
	sha3_Init512(&sha3);
	sha3_Update(&sha3,b,s);
	ZTLF_SHA384(s384,sha3_Finalize(&sha3),64);
	for(unsigned int i=0;i<32;++i) ((uint8_t *)d)[i] = s384[i];
}
