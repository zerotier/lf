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

#ifndef ZT_LF_SHA384_H
#define ZT_LF_SHA384_H

#include "common.h"
#include "aes.h"

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

static inline void ZTLF_Shandwich256(void *d,const void *b,const unsigned long s)
{
	uint64_t s512a[8],s512b[8];
	ZTLF_SHA512(s512a,b,s);
	ZTLF_SHA512(s512b,s512a,64);
	ZTLF_AES256ECB_encrypt(s512a,d,s512b);
	ZTLF_AES256ECB_encrypt(s512a + 4,((uint8_t *)d) + 16,s512b + 2);
}
