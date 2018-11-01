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

#ifdef __APPLE__

#include <CommonCrypto/CommonDigest.h>

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
