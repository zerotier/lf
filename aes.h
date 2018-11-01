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

#ifndef ZT_LF_AES_H
#define ZT_LF_AES_H

#include "common.h"

#ifdef __APPLE__

#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonCryptor.h>

static inline void ZTLF_AES256CFBEncrypt(void *out,const void *in,const unsigned long len,const void *key,const void *iv)
{
	if (len) {
		CCCryptorRef c;
		if (CCCryptorCreateWithMode(kCCEncrypt,kCCModeCFB,kCCAlgorithmAES,ccNoPadding,iv,key,32,(const void *)0,0,0,0,&c) != kCCSuccess) {
			abort();
		}
		size_t moved = 0;
		CCCryptorUpdate(c,in,(size_t)len,out,(size_t)len,&moved);
		if (moved != (size_t)len) {
			abort();
		}
		CCCryptorRelease(c);
	}
}

static inline void ZTLF_AES256CFBDecrypt(void *out,const void *in,const unsigned long len,const void *key,const void *iv)
{
	if (len) {
		CCCryptorRef c;
		if (CCCryptorCreateWithMode(kCCDecrypt,kCCModeCFB,kCCAlgorithmAES,ccNoPadding,iv,key,32,(const void *)0,0,0,0,&c) != kCCSuccess) {
			abort();
		}
		size_t moved = 0;
		CCCryptorUpdate(c,in,(size_t)len,out,(size_t)len,&moved);
		if (moved != (size_t)len) {
			abort();
		}
		CCCryptorRelease(c);
	}
}

#endif /* __APPLE__ */

#endif
