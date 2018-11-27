/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#ifndef ZT_LF_AES_H
#define ZT_LF_AES_H

#include "common.h"

#define ZTLF_AES256_KEY_SIZE   32
#define ZTLF_AES256CFB_IV_SIZE 16

/* Use CommonCrypto on Mac -- an older API but still available up to Mojave. */
#ifdef __APPLE__

#define ZTLF_HAVE_AES_IMPL 1

#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonCryptor.h>

typedef CCCryptorRef ZTLF_AES256CFB;

static inline void ZTLF_AES256ECB_encrypt(const void *key,void *out,const void *in)
{
	size_t moved = 0;
	if (CCCrypt(kCCEncrypt,kCCAlgorithmAES,kCCOptionECBMode,key,32,NULL,in,16,out,16,&moved) != kCCSuccess) {
		abort();
	}
}

static inline void ZTLF_AES256CFB_init(ZTLF_AES256CFB *c,const void *key,const void *iv,bool encrypt)
{
	if (CCCryptorCreateWithMode((encrypt) ? kCCEncrypt : kCCDecrypt,kCCModeCFB,kCCAlgorithmAES,ccNoPadding,iv,key,32,(const void *)0,0,0,0,c) != kCCSuccess) {
		abort();
	}
}

static inline void ZTLF_AES256CFB_crypt(ZTLF_AES256CFB *c,void *out,const void *in,const unsigned long len)
{
	if (len) {
		size_t moved = 0;
		CCCryptorUpdate(*c,in,(size_t)len,out,(size_t)len,&moved);
		if (moved != (size_t)len) {
			abort();
		}
	}
}

static inline void ZTLF_AES256CFB_destroy(ZTLF_AES256CFB *c)
{
	CCCryptorRelease(*c);
}

#endif /* __APPLE__ */

/* TODO: Windows */
#ifdef __WINDOWS__
#endif

/* If we don't have Apple or Windows, use OpenSSL/LibreSSL libcrypto */
#ifndef ZTLF_HAVE_AES_IMPL

#include <openssl/aes.h>
#include <openssl/evp.h>

typedef EVP_CIPHER_CTX ZTLF_AES256CFB;

static inline void ZTLF_AES256ECB_encrypt(const void *key,void *out,const void *in)
{
	AES_KEY c;
	AES_set_encrypt_key((const unsigned char *)key,256,&c);
	AES_encrypt((const unsigned char *)in,(unsigned char *)out,&c);
}

static inline void ZTLF_AES256CFB_init(ZTLF_AES256CFB *c,const void *key,const void *iv,bool encrypt)
{
	EVP_CIPHER_CTX_init(c);
	if (encrypt) {
		EVP_EncryptInit_ex(c,EVP_aes_256_cfb128(),NULL,key,iv);
	} else {
		EVP_DecryptInit_ex(c,EVP_aes_256_cfb128(),NULL,key,iv);
	}
}

static inline void ZTLF_AES256CFB_crypt(ZTLF_AES256CFB *c,void *out,const void *in,const unsigned long len)
{
	if (len) {
		int outl = (int)len;
		if (c->encrypt) {
			EVP_EncryptUpdate(c,out,&outl,in,(int)len);
		} else {
			EVP_DecryptUpdate(c,out,&outl,in,(int)len);
		}
		if (outl != (int)len)
			abort();
	}
}

static inline void ZTLF_AES256CFB_destroy(ZTLF_AES256CFB *c)
{
	EVP_CIPHER_CTX_cleanup(c);
}

#endif

#endif
