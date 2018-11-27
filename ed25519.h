/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#ifndef ZTLF_ED25519_H
#define ZTLF_ED25519_H

#define ZTLF_ED25519_PUBLIC_KEY_SIZE  32
#define ZTLF_ED25519_PRIVATE_KEY_SIZE 64
#define ZTLF_ED25519_SIGNATURE_SIZE   64

struct ZTLF_ed25519KeyPair
{
	unsigned char pub[ZTLF_ED25519_PUBLIC_KEY_SIZE];
	unsigned char priv[ZTLF_ED25519_PRIVATE_KEY_SIZE];
};

void ZTLF_Ed25519CreateKeypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed);
void ZTLF_Ed25519Sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key);
int ZTLF_Ed25519Verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key);

#endif
