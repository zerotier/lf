/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#ifndef ZTLF_CURVE25519_H
#define ZTLF_CURVE25519_H

#include "common.h"

#define ZTLF_CURVE25519_PUBLIC_KEY_SIZE 32
#define ZTLF_CURVE25519_PRIVATE_KEY_SIZE 32

void ZTLF_Curve25519_generate(uint8_t pub[32],uint8_t priv[64]);
void ZTLF_Curve25519_agree(uint8_t secret[32],const uint8_t theirPublic[32],const uint8_t myPrivate[32]);

#endif
