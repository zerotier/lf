/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#ifndef ZTLF_BASE64URL_H
#define ZTLF_BASE64URL_H

#include "common.h"

unsigned int ZTLF_Base64URLDecode(void *out,unsigned int outlen,const char *in);
unsigned int ZTLF_Base64URLEncode(char *out,unsigned int outlen,const void *in,unsigned int len);

#endif
