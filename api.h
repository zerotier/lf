/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#ifndef ZTLF_API_H
#define ZTLF_API_H

#include "common.h"

bool ZTLF_API_GET(struct ZTLF_Node_PeerConnection *const c,const bool auth,const bool head,const char *path);
bool ZTLF_API_POST(struct ZTLF_Node_PeerConnection *const c,const bool auth,const char *path,const void *const body,const unsigned int bodySize);

#endif
