/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#ifndef ZTLF_NODE_H
#define ZTLF_NODE_H

#include "common.h"

int ZTLF_Node_Start(struct ZTLF_Node *const n,const char *path,const unsigned int port);
void ZTLF_Node_Stop(struct ZTLF_Node *n);

#endif
