/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#ifndef ZTLF_NODE_H
#define ZTLF_NODE_H

#include "common.h"
#include "ed25519.h"

struct ZTLF_Node
{
	uint8_t publicKey[ZTLF_ED25519_PUBLIC_KEY_SIZE];
	uint8_t privateKey[ZTLF_ED25519_PRIVATE_KEY_SIZE];

	unsigned int listenPort;
	int listenSocket;

	struct ZTLF_Node_Connection *conn;
	unsigned long connCount;
	unsigned long connCapacity;
	unsigned long connDesiredCount;
	pthread_mutex_t connLock;

	volatile bool run;
};

#endif
