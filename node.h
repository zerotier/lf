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
#include "connection.h"
#include "vector.h"

struct ZTLF_Node
{
	uint8_t publicKey[ZTLF_ED25519_PUBLIC_KEY_SIZE];
	uint8_t privateKey[ZTLF_ED25519_PRIVATE_KEY_SIZE];

	unsigned int listenPort;
	int listenSocket;

	struct ZTLF_Vector connections;
	pthread_rwlock_t connectionsLock;

	struct ZTLF_ConnectionParameters connectionParameters;

	volatile bool run;
};


int ZTLF_Node_Start(struct ZTLF_Node *const n,const char *path,const unsigned int port);
void ZTLF_Node_Stop(struct ZTLF_Node *n);

#endif
