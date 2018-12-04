/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#ifndef ZTLF_NODE_H
#define ZTLF_NODE_H

#include "common.h"
#include "db.h"
#include "record.h"
#include "aes.h"
#include "map.h"
#include "ed25519.h"

#define ZTLF_TCP_TIMEOUT_MS 30000

struct ZTLF_Node_PeerConnection
{
	struct ZTLF_Node *parent;
	struct sockaddr_storage remoteAddress;

	int sock;
	int sockSendBufSize;
	ZTLF_AES256CFB *encryptor;
	uint8_t sharedSecret[32];
	pthread_mutex_t sendLock;

	uint8_t remoteKeyHash[48];
	bool incoming;

	volatile uint64_t lastReceiveTime;
	volatile long latency;
	volatile bool connectionEstablished;
	volatile bool http;
};

struct ZTLF_Node
{
	struct ZTLF_DB db;

	uint8_t networkKey[48]; /* SHA384(plain text network key), only first 32 bytes are actually used as AES key */
	uint8_t publicKey[ZTLF_ED25519_PUBLIC_KEY_SIZE];
	uint8_t privateKey[ZTLF_ED25519_PRIVATE_KEY_SIZE];

	unsigned int listenPort;
	int listenSocket;

	struct ZTLF_Node_PeerConnection *conn;
	unsigned long connCount;
	unsigned long connCapacity;
	unsigned long connDesiredCount;
	pthread_mutex_t connLock;

	volatile bool run;
};

#endif
