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

#ifndef ZTLF_NODE_H
#define ZTLF_NODE_H

#include "common.h"
#include "db.h"
#include "record.h"
#include "aes.h"
#include "map.h"

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
};

struct ZTLF_Node
{
	struct ZTLF_DB db;

	uint8_t networkKey[32];
	uint8_t publicKey[32];
	uint8_t privateKey[32];

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
