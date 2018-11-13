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
#include "config.h"
#include "aes.h"
#include "thirdparty/sandbird/sandbird.h"

struct ZTLF_Node_PeerConnection
{
	uint8_t remotePublicKey[32];
	ZTLF_AES256CFB encryptor;
	ZTLF_AES256CFB decryptor;

	struct sockaddr_storage remoteAddress;

	uint64_t connectTime;
	uint64_t lastReceiveTime;
	uint64_t lastSendTime;

	pthread_t receiveThread;

	pthread_mutex_t sendLock;
	int sock;

	bool incoming;
};

struct ZTLF_Node
{
	struct ZTLF_DB db;
	struct ZTLF_Config config;

	int p2pListenSocket;
	sb_Server *httpServer;

	struct ZTLF_Node_PeerConnection *conn;
	unsigned long connCount;
	unsigned long connCapacity;
	pthread_mutex_t connLock;
};

#endif
