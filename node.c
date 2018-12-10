/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#include "node.h"
#include "protocol.h"
#include "curve25519.h"
#include "version.h"

#define ZTLF_C25519_PUBLIC_FILE "key-p2p-curve25519.public"
#define ZTLF_C25519_SECRET_FILE "key-p2p-curve25519.secret"

static void _ZTLF_Node_onConnectionEstablished(struct ZTLF_Connection *c)
{
}

static void _ZTLF_Node_onConnectionClosed(struct ZTLF_Connection *c)
{
}

static void _ZTLF_Node_onPeerInfo(struct ZTLF_Connection *c,const int addressType,const uint8_t *ip,const unsigned int port,const uint8_t keyHash[48])
{
}

static void _ZTLF_Node_onRecord(struct ZTLF_Connection *c,const struct ZTLF_Record *r,const unsigned int rsize)
{
}

static void _ZTLF_Node_onRecordRequestByHash(struct ZTLF_Connection *c,const uint8_t hash[32])
{
}

static void _ZTLF_Node_onRecordQuery(struct ZTLF_Connection *c,uint32_t requestId,unsigned int maxResults,const uint8_t id[32],const uint8_t owner[32],const uint8_t sel0[32],const uint8_t sel1[32])
{
}

int ZTLF_Node_Start(struct ZTLF_Node *const n,const char *path,const unsigned int port)
{
	const int listenSocket = socket(AF_INET6,SOCK_STREAM,0);
	if (listenSocket < 0)
		return errno;
	int fl = 0;
	setsockopt(listenSocket,IPPROTO_IPV6,IPV6_V6ONLY,&fl,sizeof(fl));
	fl = 1;
	setsockopt(listenSocket,SOL_SOCKET,SO_REUSEADDR,&fl,sizeof(fl));
	fl = 1;
	setsockopt(listenSocket,SOL_SOCKET,SO_REUSEPORT,&fl,sizeof(fl));
	struct sockaddr_in6 sin6;
	memset(&sin6,0,sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_port = htons((uint16_t)port);
	if (bind(listenSocket,(const struct sockaddr *)&sin6,sizeof(sin6))) {
		close(listenSocket);
		return errno;
	}
	if (listen(listenSocket,64)) {
		close(listenSocket);
		return errno;
	}
	fcntl(listenSocket,F_SETFL,fcntl(listenSocket,F_GETFL)|O_NONBLOCK);

	n->listenPort = port;
	n->listenSocket = listenSocket;

	ZTLF_Vector_Init(&n->connections,128);
	pthread_rwlock_init(&n->connectionsLock,NULL);

	n->connectionParameters.onConnectionEstablished = _ZTLF_Node_onConnectionEstablished;
	n->connectionParameters.onConnectionClosed = _ZTLF_Node_onConnectionClosed;
	n->connectionParameters.onPeerInfo = _ZTLF_Node_onPeerInfo;
	n->connectionParameters.onRecord = _ZTLF_Node_onRecord;
	n->connectionParameters.onRecordRequestByHash = _ZTLF_Node_onRecordRequestByHash;
	n->connectionParameters.onRecordQueryResult = NULL;
	n->connectionParameters.onRecordQuery = _ZTLF_Node_onRecordQuery;

	char tmp[PATH_MAX];
	snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR ZTLF_C25519_PUBLIC_FILE,path);
	bool keyOk = (ZTLF_readFile(tmp,n->connectionParameters.publicKey,ZTLF_CURVE25519_PUBLIC_KEY_SIZE) == ZTLF_CURVE25519_PUBLIC_KEY_SIZE);
	if (keyOk) {
		snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR ZTLF_C25519_SECRET_FILE,path);
		keyOk = (ZTLF_readFile(tmp,n->connectionParameters.privateKey,ZTLF_CURVE25519_PRIVATE_KEY_SIZE) == ZTLF_CURVE25519_PRIVATE_KEY_SIZE);
	}
	if (!keyOk) {
		ZTLF_Curve25519_generate(n->connectionParameters.publicKey,n->connectionParameters.privateKey);
		snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR ZTLF_C25519_PUBLIC_FILE,path);
		if (ZTLF_writeFile(tmp,n->connectionParameters.publicKey,ZTLF_CURVE25519_PUBLIC_KEY_SIZE,0644)) {
			ZTLF_L_warning("unable to write " ZTLF_C25519_PUBLIC_FILE " to %s",path);
			return EIO;
		}
		snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR ZTLF_C25519_SECRET_FILE,path);
		if (ZTLF_writeFile(tmp,n->connectionParameters.privateKey,ZTLF_CURVE25519_PRIVATE_KEY_SIZE,0600)) {
			ZTLF_L_warning("unable to write " ZTLF_C25519_SECRET_FILE " to %s",path);
			return EIO;
		}
	}

	n->connectionParameters.ptr = n;
	n->connectionParameters.helloFlags = ZTLF_PROTO_MESSAGE_HELLO_FLAGS_P2P_NODE;

	n->run = true;

	struct sockaddr_storage from;
	fd_set rfds,wfds,efds;
	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&efds);
	uint64_t lastCheckedConnections = ZTLF_timeSec();
	while (n->run) {
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_SET(listenSocket,&rfds);
		FD_SET(listenSocket,&efds);
		select(listenSocket+1,&rfds,&wfds,&efds,&tv);

		if (FD_ISSET(listenSocket,&rfds)||FD_ISSET(listenSocket,&efds)) {
			memset(&from,0,sizeof(from));
			socklen_t fromlen = 0;
			const int ns = accept(listenSocket,(struct sockaddr *)&from,&fromlen);
			if (ns >= 0) {
				struct ZTLF_Connection *const c = ZTLF_Connection_New(&n->connectionParameters,&from,ns,true,NULL);
				if (c) {
					pthread_rwlock_wrlock(&n->connectionsLock);
					ZTLF_Vector_Append(&n->connections,c);
					pthread_rwlock_unlock(&n->connectionsLock);
				}
			}
		}

		const uint64_t nowSec = ZTLF_timeSec();
		if ((nowSec - lastCheckedConnections) >= 5) {
			lastCheckedConnections = nowSec;
		}
	}

	pthread_rwlock_wrlock(&n->connectionsLock);
	for(unsigned long i=0;i<n->connections.size;++i)
		ZTLF_Connection_Close((struct ZTLF_Connection *)n->connections.v[i]);
	pthread_rwlock_unlock(&n->connectionsLock);

	pthread_rwlock_destroy(&n->connectionsLock);

	return 0;
}

void ZTLF_Node_Stop(struct ZTLF_Node *n)
{
	n->run = false;
	if (n->listenSocket >= 0)
		close(n->listenSocket);
}
