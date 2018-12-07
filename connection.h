/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#ifndef ZTLF_CONNECTION_H
#define ZTLF_CONNECTION_H

#include "common.h"
#include "aes.h"
#include "ed25519.h"
#include "curve25519.h"
#include "record.h"

#define ZTLF_TCP_TIMEOUT_MS 30000

#define ZTLF_RECV_BUF_SIZE 65536
#define ZTLF_SEND_BUF_SIZE 524288

struct ZTLF_Connection;

struct ZTLF_ConnectionParameters
{
	/* Parameters: connection */
	void (*onConnectionEstablished)(struct ZTLF_Connection *);

	/* Parameters: connection */
	void (*onConnectionClosed)(struct ZTLF_Connection *);

	/* Parameters: connection address type (4 or 6), IP (4 or 16 bytes), port, public key hash */
	void (*onPeerInfo)(struct ZTLF_Connection *,const int,const uint8_t *,const unsigned int,const uint8_t [48]);

	/* Parameters: record, record size in bytes */
	void (*onRecord)(struct ZTLF_Connection *,const struct ZTLF_Record *,const unsigned int);

	/* Parameters: connection, hash */
	void (*onRecordRequestByHash)(struct ZTLF_Connection *,const uint8_t [32]);

	/* Paramters: connection, request ID (from query), result number, total results, record, record size in bytes. */
	void (*onRecordQueryResult)(struct ZTLF_Connection *,uint32_t,unsigned int,unsigned int,const struct ZTLF_Record *,unsigned int);

	/* Parameters: connection, request ID, max results to return (in descending order of weight), ID, owner, sel0, sel1.
	 * The last four parameters are fields to match and any of these can be NULL to omit it. */
	void (*onRecordQuery)(struct ZTLF_Connection *,uint32_t,unsigned int,const uint8_t [32],const uint8_t [32],const uint8_t [32],const uint8_t [32]);

	uint8_t publicKey[ZTLF_ED25519_PUBLIC_KEY_SIZE];   /* local public key */
	uint8_t privateKey[ZTLF_ED25519_PRIVATE_KEY_SIZE]; /* local private key */
	void *ptr;                                         /* Arbitrary user-settable pointer */
	uint32_t helloFlags;                               /* flags to send to peer in our HELLO */
};

struct ZTLF_Connection
{
	uint8_t recvBuf[ZTLF_RECV_BUF_SIZE];           /* Buffer used for receiving messages. */
	const struct ZTLF_ConnectionParameters *param; /* Pointer to connection prameters */
	struct sockaddr_storage remoteAddress;         /* Remote IP address / port */
	int sock;                                      /* Underlying stream socket */
	int sockSendBufSize;                           /* Send buffer size or 0 if unknown */
	ZTLF_AES256CFB *encryptor;                     /* AES256-CFB encryptor for stream or NULL if not yet initialized */
	pthread_mutex_t sendLock;                      /* Lock for sending data to stream */
	uint8_t remoteKeyHash[48];                     /* Incoming: SHA384(public key), outgoing: expected SHA384(public key) */
	bool incoming;                                 /* True if this is an incoming connection */
	volatile uint64_t lastReceiveTime;             /* Time a valid message was last received (set to current time on connection create or connect) */
	volatile uint32_t helloFlags;                  /* Flags from remote HELLO message */
	volatile long latency;                         /* Apparently latency in ms (not extremely accurate since it's only measured on connect) */
	volatile bool established;                     /* True if connection is currently established */
	pthread_t thread;                              /* Connection read thread */
};

/**
 * Create a new connection that wraps a socket
 * 
 * @param param Connection parameters and pointers to handler functions (pointer must remain valid until connection closes)
 * @param remoteAddress Remote IP
 * @param sock Stream socket
 * @param incoming If true this is an inbound connection
 * @param expectedRemoteKeyHash If non-NULL this is the expected remote key hash (only used for outgoing connections)
 */
struct ZTLF_Connection *ZTLF_Connection_New(const struct ZTLF_ConnectionParameters *param,const struct sockaddr_storage *remoteAddress,const int sock,const bool incoming,const void *expectedRemoteKeyHash);

/**
 * Shut down this connection
 * 
 * This will generate an onConnectionClosed event.
 */
void ZTLF_Connection_Close(struct ZTLF_Connection *const c);

bool ZTLF_Connection_SendRecord(struct ZTLF_Connection *const c,const void *rdata,unsigned int rsize);

bool ZTLF_Connection_SendRecordRequestByHash(struct ZTLF_Connection *const c,const uint8_t hash[32]);

bool ZTLF_Connection_SendRecordQueryResult(struct ZTLF_Connection *const c,uint32_t requestId,unsigned int resultNo,unsigned int totalResults,const void *rdata,unsigned int rsize);

bool ZTLF_Connection_SendRecordQuery(struct ZTLF_Connection *const c,uint32_t requestId,unsigned int maxResults,const uint8_t id[32],const uint8_t owner[32],const uint8_t sel0[32],const uint8_t sel1[32]);

#endif
