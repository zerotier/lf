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

#define ZTLF_RECV_BUF_SIZE 131072
#define ZTLF_SEND_BUF_SIZE 524288

/* Compute fletcher16, encrypt, and send to destination peer if possible. */
static bool _ZTLF_Node_sendTo(struct ZTLF_Node_PeerConnection *const c,void *const msgp,const unsigned int len)
{
	struct ZTLF_Message *const msg = (struct ZTLF_Message *)msgp;
	bool result = false;

	const uint16_t f16 = ZTLF_fletcher16(((const uint8_t *)msg) + sizeof(struct ZTLF_Message),len - sizeof(struct ZTLF_Message));
	ZTLF_setu16(msg->fletcher16,f16);

	pthread_mutex_lock(&(c->sendLock));
	if (likely(c->sock >= 0)) {
		if (likely(c->sockSendBufSize > 0)) {
			if (unlikely(len > (unsigned int)c->sockSendBufSize))
				return false;
#ifdef SO_NWRITE
			int bufsize = 0;
			socklen_t bufsizesize = sizeof(bufsize);
			if (unlikely(getsockopt(c->sock,SOL_SOCKET,SO_NWRITE,&bufsize,&bufsizesize) != 0)) {
				ZTLF_L_warning("getsockopt(SO_NWRITE) failed: %s",strerror(errno));
				return false;
			}
			if (bufsize >= (c->sockSendBufSize - (int)len)) {
				ZTLF_L_trace("send failed: buffer contains %d bytes, message is %u bytes",bufsize,len);
				return false;
			}
#else
			TODO;
#endif
		}
		if (c->encryptor != NULL) {
			ZTLF_AES256CFB_crypt(c->encryptor,msg,msg,len);
		}
		result = (send(c->sock,msg,len,MSG_DONTWAIT) == (ssize_t)len);
		if (!result) {
			close(c->sock);
			c->sock = -1;
		}
	}
	pthread_mutex_unlock(&(c->sendLock));

	return result;
}

/* Send goodbye if provided and close. */
static void _ZTLF_Node_closeConnection(struct ZTLF_Node_PeerConnection *const c,unsigned int reason)
{
	pthread_mutex_lock(&(c->sendLock));
	if (c->sock >= 0) {
		if (reason != ZTLF_PROTO_GOODBYE_REASON_NONE) {
			struct ZTLF_Message_Goodbye bye;
			ZTLF_Message_setHdr(&bye,ZTLF_PROTO_MESSAGE_TYPE_GOODBYE,sizeof(struct ZTLF_Message_Goodbye));
			bye.reason = (uint8_t)reason;
			if (c->encryptor != NULL)
				ZTLF_AES256CFB_crypt(c->encryptor,&bye,&bye,sizeof(bye));
			send(c->sock,&bye,sizeof(bye),MSG_DONTWAIT);
		}
		close(c->sock);
		c->sock = -1;
	}
	pthread_mutex_unlock(&(c->sendLock));
}

/* Create a HELLO message to send to a peer. */
static void _ZTLF_Node_mkHello(struct ZTLF_Node_PeerConnection *const c,struct ZTLF_Message_Hello *const h,const uint8_t *const publicKey,const uint64_t flags)
{
	ZTLF_Message_setHdr(h,ZTLF_PROTO_MESSAGE_TYPE_HELLO,sizeof(struct ZTLF_Message_Hello));

	ZTLF_secureRandom(h->iv,sizeof(h->iv));
	h->protoVersion = ZTLF_PROTO_VERSION;
	h->protoFlags = 0;
	ZTLF_setu64(h->currentTime,ZTLF_timeMs());
	ZTLF_setu64(h->flags,flags);
	h->cipher = ZTLF_PROTO_CIPHER_C25519_AES256_CFB;
	memcpy(h->publicKey,publicKey,sizeof(h->publicKey));

	/* Hello is initially sent in the clear, so everything after the IV is encrypted with
	 * the network key. */
	uint8_t encIv[48];
	ZTLF_SHA384(encIv,h->iv,sizeof(h->iv));
	ZTLF_AES256CFB enc;
	ZTLF_AES256CFB_init(&enc,c->parent->networkKey,encIv,true);
	uint8_t *const encStart = ((uint8_t *)h) + sizeof(h->hdr) + sizeof(h->fletcher16) + sizeof(h->iv);
	ZTLF_AES256CFB_crypt(&enc,encStart,encStart,sizeof(struct ZTLF_Message_Hello) - (sizeof(h->hdr) + sizeof(h->fletcher16) + sizeof(h->iv)));
	ZTLF_AES256CFB_destroy(&enc);
}

/* Announce all currently successfully connected outbound (and thus verified) peers to a given peer. */
static void _ZTLF_Node_announcePeersTo(struct ZTLF_Node_PeerConnection *const c)
{
	uint64_t tmp[32];
	struct ZTLF_Message_PeerInfo *pi = (struct ZTLF_Message_PeerInfo *)tmp;
	pthread_mutex_lock(&(c->parent->connLock));
	for(unsigned long i=0;i<c->parent->connCount;++i) {
		if ((&(c->parent->conn[i]) != c)&&(c->parent->conn[i].connectionEstablished)&&(!c->parent->conn[i].incoming)) {
			struct ZTLF_Node_PeerConnection *c2 = (struct ZTLF_Node_PeerConnection *)&(c->parent->conn[i]);
			memcpy(pi->keyHash,c2->remoteKeyHash,48);
			unsigned int pilen = 0;
			switch(c2->remoteAddress.ss_family) {
				case AF_INET:
					pilen = sizeof(struct ZTLF_Message_PeerInfo) + 6;
					pi->addressType = 4;
					memcpy(pi->address,&(((const struct sockaddr_in *)&(c2->remoteAddress))->sin_addr),4);
					memcpy(pi->address + 4,&(((const struct sockaddr_in6 *)&(c2->remoteAddress))->sin6_port),2);
					break;
				case AF_INET6:
					pilen = sizeof(struct ZTLF_Message_PeerInfo) + 18;
					pi->addressType = 6;
					memcpy(pi->address,(((const struct sockaddr_in6 *)&(c2->remoteAddress))->sin6_addr.s6_addr),16);
					memcpy(pi->address + 16,&(((const struct sockaddr_in6 *)&(c2->remoteAddress))->sin6_port),2);
					break;
			}
			if (pilen > 0) {
				ZTLF_Message_setHdr(pi,ZTLF_PROTO_MESSAGE_TYPE_PEER_INFO,pilen);
				_ZTLF_Node_sendTo(c,pi,pilen);
			}
		}
	}
	pthread_mutex_unlock(&(c->parent->connLock));
}

/* Per-connection thread main */
static void *_ZTLF_Node_connectionHandler(void *tptr)
{
	struct ZTLF_Node_PeerConnection *const c = (struct ZTLF_Node_PeerConnection *)tptr;
	uint8_t *mbuf;
	ZTLF_MALLOC_CHECK(mbuf = (uint8_t *)malloc(ZTLF_RECV_BUF_SIZE));

	{
		int fl = 1;
		setsockopt(c->sock,SOL_SOCKET,SO_KEEPALIVE,&fl,sizeof(fl));
#ifdef TCP_NODELAY
		fl = 0;
		setsockopt(c->sock,IPPROTO_TCP,TCP_NODELAY,&fl,sizeof(fl));
#endif
#ifdef TCP_KEEPALIVE /* name of KEEPIDLE on Mac, probably others */
		fl = 10;
		setsockopt(c->sock,IPPROTO_TCP,TCP_KEEPALIVE,&fl,sizeof(fl));
#endif
#ifdef TCP_KEEPIDLE
		fl = 10;
		setsockopt(c->sock,IPPROTO_TCP,TCP_KEEPIDLE,&fl,sizeof(fl));
#endif
#ifdef TCP_KEEPCNT
		fl = 3;
		setsockopt(c->sock,IPPROTO_TCP,TCP_KEEPCNT,&fl,sizeof(fl));
#endif
#ifdef TCP_KEEPINTVL
		fl = 10;
		setsockopt(c->sock,IPPROTO_TCP,TCP_KEEPINTVL,&fl,sizeof(fl));
#endif

		for(fl=ZTLF_SEND_BUF_SIZE;fl>=(ZTLF_SEND_BUF_SIZE / 8);fl-=(ZTLF_SEND_BUF_SIZE / 8)) {
			if (setsockopt(c->sock,SOL_SOCKET,SO_SNDBUF,&fl,sizeof(fl)) == 0) {
				c->sockSendBufSize = (int)fl;
				break;
			}
		}
		if (!c->sockSendBufSize) {
			ZTLF_L_warning("unable to set any send buffer size on TCP connection!");
		}

		fcntl(c->sock,F_SETFL,fcntl(c->sock,F_GETFL)&(~O_NONBLOCK));
	}

	uint8_t sharedSecret[32];
	ZTLF_AES256CFB encryptor;
	ZTLF_AES256CFB decryptor;
	bool encryptionInitialized = false;
	bool connectionEstablished = false;
	bool firstFourBytes = true;
	bool sockHandedOff = false;
	unsigned int termReason = ZTLF_PROTO_GOODBYE_REASON_TCP_ERROR;

	struct ZTLF_Message_Hello lastHelloSent;
	_ZTLF_Node_mkHello(c,&lastHelloSent,c->parent->publicKey,0ULL);
	_ZTLF_Node_sendTo(c,&lastHelloSent,sizeof(lastHelloSent));

	unsigned int rptr = 0;
	for(;;) {
		const int nr = (int)recv(c->sock,mbuf + rptr,ZTLF_RECV_BUF_SIZE - rptr,0);
		if (nr < 0) {
			if ((errno == EINTR)||(errno == EAGAIN))
				continue;
			goto terminate_connection;
		}

		if (encryptionInitialized) {
			ZTLF_AES256CFB_crypt(&decryptor,mbuf + rptr,mbuf + rptr,(unsigned long)nr);
		}
		rptr += (unsigned int)nr;

		while (rptr >= sizeof(struct ZTLF_Message)) {
			/* Detect HTTP connections and hand these off to the HTTP API code. The 
			 * P2P protocol is designed so initial HELLO will never look like this. */
			if (firstFourBytes) {
				bool http = false;
				switch (mbuf[0]) {
					case 'G': if ((mbuf[1] == 'E')&&(mbuf[2] == 'T')&&(mbuf[3] == ' ')) http = true; break;
					case 'H': if ((mbuf[1] == 'E')&&(mbuf[2] == 'E')&&(mbuf[3] == 'D')) http = true; break;
					case 'P': if ( ((mbuf[1] == 'O')&&(mbuf[2] == 'S')&&(mbuf[3] == 'T')) || ((mbuf[1] == 'U')&&(mbuf[2] == 'T')&&(mbuf[3] == ' ')) ) http = true; break;
					case 'D': if ((mbuf[1] == 'E')&&(mbuf[2] == 'L')&&(mbuf[3] == 'E')) http = true; break;
				}
				if (http) {
					sockHandedOff = true;
					goto terminate_connection;
				}
				firstFourBytes = false;
			}

			unsigned int msize = (((unsigned int)mbuf[0]) << 8) | (unsigned int)mbuf[1];
			const unsigned int mtype = (msize >> 12) & 0xf;
			msize &= 0xfff;
			msize += sizeof(struct ZTLF_Message) + 1; /* message size doesn't include header size, and range is 1-4096 not 0-4095 */

			if (rptr >= msize) { /* a complete message was received */
				const uint16_t f16 = ZTLF_getu16(((struct ZTLF_Message *)mbuf)->fletcher16);
				if (f16 != ZTLF_fletcher16(mbuf + sizeof(struct ZTLF_Message),msize - sizeof(struct ZTLF_Message))) {
					termReason = ZTLF_PROTO_GOODBYE_REASON_NONE;
					goto terminate_connection;
				}

				if ((!encryptionInitialized)&&(mtype != ZTLF_PROTO_MESSAGE_TYPE_HELLO)) {
					termReason = (mtype == ZTLF_PROTO_MESSAGE_TYPE_GOODBYE) ? ZTLF_PROTO_GOODBYE_REASON_NONE : ZTLF_PROTO_GOODBYE_REASON_INVALID_MESSAGE;
					goto terminate_connection;
				} else if ((!connectionEstablished)&&(mtype != ZTLF_PROTO_MESSAGE_TYPE_OK)) {
					termReason = (mtype == ZTLF_PROTO_MESSAGE_TYPE_GOODBYE) ? ZTLF_PROTO_GOODBYE_REASON_NONE : ZTLF_PROTO_GOODBYE_REASON_INVALID_MESSAGE;
					goto terminate_connection;
				}

				const uint64_t now = ZTLF_timeMs();
				c->lastReceiveTime = now;

				switch(mtype) {

					case ZTLF_PROTO_MESSAGE_TYPE_NOP:
						break;

					case ZTLF_PROTO_MESSAGE_TYPE_HELLO:
						if (likely(msize >= sizeof(struct ZTLF_Message_Hello))) {
							struct ZTLF_Message_Hello *h = (struct ZTLF_Message_Hello *)mbuf;

							ZTLF_SHA384_CTX ackHash;
							ZTLF_SHA384_init(&ackHash);
							ZTLF_SHA384_update(&ackHash,mbuf,msize);

							uint8_t decIv[48];
							ZTLF_SHA384(decIv,h->iv,sizeof(h->iv));
							ZTLF_AES256CFB dec;
							ZTLF_AES256CFB_init(&dec,c->parent->networkKey,decIv,false);
							uint8_t *const decStart = ((uint8_t *)h) + sizeof(h->hdr) + sizeof(h->fletcher16) + sizeof(h->iv);
							ZTLF_AES256CFB_crypt(&dec,decStart,decStart,sizeof(struct ZTLF_Message_Hello) - (sizeof(h->hdr) + sizeof(h->fletcher16) + sizeof(h->iv)));
							ZTLF_AES256CFB_destroy(&dec);

							if ((h->protoVersion != ZTLF_PROTO_VERSION)||(h->cipher != ZTLF_PROTO_CIPHER_C25519_AES256_CFB)) {
								termReason = ZTLF_PROTO_GOODBYE_REASON_UNSUPPORTED_PROTOCOL;
								goto terminate_connection;
							}

							/* Check against expectation (outgoing) or learn (incoming) remote key hash. */
							uint8_t remoteKeyHash[48];
							ZTLF_SHA384(remoteKeyHash,h->publicKey,32);
							if (c->incoming) {
								memcpy(c->remoteKeyHash,remoteKeyHash,sizeof(c->remoteKeyHash));
							} else if (memcmp(remoteKeyHash,c->remoteKeyHash,sizeof(remoteKeyHash)) != 0) {
								termReason = ZTLF_PROTO_GOODBYE_REASON_NONE;
								goto terminate_connection;
							}

							/* Perform key agreement with remote. */
							ZTLF_Curve25519_agree(sharedSecret,h->publicKey,c->parent->privateKey);

							ZTLF_SHA384_update(&ackHash,sharedSecret,sizeof(sharedSecret));

							pthread_mutex_lock(&(c->parent->connLock));

							/* Close any other connections that are to/from the same peer. */
							for(unsigned long i=0;i<c->parent->connCount;++i) {
								if ((c != &(c->parent->conn[i]))&&(memcmp(c->parent->conn[i].sharedSecret,sharedSecret,sizeof(sharedSecret)) == 0)) {
									_ZTLF_Node_closeConnection(&(c->parent->conn[i]),ZTLF_PROTO_GOODBYE_REASON_DUPLICATE_LINK);
								}
							}

							/* Initialize or re-initialize cipher. */
							pthread_mutex_lock(&(c->sendLock));
							if (encryptionInitialized) {
								ZTLF_AES256CFB_destroy(&encryptor);
								ZTLF_AES256CFB_destroy(&decryptor);
							}
							ZTLF_AES256CFB_init(&encryptor,sharedSecret,lastHelloSent.iv,true);
							ZTLF_AES256CFB_init(&decryptor,sharedSecret,h->iv,false);
							c->encryptor = &encryptor;
							memcpy(c->sharedSecret,sharedSecret,sizeof(c->sharedSecret));
							pthread_mutex_unlock(&(c->sendLock));
							encryptionInitialized = true;

							pthread_mutex_unlock(&(c->parent->connLock));

							/* Send encrypted OK to peer with acknowledgement of HELLO. */
							struct ZTLF_Message_OK ok;
							memset(&ok,0,sizeof(ok));
							ZTLF_Message_setHdr(&ok,ZTLF_PROTO_MESSAGE_TYPE_OK,sizeof(struct ZTLF_Message_OK));
							ZTLF_SHA384_final(&ackHash,ok.ack);
							ZTLF_UNALIGNED_ASSIGN_8(ok.helloTime,h->currentTime);
							ZTLF_setu64(ok.currentTime,now);
							ok.version[0] = ZTLF_VERSION_MAJOR;
							ok.version[1] = ZTLF_VERSION_MINOR;
							ok.version[2] = ZTLF_VERSION_REVISION;
							ok.version[3] = ZTLF_VERSION_REVISION;
							_ZTLF_Node_sendTo(c,&ok,sizeof(ok));
						}
						break;

					case ZTLF_PROTO_MESSAGE_TYPE_OK:
						if (likely(msize >= sizeof(struct ZTLF_Message_OK))) {
							struct ZTLF_Message_OK *ok = (struct ZTLF_Message_OK *)mbuf;

							/* Check that our HELLO was properly acknowledged and the other side has the same shared secret. */
							uint8_t expectedAck[48];
							ZTLF_SHA384_CTX ackHash;
							ZTLF_SHA384_init(&ackHash);
							ZTLF_SHA384_update(&ackHash,&lastHelloSent,sizeof(lastHelloSent));
							ZTLF_SHA384_update(&ackHash,sharedSecret,sizeof(sharedSecret));
							ZTLF_SHA384_final(&ackHash,expectedAck);
							if (memcmp(expectedAck,ok->ack,sizeof(ok->ack)) != 0) {
								termReason = ZTLF_PROTO_GOODBYE_REASON_NONE;
								goto terminate_connection;
							}

							if ((!c->incoming)&&(!connectionEstablished)) {
								uint64_t tmp[32];
								struct ZTLF_Message_PeerInfo *pi = (struct ZTLF_Message_PeerInfo *)tmp;
								unsigned int pilen = 0;
								switch(c->remoteAddress.ss_family) {
									case AF_INET:
										if (ZTLF_DB_logOutgoingPeerConnectSuccess(&(c->parent->db),c->remoteKeyHash,4,&(((const struct sockaddr_in *)&(c->remoteAddress))->sin_addr),4,ntohs(((const struct sockaddr_in *)&(c->remoteAddress))->sin_port))) {
											pilen = sizeof(struct ZTLF_Message_PeerInfo) + 6;
											pi->addressType = 4;
											memcpy(pi->address,&(((const struct sockaddr_in *)&(c->remoteAddress))->sin_addr),4);
											memcpy(pi->address + 4,&(((const struct sockaddr_in6 *)&(c->remoteAddress))->sin6_port),2);
										}
										break;
									case AF_INET6:
										if (ZTLF_DB_logOutgoingPeerConnectSuccess(&(c->parent->db),c->remoteKeyHash,6,(((const struct sockaddr_in6 *)&(c->remoteAddress))->sin6_addr.s6_addr),16,ntohs(((const struct sockaddr_in6 *)&(c->remoteAddress))->sin6_port))) {
											pilen = sizeof(struct ZTLF_Message_PeerInfo) + 18;
											pi->addressType = 6;
											memcpy(pi->address,(((const struct sockaddr_in6 *)&(c->remoteAddress))->sin6_addr.s6_addr),16);
											memcpy(pi->address + 16,&(((const struct sockaddr_in6 *)&(c->remoteAddress))->sin6_port),2);
										}
										break;
								}
								if (pilen > 0) {
									ZTLF_Message_setHdr(pi,ZTLF_PROTO_MESSAGE_TYPE_PEER_INFO,pilen);
									memcpy(pi->keyHash,c->remoteKeyHash,48);
									pthread_mutex_lock(&(c->parent->connLock));
									for(unsigned long i=0;i<c->parent->connCount;++i) {
										if ((&(c->parent->conn[i]) != c)&&(c->parent->conn[i].connectionEstablished))
											_ZTLF_Node_sendTo(&(c->parent->conn[i]),pi,pilen);
									}
									pthread_mutex_unlock(&(c->parent->connLock));
								}
							}

							_ZTLF_Node_announcePeersTo(c);

							const uint64_t ht = ZTLF_getu64(ok->helloTime);
							c->latency = (now > ht) ? (long)(now - ht) : (long)0;
							c->connectionEstablished = true;
							connectionEstablished = true;
						}
						break;

					case ZTLF_PROTO_MESSAGE_TYPE_GOODBYE:
						if (likely(msize >= sizeof(struct ZTLF_Message_Goodbye))) {
							termReason = ZTLF_PROTO_GOODBYE_REASON_NONE;
							goto terminate_connection;
						}
						break;

					case ZTLF_PROTO_MESSAGE_TYPE_PEER_INFO:
						if (likely(msize >= sizeof(struct ZTLF_Message_PeerInfo))) {
							struct ZTLF_Message_PeerInfo *pi = (struct ZTLF_Message_PeerInfo *)mbuf;
							switch(pi->addressType) {
								case 4:
									if (msize >= (sizeof(struct ZTLF_Message_PeerInfo) + 6)) {
										const unsigned int port = (((unsigned int)pi->address[4]) << 8) | (unsigned int)pi->address[5];
										ZTLF_DB_logPotentialPeer(&(c->parent->db),pi->keyHash,4,pi->address,4,port);
									}
									break;
								case 6:
									if (msize >= (sizeof(struct ZTLF_Message_PeerInfo) + 18)) {
										const unsigned int port = (((unsigned int)pi->address[16]) << 8) | (unsigned int)pi->address[17];
										ZTLF_DB_logPotentialPeer(&(c->parent->db),pi->keyHash,6,pi->address,16,port);
									}
									break;
							}
						}
						break;

					case ZTLF_PROTO_MESSAGE_TYPE_RECORD:
						if (likely(msize >= ZTLF_RECORD_MIN_SIZE)) {
							struct ZTLF_Message_Record *rm = (struct ZTLF_Message_Record *)mbuf;
						}
						break;

					case ZTLF_PROTO_MESSAGE_TYPE_RECORD_REQUEST_BY_ID:
						if (likely(msize >= sizeof(struct ZTLF_Message_RecordRequestByID))) {
							struct ZTLF_Message_RecordRequestByID *req = (struct ZTLF_Message_RecordRequestByID *)mbuf;
						}
						break;

					case ZTLF_PROTO_MESSAGE_TYPE_RECORD_REQUEST_BY_HASH:
						if (likely(msize >= sizeof(struct ZTLF_Message_RecordRequestByHash))) {
							struct ZTLF_Message_RecordRequestByHash *req = (struct ZTLF_Message_RecordRequestByHash *)mbuf;
						}
						break;

					default:
						break;
				}

				if (rptr > msize)
					memmove(mbuf,mbuf + msize,rptr - msize);
				rptr -= msize;
			} else {
				break;
			}
		}
	}

terminate_connection:
	c->connectionEstablished = false;

	pthread_mutex_lock(&(c->parent->connLock));
	for(unsigned long i=0,j=0;i<c->parent->connCount;++i) {
		if (&(c->parent->conn[i]) != c) {
			if (i != j)
				memcpy(&(c->parent->conn[j]),&(c->parent->conn[i]),sizeof(struct ZTLF_Node_PeerConnection));
			++j;
		}
	}
	--c->parent->connCount;
	pthread_mutex_unlock(&(c->parent->connLock));

	if (!sockHandedOff) {
		pthread_mutex_lock(&(c->sendLock));
		_ZTLF_Node_closeConnection(c,termReason);
		pthread_mutex_unlock(&(c->sendLock));
		free(mbuf);
	}

	if (encryptionInitialized) {
		ZTLF_AES256CFB_destroy(&decryptor);
		ZTLF_AES256CFB_destroy(&encryptor);
	}

	pthread_mutex_destroy(&(c->sendLock));

	return NULL;
}

static void _ZTLF_Node_newConnection(struct ZTLF_Node *const n,const struct sockaddr_storage *addr,const int sock,const bool incoming,const void *expectedRemoteKeyHash)
{
	pthread_mutex_lock(&(n->connLock));

	if (n->connCount >= n->connCapacity) {
		ZTLF_MALLOC_CHECK(n->conn = (struct ZTLF_Node_PeerConnection *)realloc(n->conn,sizeof(struct ZTLF_Node_PeerConnection) * (n->connCapacity << 1)));
	}
	struct ZTLF_Node_PeerConnection *const c = &(n->conn[n->connCount++]);

	c->parent = n;
	memcpy(&(c->remoteAddress),addr,sizeof(struct sockaddr_storage));
	c->sock = sock;
	c->sockSendBufSize = 0;
	c->encryptor = NULL;
	pthread_mutex_init(&(c->sendLock),NULL);
	if (expectedRemoteKeyHash)
		memcpy(c->remoteKeyHash,expectedRemoteKeyHash,sizeof(c->remoteKeyHash));
	c->incoming = incoming;
	c->latency = -1;
	c->connectionEstablished = false;

	pthread_mutex_unlock(&(n->connLock));

	pthread_t t;
	if (pthread_create(&t,NULL,_ZTLF_Node_connectionHandler,(void *)c) != 0) {
		fprintf(stderr,"FATAL: pthread_create failed: %d\n",errno);
		abort();
	}
	pthread_detach(t);
}

int ZTLF_Node_start(struct ZTLF_Node *const n,const char *path,const unsigned int port)
{
	const int sock = socket(AF_INET6,SOCK_STREAM,0);
	if (sock < 0)
		return errno;
	int fl = 0;
	setsockopt(sock,IPPROTO_IPV6,IPV6_V6ONLY,&fl,sizeof(fl));
	fl = 1;
	setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&fl,sizeof(fl));
	fl = 1;
	setsockopt(sock,SOL_SOCKET,SO_REUSEPORT,&fl,sizeof(fl));
	struct sockaddr_in6 sin6;
	memset(&sin6,0,sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_port = htons((uint16_t)port);
	if (bind(sock,(const struct sockaddr *)&sin6,sizeof(sin6))) {
		close(sock);
		return errno;
	}
	if (listen(sock,64)) {
		close(sock);
		return errno;
	}
	fcntl(sock,F_SETFL,fcntl(sock,F_GETFL)|O_NONBLOCK);

	const int err = ZTLF_DB_open(&n->db,path);
	if (err != 0) {
		close(sock);
		return err;
	}

	memset(n->networkKey,0,sizeof(n->networkKey));

	n->listenPort = port;
	n->listenSocket = sock;
	ZTLF_MALLOC_CHECK(n->conn = (struct ZTLF_Node_PeerConnection *)malloc(sizeof(struct ZTLF_Node_PeerConnection) * 128));
	n->connCount = 0;
	n->connCapacity = 128;
	n->connDesiredCount = 64;
	pthread_mutex_init(&(n->connLock),NULL);
	n->run = true;

	struct sockaddr_storage from;
	fd_set rfds,wfds,efds;
	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&efds);
	while (n->run) {
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_SET(sock,&rfds);
		FD_SET(sock,&efds);
		select(sock+1,&rfds,&wfds,&efds,&tv);

		if (FD_ISSET(sock,&rfds)||FD_ISSET(sock,&efds)) {
			memset(&from,0,sizeof(from));
			socklen_t fromlen = 0;
			const int ns = accept(sock,(struct sockaddr *)&from,&fromlen);
			if (ns < 0) {
				if ((errno == EINTR)||(errno == EAGAIN))
					continue;
				break;
			}
			_ZTLF_Node_newConnection(n,&from,ns,true,NULL);
		}

		pthread_mutex_lock(&(n->connLock));
		if (n->connCount < n->connDesiredCount) {
		}
		pthread_mutex_unlock(&(n->connLock));
	}

	pthread_mutex_lock(&(n->connLock));
	for(unsigned long i=0;i<n->connCount;++i) {
		pthread_mutex_lock(&(n->conn[i].sendLock));
		_ZTLF_Node_closeConnection(&(n->conn[i]),ZTLF_PROTO_GOODBYE_REASON_SHUTDOWN);
		pthread_mutex_unlock(&(n->conn[i].sendLock));
	}
	pthread_mutex_unlock(&(n->connLock));

	for(;;) {
		pthread_mutex_lock(&(n->connLock));
		const unsigned long cc = n->connCount;
		pthread_mutex_unlock(&(n->connLock));
		if (!cc)
			break;
		usleep(50);
	}

	pthread_mutex_destroy(&(n->connLock));

	ZTLF_DB_close(&(n->db));

	return 0;
}

void ZTLF_Node_stop(struct ZTLF_Node *n)
{
	n->run = false;
	if (n->listenSocket >= 0)
		close(n->listenSocket);
}
