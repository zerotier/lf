/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#include "connection.h"
#include "protocol.h"
#include "version.h"

static bool _ZTLF_Connection_send(struct ZTLF_Connection *const c,void *const msgp,const unsigned int len)
{
	struct ZTLF_Message *const msg = (struct ZTLF_Message *)msgp;

	if (unlikely(len < sizeof(struct ZTLF_Message))) return false;
	ZTLF_setu16(msg->fletcher16,ZTLF_fletcher16(((const uint8_t *)msg) + sizeof(struct ZTLF_Message),len - sizeof(struct ZTLF_Message)));

	pthread_mutex_lock(&(c->sendLock));
	if (likely(c->sock >= 0)) {
		if (likely(c->sockSendBufSize > 0)) {
			if (unlikely(len > (unsigned int)c->sockSendBufSize))
				return false;
			int tcpQueued = 0;
#ifdef SO_NWRITE /* Apple, BSD */
			socklen_t siz = sizeof(tcpQueued);
			if (getsockopt(c->sock,SOL_SOCKET,SO_NWRITE,&tcpQueued,&siz) != 0) {
				pthread_mutex_unlock(&(c->sendLock));
				ZTLF_L_warning("getsockopt(SO_NWRITE) failed: %s",strerror(errno));
				return false;
			}
#else /* Linux / other Unix */
			if (ioctl(c->sock,TIOCOUTQ,&tcpQueued) < 0) {
				pthread_mutex_unlock(&(c->sendLock));
				ZTLF_L_warning("ioctl(TIOCOUTQ) failed: %s",strerror(errno));
				return false;
			}
#endif
			if (tcpQueued >= (c->sockSendBufSize - (int)len)) {
				pthread_mutex_unlock(&(c->sendLock));
				ZTLF_L_trace("send failed: buffer contains %d bytes, message is %u bytes",tcpQueued,len);
				return false;
			}
		}
		if (c->encryptor != NULL) {
			ZTLF_AES256CFB_crypt(c->encryptor,msg,msg,len);
		}
		if (send(c->sock,msg,len,MSG_DONTWAIT) != (ssize_t)len) {
			pthread_mutex_unlock(&(c->sendLock));
			close(c->sock);
			c->sock = -1;
			return false;
		}
	}
	pthread_mutex_unlock(&(c->sendLock));

	return true;
}

static void _ZTLF_Connection_mkHello(struct ZTLF_Connection *const c,struct ZTLF_Message_Hello *const h,const uint8_t *const publicKey,const uint32_t flags)
{
	ZTLF_Message_setHdr(h,ZTLF_PROTO_MESSAGE_TYPE_HELLO,sizeof(struct ZTLF_Message_Hello));
	ZTLF_secureRandom(h->iv,sizeof(h->iv));
	h->protoVersion = ZTLF_PROTO_VERSION;
	h->protoFlags = 0;
	ZTLF_setu64(h->currentTime,ZTLF_timeMs());
	ZTLF_setu32(h->flags,flags);
	h->cipher = ZTLF_PROTO_CIPHER_C25519_AES256_CFB;
	memcpy(h->publicKey,publicKey,sizeof(h->publicKey));
}

static void *_ZTLF_Connection_connectionHandler(void *tptr)
{
	struct ZTLF_Connection *const c = (struct ZTLF_Connection *)tptr;
	uint8_t *mbuf = c->recvBuf;

	{
		int fl = 1;
		setsockopt(c->sock,SOL_SOCKET,SO_KEEPALIVE,&fl,sizeof(fl));
#ifdef TCP_NODELAY
		fl = 0;
		setsockopt(c->sock,IPPROTO_TCP,TCP_NODELAY,&fl,sizeof(fl));
#endif
#ifdef TCP_KEEPALIVE /* name of KEEPIDLE on Mac, probably others */
		fl = (int)(ZTLF_TCP_TIMEOUT_MS/3000);
		setsockopt(c->sock,IPPROTO_TCP,TCP_KEEPALIVE,&fl,sizeof(fl));
#endif
#ifdef TCP_KEEPIDLE
		fl = (int)(ZTLF_TCP_TIMEOUT_MS/3000);
		setsockopt(c->sock,IPPROTO_TCP,TCP_KEEPIDLE,&fl,sizeof(fl));
#endif
#ifdef TCP_KEEPCNT
		fl = 3;
		setsockopt(c->sock,IPPROTO_TCP,TCP_KEEPCNT,&fl,sizeof(fl));
#endif
#ifdef TCP_KEEPINTVL
		fl = (int)(ZTLF_TCP_TIMEOUT_MS/3000);
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

	struct ZTLF_Message_Hello lastHelloSent;
	_ZTLF_Connection_mkHello(c,&lastHelloSent,c->param->publicKey,c->param->helloFlags);
	_ZTLF_Connection_send(c,&lastHelloSent,sizeof(lastHelloSent));

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
			unsigned int msize = (((unsigned int)mbuf[0]) << 8) | (unsigned int)mbuf[1];
			const unsigned int mtype = (msize >> 12) & 0xf;
			msize &= 0xfff;
			msize += sizeof(struct ZTLF_Message) + 1; /* message size doesn't include header size, and range is 1-4096 not 0-4095 */

			if (rptr >= msize) { /* a complete message was received */
				const uint16_t f16 = ZTLF_getu16(((struct ZTLF_Message *)mbuf)->fletcher16);
				if (f16 != ZTLF_fletcher16(mbuf + sizeof(struct ZTLF_Message),msize - sizeof(struct ZTLF_Message))) {
					goto terminate_connection;
				}

				if ((!encryptionInitialized)&&(mtype != ZTLF_PROTO_MESSAGE_TYPE_HELLO)) {
					goto terminate_connection;
				} else if ((!connectionEstablished)&&(mtype != ZTLF_PROTO_MESSAGE_TYPE_OK)) {
					goto terminate_connection;
				}

				const uint64_t now = ZTLF_timeMs();
				c->lastReceiveTime = now;

				switch(mtype) {

					case ZTLF_PROTO_MESSAGE_TYPE_HELLO:
						if (likely(msize >= sizeof(struct ZTLF_Message_Hello))) {
							struct ZTLF_Message_Hello *h = (struct ZTLF_Message_Hello *)mbuf;

							ZTLF_SHA384_CTX ackHash;
							ZTLF_SHA384_init(&ackHash);
							ZTLF_SHA384_update(&ackHash,mbuf,msize);

							if ((h->protoVersion != ZTLF_PROTO_VERSION)||(h->cipher != ZTLF_PROTO_CIPHER_C25519_AES256_CFB)) {
								goto terminate_connection;
							}

							/* Check against expectation (outgoing) or learn (incoming) remote key hash. */
							uint8_t remoteKeyHash[48];
							ZTLF_SHA384(remoteKeyHash,h->publicKey,32);
							if (c->incoming) {
								memcpy(c->remoteKeyHash,remoteKeyHash,sizeof(c->remoteKeyHash));
							} else if ((memcmp(remoteKeyHash,c->remoteKeyHash,sizeof(remoteKeyHash)) != 0)&&(!ZTLF_allZero(c->remoteKeyHash,sizeof(c->remoteKeyHash)))) {
								goto terminate_connection;
							}

							/* Perform key agreement with remote. */
							ZTLF_Curve25519_agree(sharedSecret,h->publicKey,c->param->privateKey);

							ZTLF_SHA384_update(&ackHash,sharedSecret,sizeof(sharedSecret));

							/* Initialize or re-initialize cipher. */
							pthread_mutex_lock(&(c->sendLock));
							if (encryptionInitialized) {
								ZTLF_AES256CFB_destroy(&encryptor);
								ZTLF_AES256CFB_destroy(&decryptor);
							}
							ZTLF_AES256CFB_init(&encryptor,sharedSecret,lastHelloSent.iv,true);
							ZTLF_AES256CFB_init(&decryptor,sharedSecret,h->iv,false);
							c->encryptor = &encryptor;
							pthread_mutex_unlock(&(c->sendLock));

							c->helloFlags = ZTLF_getu32(h->flags);
							encryptionInitialized = true;

							/* Send encrypted OK to peer with acknowledgement of HELLO. */
							struct ZTLF_Message_OK ok;
							memset(&ok,0,sizeof(ok));
							ZTLF_Message_setHdr(&ok,ZTLF_PROTO_MESSAGE_TYPE_OK,sizeof(struct ZTLF_Message_OK));
							ZTLF_SHA384_final(&ackHash,ok.ack);
							for(int i=0;i<sizeof(uint64_t);++i) ((uint8_t *)&(ok.helloTime))[i] = ((const uint8_t *)&(h->currentTime))[i];
							ZTLF_setu64(ok.currentTime,now);
							ok.version[0] = ZTLF_VERSION_MAJOR;
							ok.version[1] = ZTLF_VERSION_MINOR;
							ok.version[2] = ZTLF_VERSION_REVISION;
							ok.version[3] = ZTLF_VERSION_REVISION;
							_ZTLF_Connection_send(c,&ok,sizeof(ok));
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
								goto terminate_connection;
							}

							if ((!c->incoming)&&(!connectionEstablished)) {
								if (c->param->onConnectionEstablished)
									c->param->onConnectionEstablished(c);
#if 0
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
#endif
							}

							const uint64_t ht = ZTLF_getu64(ok->helloTime);
							c->latency = (now > ht) ? (long)(now - ht) : (long)0;
							c->established = true;
							connectionEstablished = true;
						}
						break;

					case ZTLF_PROTO_MESSAGE_TYPE_PEER_INFO:
						if ((msize >= sizeof(struct ZTLF_Message_PeerInfo))&&(c->param->onPeerInfo)) {
							struct ZTLF_Message_PeerInfo *pi = (struct ZTLF_Message_PeerInfo *)mbuf;
							switch(pi->addressType) {
								case 4:
									if (msize >= (sizeof(struct ZTLF_Message_PeerInfo) + 6)) {
										const unsigned int port = (((unsigned int)pi->address[4]) << 8) | (unsigned int)pi->address[5];
										c->param->onPeerInfo(c,4,pi->address,port,pi->keyHash);
									}
									break;
								case 6:
									if (msize >= (sizeof(struct ZTLF_Message_PeerInfo) + 18)) {
										const unsigned int port = (((unsigned int)pi->address[16]) << 8) | (unsigned int)pi->address[17];
										c->param->onPeerInfo(c,6,pi->address,port,pi->keyHash);
									}
									break;
							}
						}
						break;

					case ZTLF_PROTO_MESSAGE_TYPE_RECORD:
						if ((msize >= (sizeof(struct ZTLF_Message_Record) + ZTLF_RECORD_MIN_SIZE))&&(c->param->onRecord)) {
							struct ZTLF_Message_Record *rm = (struct ZTLF_Message_Record *)mbuf;
							c->param->onRecord(c,(const struct ZTLF_Record *)&(rm->record),msize - sizeof(struct ZTLF_Message_Record));
						}
						break;

					case ZTLF_PROTO_MESSAGE_TYPE_RECORD_REQUEST_BY_HASH:
						if ((msize >= sizeof(struct ZTLF_Message_RecordRequestByHash))&&(c->param->onRecordRequestByHash)) {
							struct ZTLF_Message_RecordRequestByHash *req = (struct ZTLF_Message_RecordRequestByHash *)mbuf;
							c->param->onRecordRequestByHash(c,req->hash);
						}
						break;

					case ZTLF_PROTO_MESSAGE_TYPE_RECORD_QUERY_RESULT:
						break;

					case ZTLF_PROTO_MESSAGE_TYPE_RECORD_QUERY:
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
	c->established = false;

	if (c->param->onConnectionClosed)
		c->param->onConnectionClosed(c);

	pthread_mutex_lock(&(c->sendLock));
	if (c->sock >= 0) {
		close(c->sock);
		c->sock = -1;
	}
	c->encryptor = NULL;
	pthread_mutex_unlock(&(c->sendLock));

	if (encryptionInitialized) {
		ZTLF_AES256CFB_destroy(&decryptor);
		ZTLF_AES256CFB_destroy(&encryptor);
	}

	pthread_mutex_destroy(&(c->sendLock));
	free(c);

	return NULL;
}

struct ZTLF_Connection *ZTLF_Connection_New(const struct ZTLF_ConnectionParameters *param,const struct sockaddr_storage *remoteAddress,const int sock,const bool incoming,const void *expectedRemoteKeyHash)
{
	struct ZTLF_Connection *c;
	ZTLF_MALLOC_CHECK(c = (struct ZTLF_Connection *)malloc(sizeof(struct ZTLF_Connection)));

	c->param = param;
	memcpy(&c->remoteAddress,remoteAddress,sizeof(struct sockaddr_storage));
	c->sock = sock;
	c->sockSendBufSize = 0;
	c->encryptor = NULL;
	pthread_mutex_init(&c->sendLock,NULL);
	if (expectedRemoteKeyHash)
		memcpy(c->remoteKeyHash,expectedRemoteKeyHash,sizeof(c->remoteKeyHash));
	else memset(c->remoteKeyHash,0,sizeof(c->remoteKeyHash));
	c->incoming = incoming;
	c->lastReceiveTime = ZTLF_timeMs();
	c->helloFlags = 0;
	c->latency = -1;
	c->established = false;
	c->thread = ZTLF_threadCreate(_ZTLF_Connection_connectionHandler,(void *)c,false);

	return c;
}

void ZTLF_Connection_Close(struct ZTLF_Connection *const c)
{
	pthread_mutex_lock(&(c->sendLock));
	if (c->sock >= 0) {
		shutdown(c->sock,SHUT_RD);
	}
	pthread_mutex_unlock(&(c->sendLock));
	pthread_join(c->thread,NULL);
}
