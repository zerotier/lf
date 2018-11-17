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

#include "node.h"
#include "protocol.h"

static void *_ZTLF_Node_connectionHandler(void *tptr)
{
	struct ZTLF_Node_PeerConnection *const c = (struct ZTLF_Node_PeerConnection *)tptr;
	uint8_t *rbuf = (uint8_t *)malloc(131072);

	{
		int fl = 1;
		setsockopt(c->sock,SOL_SOCKET,SO_KEEPALIVE,&fl,sizeof(fl));
		for(fl=524288;fl>=131072;fl-=131072) {
			if (setsockopt(c->sock,SOL_SOCKET,SO_RCVBUF,&fl,sizeof(fl)) == 0)
				break;
		}
		for(fl=524288;fl>=131072;fl-=131072) {
			if (setsockopt(c->sock,SOL_SOCKET,SO_SNDBUF,&fl,sizeof(fl)) == 0)
				break;
		}
		fcntl(c->sock,F_SETFL,fcntl(c->sock,F_GETFL)&(~O_NONBLOCK));
	}

	unsigned int rptr = 0;
	bool run = true;
	while (run) {
		long nr = (long)recv(c->sock,rbuf + rptr,131072 - rptr,0);
		if (nr < 0) {
			if ((errno == EINTR)||(errno == EAGAIN))
				continue;
			break;
		}
		rptr += (unsigned int)nr;

		if (rptr >= 2) {
			unsigned int msize = (((unsigned int)rbuf[0]) << 8) | (unsigned int)rbuf[1];
			const unsigned int mtype = (msize >> 12) & 0xf;
			msize &= 0xfff;
			++msize; /* size: 1-4096 */
			uint8_t *msg = rbuf + 2;
			if (rptr >= (msize+2)) {
				switch(mtype) {

					case ZTLF_PROTO_MESSAGE_TYPE_HELLO:
						break;

					case ZTLF_PROTO_MESSAGE_TYPE_PEER_INFO:
						if (msize >= sizeof(struct ZTLF_Message_PeerInfo)) {
							struct ZTLF_Message_PeerInfo pi;
							memcpy(&pi,msg,sizeof(pi));

							pi.protoVersion = ntohs(pi.protoVersion);
							pi.flags = ntohs(pi.flags);
							pi.addressPort = ntohs(pi.addressPort);
						}
						break;

					case ZTLF_PROTO_MESSAGE_TYPE_RECORD:
						if (msize >= ZTLF_RECORD_MIN_SIZE) {
						}
						break;

					case ZTLF_PROTO_MESSAGE_TYPE_RECORD_REQUEST_BEST_BY_ID:
						if (msize >= sizeof(struct ZTLF_Message_RecordRequestBestByID)) {
						}
						break;

					case ZTLF_PROTO_MESSAGE_TYPE_RECORD_REQUEST_BY_HASH:
						if (msize >= sizeof(struct ZTLF_Message_RecordRequestByHash)) {
						}
						break;

					case ZTLF_PROTO_MESSAGE_TYPE_RECORD_REQUEST_BY_TIMESTAMP_RANGE:
						if (msize >= sizeof(struct ZTLF_Message_RecordRequestByTimestampRange)) {
						}
						break;

					case ZTLF_PROTO_MESSAGE_TYPE_SUBSCRIBE_TO_ID:
						if (msize >= sizeof(struct ZTLF_Message_SubscribeToID)) {
						}
						break;

					case ZTLF_PROTO_MESSAGE_TYPE_SUBSCRIBE_TO_OWNER:
						if (msize >= sizeof(struct ZTLF_Message_SubscribeToOwner)) {
						}
						break;

					case ZTLF_PROTO_MESSAGE_TYPE_SUBSCRIBE_TO_ALL:
						pthread_mutex_lock(&(c->subscribedLock));
						if (msize > 0)
							c->subscribedToAll = (msg[0] != 0);
						else c->subscribedToAll = false;
						pthread_mutex_unlock(&(c->subscribedLock));
						break;

				}

				msize += 2;
				if (rptr > msize)
					memmove(rbuf,rbuf + msize,rptr - msize);
				rptr -= msize;
			}
		}
	}

	pthread_mutex_lock(&(c->sendLock));
	close(c->sock);
	c->sock = -1;
	pthread_mutex_unlock(&(c->sendLock));

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

	pthread_mutex_destroy(&(c->sendLock));
	pthread_mutex_destroy(&(c->subscribedLock));

	ZTLF_Map256_destroy(&(c->subscribedToOwners));
	ZTLF_Map256_destroy(&(c->subscribedToIds));
	free(rbuf);

	return NULL;
}

static void _ZTLF_Node_newConnection(struct ZTLF_Node *const n,const struct sockaddr_storage *addr,const int sock,const bool incoming)
{
	pthread_mutex_lock(&(n->connLock));

	if (n->connCount >= n->connCapacity) {
		ZTLF_MALLOC_CHECK(n->conn = (struct ZTLF_Node_PeerConnection *)realloc(n->conn,sizeof(struct ZTLF_Node_PeerConnection) * (n->connCapacity << 1)));
	}
	struct ZTLF_Node_PeerConnection *const c = &(n->conn[n->connCount++]);

	c->parent = n;
	memcpy(&(c->remoteAddress),addr,sizeof(struct sockaddr_storage));
	c->sock = sock;
	pthread_mutex_init(&(c->sendLock),NULL);
	pthread_mutex_init(&(c->subscribedLock),NULL);
	ZTLF_Map256_init(&(c->subscribedToIds),4,NULL);
	ZTLF_Map256_init(&(c->subscribedToOwners),4,NULL);
	c->subscribedToAll = false;
	c->incoming = incoming;

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

	const int err = ZTLF_DB_open(&n->db,path);
	if (err != 0) {
		close(sock);
		return err;
	}

	n->listenPort = port;
	n->listenSocket = sock;
	ZTLF_MALLOC_CHECK(n->conn = (struct ZTLF_Node_PeerConnection *)malloc(sizeof(struct ZTLF_Node_PeerConnection) * 128));
	n->connCount = 0;
	n->connCapacity = 128;
	pthread_mutex_init(&(n->connLock),NULL);

	struct sockaddr_storage from;
	for(;;) {
		memset(&from,0,sizeof(from));
		socklen_t fromlen = 0;
		const int ns = accept(sock,(struct sockaddr *)&from,&fromlen);
		if (ns < 0) {
			if ((errno == EINTR)||(errno == EAGAIN))
				continue;
			break;
		}
		_ZTLF_Node_newConnection(n,&from,ns,true);
	}

	pthread_mutex_lock(&(n->connLock));
	for(unsigned long i=0;i<n->connCount;++i) {
		pthread_mutex_lock(&(n->conn[i].sendLock));
		if (n->conn[i].sock >= 0)
			close(n->conn[i].sock);
		pthread_mutex_unlock(&(n->conn[i].sendLock));
	}
	pthread_mutex_unlock(&(n->connLock));
	for(;;) {
		pthread_mutex_lock(&(n->connLock));
		const unsigned long cc = n->connCount;
		pthread_mutex_unlock(&(n->connLock));
		if (!cc)
			break;
		usleep(100);
	}

	pthread_mutex_destroy(&(n->connLock));

	return 0;
}

void ZTLF_Node_stop(struct ZTLF_Node *n)
{
}
