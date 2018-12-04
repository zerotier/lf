/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#include "api.h"
#include "node.h"
#include "db.h"
#include "tiny-json.h"

static bool s(const int sock,const char *fmt,...)
{
	va_list ap;
	char msg[4096];
	va_start(ap, fmt);
	long ml = (long)vsnprintf(msg,sizeof(msg),fmt,ap);
	va_end(ap);
	if ((ml < 0)||(ml >= 16384)) return false;
	if (ml == 0) return true;
	long written = 0;
	for(;;) {
		long n = send(sock,msg + written,ml - written,MSG_DONTWAIT);
		if (n < 0) {
			if ((errno != EAGAIN)&&(errno != EWOULDBLOCK))
				return false;
		} else if (n > 0) {
			written += n;
		}
		if (written < ml) {
			fd_set nfds,wfds;
			FD_ZERO(&nfds);
			FD_ZERO(&wfds);
			FD_SET(sock,&wfds);
			struct timeval tv;
			tv.tv_sec = ZTLF_TCP_TIMEOUT_MS;
			tv.tv_usec = 0;
			select(sock+1,&nfds,&wfds,&nfds,&tv);
			if (!FD_ISSET(sock,&wfds)) {
				return false;
			}
		} else {
			break;
		}
	}
	return true;
}

bool ZTLF_API_GET(struct ZTLF_Node_PeerConnection *const c,const bool auth,const bool head,const char *path)
{
	if (!strncmp(path,"/lf/",4)) {
		path += 4;
	} else if ((path[0] == 0)||((path[0] == '/')&&(path[1] == 0))) {
	} else {
		return s(c->sock,"HTTP/1.1 404 Not Found\r\nConnection: keep-alive\r\nKeep-Alive: timeout=10,max=2147483647\r\n\r\n");
	}
}

bool ZTLF_API_POST(struct ZTLF_Node_PeerConnection *const c,const bool auth,const char *path,const void *const body,const unsigned int bodySize)
{
}
