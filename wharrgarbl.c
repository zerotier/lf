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

#include "wharrgarbl.h"
#include "sha.h"

struct _wharrgarblState
{
	uint64_t runNonce;
	uint64_t difficulty;
	uint64_t memory;
	uint64_t *out;
	uint64_t *collisionTable;
	unsigned char inHash[48];
	pthread_mutex_t doneLock;
	pthread_cond_t doneCond;
	volatile unsigned int done;
};

static void *_wharrgarbl(void *ptr)
{
	struct _wharrgarblState *const ws = (struct _wharrgarblState *)ptr;

	uint64_t thisCollision,otherCollider,otherCollision;
	uint64_t thisCollider = ZTLF_prng();
	uint64_t hbuf[6];
	uint64_t *ctabEntry;
	ZTLF_SHA384_CTX hash;

	while (ws->done == 0) {
		++thisCollider;
		ZTLF_SHA384_init(&hash);
		ZTLF_SHA384_update(&hash,ws->inHash,sizeof(ws->inHash));
		ZTLF_SHA384_update(&hash,&thisCollider,sizeof(thisCollider));
		ZTLF_SHA384_final(&hash,hbuf);
		thisCollision = ZTLF_ntohll(hbuf[0]) % ws->difficulty;

		ctabEntry = ws->collisionTable + (((thisCollision ^ ws->runNonce) % ws->memory) << 1);

		if (*ctabEntry == thisCollision) {
			otherCollider = *(ctabEntry + 1);

			if (otherCollider != thisCollider) {
				ZTLF_SHA384_init(&hash);
				ZTLF_SHA384_update(&hash,ws->inHash,sizeof(ws->inHash));
				ZTLF_SHA384_update(&hash,&otherCollider,sizeof(otherCollider));
				ZTLF_SHA384_final(&hash,hbuf);
				otherCollision = ZTLF_ntohll(hbuf[0]) % ws->difficulty;

				if (otherCollision == thisCollision) {
					pthread_mutex_lock(&ws->doneLock);
					if (!ws->done) {
						ws->out[0] = thisCollider;
						ws->out[1] = otherCollider;
						ws->out[2] = ZTLF_htonll(ws->difficulty);
					}
					++ws->done;
					pthread_mutex_unlock(&ws->doneLock);
					pthread_cond_broadcast(&ws->doneCond);
					return NULL;
				}
			}
		}

		*(ctabEntry++) = thisCollision;
		*ctabEntry = thisCollider;
	}

	pthread_mutex_lock(&ws->doneLock);
	++ws->done;
	pthread_mutex_unlock(&ws->doneLock);
	pthread_cond_broadcast(&ws->doneCond);

	return NULL;
}

void ZTLF_wharrgarbl(uint64_t wresult[3],const void *in,const unsigned long inlen,const uint64_t difficulty,const unsigned long memory)
{
	static volatile unsigned int s_cpuCount = 0;

	struct _wharrgarblState ws;

	unsigned int nt;
	if (!(nt = s_cpuCount)) {
		nt = s_cpuCount = ZTLF_ncpus();
	}

	ws.runNonce = ZTLF_prng; /* nonce to avoid time-wasting false positives and so memset(0) is not needed */
	ws.difficulty = difficulty;
	if (ws.difficulty == 0) {
		++ws.difficulty;
	}
	ws.memory = memory;
	if (ws.memory < 1024) {
		ws.memory = 1024;
	}
	ws.out = wresult;
	ws.collisionTable = (uint64_t *)malloc(ws.memory * 16);
	ZTLF_SHA384(ws.inHash,in,inlen);
	pthread_mutex_init(&ws.doneLock,NULL);
	pthread_cond_init(&ws.doneCond,NULL);
	ws.done = 0;

	for(unsigned int t=0;t<nt;++t) {
		pthread_t thr;
		pthread_create(&thr,NULL,&_wharrgarbl,&ws);
	}

	pthread_mutex_lock(&ws.doneLock);
	for(;;) {
		if (ws.done >= nt) {
			pthread_mutex_unlock(&ws.doneLock);
			break;
		}
		pthread_cond_wait(&ws.doneCond,&ws.doneLock);
	}

	pthread_cond_destroy(&ws.doneCond);
	pthread_mutex_destroy(&ws.doneLock);
	free(ws.collisionTable);
}

uint64_t ZTLF_wharrgarblVerify2(const uint64_t wresult[2],const void *in,const unsigned long inlen,const uint64_t difficulty)
{
	unsigned char inHash[48];
	uint64_t hbuf[6];
	uint64_t collision[2],difficulty;
	int i;
	ZTLF_SHA384_CTX hash;

	ZTLF_SHA384_init(&hash);
	ZTLF_SHA384_update(&hash,in,inlen);
	ZTLF_SHA384_final(&hash,inHash);

	if ((wresult[0] == wresult[1])||(!difficulty)) {
		return 0;
	}

	for(i=0;i<2;++i) {
		ZTLF_SHA384_init(&hash);
		ZTLF_SHA384_update(&hash,inHash,sizeof(inHash));
		ZTLF_SHA384_update(&hash,&(wresult[i]),sizeof(uint64_t));
		ZTLF_SHA384_final(&hash,hbuf);
		collision[i] = ZTLF_ntohll(hbuf[0]) % difficulty;
	}

	return ((collision[0] == collision[1]) ? difficulty : 0ULL);
}
