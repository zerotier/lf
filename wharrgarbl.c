/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#include "wharrgarbl.h"
#include "sha.h"

struct _wharrgarblState
{
	uint64_t runNonce;
	uint64_t difficulty; /* 32-bit difficulty << 32 */
	uint64_t memory;
	volatile uint64_t iterations;
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

	uint64_t iter = 0;
	while (ws->done == 0) {
		++thisCollider;
		ZTLF_SHA384_init(&hash);
		ZTLF_SHA384_update(&hash,ws->inHash,sizeof(ws->inHash));
		ZTLF_SHA384_update(&hash,&thisCollider,sizeof(thisCollider));
		ZTLF_SHA384_final(&hash,hbuf);
		thisCollision = ZTLF_ntohll(hbuf[0]) % ws->difficulty;

		ctabEntry = ws->collisionTable + (((thisCollision ^ ws->runNonce) % ws->memory) << 1);

		if (unlikely(*ctabEntry == thisCollision)) {
			otherCollider = *(ctabEntry + 1);

			if (otherCollider != thisCollider) {
				ZTLF_SHA384_init(&hash);
				ZTLF_SHA384_update(&hash,ws->inHash,sizeof(ws->inHash));
				ZTLF_SHA384_update(&hash,&otherCollider,sizeof(otherCollider));
				ZTLF_SHA384_final(&hash,hbuf);
				otherCollision = ZTLF_ntohll(hbuf[0]) % ws->difficulty;

				if (otherCollision == thisCollision) {
					pthread_mutex_lock(&ws->doneLock);
					ws->iterations += iter;
					if (!ws->done) {
						ws->out[0] = thisCollider;
						ws->out[1] = otherCollider;
					}
					++ws->done;
					pthread_cond_broadcast(&ws->doneCond);
					pthread_mutex_unlock(&ws->doneLock);
					return NULL;
				}
			}
		}

		*(ctabEntry++) = thisCollision;
		*ctabEntry = thisCollider;

		++iter;
	}

	pthread_mutex_lock(&ws->doneLock);
	ws->iterations += iter;
	++ws->done;
	pthread_cond_broadcast(&ws->doneCond);
	pthread_mutex_unlock(&ws->doneLock);

	return NULL;
}

uint64_t ZTLF_wharrgarbl(void *pow,const void *in,const unsigned long inlen,const uint32_t difficulty,void *memory,const unsigned long memorySize,unsigned int threads)
{
	struct _wharrgarblState ws;

	uint64_t out[2];
	ws.runNonce = ZTLF_prng(); /* nonce to avoid time-wasting false positives and so memset(0) is not needed */
	ws.difficulty = ((uint64_t)difficulty) << 32;
	if (ws.difficulty == 0) {
		++ws.difficulty;
	}
	ws.memory = (memorySize / 16);
	if (!ws.memory)
		return 0;
	ws.iterations = 0;
	ws.out = out;
	ws.collisionTable = (uint64_t *)memory;
	ZTLF_SHA384(ws.inHash,in,inlen);
	pthread_mutex_init(&ws.doneLock,NULL);
	pthread_cond_init(&ws.doneCond,NULL);
	ws.done = 0;

	if (threads < 1) threads = ZTLF_ncpus();
	for(unsigned int t=1;t<threads;++t)
		pthread_detach(ZTLF_threadCreate(&_wharrgarbl,&ws,true));
	_wharrgarbl(&ws);

	pthread_mutex_lock(&ws.doneLock);
	for(;;) {
		if (ws.done >= threads) {
			pthread_mutex_unlock(&ws.doneLock);
			break;
		}
		pthread_cond_wait(&ws.doneCond,&ws.doneLock);
	}

	pthread_cond_destroy(&ws.doneCond);
	pthread_mutex_destroy(&ws.doneLock);

	for(unsigned int i=0;i<16;++i)
		((uint8_t *)pow)[i] = ((uint8_t *)out)[i];
	(((uint8_t *)pow)[16]) = (uint8_t)((difficulty >> 24) & 0xff);
	(((uint8_t *)pow)[17]) = (uint8_t)((difficulty >> 16) & 0xff);
	(((uint8_t *)pow)[18]) = (uint8_t)((difficulty >> 8) & 0xff);
	(((uint8_t *)pow)[19]) = (uint8_t)(difficulty & 0xff);

	return ws.iterations;
}

uint32_t ZTLF_wharrgarblVerify(const void *pow,const void *in,const unsigned long inlen)
{
	unsigned char inHash[48];
	uint64_t hbuf[6];
	uint64_t collision[2];
	uint64_t powq[2];
	int i;
	ZTLF_SHA384_CTX hash;

	for(unsigned int i=0;i<16;++i)
		((uint8_t *)powq)[i] = ((const uint8_t *)pow)[i];
	const uint32_t diff32 = ZTLF_wharrgarblGetDifficulty(pow);
	const uint64_t difficulty = ((uint64_t)diff32) << 32;

	ZTLF_SHA384_init(&hash);
	ZTLF_SHA384_update(&hash,in,inlen);
	ZTLF_SHA384_final(&hash,inHash);

	if ((powq[0] == powq[1])||(!difficulty)) {
		return 0;
	}

	for(i=0;i<2;++i) {
		ZTLF_SHA384_init(&hash);
		ZTLF_SHA384_update(&hash,inHash,sizeof(inHash));
		ZTLF_SHA384_update(&hash,&(powq[i]),sizeof(uint64_t));
		ZTLF_SHA384_final(&hash,hbuf);
		collision[i] = ZTLF_ntohll(hbuf[0]) % difficulty;
	}

	return ((collision[0] == collision[1]) ? diff32 : 0ULL);
}
