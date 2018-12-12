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
	uint64_t difficulty;          /* 32-bit difficulty << 32 */
	uint64_t collisionTableSize;  /* size of collision table in entries (entry == 12 bytes, 3 uint32's) */
	volatile uint64_t iterations; /* sum of threads' iteration counters */
	uint64_t *out;
	uint32_t *collisionTable;     /* entry: least significant 32 bits of collision, 64-bit collider */
	unsigned char inHash[48];
	pthread_mutex_t doneLock;
	pthread_cond_t doneCond;
	volatile unsigned int done;
};

static void *_wharrgarbl(void *ptr)
{
	struct _wharrgarblState *const ws = (struct _wharrgarblState *)ptr;
	uint64_t hbuf[6];
	ZTLF_SHA384_CTX hash;

	uint64_t thisCollider = ZTLF_prng();
	uint64_t iter = 0;
	while (ws->done == 0) {
		++thisCollider;
		ZTLF_SHA384_init(&hash);
		ZTLF_SHA384_update(&hash,ws->inHash,sizeof(ws->inHash));
		ZTLF_SHA384_update(&hash,&thisCollider,sizeof(thisCollider));
		ZTLF_SHA384_final(&hash,hbuf);
		const uint64_t thisCollision = ZTLF_ntohll(hbuf[0]) % ws->difficulty;

		uint32_t *ctabEntry = ws->collisionTable + (((thisCollision ^ ws->runNonce) % ws->collisionTableSize) * 3);

		const uint32_t thisCollision32 = (uint32_t)thisCollision;
		if (unlikely(*ctabEntry == thisCollision32)) {
#ifdef ZTLF_UNALIGNED_OKAY
			const uint64_t otherCollider = *((uint64_t *)(ctabEntry + 1));
#else
			const uint64_t otherCollider = (((uint64_t)*(ctabEntry + 1)) << 32) | (uint64_t)*(ctabEntry + 2);
#endif

			if (otherCollider != thisCollider) {
				ZTLF_SHA384_init(&hash);
				ZTLF_SHA384_update(&hash,ws->inHash,sizeof(ws->inHash));
				ZTLF_SHA384_update(&hash,&otherCollider,sizeof(otherCollider));
				ZTLF_SHA384_final(&hash,hbuf);
				const uint64_t otherCollision = ZTLF_ntohll(hbuf[0]) % ws->difficulty;

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

		*(ctabEntry++) = thisCollision32;
#ifdef ZTLF_UNALIGNED_OKAY
		*((uint64_t *)ctabEntry) = thisCollider;
#else
		*(ctabEntry++) = (uint32_t)(thisCollider >> 32);
		*ctabEntry = (uint32_t)thisCollider;
#endif

		++iter;
	}

	pthread_mutex_lock(&ws->doneLock);
	ws->iterations += iter;
	++ws->done;
	pthread_cond_broadcast(&ws->doneCond);
	pthread_mutex_unlock(&ws->doneLock);

	return NULL;
}

uint64_t ZTLF_Wharrgarbl(void *pow,const void *in,const unsigned long inlen,const uint32_t difficulty,void *memory,const unsigned long memorySize,unsigned int threads)
{
	struct _wharrgarblState ws;
	uint64_t out[2];

	ws.runNonce = ZTLF_prng(); /* nonce to avoid time-wasting false positives and so memset(0) is not needed */
	ws.difficulty = (((uint64_t)difficulty) << 32) | 0x00000000ffffffffULL;
	if (ws.difficulty == 0) {
		++ws.difficulty;
	}
	ws.collisionTableSize = (memorySize / (sizeof(uint32_t) * 3));
	if (!ws.collisionTableSize)
		return 0;
	ws.iterations = 0;
	ws.out = out;
	ws.collisionTable = (uint32_t *)memory;
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

uint32_t ZTLF_WharrgarblVerify(const void *pow,const void *in,const unsigned long inlen)
{
	unsigned char inHash[48];
	uint64_t hbuf[6];
	uint64_t collision[2];
	uint64_t powq[2];
	int i;
	ZTLF_SHA384_CTX hash;

	for(unsigned int i=0;i<16;++i)
		((uint8_t *)powq)[i] = ((const uint8_t *)pow)[i];
	const uint32_t diff32 = ZTLF_WharrgarblGetDifficulty(pow);
	const uint64_t difficulty = (((uint64_t)diff32) << 32) | 0x00000000ffffffffULL;

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
