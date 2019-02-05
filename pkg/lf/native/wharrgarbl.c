/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#include "wharrgarbl.h"

#ifdef __WINDOWS__

static unsigned int ZTLF_ncpus()
{
	static volatile unsigned int nc = 0;
	const unsigned int tmp = nc;
	if (!tmp) {
		SYSTEM_INFO info;
		GetSystemInfo(&info);
		return (nc = (info.dwNumberOfProcessors <= 0) ? (unsigned int)1 : (unsigned int)(info.dwNumberOfProcessors));
	}
	return tmp;
}

#else /* non-Windows */

static unsigned int ZTLF_ncpus()
{
	static volatile unsigned int nc = 0;
	const unsigned int tmp = nc;
	if (tmp == 0) {
		long n = sysconf(_SC_NPROCESSORS_ONLN);
		return (nc = (n <= 0) ? (unsigned int)1 : (unsigned int)n);
	}
	return tmp;
}

#endif /* Windows / non-Windows */

/* Speck algorithm from https://en.wikipedia.org/wiki/Speck_(cipher) */
/* Byte swapping added so this will generate the same result on big or little endian systems. */
#define SPECK_ROR(x, r) ((x >> r) | (x << (64 - r)))
#define SPECK_ROL(x, r) ((x << r) | (x >> (64 - r)))
#define SPECK_R(x, y, k) (x = SPECK_ROR(x, 8), x += y, x ^= k, y = SPECK_ROL(y, 3), y ^= x)
#define SPECK_ROUNDS 32
static inline void _ZTLF_SpeckEncrypt(uint64_t ct[2],uint64_t const pt[2],uint64_t const K[2])
{
	uint64_t y=ZTLF_ntohll(pt[0]),x=ZTLF_ntohll(pt[1]),b=ZTLF_ntohll(K[0]),a=ZTLF_ntohll(K[1]);
	SPECK_R(x,y,b);
	for (uint64_t i=0;i<(SPECK_ROUNDS-1);++i) { SPECK_R(a,b,i); SPECK_R(x,y,b); }
	ct[0] = ZTLF_htonll(y);
	ct[1] = ZTLF_htonll(x);
}

void ZTLF_SpeckHash(uint64_t out[2],const void *in,const unsigned long len)
{
	uint64_t buf[2];
	unsigned int p = 0;

	/* Hash message block by block (Davies-Meyer) */
	out[0] = 0x7171717171717171ULL;
	out[1] = 0x1717171717171717ULL; /* endian-neutral initial state constants */
	for(unsigned long i=0;i<len;++i) {
		((uint8_t *)buf)[p++] = ((const uint8_t *)in)[i];
		if (p == 16) {
			p = 0;
			_ZTLF_SpeckEncrypt(out,buf,out);
			out[0] ^= buf[0];
			out[1] ^= buf[1];
		}
	}

	/* Append length of input */
	((uint8_t *)buf)[p++] = (uint8_t)(len >> 24);
	if (p == 16) {
		p = 0;
		_ZTLF_SpeckEncrypt(out,buf,out);
		out[0] ^= buf[0];
		out[1] ^= buf[1];
	}
	((uint8_t *)buf)[p++] = (uint8_t)(len >> 16);
	if (p == 16) {
		p = 0;
		_ZTLF_SpeckEncrypt(out,buf,out);
		out[0] ^= buf[0];
		out[1] ^= buf[1];
	}
	((uint8_t *)buf)[p++] = (uint8_t)(len >> 8);
	if (p == 16) {
		p = 0;
		_ZTLF_SpeckEncrypt(out,buf,out);
		out[0] ^= buf[0];
		out[1] ^= buf[1];
	}
	((uint8_t *)buf)[p++] = (uint8_t)len;
	if (p == 16) {
		p = 0;
		_ZTLF_SpeckEncrypt(out,buf,out);
		out[0] ^= buf[0];
		out[1] ^= buf[1];
	}

	/* Pad and hash final block */
	while (p < 16) {
		((uint8_t *)buf)[p++] = 0x7f;
	}
	_ZTLF_SpeckEncrypt(out,buf,out);
	out[0] ^= buf[0];
	out[1] ^= buf[1];
}

struct _wharrgarblState
{
	uint64_t runNonce;
	uint64_t difficulty;          /* 32-bit difficulty << 32 */
	uint64_t collisionTableSize;  /* size of collision table in entries (entry == 12 bytes, 3 uint32's) */
	volatile uint64_t iterations; /* sum of threads' iteration counters */
	uint64_t *out;
	uint32_t *collisionTable;     /* entry: least significant 32 bits of collision, 64-bit collider */
	uint64_t inHash[2];
	pthread_mutex_t doneLock;
	pthread_cond_t doneCond;
	volatile unsigned int done;
};

static void *_wharrgarbl(void *ptr)
{
	struct _wharrgarblState *const ws = (struct _wharrgarblState *)ptr;
	uint64_t hout[2];
	uint64_t hin[3];

	hin[0] = ws->inHash[0];
	hin[1] = ws->inHash[1];
	uint64_t thisCollider = (((uint64_t)rand()) << 32) ^ (uint64_t)rand();
	uint64_t iter = 0;
	while (ws->done == 0) {
		hin[2] = ++thisCollider;
		ZTLF_SpeckHash(hout,hin,sizeof(hin));
		const uint64_t thisCollision = ZTLF_ntohll(hout[0] ^ hout[1]) % ws->difficulty;

		uint32_t *ctabEntry = ws->collisionTable + (((thisCollision ^ ws->runNonce) % ws->collisionTableSize) * 3);

		const uint32_t thisCollision32 = (uint32_t)thisCollision;
		if (unlikely(*ctabEntry == thisCollision32)) {
#ifdef ZTLF_UNALIGNED_OKAY
			const uint64_t otherCollider = *((uint64_t *)(ctabEntry + 1));
#else
			const uint64_t otherCollider = (((uint64_t)*(ctabEntry + 1)) << 32) | (uint64_t)*(ctabEntry + 2);
#endif

			if (otherCollider != thisCollider) {
				hin[2] = otherCollider;
				ZTLF_SpeckHash(hout,hin,sizeof(hin));
				const uint64_t otherCollision = ZTLF_ntohll(hout[0] ^ hout[1]) % ws->difficulty;

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
	bool needFree = false;

	ws.runNonce = (((uint64_t)rand()) << 32) ^ (uint64_t)rand(); /* nonce to avoid time-wasting false positives and so memset(0) is not needed */
	ws.difficulty = (((uint64_t)difficulty) << 32) | 0x00000000ffffffffULL;
	if (ws.difficulty == 0)
		++ws.difficulty;
	ws.collisionTableSize = (memorySize / (sizeof(uint32_t) * 3));
	if (!ws.collisionTableSize)
		return 0;
	ws.iterations = 0;
	ws.out = out;
	if (!memory) {
		ZTLF_MALLOC_CHECK(memory = malloc(memorySize));
		needFree = true;
	}
	ws.collisionTable = (uint32_t *)memory;
	ZTLF_SpeckHash(ws.inHash,in,inlen);
	pthread_mutex_init(&ws.doneLock,NULL);
	pthread_cond_init(&ws.doneCond,NULL);
	ws.done = 0;

	if (threads < 1) threads = ZTLF_ncpus();
	for(unsigned int t=1;t<threads;++t) {
		pthread_t t;
		if (pthread_create(&t,NULL,&_wharrgarbl,&ws) != 0) {
			fprintf(stderr,"pthread_create() failed!" ZTLF_EOL);
			abort();
		}
		pthread_detach(t);
	}
	_wharrgarbl(&ws);

	pthread_mutex_lock(&ws.doneLock);
	for(;;) {
		if (ws.done >= threads) {
			pthread_mutex_unlock(&ws.doneLock);
			break;
		}
		pthread_cond_wait(&ws.doneCond,&ws.doneLock);
	}

exit_wharrgarbl:
	pthread_cond_destroy(&ws.doneCond);
	pthread_mutex_destroy(&ws.doneLock);

	for(unsigned int i=0;i<16;++i)
		((uint8_t *)pow)[i] = ((uint8_t *)out)[i];
	(((uint8_t *)pow)[16]) = (uint8_t)((difficulty >> 24) & 0xff);
	(((uint8_t *)pow)[17]) = (uint8_t)((difficulty >> 16) & 0xff);
	(((uint8_t *)pow)[18]) = (uint8_t)((difficulty >> 8) & 0xff);
	(((uint8_t *)pow)[19]) = (uint8_t)(difficulty & 0xff);

	if (needFree)
		free(memory);

	return ws.iterations;
}

uint32_t ZTLF_WharrgarblVerify(const void *pow,const void *in,const unsigned long inlen)
{
	uint64_t hin[3];
	uint64_t hout[2];
	uint64_t collision[2];
	uint64_t powq[2];
	int i;

	for(unsigned int i=0;i<16;++i)
		((uint8_t *)powq)[i] = ((const uint8_t *)pow)[i];
	uint32_t diff32 = ((const uint8_t *)pow)[16];
	diff32 <<= 8;
	diff32 |= ((const uint8_t *)pow)[17];
	diff32 <<= 8;
	diff32 |= ((const uint8_t *)pow)[18];
	diff32 <<= 8;
	diff32 |= ((const uint8_t *)pow)[19];
	const uint64_t difficulty = (((uint64_t)diff32) << 32) | 0x00000000ffffffffULL;

	ZTLF_SpeckHash(hin,in,inlen);

	if ((powq[0] == powq[1])||(!difficulty))
		return 0;

	for(i=0;i<2;++i) {
		hin[2] = powq[i];
		ZTLF_SpeckHash(hout,hin,sizeof(hin));
		collision[i] = ZTLF_ntohll(hout[0] ^ hout[1]) % difficulty;
	}

	return ((collision[0] == collision[1]) ? diff32 : 0ULL);
}
