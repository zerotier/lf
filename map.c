/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#include "map.h"

void ZTLF_Map256_init(struct ZTLF_Map256 *m,unsigned long initialBucketCountHint,void (*valueDeleter)(void *))
{
	m->nonce = ZTLF_prng(); /* randomizes bucket allocation */
	initialBucketCountHint >>= 12;
	initialBucketCountHint <<= 12;
	m->bucketCount = (initialBucketCountHint > 4096) ? initialBucketCountHint : 4096;
	ZTLF_MALLOC_CHECK(m->buckets = (struct ZTLF_Map256Entry *)malloc(sizeof(struct ZTLF_Map256Entry) * m->bucketCount));
	memset(m->buckets,0,sizeof(struct ZTLF_Map256Entry) * m->bucketCount);
	m->valueDeleter = valueDeleter;
}

void ZTLF_Map256_destroy(struct ZTLF_Map256 *m)
{
	if (m->buckets) {
		if (m->valueDeleter) {
			for(unsigned long b=0;b<m->bucketCount;++b) {
				if (m->buckets[b].value) {
					m->valueDeleter(m->buckets[b].value);
				}
			}
		}
		free(m->buckets);
	}
	m->buckets = NULL;
}

int ZTLF_Map256_set(struct ZTLF_Map256 *m,const uint64_t k[4],void *v)
{
	const unsigned long bucket = ((unsigned long)ZTLF_xorshift64starOnce(m->nonce ^ k[0] ^ k[1] ^ k[2] ^ k[3])) % m->bucketCount;

	if (!m->buckets[bucket].value) {
		m->buckets[bucket].key[0] = k[0];
		m->buckets[bucket].key[1] = k[1];
		m->buckets[bucket].key[2] = k[2];
		m->buckets[bucket].key[3] = k[3];
		m->buckets[bucket].value = v;
		return 1;
	} else if (ZTLF_eq256qw(m->buckets[bucket].key,k)) {
		if (m->valueDeleter)
			m->valueDeleter(m->buckets[bucket].value);
		m->buckets[bucket].value = v;
		return 0;
	}

	struct ZTLF_Map256 nm;
	nm.nonce = ZTLF_prng();
	nm.valueDeleter = NULL;
	nm.bucketCount = m->bucketCount << 1;
	ZTLF_MALLOC_CHECK(nm.buckets = (struct ZTLF_Map256Entry *)malloc(sizeof(struct ZTLF_Map256Entry) * nm.bucketCount));
	memset(nm.buckets,0,sizeof(struct ZTLF_Map256Entry) * nm.bucketCount);
	for(unsigned long b=0;b<m->bucketCount;++b) {
		if (m->buckets[b].value)
			ZTLF_Map256_set(&nm,m->buckets[b].key,m->buckets[b].value);
	}

	ZTLF_Map256_set(&nm,k,v);

	m->nonce = nm.nonce;
	free(m->buckets);
	m->buckets = nm.buckets;
	m->bucketCount = nm.bucketCount;

	return 1;
}

void ZTLF_Map256_clear(struct ZTLF_Map256 *m)
{
	if (m->valueDeleter) {
		for(unsigned long b=0;b<m->bucketCount;++b) {
			if (m->buckets[b].value) {
				m->valueDeleter(m->buckets[b].value);
				m->buckets[b].value = (void *)0;
			}
		}
	} else {
		memset(m->buckets,0,sizeof(struct ZTLF_Map256Entry) * m->bucketCount);
	}
}
