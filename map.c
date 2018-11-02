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

#include "map.h"

void ZTLF_Map_init(struct ZTLF_Map *m,unsigned long initialBucketCountHint,void (*valueDeleter)(void *))
{
	m->nonce = ZTLF_prng(); /* randomizes bucket allocation */
	initialBucketCountHint >>= 12;
	initialBucketCountHint <<= 12;
	m->bucketCount = (initialBucketCountHint > 4096) ? initialBucketCountHint : 4096;
	ZTLF_MALLOC_CHECK(m->buckets = (struct ZTLF_MapEntry *)malloc(sizeof(struct ZTLF_MapEntry) * m->bucketCount));
	memset(m->buckets,0,sizeof(struct ZTLF_MapEntry) * m->bucketCount);
	m->valueDeleter = valueDeleter;
}

void ZTLF_Map_destroy(struct ZTLF_Map *m)
{
	for(unsigned long b=0;b<m->bucketCount;++b) {
		if (m->buckets[b].value) {
			if (m->valueDeleter)
				m->valueDeleter(m->buckets[b].value);
		}
	}
	free(m->buckets);
}

int ZTLF_Map_set(struct ZTLF_Map *m,const void *k,const unsigned long klen,void *v)
{
	uint64_t key[ZTLF_MAP_MAX_KEY_SIZE / 8];
	for(unsigned long i=0;i<klen;i++)
		((uint8_t *)key)[i] = ((const uint8_t *)k)[i];
	for(unsigned long i=klen;i<ZTLF_MAP_MAX_KEY_SIZE;++i)
		((uint8_t *)key)[i % ZTLF_MAP_MAX_KEY_SIZE] = 0;
	uint64_t hash = m->nonce;
	for(unsigned long i=0;i<(ZTLF_MAP_MAX_KEY_SIZE / 8);++i)
		hash += ZTLF_xorshift64star(hash + key[i]);
	const unsigned long bucket = ((unsigned long)hash) % m->bucketCount;

	if (!m->buckets[bucket].value) {
		for(unsigned long i=0;i<(ZTLF_MAP_MAX_KEY_SIZE / 8);++i)
			m->buckets[bucket].key[i] = key[i];
		m->buckets[bucket].value = v;
		return 1;
	} else if (!memcmp(m->buckets[bucket].key,key,ZTLF_MAP_MAX_KEY_SIZE)) {
		if (m->buckets[bucket].value != v) {
			if (m->valueDeleter)
				m->valueDeleter(m->buckets[bucket].value);
			m->buckets[bucket].value = v;
		}
		return 0;
	}

	struct ZTLF_Map nm;
	nm.nonce = ZTLF_prng();
	nm.bucketCount = m->bucketCount << 1;
	ZTLF_MALLOC_CHECK(nm.buckets = (struct ZTLF_MapEntry *)malloc(sizeof(struct ZTLF_MapEntry) * nm.bucketCount));
	memset(nm.buckets,0,sizeof(struct ZTLF_MapEntry) * nm.bucketCount);
	nm.valueDeleter = NULL;
	for(unsigned long b=0;b<m->bucketCount;++b) {
		if (m->buckets[b].value)
			ZTLF_Map_set(&nm,m->buckets[b].key,ZTLF_MAP_MAX_KEY_SIZE,m->buckets[b].value);
	}

	m->nonce = nm.nonce;
	m->bucketCount = nm.bucketCount;
	free(m->buckets);
	m->buckets = nm.buckets;

	return 1;
}

void *ZTLF_Map_get(struct ZTLF_Map *m,const void *k,const unsigned long klen)
{
	uint64_t key[ZTLF_MAP_MAX_KEY_SIZE / 8];
	for(unsigned long i=0;i<klen;i++)
		((uint8_t *)key)[i % ZTLF_MAP_MAX_KEY_SIZE] = ((const uint8_t *)k)[i];
	for(unsigned long i=klen;i<ZTLF_MAP_MAX_KEY_SIZE;++i)
		((uint8_t *)key)[i] = 0;
	uint64_t hash = m->nonce;
	for(unsigned long i=0;i<(ZTLF_MAP_MAX_KEY_SIZE / 8);++i)
		hash += ZTLF_xorshift64star(hash + key[i]);
	const unsigned long bucket = ((unsigned long)hash) % m->bucketCount;

	if (!memcmp(m->buckets[bucket].key,key,ZTLF_MAP_MAX_KEY_SIZE))
		return m->buckets[bucket].value;
	return (void *)0;
}
