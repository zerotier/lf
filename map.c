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

int ZTLF_Map_set(struct ZTLF_Map *m,const uint64_t k,void *v)
{
	const unsigned long bucket = ((unsigned long)ZTLF_xorshift64starOnce(m->nonce ^ k)) % m->bucketCount;

	if (!m->buckets[bucket].value) {
		m->buckets[bucket].key = k;
		m->buckets[bucket].value = v;
		return 1;
	} else if (m->buckets[bucket].key == k) {
		if (m->valueDeleter)
			m->valueDeleter(m->buckets[bucket].value);
		m->buckets[bucket].value = v;
		return 0;
	}

	struct ZTLF_Map nm;
	nm.nonce = ZTLF_prng();
	nm.valueDeleter = NULL;
	nm.bucketCount = m->bucketCount << 1;
	ZTLF_MALLOC_CHECK(nm.buckets = (struct ZTLF_MapEntry *)malloc(sizeof(struct ZTLF_MapEntry) * nm.bucketCount));
	memset(nm.buckets,0,sizeof(struct ZTLF_MapEntry) * nm.bucketCount);
	for(unsigned long b=0;b<m->bucketCount;++b) {
		if (m->buckets[b].value)
			ZTLF_Map_set(&nm,m->buckets[b].key,m->buckets[b].value);
	}

	ZTLF_Map_set(&nm,k,v);

	m->nonce = nm.nonce;
	free(m->buckets);
	m->buckets = nm.buckets;
	m->bucketCount = nm.bucketCount;

	return 1;
}

void ZTLF_Map_clear(struct ZTLF_Map *m)
{
	if (m->valueDeleter) {
		for(unsigned long b=0;b<m->bucketCount;++b) {
			if (m->buckets[b].value) {
				m->valueDeleter(m->buckets[b].value);
				m->buckets[b].value = (void *)0;
			}
		}
	} else {
		memset(m->buckets,0,sizeof(struct ZTLF_MapEntry) * m->bucketCount);
	}
}
