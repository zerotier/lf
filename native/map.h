/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * --
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial closed-source software that incorporates or links
 * directly against ZeroTier software without disclosing the source code
 * of your own application.
 */

#ifndef ZTLF_MAP_H
#define ZTLF_MAP_H

#include "common.h"

#define ZTLF_eq128qw(a,b) (((a)[0] == (b)[0])&&((a)[1] == (b)[1]))
#define ZTLF_eq256qw(a,b) (((a)[0] == (b)[0])&&((a)[1] == (b)[1])&&((a)[2] == (b)[2])&&((a)[3] == (b)[3]))

/****************************************************************************/

#if 0
struct ZTLF_Map256Entry
{
	uint64_t key[4];
	void *value;
};

struct ZTLF_Map256
{
	uint64_t nonce;
	void (*valueDeleter)(void *);
	struct ZTLF_Map256Entry *buckets;
	unsigned long bucketCount;
};

/* If valueDeleter is non-NULL it will be used to free values when they're replaced and on map destroy. */
static inline void ZTLF_Map256_Init(struct ZTLF_Map256 *m,unsigned long initialBucketCountHint,void (*valueDeleter)(void *))
{
	m->nonce = (((uint64_t)rand()) << 32) ^ (uint64_t)rand(); /* randomizes bucket allocation */
	initialBucketCountHint >>= 12;
	initialBucketCountHint <<= 12;
	m->bucketCount = (initialBucketCountHint > 4096) ? initialBucketCountHint : 4096;
	ZTLF_MALLOC_CHECK(m->buckets = (struct ZTLF_Map256Entry *)malloc(sizeof(struct ZTLF_Map256Entry) * m->bucketCount));
	memset(m->buckets,0,sizeof(struct ZTLF_Map256Entry) * m->bucketCount);
	m->valueDeleter = valueDeleter;
}

static inline void ZTLF_Map256_Destroy(struct ZTLF_Map256 *m)
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

/* Set key to NULL to delete; returns >0 if new, 0 if existing */
static inline bool ZTLF_Map256_Set(struct ZTLF_Map256 *m,const uint64_t k[4],void *v)
{
	const unsigned long bucket = ((unsigned long)(0x9e3779b97f4a7c13ULL * (m->nonce + k[0] + k[1] + k[2] + k[3]))) % m->bucketCount;

	if (!m->buckets[bucket].value) {
		m->buckets[bucket].key[0] = k[0];
		m->buckets[bucket].key[1] = k[1];
		m->buckets[bucket].key[2] = k[2];
		m->buckets[bucket].key[3] = k[3];
		m->buckets[bucket].value = v;
		return true;
	} else if (ZTLF_eq256qw(m->buckets[bucket].key,k)) {
		if (m->valueDeleter)
			m->valueDeleter(m->buckets[bucket].value);
		m->buckets[bucket].value = v;
		return false;
	}

	struct ZTLF_Map256 nm;
	nm.nonce = (((uint64_t)rand()) << 32) ^ (uint64_t)rand();
	nm.valueDeleter = NULL;
	nm.bucketCount = m->bucketCount << 1;
	ZTLF_MALLOC_CHECK(nm.buckets = (struct ZTLF_Map256Entry *)malloc(sizeof(struct ZTLF_Map256Entry) * nm.bucketCount));
	memset(nm.buckets,0,sizeof(struct ZTLF_Map256Entry) * nm.bucketCount);
	for(unsigned long b=0;b<m->bucketCount;++b) {
		if (m->buckets[b].value)
			ZTLF_Map256_Set(&nm,m->buckets[b].key,m->buckets[b].value);
	}

	ZTLF_Map256_Set(&nm,k,v);

	m->nonce = nm.nonce;
	free(m->buckets);
	m->buckets = nm.buckets;
	m->bucketCount = nm.bucketCount;

	return true;
}

static inline bool ZTLF_Map256_Rename(struct ZTLF_Map256 *m,const uint64_t oldKey[4],const uint64_t newKey[4])
{
	const unsigned long oldBucket = ((unsigned long)(0x9e3779b97f4a7c13ULL * (m->nonce + oldKey[0] + oldKey[1] + oldKey[2] + oldKey[3]))) % m->bucketCount;
	if ((m->buckets[oldBucket].value)&&(ZTLF_eq256qw(m->buckets[oldBucket].key,oldKey))) {
		void *oldValue = m->buckets[oldBucket].value;
		m->buckets[oldBucket].value = NULL;
		return ZTLF_Map256_Set(m,newKey,oldValue);
	}
	return false;
}

/* Returns NULL if key is not found */
static inline void *ZTLF_Map256_Get(struct ZTLF_Map256 *m,const uint64_t k[4])
{
	const unsigned long bucket = ((unsigned long)(0x9e3779b97f4a7c13ULL * (m->nonce + k[0] + k[1] + k[2] + k[3]))) % m->bucketCount;
	return ((ZTLF_eq256qw(m->buckets[bucket].key,k)) ? m->buckets[bucket].value : (void *)0);
}

static inline void ZTLF_Map256_Clear(struct ZTLF_Map256 *m)
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

/* Iterates by running a command or block of code against all keys. The variables ztlfMapKey and
 * ztlfMapValue are set in the loop to keys and values. ZTLF_Map_set is not safe here, but ztlfMapValue
 * is safe to change in place to change or delete existing keys. A root level "break" in the supplied
 * code fragment will terminate iteration. */
#define ZTLF_Map256_Each(m,c) \
	for(unsigned long _ztmi_i=0;_ztmi_i<(m)->bucketCount;++_ztmi_i) { \
		if ((m)->buckets[_ztmi_i].value) { \
			const uint64_t *const ztlfMapKey = (m)->buckets[_ztmi_i].key; \
			void *ztlfMapValue = (void *)(m)->buckets[_ztmi_i].value; \
			c \
			if (ztlfMapValue != (void *)(m)->buckets[_ztmi_i].value) { \
				if ((m)->valueDeleter) (m)->valueDeleter((m)->buckets[_ztmi_i].value); \
				(m)->buckets[_ztmi_i].value = ztlfMapValue; \
			} \
		} \
	}

/* Version of each that omits key to avoid compiler warnings. */
#define ZTLF_Map256_EachValueRO(m,c) \
	for(unsigned long _ztmi_i=0;_ztmi_i<(m)->bucketCount;++_ztmi_i) { \
		if ((m)->buckets[_ztmi_i].value) { \
			void *const ztlfMapValue = (void *)(m)->buckets[_ztmi_i].value; \
			c \
		} \
	}

/* Version of each that also deletes entries after executing the block. */
#define ZTLF_Map256_EachAndClear(m,c) \
	for(unsigned long _ztmi_i=0;_ztmi_i<(m)->bucketCount;++_ztmi_i) { \
		if ((m)->buckets[_ztmi_i].value) { \
			const uint64_t *const ztlfMapKey = (m)->buckets[_ztmi_i].key; \
			void *const ztlfMapValue = (void *)(m)->buckets[_ztmi_i].value; \
			c \
			if ((m)->valueDeleter) (m)->valueDeleter((m)->buckets[_ztmi_i].value); \
			(m)->buckets[_ztmi_i].value = (void *)0; \
		} \
	}
#endif

/****************************************************************************/

struct ZTLF_Map128Entry
{
	uint64_t key[2];
	void *value;
};

struct ZTLF_Map128
{
	uint64_t nonce;
	void (*valueDeleter)(void *);
	struct ZTLF_Map128Entry *buckets;
	unsigned long bucketCount;
};

/* If valueDeleter is non-NULL it will be used to free values when they're replaced and on map destroy. */
static inline void ZTLF_Map128_Init(struct ZTLF_Map128 *m,unsigned long initialBucketCountHint,void (*valueDeleter)(void *))
{
	m->nonce = (((uint64_t)rand()) << 32) ^ (uint64_t)rand(); /* randomizes bucket allocation */
	initialBucketCountHint >>= 12;
	initialBucketCountHint <<= 12;
	m->bucketCount = (initialBucketCountHint > 4096) ? initialBucketCountHint : 4096;
	ZTLF_MALLOC_CHECK(m->buckets = (struct ZTLF_Map128Entry *)malloc(sizeof(struct ZTLF_Map128Entry) * m->bucketCount));
	memset(m->buckets,0,sizeof(struct ZTLF_Map128Entry) * m->bucketCount);
	m->valueDeleter = valueDeleter;
}

static inline void ZTLF_Map128_Destroy(struct ZTLF_Map128 *m)
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

/* Set key to NULL to delete; returns >0 if new, 0 if existing */
static inline bool ZTLF_Map128_Set(struct ZTLF_Map128 *m,const uint64_t k[2],void *v)
{
	const unsigned long bucket = ((unsigned long)(0x9e3779b97f4a7c13ULL * (m->nonce + k[0] + k[1]))) % m->bucketCount;

	if (!m->buckets[bucket].value) {
		m->buckets[bucket].key[0] = k[0];
		m->buckets[bucket].key[1] = k[1];
		m->buckets[bucket].value = v;
		return true;
	} else if (ZTLF_eq128qw(m->buckets[bucket].key,k)) {
		if (m->valueDeleter)
			m->valueDeleter(m->buckets[bucket].value);
		m->buckets[bucket].value = v;
		return false;
	}

	struct ZTLF_Map128 nm;
	nm.nonce = (((uint64_t)rand()) << 32) ^ (uint64_t)rand();
	nm.valueDeleter = NULL;
	nm.bucketCount = m->bucketCount << 1;
	ZTLF_MALLOC_CHECK(nm.buckets = (struct ZTLF_Map128Entry *)malloc(sizeof(struct ZTLF_Map128Entry) * nm.bucketCount));
	memset(nm.buckets,0,sizeof(struct ZTLF_Map128Entry) * nm.bucketCount);
	for(unsigned long b=0;b<m->bucketCount;++b) {
		if (m->buckets[b].value)
			ZTLF_Map128_Set(&nm,m->buckets[b].key,m->buckets[b].value);
	}

	ZTLF_Map128_Set(&nm,k,v);

	m->nonce = nm.nonce;
	free(m->buckets);
	m->buckets = nm.buckets;
	m->bucketCount = nm.bucketCount;

	return true;
}

/* Returns NULL if key is not found */
static inline void *ZTLF_Map128_Get(struct ZTLF_Map128 *m,const uint64_t k[2])
{
	const unsigned long bucket = ((unsigned long)(0x9e3779b97f4a7c13ULL * (m->nonce + k[0] + k[1]))) % m->bucketCount;
	return ((ZTLF_eq128qw(m->buckets[bucket].key,k)) ? m->buckets[bucket].value : (void *)0);
}

static inline void ZTLF_Map128_Clear(struct ZTLF_Map128 *m)
{
	if (m->valueDeleter) {
		for(unsigned long b=0;b<m->bucketCount;++b) {
			if (m->buckets[b].value) {
				m->valueDeleter(m->buckets[b].value);
				m->buckets[b].value = (void *)0;
			}
		}
	} else {
		memset(m->buckets,0,sizeof(struct ZTLF_Map128Entry) * m->bucketCount);
	}
}

/* Iterates by running a command or block of code against all keys. The variables ztlfMapKey and
 * ztlfMapValue are set in the loop to keys and values. ZTLF_Map_set is not safe here, but ztlfMapValue
 * is safe to change in place to change or delete existing keys. A root level "break" in the supplied
 * code fragment will terminate iteration. */
#define ZTLF_Map128_Each(m,c) \
	for(unsigned long _ztmi_i=0;_ztmi_i<(m)->bucketCount;++_ztmi_i) { \
		if ((m)->buckets[_ztmi_i].value) { \
			const uint64_t *const ztlfMapKey = (m)->buckets[_ztmi_i].key; \
			void *ztlfMapValue = (void *)(m)->buckets[_ztmi_i].value; \
			c \
			if (ztlfMapValue != (void *)(m)->buckets[_ztmi_i].value) { \
				if ((m)->valueDeleter) (m)->valueDeleter((m)->buckets[_ztmi_i].value); \
				(m)->buckets[_ztmi_i].value = ztlfMapValue; \
			} \
		} \
	}

/****************************************************************************/

#endif
