/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#ifndef ZTLF_MAP_H
#define ZTLF_MAP_H

#include "common.h"

#define ZTLF_eq128qw(a,b) (((a)[0] == (b)[0])&&((a)[1] == (b)[1]))
#define ZTLF_eq256qw(a,b) (((a)[0] == (b)[0])&&((a)[1] == (b)[1])&&((a)[2] == (b)[2])&&((a)[3] == (b)[3]))

/****************************************************************************/

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
void ZTLF_Map256_init(struct ZTLF_Map256 *m,unsigned long initialBucketCountHint,void (*valueDeleter)(void *));

void ZTLF_Map256_destroy(struct ZTLF_Map256 *m);

/* Set key to NULL to delete; returns >0 if new, 0 if existing */
bool ZTLF_Map256_set(struct ZTLF_Map256 *m,const uint64_t k[4],void *v);

bool ZTLF_Map256_rename(struct ZTLF_Map256 *m,const uint64_t oldKey[4],const uint64_t newKey[4]);

/* Returns NULL if key is not found */
static inline void *ZTLF_Map256_get(struct ZTLF_Map256 *m,const uint64_t k[4])
{
	const unsigned long bucket = ((unsigned long)(0x9e3779b97f4a7c13ULL * (m->nonce + k[0] + k[1] + k[2] + k[3]))) % m->bucketCount;
	return ((ZTLF_eq256qw(m->buckets[bucket].key,k)) ? m->buckets[bucket].value : (void *)0);
}

void ZTLF_Map256_clear(struct ZTLF_Map256 *m);

/* Iterates by running a command or block of code against all keys. The variables ztlfMapKey and
 * ztlfMapValue are set in the loop to keys and values. ZTLF_Map_set is not safe here, but ztlfMapValue
 * is safe to change in place to change or delete existing keys. A root level "break" in the supplied
 * code fragment will terminate iteration. */
#define ZTLF_Map256_each(m,c) \
	for(unsigned long _ztmi_i=0;_ztmi_i<(m)->bucketCount;++_ztmi_i) { \
		if ((m)->buckets[_ztmi_i].value) { \
			const uint64_t *const ztlfMapKey = (m)->buckets[_ztmi_i].key; \
			void *ztlfMapValue = (void *)(m)->buckets[_ztmi_i].value; \
			c \
			if (ztlfMapValue != (void *)(m)->buckets[_ztmi_i].value) { \
				if ((m)->valueDeleter) \
					(m)->valueDeleter((m)->buckets[_ztmi_i].value); \
				(m)->buckets[_ztmi_i].value = ztlfMapValue; \
			} \
		} \
	}

/* Version of each that omits key to avoid compiler warnings. */
#define ZTLF_Map256_eachValueRO(m,c) \
	for(unsigned long _ztmi_i=0;_ztmi_i<(m)->bucketCount;++_ztmi_i) { \
		if ((m)->buckets[_ztmi_i].value) { \
			void *const ztlfMapValue = (void *)(m)->buckets[_ztmi_i].value; \
			c \
		} \
	}

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
void ZTLF_Map128_init(struct ZTLF_Map128 *m,unsigned long initialBucketCountHint,void (*valueDeleter)(void *));

void ZTLF_Map128_destroy(struct ZTLF_Map128 *m);

/* Set key to NULL to delete; returns >0 if new, 0 if existing */
bool ZTLF_Map128_set(struct ZTLF_Map128 *m,const uint64_t k[2],void *v);

/* Returns NULL if key is not found */
static inline void *ZTLF_Map128_get(struct ZTLF_Map128 *m,const uint64_t k[2])
{
	const unsigned long bucket = ((unsigned long)(0x9e3779b97f4a7c13ULL * (m->nonce + k[0] + k[1]))) % m->bucketCount;
	return ((ZTLF_eq128qw(m->buckets[bucket].key,k)) ? m->buckets[bucket].value : (void *)0);
}

void ZTLF_Map128_clear(struct ZTLF_Map128 *m);

/* Iterates by running a command or block of code against all keys. The variables ztlfMapKey and
 * ztlfMapValue are set in the loop to keys and values. ZTLF_Map_set is not safe here, but ztlfMapValue
 * is safe to change in place to change or delete existing keys. A root level "break" in the supplied
 * code fragment will terminate iteration. */
#define ZTLF_Map128_each(m,c) \
	for(unsigned long _ztmi_i=0;_ztmi_i<(m)->bucketCount;++_ztmi_i) { \
		if ((m)->buckets[_ztmi_i].value) { \
			const uint64_t *const ztlfMapKey = (m)->buckets[_ztmi_i].key; \
			void *ztlfMapValue = (void *)(m)->buckets[_ztmi_i].value; \
			c \
			if (ztlfMapValue != (void *)(m)->buckets[_ztmi_i].value) { \
				if ((m)->valueDeleter) \
					(m)->valueDeleter((m)->buckets[_ztmi_i].value); \
				(m)->buckets[_ztmi_i].value = ztlfMapValue; \
			} \
		} \
	}

/****************************************************************************/

#endif
