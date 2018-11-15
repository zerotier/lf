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

#ifndef ZTLF_MAP_H
#define ZTLF_MAP_H

#include "common.h"

/* Set a key to this (NULL) to delete */
#define ZTLF_MAP_VALUE_EMPTY ((void *)0)

struct ZTLF_MapEntry
{
	uint64_t key;
	void *value;
};

struct ZTLF_Map
{
	uint64_t nonce;
	void (*valueDeleter)(void *);
	struct ZTLF_MapEntry *buckets;
	unsigned long bucketCount;
};

/* If valueDeleter is non-NULL it will be used to free values when they're replaced and on map destroy. */
void ZTLF_Map_init(struct ZTLF_Map *m,unsigned long initialBucketCountHint,void (*valueDeleter)(void *));

void ZTLF_Map_destroy(struct ZTLF_Map *m);

/* Set key to NULL to delete; returns >0 if new, 0 if existing */
int ZTLF_Map_set(struct ZTLF_Map *m,const uint64_t k,void *v);

/* Returns NULL if key is not found */
static inline void *ZTLF_Map_get(struct ZTLF_Map *m,const uint64_t k)
{
	const unsigned long bucket = ((unsigned long)ZTLF_xorshift64starOnce(m->nonce ^ k)) % m->bucketCount;
	return ((m->buckets[bucket].key == k) ? m->buckets[bucket].value : (void *)0);
}

void ZTLF_Map_clear(struct ZTLF_Map *m);

/* Iterates by running a command or block of code against all keys. The variables ztlfMapKey and
 * ztlfMapValue are set in the loop to keys and values. ZTLF_Map_set is not safe here, but ztlfMapValue
 * is safe to change in place to change or delete existing keys. A root level "break" in the supplied
 * code fragment will terminate iteration. */
#define ZTLF_Map_each(m,c) \
	for(unsigned long _ztmi_i=0;_ztmi_i<(m)->bucketCount;++_ztmi_i) { \
		if ((m)->buckets[_ztmi_i].value) { \
			const uint64_t ztlfMapKey = (m)->buckets[_ztmi_i].key; \
			void *ztlfMapValue = (void *)(m)->buckets[_ztmi_i].value; \
			c \
			if (ztlfMapValue != (void *)(m)->buckets[_ztmi_i].value) { \
				if ((m)->valueDeleter) \
					(m)->valueDeleter((m)->buckets[_ztmi_i].value); \
				(m)->buckets[_ztmi_i].value = ztlfMapValue; \
			} \
		} \
	}

#endif
