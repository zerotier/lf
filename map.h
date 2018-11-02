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

/* Can be increased, but must be a multiple of 8. Keys larger than this may collide!. */
#define ZTLF_MAP_MAX_KEY_SIZE 32

/* Set a key to this (NULL) to delete */
#define ZTLF_MAP_VALUE_EMPTY ((void *)0)

/* Use this value for set-like behavior */
#define ZTLF_MAP_VALUE_SET   ((void *)1)

struct ZTLF_MapEntry
{
	uint64_t key[ZTLF_MAP_MAX_KEY_SIZE / 8];
	void *value;
};

struct ZTLF_Map
{
	uint64_t nonce;
	unsigned long bucketCount;
	struct ZTLF_MapEntry *buckets;
	void (*valueDeleter)(void *);
};

/* If valueDeleter is non-NULL it will be used to free values when they're replaced and on map destroy */
void ZTLF_Map_init(struct ZTLF_Map *m,unsigned long initialBucketCountHint,void (*valueDeleter)(void *));

void ZTLF_Map_destroy(struct ZTLF_Map *m);

/* Set key to NULL to delete */
int ZTLF_Map_set(struct ZTLF_Map *m,const void *k,const unsigned long klen,void *v);

/* Returns NULL if key is not found */
void *ZTLF_Map_get(struct ZTLF_Map *m,const void *k,const unsigned long klen);

/* Iterates by running a command or block of code against all keys. The variables ztlfMapKey and
 * ztlfMapValue are set in the loop to keys and values. It's up to the code to know what the
 * key length should be. It's unsafe to structurally change the map here, though the ztlfMapValue
 * temporary variable can be changed or set to NULL to delete. Using "break" in the code (at its
 * top level) will terminate iteration. Iteration cannot be nested. */
#define ZTLF_Map_iterate(m,c) \
	for(unsigned long _ztmi_i=0;_ztmi_i<(m)->bucketCount;++_ztmi_i) { \
		if ((m)->buckets[_ztmi_i].value) { \
			const void *const ztlfMapKey = (void *)(m)->buckets[_ztmi_i].key; \
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
