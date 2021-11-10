/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c)2019-2021 ZeroTier, Inc.
 * https://www.zerotier.com/
 */

#ifndef ZTLF_VECTOR_H
#define ZTLF_VECTOR_H

#include "common.h"

/* Vector for pointers */

struct ZTLF_Vector
{
	void **v;
	unsigned long size;
	unsigned long cap;
};

static inline void ZTLF_Vector_Init(struct ZTLF_Vector *const vec,const unsigned long initialCapacity)
{
	if (initialCapacity > 0) {
		ZTLF_MALLOC_CHECK(vec->v = (void **)malloc(sizeof(void *) * initialCapacity));
	} else {
		vec->v = NULL;
	}
	vec->size = 0;
	vec->cap = initialCapacity;
}

#define ZTLF_Vector_Append(vec,i) { \
	if (unlikely((vec)->size >= (vec)->cap)) { \
		(vec)->cap = ((vec)->cap) ? ((vec)->cap << 1) : 1024; \
		ZTLF_MALLOC_CHECK((vec)->v = (void **)realloc((vec)->v,sizeof(void *) * (vec)->cap)); \
	} \
	(vec)->v[(vec)->size++] = (i); \
}

#define ZTLF_Vector_Clear(vec) (vec)->size = 0

#define ZTLF_Vector_Free(vec) if ((vec)->v) { free((vec)->v); }

/* Vector for 64-bit ints */

struct ZTLF_Vector_i64
{
	int64_t *v;
	unsigned long size;
	unsigned long cap;
};

static inline void ZTLF_Vector_i64_Init(struct ZTLF_Vector_i64 *const vec,const unsigned long initialCapacity)
{
	if (initialCapacity > 0) {
		ZTLF_MALLOC_CHECK(vec->v = (int64_t *)malloc(sizeof(int64_t) * initialCapacity));
	} else {
		vec->v = NULL;
	}
	vec->size = 0;
	vec->cap = initialCapacity;
}

#define ZTLF_Vector_i64_Append(vec,i) { \
	if (unlikely((vec)->size >= (vec)->cap)) { \
		(vec)->cap = ((vec)->cap) ? ((vec)->cap << 1) : 1024; \
		ZTLF_MALLOC_CHECK((vec)->v = (int64_t *)realloc((vec)->v,sizeof(int64_t) * (vec)->cap)); \
	} \
	(vec)->v[(vec)->size++] = (i); \
}

#define ZTLF_Vector_i64_Clear(vec) (vec)->size = 0

#define ZTLF_Vector_i64_Free(vec) if ((vec)->v) { free((vec)->v); }

#endif
