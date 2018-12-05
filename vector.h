/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#ifndef ZTLF_VECTOR_H
#define ZTLF_VECTOR_H

#include "common.h"

#if 0
/* Vector for arbitrary size byte arrays */

struct ZTLF_Vector
{
	void *v;
	uint8_t *p;
	unsigned long size;
	unsigned long esize;
	unsigned long cap;
};

static inline void ZTLF_Vector_init(struct ZTLF_Vector *const vec,const unsigned long elementSize,const unsigned long initialCapacity)
{
	if (initialCapacity > 0) {
		ZTLF_MALLOC_CHECK(vec->v = malloc(elementSize * initialCapacity));
	} else {
		vec->v = NULL;
	}
	vec->p = (uint8_t *)vec->v;
	vec->size = 0;
	vec->esize = elementSize;
	vec->cap = initialCapacity;
}

#define ZTLF_Vector_append(vec,e) { \
	if (unlikely((vec)->size >= (vec)->cap)) { \
		(vec)->cap = ((vec)->cap) ? ((vec)->cap << 1) : 1024; \
		ZTLF_MALLOC_CHECK((vec)->v = realloc((vec)->v,(vec)->esize * (vec)->cap)); \
		(vec)->p = (((uint8_t *)(vec)->v) + ((vec)->size * (vec)->esize)); \
	} \
	memcpy((void *)((vec)->p),(const void *)(e),(vec)->esize); \
	(vec)->p += (vec)->esize; \
	(vec)->size++; \
}

#define ZTLF_Vector_get(vec,i) ((void *)(((uint8_t *)(vec)->p) + ((unsigned long)(i) * (vec)->esize)))

#define ZTLF_Vector_getb(vec,i) (((uint8_t *)(vec)->p) + ((unsigned long)(i) * (vec)->esize))

#define ZTLF_Vector_clear(vec) { (vec)->p = (uint8_t *)(vec)->v; (vec)->size = 0; }

#define ZTLF_Vector_free(vec) if ((vec)->v) { free((vec)->v); }

#endif

/* Vector for 64-bit ints */

struct ZTLF_Vector_i64
{
	int64_t *v;
	unsigned long size;
	unsigned long cap;
};

static inline void ZTLF_Vector_i64_init(struct ZTLF_Vector_i64 *const vec,const unsigned long initialCapacity)
{
	if (initialCapacity > 0) {
		ZTLF_MALLOC_CHECK(vec->v = (int64_t *)malloc(sizeof(int64_t) * initialCapacity));
	} else {
		vec->v = NULL;
	}
	vec->size = 0;
	vec->cap = initialCapacity;
}

#define ZTLF_Vector_i64_append(vec,i) { \
	if (unlikely((vec)->size >= (vec)->cap)) { \
		(vec)->cap = ((vec)->cap) ? ((vec)->cap << 1) : 1024; \
		ZTLF_MALLOC_CHECK((vec)->v = (int64_t *)realloc((vec)->v,sizeof(int64_t) * (vec)->cap)); \
	} \
	(vec)->v[(vec)->size++] = (i); \
}

#define ZTLF_Vector_i64_clear(vec) (vec)->size = 0

#define ZTLF_Vector_i64_free(vec) if ((vec)->v) { free((vec)->v); }

#endif
