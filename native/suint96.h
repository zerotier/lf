/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c)2019-2021 ZeroTier, Inc.
 * https://www.zerotier.com/
 */

#ifndef ZTLF_SUINT96_H
#define ZTLF_SUINT96_H

#include "common.h"
#include "mappedfile.h"

/**
 * A memory mapped 96-bit unsigned integer array that is striped across three files.
 *
 * The purpose of this is to store weights. Weights are constantly increased, causing
 * their least significant 32 bits to change frequently and more significant parts to
 * change much less often. Striping this across files dramatically decreases unnecessary
 * bytes written to disk by writing less frequently modified parts of the total weight
 * much less often. It trades a bit of extra CPU and read overhead for a large decrease
 * in write IOPs, and reads are generally much faster than writes (and don't wear SSDs).
 */
struct ZTLF_SUInt96
{
	struct ZTLF_MappedFile l,m,h;
	pthread_mutex_t lock;
};

static inline int ZTLF_SUint96_Open(struct ZTLF_SUInt96 *sui,const char *path)
{
	char ptmp[PATH_MAX];
	snprintf(ptmp,sizeof(ptmp),"%s.b00",path);
	int r = ZTLF_MappedFile_Open(&sui->l,ptmp,1048576,1048576);
	if (r) {
		return r;
	}
	snprintf(ptmp,sizeof(ptmp),"%s.b32",path);
	r = ZTLF_MappedFile_Open(&sui->m,ptmp,1048576,1048576);
	if (r) {
		ZTLF_MappedFile_Close(&sui->l);
		return r;
	}
	snprintf(ptmp,sizeof(ptmp),"%s.b64",path);
	r = ZTLF_MappedFile_Open(&sui->h,ptmp,1048576,1048576);
	if (r) {
		ZTLF_MappedFile_Close(&sui->l);
		ZTLF_MappedFile_Close(&sui->m);
		return r;
	}
	pthread_mutex_init(&sui->lock,NULL);
	return 0;
}

static inline void ZTLF_SUint96_Close(struct ZTLF_SUInt96 *sui)
{
	pthread_mutex_lock(&sui->lock);
	ZTLF_MappedFile_Close(&sui->l);
	ZTLF_MappedFile_Close(&sui->m);
	ZTLF_MappedFile_Close(&sui->h);
	pthread_mutex_unlock(&sui->lock);
	pthread_mutex_destroy(&sui->lock);
}

static inline void ZTLF_SUint96_Get(struct ZTLF_SUInt96 *sui,const uintptr_t i,uint32_t *u96l,uint32_t *u96m,uint32_t *u96h)
{
	pthread_mutex_lock(&sui->lock);
	const uint32_t *const l = (const uint32_t *)ZTLF_MappedFile_TryGet(&sui->l,4 * i,4);
	const uint32_t *const m = (const uint32_t *)ZTLF_MappedFile_TryGet(&sui->m,4 * i,4);
	const uint32_t *const h = (const uint32_t *)ZTLF_MappedFile_TryGet(&sui->h,4 * i,4);
	if ((l)&&(m)&&(h)) {
		*u96l = ZTLF_getu32_le(*l);
		*u96m = ZTLF_getu32_le(*m);
		*u96h = ZTLF_getu32_le(*h);
	} else {
		*u96l = 0;
		*u96m = 0;
		*u96h = 0;
	}
	pthread_mutex_unlock(&sui->lock);
}

static inline void ZTLF_SUint96_Set(struct ZTLF_SUInt96 *sui,const uintptr_t i,const uint32_t u96l,const uint32_t u96m,const uint32_t u96h)
{
	pthread_mutex_lock(&sui->lock);
	uint32_t *const l = (uint32_t *)ZTLF_MappedFile_Get(&sui->l,4 * i,4);
	uint32_t *const m = (uint32_t *)ZTLF_MappedFile_Get(&sui->m,4 * i,4);
	uint32_t *const h = (uint32_t *)ZTLF_MappedFile_Get(&sui->h,4 * i,4);
	if ((l)&&(m)&&(h)) {
		ZTLF_setu32_le(*l,u96l);
		ZTLF_setu32_le(*m,u96m);
		ZTLF_setu32_le(*h,u96h);
	}
	pthread_mutex_unlock(&sui->lock);
}

static inline void ZTLF_SUint96_Add(struct ZTLF_SUInt96 *sui,const uintptr_t i,const uint32_t u96l,const uint32_t u96m,const uint32_t u96h)
{
	pthread_mutex_lock(&sui->lock);
	uint32_t *const l = (uint32_t *)ZTLF_MappedFile_Get(&sui->l,4 * i,4);
	uint32_t *const m = (uint32_t *)ZTLF_MappedFile_Get(&sui->m,4 * i,4);
	uint32_t *const h = (uint32_t *)ZTLF_MappedFile_Get(&sui->h,4 * i,4);
	if ((l)&&(m)&&(h)) {
		uint32_t ll = ZTLF_getu32_le(*l);
		const uint32_t oldll = ll;
		ll += u96l;
		ZTLF_setu32_le(*l,ll);
		if ((ll < oldll)||(u96m != 0)) {
			uint32_t mm = ZTLF_getu32_le(*m);
			const uint32_t oldmm = mm;
			mm += (uint32_t)(ll < oldll);
			mm += u96m;
			ZTLF_setu32_le(*m,mm);
			if ((mm < oldmm)||(u96h != 0)) {
				uint32_t hh = ZTLF_getu32_le(*h);
				hh += (uint32_t)(mm < oldmm);
				hh += u96h;
				ZTLF_setu32_le(*h,hh);
			}
		}
	}
	pthread_mutex_unlock(&sui->lock);
}

#endif
