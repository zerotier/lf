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

#include "record.h"
#include "sha.h"
#include "wharrgarbl.h"

void ZTLF_Record_idOwnerHash(const struct ZTLF_Record *r,uint64_t out[3])
{
	uint64_t tmp[6];
	ZTLF_SHA384_CTX h;

	ZTLF_SHA384_init(&h);
	ZTLF_SHA384_update(&h,r->id,sizeof(r->id));
	ZTLF_SHA384_update(&h,r->owner,sizeof(r->owner));
	ZTLF_SHA384_final(&h,tmp);

	ZTLF_SHA384_init(&h);
	ZTLF_SHA384_update(&h,tmp,sizeof(tmp));
	ZTLF_SHA384_update(&h,r->owner,sizeof(r->owner));
	ZTLF_SHA384_final(&h,tmp);

	out[0] = tmp[0] ^ tmp[1];
	out[1] = tmp[2] ^ tmp[3];
	out[2] = tmp[4] ^ tmp[5];
}

double ZTLF_Record_getInternalWeight(const struct ZTLF_Record *r,const unsigned long rsize)
{
	const uint8_t *const eof = ((uint8_t *)r) + rsize;
	const uint8_t *p;
	double w = 0.0;

	switch(r->flags & ZTLF_RECORD_FLAGS_MASK_TYPE) {
		case ZTLF_RECORD_TYPE_ED25519_AES256CFB:
			p = ((uint8_t *)r) + sizeof(struct ZTLF_Record) + 1 + r->p.t0.valueSize;
			break;
		default:
			return 0.0;
	}

	while (p < eof) {
		const uint8_t ft = *p;
		if (++p >= eof) break;
		unsigned long fs = ((unsigned long)*p) << 8;
		if (++p >= eof) break;
		fs |= (unsigned long)*p;
		if (++p >= eof) break;

		switch(ft) {
			case ZTLF_RECORD_ATTACHMENT_TYPE_WHARRGARBL_POW:
				if (fs == ZTLF_WHARRGARBL_SIZE_BYTES) {
					uint64_t tmp[ZTLF_WHARRGARBL_SIZE_QW];
					memcpy(tmp,p,ZTLF_WHARRGARBL_SIZE_BYTES);
					w += ((double)ZTLF_wharrgarblGetDifficulty(tmp)) / (double)(0xffffffffffffffffULL);
				}
				break;
		}

		p += fs;
	}

	return w;
}
