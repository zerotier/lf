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
#include "score.h"

void ZTLF_Record_keyToId(uint64_t id[4],const void *k,const unsigned long klen)
{
	uint8_t seed[64],priv[64];
	ZTLF_SHA512(seed,k,klen);
	ZTLF_Ed25519CreateKeypair((unsigned char *)id,priv,seed); /* only the first 32 bytes of the hash are used here */
}

bool ZTLF_Record_expand(struct ZTLF_RecordInfo *ri,const struct ZTLF_Record *r,const unsigned long rsize)
{
	if (rsize < ZTLF_RECORD_MIN_SIZE)
		return false;
	if (rsize > ZTLF_RECORD_MAX_SIZE)
		return false;
	if ((r->flags & 0xf) != ZTLF_RECORD_TYPE_ED25519_ED25519_AES256CFB)
		return false;

	ZTLF_Shandwich256(ri->hash,r,rsize);
	ri->r = r;
	ri->size = rsize;
	ri->timestamp = ZTLF_Record_timestamp(r);
	ri->expiration = ri->timestamp + (uint64_t)ri->r->ttl;
	ri->value = NULL;
	ri->idClaimSignatureEd25519 = NULL;
	ri->ownerSignatureEd25519 = NULL;
	ri->wharrgarblPow = NULL;
	ri->weight = ((double)ZTLF_score((const uint8_t *)(ri->hash))) / 4294967295.0;
	ri->linkCount = 0;
	ri->valueSize = 0;

	const uint8_t *p = r->data;
	const uint8_t *eof = p + (rsize - sizeof(struct ZTLF_Record));
	if (p > eof)
		return false;
	while (p < eof) {
		unsigned int fs = *(p++);
		if (p >= eof) return 1;
		fs <<= 8;
		fs |= *(p++);
		const unsigned int ft = (fs >> 12); /* most significant 4 bits are field type */
		fs &= 0xfff; /* least significant 12 bits are size-1 */
		++fs; /* actual size is from 1 to 4096, not 0 to 4095 */

		const uint8_t *const nextp = p + fs;
		if (nextp > eof)
			return 1;

		switch(ft) {
			case ZTLF_RECORD_FIELD_VALUE:
				ri->value = p;
				ri->valueSize = fs;
				break;
			case ZTLF_RECORD_FIELD_LINKS:
				ri->links = p;
				ri->linkCount = fs / 32;
				break;
			case ZTLF_RECORD_FIELD_ID_CLAIM_SIGNATURE:
				if (fs != ZTLF_ED25519_SIGNATURE_SIZE)
					return false;
				ri->idClaimSignatureEd25519 = p;
				break;
			case ZTLF_RECORD_FIELD_OWNER_SIGNATURE:
				if (fs != ZTLF_ED25519_SIGNATURE_SIZE)
					return false;
				ri->ownerSignatureEd25519 = p;
				break;
			case ZTLF_RECORD_FIELD_WHARRGARBL_POW:
				if (fs != ZTLF_WHARRGARBL_POW_BYTES)
					return false;
				ri->wharrgarblPow = p;
				break;
		}

		p = nextp;
	}

	return true;
}

unsigned int ZTLF_Record_open(const struct ZTLF_RecordInfo *ri,void *out,const void *k,const unsigned long klen)
{
	if ((ri->r->flags & ZTLF_RECORD_FLAG_UNMASKED) == 0) {
		uint8_t khash[64];
		ZTLF_AES256CFB c;
		ZTLF_SHA512(khash,k,klen);

		/* For AES256-CFB we use the last 32 bytes of the hash as the AES256 key
		 * and the last 16 bytes of the record header (which includes the last link
		 * and the TTL and timestamp) as the IV. */
		ZTLF_AES256CFB_init(&c,khash + 32,((const uint8_t *)ri->r) + (sizeof(struct ZTLF_Record) - 16),true);
		ZTLF_AES256CFB_crypt(&c,out,ri->value,ri->valueSize);
		ZTLF_AES256CFB_destroy(&c);

		return ri->valueSize;
	} else {
		memcpy(out,ri->value,ri->valueSize);
		return ri->valueSize;
	}
}
