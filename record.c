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

int ZTLF_Record_expand(struct ZTLF_RecordInfo *ri,const struct ZTLF_Record *r,const unsigned long rsize)
{
	uint64_t wresult[3];

	if (rsize < sizeof(struct ZTLF_Record))
		return 1;

	ri->r = r;
	ri->timestamp = ZTLF_Record_timestamp(r);
	ri->expiration = ri->timestamp + ri->r->ttl;
	ri->value = NULL;
	ri->idClaimSignatureEd25519 = NULL;
	ri->ownerSignatureEd25519 = NULL;
	ri->wharrgarblPow = NULL;
	ri->weight = 0.0;
	ri->caSignatureCount = 0;
	ri->valueSize = 0;

	const uint8_t *p = r->data;
	const uint8_t *eof = p + (rsize - sizeof(struct ZTLF_Record));
	if (p > eof)
		return 1;
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
			case ZTLF_RECORD_FIELD_ID_CLAIM_SIGNATURE_ED25519:
				if (fs != ZTLF_ED25519_SIGNATURE_SIZE)
					return 1;
				ri->idClaimSignatureEd25519 = p;
				break;
			case ZTLF_RECORD_FIELD_OWNER_SIGNATURE_ED25519:
				if (fs != ZTLF_ED25519_SIGNATURE_SIZE)
					return 1;
				ri->ownerSignatureEd25519 = p;
				break;
			case ZTLF_RECORD_FIELD_CA_SIGNATURE_ED25519:
				if (fs != ZTLF_ED25519_SIGNATURE_SIZE)
					return 1;
				if (ri->caSignatureCount >= ZTLF_RECORD_MAX_CA_SIGNATURES) return 1;
				ri->caSignatureEd25519[ri->caSignatureCount++] = p;
				break;
			case ZTLF_RECORD_FIELD_WHARRGARBL_POW:
				if (fs != ZTLF_WHARRGARBL_SIZE_BYTES)
					return 1;
				ri->wharrgarblPow = p;
				memcpy(wresult,p,sizeof(wresult));
				ri->weight += ((double)ZTLF_wharrgarblGetDifficulty(wresult)) / ((double)0xffffffffffffffffULL);
				break;
		}

		p = nextp;
	}

	return 0;
}
