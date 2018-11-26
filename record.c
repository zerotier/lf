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

bool ZTLF_Record_expand(struct ZTLF_ExpandedRecord *const er,const struct ZTLF_Record *const r,const unsigned int rsize)
{
	er->valueCipher = (r->algorithms >> 6) & 3;
	er->workAlgorithm = (r->algorithms >> 4) & 3;
	er->idClaimSignatureAlgorithm = (r->algorithms >> 2) & 3;
	er->ownerSignatureAlgorithm = r->algorithms & 3;

	ZTLF_Shandwich256(er->hash,r,rsize);
	er->timestamp = ZTLF_Record_timestamp(r);
	er->ttl = ZTLF_Record_ttl(r);
	er->weight = ZTLF_score((const uint8_t *)er->hash);
	er->size = rsize;

	switch (er->workAlgorithm) {
		case ZTLF_RECORD_ALG_WORK_NONE:
			er->workSize = 0;
			break;
		case ZTLF_RECORD_ALG_WORK_WHARRGARBL:
			er->workSize = ZTLF_WHARRGARBL_POW_BYTES;
			break;
		default:
			return false;
	}
	switch (er->idClaimSignatureAlgorithm) {
		case ZTLF_RECORD_ALG_SIG_ED25519:
			er->idClaimSignatureSize = ZTLF_ED25519_SIGNATURE_SIZE;
			break;
		default:
			return false;
	}
	switch (er->ownerSignatureAlgorithm) {
		case ZTLF_RECORD_ALG_SIG_ED25519:
			er->ownerSignatureSize = ZTLF_ED25519_SIGNATURE_SIZE;
			break;
		default:
			return false;
	}
	er->valueSize = rsize - (er->workSize + er->idClaimSignatureSize + er->ownerSignatureSize + (32 * (unsigned int)r->linkCount));
	if (er->valueSize > rsize)
		return false;

	er->r = r;

	er->value = r->data;
	er->work = ((const uint8_t *)er->value) + er->valueSize;
	er->links = ((const uint8_t *)er->work) + er->workSize;
	er->idClaimSignature = ((const uint8_t *)er->links) + (32 * (unsigned int)r->linkCount);
	er->ownerSignature = ((const uint8_t *)er->idClaimSignature) + er->idClaimSignatureSize;

	return true;
}
