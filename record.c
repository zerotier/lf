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

bool ZTLF_Record_createInit(
	struct ZTLF_RecordBuffer *rb,
	const void *plainTextKey,
	const unsigned long plainTextKeyLength,
	const void *value,
	const unsigned long valueLength,
	const void *ownerPublicKey,
	const uint64_t timestamp,
	const uint64_t ttl,
	const bool encryptValue,
	uint8_t *linkHashPrefix,
	unsigned int linkHashPrefixLength)
{
	if (valueLength > ZTLF_RECORD_MAX_VALUE_SIZE)
		return false;

	uint8_t seed[64]; /* Ed25519 seed (first 32 bytes), secret key for value masking (second 32 bytes) */
	ZTLF_SHA512(seed,plainTextKey,plainTextKeyLength);
	ZTLF_Ed25519CreateKeypair((unsigned char *)rb->data.r.id,(unsigned char *)rb->idClaimPrivateKey,(const unsigned char *)seed);

	memcpy(rb->data.r.owner,ownerPublicKey,ZTLF_ED25519_PUBLIC_KEY_SIZE);
	rb->data.r.timestamp[0] = (uint8_t)((timestamp >> 32) & 0xff);
	rb->data.r.timestamp[1] = (uint8_t)((timestamp >> 24) & 0xff);
	rb->data.r.timestamp[2] = (uint8_t)((timestamp >> 16) & 0xff);
	rb->data.r.timestamp[3] = (uint8_t)((timestamp >> 8) & 0xff);
	rb->data.r.timestamp[4] = (uint8_t)(timestamp & 0xff);
	unsigned int ttlb = (unsigned int)(ttl / ZTLF_RECORD_TTL_INCREMENT_SEC);
	if (ttlb > 255) {
		ttlb = 255;
	} else if (ttlb == 0) {
		ttlb = (ttl > 0) ? 1 : 0;
	}
	rb->data.r.ttl = (uint8_t)ttlb;
	rb->data.r.algorithms = (uint8_t)(
		((encryptValue ? ZTLF_RECORD_ALG_CIPHER_AES256CFB : ZTLF_RECORD_ALG_CIPHER_NONE) << 6) |
		(ZTLF_RECORD_ALG_WORK_WHARRGARBL << 4) |
		(ZTLF_RECORD_ALG_SIG_ED25519 << 2) |
		(ZTLF_RECORD_ALG_SIG_ED25519)
	);
	rb->data.r.valueSize[0] = (uint8_t)(((valueLength) >> 8) & 0xff);
	rb->data.r.valueSize[1] = (uint8_t)(valueLength & 0xff);

	unsigned int s = sizeof(struct ZTLF_Record);
	for(unsigned long i=0;i<valueLength;++i)
		rb->data.b[s++] = ((const uint8_t *)value)[i];

	uint8_t workHash[48],work[ZTLF_WHARRGARBL_POW_BYTES],bestWork[ZTLF_WHARRGARBL_POW_BYTES];
	uint8_t scoringHash[48];
	ZTLF_SHA384(workHash,rb->data.b,s);
	void *workMemory = malloc(ZTLF_RECORD_WHARRGARBL_POW_ITERATION_MEMORY);
	if (!workMemory)
		return false;
	ZTLF_SHA384_CTX sh;
	for(uint32_t bestScore=0;;) {
		ZTLF_wharrgarbl(work,workHash,sizeof(workHash),ZTLF_RECORD_WHARRGARBL_POW_ITERATION_DIFFICULTY,workMemory,ZTLF_RECORD_WHARRGARBL_POW_ITERATION_MEMORY,0);

		ZTLF_SHA384_init(&sh);
		ZTLF_SHA384_update(&sh,rb->data.b,s);
		ZTLF_SHA384_update(&sh,work,ZTLF_WHARRGARBL_POW_BYTES);
		ZTLF_SHA384_final(&sh,scoringHash);
		const uint32_t score = ZTLF_score(scoringHash);

		if (score >= bestScore) {
			bestScore = score;
			memcpy(bestWork,work,ZTLF_WHARRGARBL_POW_BYTES);
		}
	}
	memcpy(rb->data.b + s,bestWork,ZTLF_WHARRGARBL_POW_BYTES);
	s += ZTLF_WHARRGARBL_POW_BYTES;

	rb->size = s;
	return true;
}

bool ZTLF_Record_createFinal(
	struct ZTLF_RecordBuffer *rb,
	const void *links,
	const unsigned int linkCount,
	const void *ownerPrivateKey)
{
}

bool ZTLF_Record_expand(struct ZTLF_ExpandedRecord *const er,const struct ZTLF_Record *const r,const unsigned int rsize)
{
	er->valueCipher = (r->algorithms >> 6) & 3;
	er->workAlgorithm = (r->algorithms >> 4) & 3;
	er->idClaimSignatureAlgorithm = (r->algorithms >> 2) & 3;
	er->ownerSignatureAlgorithm = r->algorithms & 3;

	ZTLF_Shandwich256(er->hash,r,rsize);
	er->timestamp = ZTLF_Record_timestamp(r);
	er->ttl = ZTLF_Record_ttl(r);
	er->size = rsize;

	er->valueSize = ((unsigned int)r->valueSize[0]) << 8;
	er->valueSize |= (unsigned int)r->valueSize[1];
	if (er->valueSize > ZTLF_RECORD_MAX_VALUE_SIZE)
		return false;
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

	er->r = r;

	er->value = r->data;
	er->work = ((const uint8_t *)er->value) + er->valueSize;
	if ((((const uint8_t *)er->value) + er->valueSize) >= (((const uint8_t *)r) + rsize)) return false;
	er->linkCount = *(((const uint8_t *)er->work) + er->workSize);
	er->links = ((const uint8_t *)er->work) + er->workSize + 1;
	er->idClaimSignature = ((const uint8_t *)er->links) + (32 * er->linkCount);
	er->ownerSignature = ((const uint8_t *)er->idClaimSignature) + er->idClaimSignatureSize;
	if ((((const uint8_t *)er->ownerSignature) + er->ownerSignatureSize) > (((const uint8_t *)r) + rsize)) return false;

	if (er->workSize > 0) {
		uint8_t scoringHash[48];
		ZTLF_SHA384(scoringHash,er->value,er->valueSize + er->workSize);
		er->weight = 1.0 + (((double)ZTLF_score(scoringHash)) / 4294967295.0);
	} else {
		er->weight = 1.0;
	}

	return true;
}
