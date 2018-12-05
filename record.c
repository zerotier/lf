/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#include "record.h"
#include "score.h"

void ZTLF_Record_keyToId(uint64_t id[4],const void *k,const unsigned long klen)
{
	uint8_t seed[64],priv[64];
	ZTLF_SHA512(seed,k,klen);
	ZTLF_Ed25519CreateKeypair((unsigned char *)id,priv,seed); /* only the first 32 bytes of the hash are used here */
}

int ZTLF_Record_create(
	struct ZTLF_RecordBuffer *rb,
	const void *plainTextKey,
	unsigned int plainTextKeyLength,
	const void *value,
	unsigned int valueLength,
	const void *ownerPublicKey,
	const void *ownerPrivateKey,
	const void *links,
	unsigned int linkCount,
	uint64_t timestamp,
	uint64_t ttl,
	bool skipWork,
	bool encryptValue,
	bool (*statusCallback)(uint32_t,uint32_t))
{
	if (valueLength > ZTLF_RECORD_MAX_VALUE_SIZE)
		return ZTLF_ERR_OBJECT_TOO_LARGE;
	if (linkCount > 0x1f)
		linkCount = 0x1f;

	/* Create ID and ID claim signing secret by using a hash of the plain text key to generate an ed25519 key pair. */
	uint8_t seed[64]; /* first 32 bytes are used as ed25519 seed to generate pair, second 32 bytes are used for optional value masking encryption */
	ZTLF_SHA512(seed,plainTextKey,plainTextKeyLength);
	ZTLF_Ed25519CreateKeypair((unsigned char *)rb->data.r.id,(unsigned char *)rb->idClaimPrivateKey,(const unsigned char *)seed);

	/* Owner is owner public key (no hashing is needed for ed25519 since key size == owner field size) */
	memcpy(rb->data.r.owner,ownerPublicKey,ZTLF_ED25519_PUBLIC_KEY_SIZE);

	rb->data.r.timestamp[0] = (uint8_t)((timestamp >> 32) & 0xff);
	rb->data.r.timestamp[1] = (uint8_t)((timestamp >> 24) & 0xff);
	rb->data.r.timestamp[2] = (uint8_t)((timestamp >> 16) & 0xff);
	rb->data.r.timestamp[3] = (uint8_t)((timestamp >> 8) & 0xff);
	rb->data.r.timestamp[4] = (uint8_t)(timestamp & 0xff);
	uint8_t ttlb;
	if (ttl == ZTLF_TTL_FOREVER) {
		ttlb = 255;
	} else if (ttl == 0) {
		ttlb = 0;
	} else {
		ttl /= ZTLF_RECORD_TTL_INCREMENT_SEC;
		if (ttl >= 254)
			ttlb = 254;
		else if (ttl == 0)
			ttlb = 1;
		else ttlb = (uint8_t)ttl;
	}
	rb->data.r.ttl = ttlb;
	rb->data.r.algorithms = (uint8_t)(
		((encryptValue ? ZTLF_RECORD_ALG_CIPHER_AES256CFB : ZTLF_RECORD_ALG_CIPHER_NONE) << 6) |
		(ZTLF_RECORD_ALG_WORK_WHARRGARBL << 4) |
		(ZTLF_RECORD_ALG_SIG_ED25519 << 2) |
		(ZTLF_RECORD_ALG_SIG_ED25519)
	);
	rb->data.r.metadata = 0;
	const unsigned long vlSize = ((linkCount & 0x1f) << 11) | (valueLength & 0x7ff);
	rb->data.r.vlSize[0] = (uint8_t)(((vlSize) >> 8) & 0xff);
	rb->data.r.vlSize[1] = (uint8_t)(vlSize & 0xff);

	unsigned int s = sizeof(struct ZTLF_Record);
	if (encryptValue) {
		uint8_t ivHash[48];
		ZTLF_SHA384(ivHash,rb->data.b,sizeof(struct ZTLF_Record));
		ZTLF_AES256CFB c;
		ZTLF_AES256CFB_init(&c,seed + 32,ivHash,true);
		ZTLF_AES256CFB_crypt(&c,rb->data.b + s,value,valueLength);
		ZTLF_AES256CFB_destroy(&c);
		s += valueLength;
	} else {
		for(unsigned int i=0;i<valueLength;++i)
			rb->data.b[s++] = ((const uint8_t *)value)[i];
	}
	for(unsigned int i=0,j=(linkCount*32);i<j;++i)
		rb->data.b[s++] = ((const uint8_t *)links)[i];

	const unsigned int neededBytes = s + ZTLF_WHARRGARBL_POW_BYTES + ZTLF_ED25519_SIGNATURE_SIZE + ZTLF_ED25519_SIGNATURE_SIZE;
	if (neededBytes > ZTLF_RECORD_MAX_SIZE) /* sanity check, should be impossible */
		return ZTLF_ERR_OBJECT_TOO_LARGE;
	uint64_t neededScore64 = (uint64_t)neededBytes * (uint64_t)ZTLF_RECORD_WORK_COST_DIVISOR;
	const uint32_t neededScore = (neededScore64 > 0xffffffffULL) ? (uint32_t)0xffffffff : (uint32_t)neededScore64;

	if (skipWork) {
		memset(rb->data.b + s,0,ZTLF_WHARRGARBL_POW_BYTES);
		s += ZTLF_WHARRGARBL_POW_BYTES;
	} else {
		uint8_t workHash[64],scoringHash[48];
		ZTLF_SHA512(workHash,rb->data.b,s);
		void *const workMemory = malloc(ZTLF_RECORD_WHARRGARBL_POW_ITERATION_MEMORY);
		if (!workMemory)
			return ZTLF_ERR_OUT_OF_MEMORY;
		uint32_t bestScoreSoFar = 0;
		for(;;) {
			ZTLF_wharrgarbl(rb->data.b + s,workHash,sizeof(workHash),ZTLF_RECORD_WHARRGARBL_POW_ITERATION_DIFFICULTY,workMemory,ZTLF_RECORD_WHARRGARBL_POW_ITERATION_MEMORY,0);
			ZTLF_SHA384(scoringHash,rb->data.b,s + ZTLF_WHARRGARBL_POW_BYTES);
			const uint32_t score = ZTLF_score(scoringHash);
			if (score >= neededScore)
				break;
			if (score > bestScoreSoFar)
				bestScoreSoFar = score;
			if (statusCallback) {
				if (!statusCallback(bestScoreSoFar,neededScore)) {
					free(workMemory);
					return ZTLF_ERR_ABORTED;
				}
			}
		}
		free(workMemory);
		s += ZTLF_WHARRGARBL_POW_BYTES;
	}

	uint8_t signHash[64];
	ZTLF_SHA512(signHash,rb->data.b,s);
	ZTLF_Ed25519Sign((unsigned char *)(rb->data.b + s),signHash,sizeof(signHash),(const unsigned char *)rb->data.r.id,(const unsigned char *)rb->idClaimPrivateKey);
	s += ZTLF_ED25519_SIGNATURE_SIZE;

	ZTLF_SHA512(signHash,rb->data.b,s);
	ZTLF_Ed25519Sign((unsigned char *)(rb->data.b + s),signHash,sizeof(signHash),(const unsigned char *)ownerPublicKey,(const unsigned char *)ownerPrivateKey);
	s += ZTLF_ED25519_SIGNATURE_SIZE;

	rb->size = s;

	return ZTLF_ERR_NONE;
}

int ZTLF_Record_expand(struct ZTLF_ExpandedRecord *const er,const struct ZTLF_Record *const r,const unsigned int rsize)
{
	er->valueCipher = (r->algorithms >> 6) & 3;
	er->workAlgorithm = (r->algorithms >> 4) & 3;
	er->idClaimSignatureAlgorithm = (r->algorithms >> 2) & 3;
	er->ownerSignatureAlgorithm = r->algorithms & 3;

	ZTLF_Shandwich256(er->hash,r,rsize);

	er->timestamp = ((((uint64_t)r->timestamp[0]) << 32) | (((uint64_t)r->timestamp[1]) << 24) | (((uint64_t)r->timestamp[2]) << 16) | (((uint64_t)r->timestamp[3]) << 8) | (uint64_t)r->timestamp[4]);
	if (r->ttl == 0) {
		er->ttl = 0;
		er->expiration = er->timestamp;
	} else if (r->ttl == 0xff) {
		er->ttl = ZTLF_TTL_FOREVER;
		er->expiration = ZTLF_TTL_FOREVER;
	} else {
		er->ttl = ((uint64_t)r->ttl) * ZTLF_RECORD_TTL_INCREMENT_SEC;
		er->expiration = er->timestamp + er->ttl;
	}
	er->size = rsize;

	const unsigned int vlSize = (((unsigned int)r->vlSize[0]) << 8) | (unsigned int)r->vlSize[1];

	er->valueSize = vlSize & 0x7ff;
	if (er->valueSize > ZTLF_RECORD_MAX_VALUE_SIZE)
		return ZTLF_ERR_OBJECT_TOO_LARGE;
	er->linkCount = vlSize >> 11;
	er->metaDataType[0] = r->metadata >> 4;
	er->metaDataType[1] = r->metadata & 0xf;
	for(int i=0;i<2;++i) {
		switch(er->metaDataType[i]) {
			/*case ZTLF_RECORD_METADATA_NIL:*/
			default:
				er->metaDataSize[i] = 0;
				break;
			case ZTLF_RECORD_METADATA_SELECTOR:
			case ZTLF_RECORD_METADATA_CHANGE_OWNER:
				er->metaDataSize[i] = 32;
				break;
		}
	}
	switch (er->workAlgorithm) {
		case ZTLF_RECORD_ALG_WORK_NONE:
			er->workSize = 0;
			break;
		case ZTLF_RECORD_ALG_WORK_WHARRGARBL:
			er->workSize = ZTLF_WHARRGARBL_POW_BYTES;
			break;
		default:
			return ZTLF_ERR_ALGORITHM_NOT_SUPPORTED;
	}
	switch (er->idClaimSignatureAlgorithm) {
		case ZTLF_RECORD_ALG_SIG_ED25519:
			er->idClaimSignatureSize = ZTLF_ED25519_SIGNATURE_SIZE;
			break;
		default:
			return ZTLF_ERR_ALGORITHM_NOT_SUPPORTED;
	}
	switch (er->ownerSignatureAlgorithm) {
		case ZTLF_RECORD_ALG_SIG_ED25519:
			er->ownerSignatureSize = ZTLF_ED25519_SIGNATURE_SIZE;
			break;
		default:
			return ZTLF_ERR_ALGORITHM_NOT_SUPPORTED;
	}

	er->r = r;

	const uint8_t *dp = r->data;
	er->value = dp;
	dp += er->valueSize;
	er->links = dp;
	dp += (32 * er->linkCount);
	for(int i=0;i<2;++i) {
		er->metaData[i] = dp;
		dp += er->metaDataSize[i];
	}
	er->work = dp;
	dp += er->workSize;
	er->idClaimSignature = dp;
	dp += er->idClaimSignatureSize;
	er->ownerSignature = dp;
	dp += er->ownerSignatureSize;
	if (dp > (((const uint8_t *)r) + rsize))
		return ZTLF_ERR_OBJECT_INVALID;

	if (er->workSize > 0) {
		ZTLF_SHA384(er->scoringHash,r,(unsigned long)(((const uint8_t *)er->work) - ((const uint8_t *)r)));
		er->score = ZTLF_score(er->scoringHash);
	} else {
		er->score = 1;
	}

	return 0;
}
