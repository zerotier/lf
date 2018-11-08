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

#ifndef ZT_LF_RECORD_H
#define ZT_LF_RECORD_H

#include "common.h"
#include "sha.h"
#include "wharrgarbl.h"
#include "ed25519.h"

/**
 * Overall maximum record size (cannot be changed)
 */
#define ZTLF_RECORD_MAX_SIZE                         4096

/**
 * Maximum record value size (theoretical max: 4096 - overhead)
 */
#define ZTLF_RECORD_MAX_VALUE_SIZE                   256

/**
 * Maximum number of CA signature fields (sanity limit)
 */
#define ZTLF_RECORD_MAX_CA_SIGNATURES                8

/**
 * Number of links from one record to others (cannot be changed)
 */
#define ZTLF_RECORD_LINK_COUNT                       3

/**
 * Minimum size of a record (simply size of header)
 */
#define ZTLF_RECORD_MIN_SIZE                         sizeof(struct ZTLF_Record)

/**
 * Unit for TTL in seconds (cannot be changed)
 */
#define ZTLF_RECORD_TTL_INCREMENT_SEC                123671

#define ZTLF_RECORD_FIELD_VALUE                      0x0
#define ZTLF_RECORD_FIELD_ID_CLAIM_SIGNATURE_ED25519 0x1
#define ZTLF_RECORD_FIELD_OWNER_SIGNATURE_ED25519    0x2
#define ZTLF_RECORD_FIELD_CA_SIGNATURE_ED25519       0x3
#define ZTLF_RECORD_FIELD_WHARRGARBL_POW             0x4

/**
 * Packed record as it appears on the wire and in the database
 */
ZTLF_PACKED_STRUCT(struct ZTLF_Record
{
	uint64_t id[4];                            /* public key (or hash thereof) derived from record key */
	uint64_t owner[4];                         /* public key (or hash thereof) of owner */
	uint64_t links[ZTLF_RECORD_LINK_COUNT][4]; /* links to other records by shandwich256(record) */
	uint8_t reserved[2];                       /* currently must be 0 */
	uint8_t ttl;                               /* TTL in 123671 second (~34 hour) increments */
	uint8_t timestamp[5];                      /* 40-bit (big-endian) timestamp in seconds since epoch */
	uint8_t data[];                            /* value and fields */
});

/**
 * Record information as expanded (parsed) from a record
 */
struct ZTLF_RecordInfo
{
	const struct ZTLF_Record *r;

	uint64_t timestamp;
	uint64_t expiration;

	const uint8_t *value;
	const uint8_t *idClaimSignatureEd25519;
	const uint8_t *ownerSignatureEd25519;
	const uint8_t *caSignatureEd25519[ZTLF_RECORD_MAX_CA_SIGNATURES];
	const uint8_t *wharrgarblPow;

	double weight;
	unsigned int caSignatureCount;
	unsigned int valueSize;
};

static inline uint64_t ZTLF_Record_timestamp(const struct ZTLF_Record *r)
{
	return ((((uint64_t)r->timestamp[0]) << 32) | (((uint64_t)r->timestamp[1]) << 24) | (((uint64_t)r->timestamp[2]) << 16) | (((uint64_t)r->timestamp[3]) << 8) | (uint64_t)r->timestamp[4]);
}

/**
 * Convert a plaintext key into a record ID
 */
static inline void ZTLF_Record_keyToId(uint64_t id[4],const void *k,const unsigned long klen)
{
	uint8_t seed[64],priv[64];
	ZTLF_SHA512(seed,k,klen);
	ZTLF_Ed25519CreateKeypair((unsigned char *)id,priv,seed);
}

/**
 * Parse and expand a record into a structure containing field information
 */
int ZTLF_Record_expand(struct ZTLF_RecordInfo *ri,const struct ZTLF_Record *r,const unsigned long rsize);

/**
 * Decrypt record value using its plaintext key
 */
static inline void ZTLF_Record_open(const struct ZTLF_RecordInfo *ri,void *out,const void *k,const unsigned long klen)
{
	uint8_t khash[64];
	ZTLF_SHA512(khash,k,klen);

	/* For AES256-CFB we use the last 32 bytes of the hash as the AES256 key
	 * and the last 16 bytes of the record header (which includes the last link
	 * and the TTL and timestamp) as the IV. */
	ZTLF_AES256CFB c;
	ZTLF_AES256CFB_init(&c,khash + 32,((const uint8_t *)ri->r) + (sizeof(struct ZTLF_Record) - 16),true);
	ZTLF_AES256CFB_crypt(&c,out,ri->value,ri->valueSize);
	ZTLF_AES256CFB_destroy(&c);
}

#endif
