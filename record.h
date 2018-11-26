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
#include "score.h"

#define ZTLF_RECORD_ALG_CIPHER_NONE       0x0
#define ZTLF_RECORD_ALG_CIPHER_AES256CFB  0x1
#define ZTLF_RECORD_ALG_SIG_ED25519       0x0
#define ZTLF_RECORD_ALG_WORK_NONE         0x0
#define ZTLF_RECORD_ALG_WORK_WHARRGARBL   0x1

/**
 * Minimum size of a record (simply size of header)
 */
#define ZTLF_RECORD_MIN_SIZE                         sizeof(struct ZTLF_Record)

/**
 * Overall maximum allowed record size (sanity limit, cannot be changed)
 */
#define ZTLF_RECORD_MAX_SIZE                         4096

/**
 * Maximum record value size (cannot be changed without network-wide upgrade)
 */
#define ZTLF_RECORD_MAX_VALUE_SIZE                   512

/**
 * Unit for TTL in seconds (cannot be changed)
 */
#define ZTLF_RECORD_TTL_INCREMENT_SEC                123671

/**
 * Packed record as it appears on the wire and in the database
 */
ZTLF_PACKED_STRUCT(struct ZTLF_Record
{
	uint64_t id[4];                            /* public key (or hash thereof) derived from record key */
	uint64_t owner[4];                         /* public key (or hash thereof) of owner */
	uint8_t timestamp[5];                      /* 40-bit (big-endian) timestamp in seconds since epoch */
	uint8_t ttl;                               /* TTL in 123671 second (~34 hour) increments or 0 to relinquish ID ownership now */
	uint8_t linkCount;                         /* number of 32-byte links to hashes of other records */
	uint8_t algorithms;                        /* VVWWIIOO: VV=value cipher,WW=work,II=id claim signature,OO=owner signature */
	uint8_t data[];                            /* value, work, links, id claim signature, owner signature */
});

/**
 * Expanded record with convenient pointers to record fields and sizes
 */
struct ZTLF_ExpandedRecord
{
	const struct ZTLF_Record *r;

	const void *value;
	const void *work;
	const void *links; /* size in bytes is 32*r->linkCount */
	const void *idClaimSignature;
	const void *ownerSignature;

	uint64_t hash[4];

	uint64_t timestamp;
	uint64_t ttl;
	double weight;
	unsigned int size;

	unsigned int workSize;
	unsigned int idClaimSignatureSize;
	unsigned int ownerSignatureSize;
	unsigned int valueSize;

	uint8_t valueCipher;
	uint8_t workAlgorithm;
	uint8_t idClaimSignatureAlgorithm;
	uint8_t ownerSignatureAlgorithm;
};

/**
 * Compute a record ID from a plain-text key
 * 
 * @param id Record ID buffer to fill
 * @param k Plain text key
 * @param klen Length of plain text key
 */
static inline void ZTLF_Record_keyToId(uint64_t id[4],const void *k,const unsigned long klen)
{
	uint8_t seed[64],priv[64];
	ZTLF_SHA512(seed,k,klen);
	ZTLF_Ed25519CreateKeypair((unsigned char *)id,priv,seed); /* only the first 32 bytes of the hash are used here */
}

/**
 * Extract record timestamp from record
 * 
 * @param r Record
 * @return Timestamp in seconds since Unix epoch
 */
static inline uint64_t ZTLF_Record_timestamp(const struct ZTLF_Record *r) { return ((((uint64_t)r->timestamp[0]) << 32) | (((uint64_t)r->timestamp[1]) << 24) | (((uint64_t)r->timestamp[2]) << 16) | (((uint64_t)r->timestamp[3]) << 8) | (uint64_t)r->timestamp[4]); }

/**
 * Extract record TTL from record
 * 
 * @param r Record
 * @return Time to live in seconds since Unix epoch
 */
static inline uint64_t ZTLF_Record_ttl(const struct ZTLF_Record *r) { return (((uint64_t)r->ttl) * (uint64_t)ZTLF_RECORD_TTL_INCREMENT_SEC); }

/**
 * Expand record into its constituent fields and perform basic validation
 * 
 * @param er Expanded record structure to fill
 * @param r Packed record to expand (er contains pointers into this, so it must be held while er is used)
 * @param rsize Total size of record in bytes
 * @return True if packed record appears valid
 */
bool ZTLF_Record_expand(struct ZTLF_ExpandedRecord *const er,const struct ZTLF_Record *const r,const unsigned int rsize);

#endif
