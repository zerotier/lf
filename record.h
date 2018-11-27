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
#define ZTLF_RECORD_MIN_SIZE                         (sizeof(struct ZTLF_Record))

/**
 * Overall maximum allowed record size (sanity limit, cannot be changed)
 */
#define ZTLF_RECORD_MAX_SIZE                         4096

/**
 * Maximum record value size (cannot be changed without network-wide upgrade)
 */
#define ZTLF_RECORD_MAX_VALUE_SIZE                   1024

/**
 * Unit for TTL in seconds (cannot be changed)
 */
#define ZTLF_RECORD_TTL_INCREMENT_SEC                123671

/**
 * Wharrgarbl difficulty per iteration for record PoW
 */
#define ZTLF_RECORD_WHARRGARBL_POW_ITERATION_DIFFICULTY 0x1000

/**
 * Wharrgarbl memory per iteration for record PoW
 */
#define ZTLF_RECORD_WHARRGARBL_POW_ITERATION_MEMORY 67108864

/**
 * Packed record as it appears on the wire and in the database
 */
ZTLF_PACKED_STRUCT(struct ZTLF_Record
{
	uint64_t id[4];                            /* public key (or hash thereof) derived from record key */
	uint64_t owner[4];                         /* public key (or hash thereof) of owner */
	uint8_t timestamp[5];                      /* 40-bit (big-endian) timestamp in seconds since epoch */
	uint8_t ttl;                               /* TTL in 123671 second (~34 hour) increments or 0 to relinquish ID ownership now */
	uint8_t algorithms;                        /* VVWWIIOO: VV=value cipher,WW=work,II=id claim signature,OO=owner signature */
	uint8_t valueSize[2];                      /* size of value in bytes (16-bit) */
	uint8_t data[];                            /* value, work, links, id claim signature, owner signature */
});

/**
 * Union buffer for creating records
 */
struct ZTLF_RecordBuffer
{
	unsigned int size;
	uint8_t idClaimPrivateKey[ZTLF_ED25519_PRIVATE_KEY_SIZE];
	union {
		struct ZTLF_Record r;
		uint8_t b[ZTLF_RECORD_MAX_SIZE];
	} data;
};

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

	unsigned int valueSize;
	unsigned int workSize;
	unsigned int idClaimSignatureSize;
	unsigned int ownerSignatureSize;
	unsigned int linkCount;

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
void ZTLF_Record_keyToId(uint64_t id[4],const void *k,const unsigned long klen);

/**
 * Create record, phase one -- set value, compute work
 * 
 * This can be a very time consuming operation due to work.
 * 
 * @param rb Record buffer (existing contents will be lost)
 * @param plainTextKey Plain text key
 * @param plainTextKeyLength Plain text key length
 * @param value Plain text value
 * @param valueLength Length of value in bytes
 * @param timestamp Timestamp in seconds since epoch
 * @param ttl TTL in seconds (will be quantized to ZTLF_RECORD_TTL_INCREMENT_SEC)
 * @param encryptValue If true, value will be hidden from anyone who doesn't know the plain text key (default behavior)
 * @param linkHashPrefix Buffer to fill with bytes to select prefixed for link hashes
 * @param linkHashPrefixLength Length of linkHashPrefix in bytes (up to 32)
 * @return True if parameters were valid
 */
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
	unsigned int linkHashPrefixLength);

/**
 * Create record, phase two -- add links, sign with ID claim key and owner key
 * 
 * @param rb Record buffer containing the results of createInit()
 * @param links Links (size must be 32*linkCount)
 * @param linkCount Number of links
 * @param ownerPrivateKey Private key to sign this record
 */
bool ZTLF_Record_createFinal(
	struct ZTLF_RecordBuffer *rb,
	const void *links,
	const unsigned int linkCount,
	const void *ownerPrivateKey);

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
