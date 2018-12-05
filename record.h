/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
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
 * Value to supply to create for ttl to indicate 'forever'
 */
#define ZTLF_TTL_FOREVER 0x7fffffffffffffffULL

/**
 * Minimum size of a record (simply size of header)
 */
#define ZTLF_RECORD_MIN_SIZE sizeof(struct ZTLF_Record)

/**
 * Overall maximum allowed record size (sanity limit, cannot be changed)
 */
#define ZTLF_RECORD_MAX_SIZE 4096

/**
 * Maximum record value size (cannot be changed without network-wide upgrade)
 */
#define ZTLF_RECORD_MAX_VALUE_SIZE 512

/**
 * Minimum number of links for a non-genesis record
 */
#define ZTLF_RECORD_MIN_LINKS 3

/**
 * Maximum number of links from a record (cannot be changed)
 */
#define ZTLF_RECORD_MAX_LINKS 31

/**
 * Unit for TTL in seconds (about 34 hours and set so that max TTL is about one year, cannot be changed)
 */
#define ZTLF_RECORD_TTL_INCREMENT_SEC 124158

/**
 * Wharrgarbl difficulty per iteration for record PoW (takes ~1-3 sec on a quad-core Core i7 in 2018)
 */
#define ZTLF_RECORD_WHARRGARBL_POW_ITERATION_DIFFICULTY 0x10000

/**
 * Wharrgarbl memory per iteration for record PoW
 */
#define ZTLF_RECORD_WHARRGARBL_POW_ITERATION_MEMORY 268435456

/**
 * Number by which 32-bit scoring hash score (see score.h) is divided to get the maximum number of bytes "paid for" by a record's work
 */
#define ZTLF_RECORD_WORK_COST_DIVISOR 32768

/**
 * Meta-data: [0] empty
 */
#define ZTLF_RECORD_METADATA_NIL 0x0

/**
 * Meta-data: [32] arbitrary 32-byte public selector that can be used to find records by some key
 */
#define ZTLF_RECORD_METADATA_SELECTOR 0x1

/**
 * Meta-data: [32] owner ID of new owner that should inherit prveious owners' record weights
 * 
 * Only one owner change can be made in a single revision. If there are two change owner meta-data
 * fields the second is ignored.
 */
#define ZTLF_RECORD_METADATA_CHANGE_OWNER 0x2

/**
 * Packed record as it appears on the wire
 * 
 * Use ZTLF_Record_expand to create ZTLF_ExpandedRecord with fields expanded for more convenient access.
 */
ZTLF_PACKED_STRUCT(struct ZTLF_Record
{
	uint8_t id[32];        /* public key (or hash thereof) derived from record key */
	uint8_t owner[32];     /* public key (or hash thereof) of owner */
	uint8_t timestamp[5];  /* 40-bit (big-endian) timestamp in seconds since epoch */
	uint8_t ttl;           /* TTL in 124158 second (~34 hour) increments, 0 to expire now, or 255 to "never" expire */
	uint8_t algorithms;    /* VVWWIIOO: VV=value cipher,WW=work,II=id claim signature,OO=owner signature */
	uint8_t metadata;      /* two four-bit meta-data type IDs indicating which meta-data fields are present */
	uint8_t vlSize[2];     /* number of links (most significant 5 bits) and size of value (least significant 11 bits) */
	uint8_t data[];        /* value, links, meta-data (x2), work, id claim signature, owner signature */
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
	const void *links; /* size in bytes is 32*r->linkCount */
	const void *metaData[2];
	const void *work;
	const void *idClaimSignature;
	const void *ownerSignature;

	uint64_t hash[4];

	uint64_t timestamp;
	uint64_t ttl;
	uint64_t expiration;
	uint32_t score;

	unsigned int size;

	unsigned int valueSize;
	unsigned int linkCount;
	unsigned int metaDataType[2];
	unsigned int metaDataSize[2];
	unsigned int workSize;
	unsigned int idClaimSignatureSize;
	unsigned int ownerSignatureSize;

	uint8_t scoringHash[48]; /* only first 32 bytes are used to compute score */

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
 * Create a record
 * 
 * This can be a very time consuming operation due to proof of work. The status callback
 * can be used to provide some user feedback and cancel long running jobs. Its parameters
 * are the best PoW score so far and the target PoW score, which is based on the size
 * of this record in bytes (including overhead). If the status callback returns false
 * the search is aborted and this function returns false.
 * 
 * @param rb Record buffer (existing contents will be lost)
 * @param plainTextKey Plain text key
 * @param plainTextKeyLength Plain text key length
 * @param value Plain text value
 * @param valueLength Length of value in bytes
 * @param ownerPublicKey Public key of owner (currently must be 32-byte ed25519 public key)
 * @param ownerPrivateKey Private key of owner (currently must be 32-byte ed25519 private key)
 * @param links Links (must be 32*linkCount bytes in size)
 * @param linkCount Number of links (theoretical max 255, links beyond this are ignored)
 * @param timestamp Timestamp in seconds since epoch
 * @param ttl TTL in seconds (will be quantized to ZTLF_RECORD_TTL_INCREMENT_SEC)
 * @param skipWork If true, work will be skipped and work space will be filled with all-zero (for testing)
 * @param encryptValue If true, value will be hidden from anyone who doesn't know the plain text key (default behavior)
 * @param statusCallback If non-NULL call this periodically and if it returns false terminate work and return false from create
 * @return 0 on success or error code
 */
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
	bool (*statusCallback)(uint32_t,uint32_t));

/**
 * Expand record into its constituent fields and perform basic validation
 * 
 * @param er Expanded record structure to fill
 * @param r Packed record to expand (er contains pointers into this, so it must be held while er is used)
 * @param rsize Total size of record in bytes
 * @return 0 on success or error code
 */
int ZTLF_Record_expand(struct ZTLF_ExpandedRecord *const er,const struct ZTLF_Record *const r,const unsigned int rsize);

#endif
