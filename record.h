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

#define ZTLF_RECORD_FLAGS_MASK_TYPE         0x07

#define ZTLF_RECORD_TYPE_ED25519_AES256CFB  0x00 /* ed25519 signatures, AES-256-CFB value masking */

#define ZTLF_RECORD_LINK_COUNT              8

#define ZTLF_RECORD_MIN_SIZE sizeof(struct ZTLF_Record)

#define ZTLF_RECORD_ATTACHMENT_TYPE_WHARRGARBL_POW 0x00

ZTLF_PACKED_STRUCT(struct ZTLF_Record
{
	uint64_t id[4];                    /* public key (or hash thereof) derived from record key */
	uint64_t owner[4];                 /* public key (or hash thereof) of owner */
	uint64_t timestamp;                /* timestamp in milliseconds since epoch */

	ZTLF_PACKED_STRUCT(struct {
		uint64_t idOwnerHash[3];         /* 192-bit hash computed from sha384(sha384(id | owner) | owner) */
		uint64_t timestamp;              /* timestamp of referenced record or 0 if link is unused */
	}) links[ZTLF_RECORD_LINK_COUNT];

	uint16_t ttl;                      /* TTL in hours (actual TTL is this + 1, so 0 == 1 hour) */
	uint8_t flags;                     /* FFFFFTTT: F=flags, T=record type (0-7) */

	union {
		/* Type 0 personality (the only one right now) */
		ZTLF_PACKED_STRUCT(struct {      /* ZT_LF_RECORD_TYPE_ED25519_AES256CFB */
			uint8_t keyClaimSignature[64]; /* ed25519 signature with secret computed from plaintext key */
			uint8_t ownerSignature[64];    /* ed25519 signature with owner key */
			uint8_t valueSize;             /* actual size is size + 1 */
			uint8_t data[];                /* 1-256 byte value data, work, any other optional data... */
		}) t0;

		/* Future type-selected personalities could be added here... */
	} p;
});

static inline uint64_t ZTLF_Record_expirationTime(const struct ZTLF_Record *r)
{
	return (r->timestamp + (60000ULL * (1ULL + (uint64_t)r->ttl)));
}

static inline void ZTLF_Record_transportEncode(struct ZTLF_Record *r)
{
	r->timestamp = ZTLF_htonll(r->timestamp);
	for(int i=0;i<ZTLF_RECORD_LINK_COUNT;i++)
		r->links[i].timestamp = ZTLF_htonll(r->links[i].timestamp);
	r->ttl = htons(r->ttl);
}

static inline void ZTLF_Record_transportDecode(struct ZTLF_Record *r)
{
	r->timestamp = ZTLF_ntohll(r->timestamp);
	for(int i=0;i<ZTLF_RECORD_LINK_COUNT;i++)
		r->links[i].timestamp = ZTLF_ntohll(r->links[i].timestamp);
	r->ttl = ntohs(r->ttl);
}

void ZTLF_Record_idOwnerHash(const struct ZTLF_Record *r,uint64_t out[3]);

double ZTLF_Record_getInternalWeight(const struct ZTLF_Record *r,const unsigned long rsize);

#endif
