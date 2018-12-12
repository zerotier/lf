/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#ifndef ZTLF_PROTOCOL_H
#define ZTLF_PROTOCOL_H

#include "common.h"
#include "record.h"

/*
 * LF UDP protocol:
 * 
 * A UDP packet contains one or more messages prefixed by integers.
 * The most significant 5 bits of these integers are the message type,
 * while the least significant remaining bits are its size.
 * 
 * These integers are sent as variable length integers. Each byte of a
 * variable length integer contains 7 bits of integer data and one bit
 * indicating whether or not the integer is complete (0 == complete).
 * 
 * A packet may also be prefixed by a single zero byte. This indicates
 * that the remainder of the packet is a message and its size is the
 * packet size minus one. This saves a few bytes when a message that's
 * too big to bother stacking needs to be sent, like a full record.
 * 
 * The ping/pong mechanism is primarily used to protect the protocol
 * against abuse for DDOS amplification attacks. When a node receives
 * a query or other message requesting a response from a new address,
 * it first sends a ping to determine if the peer is actually there.
 * If a valid pong is returned, it processes the message. Otherwise
 * the message is ignored.
 * 
 * The protocol needs no encryption or authentication. It's only used
 * to carry LF records, and LF records contain their own signatures.
 */

#define ZTLF_PROTO_MESSAGE_TYPE_PING                              0x0
#define ZTLF_PROTO_MESSAGE_TYPE_PONG                              0x1
#define ZTLF_PROTO_MESSAGE_TYPE_PEER_INFO                         0x2
#define ZTLF_PROTO_MESSAGE_TYPE_RECORD                            0x3
#define ZTLF_PROTO_MESSAGE_TYPE_RECORD_REQUEST_BY_HASH            0x4
#define ZTLF_PROTO_MESSAGE_TYPE_RECORD_QUERY_RESULT               0x5
#define ZTLF_PROTO_MESSAGE_TYPE_RECORD_QUERY                      0x6

#define ZTLF_PROTO_SUBSCRIPTION_RECORDS                           0x1
#define ZTLF_PROTO_SUBSCRIPTION_PEERS                             0x2
#define ZTLF_PROTO_SUBSCRIPTION_WORK                              0x4

#define ZTLF_PROTO_SUBSCRIBE_FLAG_SEND_CURRENT_PEERS              0x1

#define ZTLF_PROTO_RECORD_REQUEST_FLAG_KEY_ID                     0x1
#define ZTLF_PROTO_RECORD_REQUEST_FLAG_KEY_OWNER                  0x2
#define ZTLF_PROTO_RECORD_REQUEST_FLAG_KEY_SEL0                   0x4
#define ZTLF_PROTO_RECORD_REQUEST_FLAG_KEY_SEL1                   0x8

#define ZTLF_PROTO_RECORD_REQUEST_MAX_RESULTS                     16

#define ZTLF_PROTO_RUMOR_MILL_REPLICATION_COUNT                   2

ZTLF_PACKED_STRUCT(struct ZTLF_Message_Ping {
	uint64_t timestamp;         /* current timestamp */
	uint8_t nonce[8];           /* 8 random bytes */
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_Pong {
	uint64_t timestamp;         /* timestamp echoed from ping */
	uint8_t pingHash[8];        /* first 8 bytes of SHA384(ping) */
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_Subscribe {
	uint64_t subscriptions;
	uint64_t flags;
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_PeerInfo {
	uint8_t addressType;        /* 6 or 4 */
	uint8_t address[];          /* length depends on type: 6 (ip4, port) or 18 (ip6, port) */
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_Record {
	uint8_t record[];
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_RecordRequestByHash {
	uint8_t hash[32];
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_RecordQueryResult {
	uint32_t requestId;
	uint32_t resultNo;
	uint32_t totalResults;
	uint32_t flags;
	uint64_t weight[2];         /* 128-bit in little-endian quadword order (low, high) */
	uint8_t record[];
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_RecordQuery {
	uint32_t requestId;         /* arbitrary ID echoed back in result */
	uint16_t maxResults;        /* maximum number of results to return */
	uint16_t flags;             /* flags indicate which keys are present */
	uint8_t keys[];             /* series of keys specified by flags */
});

static uint64_t ZTLF_Varint_Read(const void *const in,const unsigned int len)
{
	const uint8_t *p = (const uint8_t *)in;
	const uint8_t *const eof = p + len;
	uint64_t i = 0;
	while (p != eof) {
		const uint8_t b = *p++;
		i <<= 7;
		i |= (uint64_t)(b & 0x7f);
		if ((b & 0x80) == 0) break;
	}
	return i;
}

static unsigned int ZTLF_Varint_Write(void *const out,const unsigned int outsize,uint64_t i)
{
	unsigned int len = 0;
	while (len < outsize) {
		const uint8_t b = ((uint8_t)i) & 0x7f;
		if (i > 0x7f) {
			i >>= 7;
			((uint8_t *)out)[len++] = b | 0x80;
		} else {
			((uint8_t *)out)[len++] = b;
			break;
		}
	}
	return len;
}

#endif
