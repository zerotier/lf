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

#define ZTLF_PROTO_VERSION                                        0x00

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

#define ZTLF_PROTO_SUBSCRIBE_FLAG_SEND_PEERS                      0x1

#define ZTLF_PROTO_RECORD_REQUEST_FLAG_KEY_ID                     0x1
#define ZTLF_PROTO_RECORD_REQUEST_FLAG_KEY_OWNER                  0x2
#define ZTLF_PROTO_RECORD_REQUEST_FLAG_KEY_SEL0                   0x4
#define ZTLF_PROTO_RECORD_REQUEST_FLAG_KEY_SEL1                   0x8

#define ZTLF_PROTO_RECORD_REQUEST_MAX_RESULTS                     64

ZTLF_PACKED_STRUCT(struct ZTLF_Message_Ping {
	uint64_t timestamp;         /* current timestamp */
	uint8_t nonce[4];           /* 4 random bytes */
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_Pong {
	uint64_t timestamp;         /* timestamp echoed from ping */
	uint8_t pingHash[48];       /* SHA384(ping) */
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
	uint32_t requestId;
	uint16_t maxResults;
	uint16_t flags;             /* flags indicate which keys are present */
	uint8_t keys[];             /* series of keys specified by flags */
});

#endif
