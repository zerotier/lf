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

#define ZTLF_PROTO_MESSAGE_TYPE_HELLO                             0x0
#define ZTLF_PROTO_MESSAGE_TYPE_OK                                0x1
#define ZTLF_PROTO_MESSAGE_TYPE_PEER_INFO                         0x2
#define ZTLF_PROTO_MESSAGE_TYPE_RECORD                            0x3
#define ZTLF_PROTO_MESSAGE_TYPE_RECORD_REQUEST_BY_HASH            0x4
#define ZTLF_PROTO_MESSAGE_TYPE_RECORD_QUERY_RESULT               0x5
#define ZTLF_PROTO_MESSAGE_TYPE_RECORD_QUERY                      0x6
#define ZTLF_PROTO_MESSAGE_TYPE_WORK                              0x7
#define ZTLF_PROTO_MESSAGE_TYPE_WORK_REQUEST                      0x8

#define ZTLF_PROTO_MESSAGE_HELLO_FLAG_SUBSCRIBE_RECORDS           0x00000001
#define ZTLF_PROTO_MESSAGE_HELLO_FLAG_SUBSCRIBE_PEERS             0x00000002
#define ZTLF_PROTO_MESSAGE_HELLO_FLAG_SUBSCRIBE_WORK              0x00000004
#define ZTLF_PROTO_MESSAGE_HELLO_FLAG_ANNOUNCE_THIS_PEER          0x00010000

#define ZTLF_PROTO_CIPHER_C25519_AES256_CFB                       0x01

#define ZTLF_PROTO_RECORD_REQUEST_FLAG_KEY_ID                     0x0001
#define ZTLF_PROTO_RECORD_REQUEST_FLAG_KEY_OWNER                  0x0002
#define ZTLF_PROTO_RECORD_REQUEST_FLAG_KEY_SEL0                   0x0004
#define ZTLF_PROTO_RECORD_REQUEST_FLAG_KEY_SEL1                   0x0008

#define ZTLF_PROTO_RECORD_REQUEST_MAX_RESULTS                     256

#define ZTLF_PROTO_MESSAGE_HELLO_FLAGS_P2P_NODE                   (ZTLF_PROTO_MESSAGE_HELLO_FLAG_SUBSCRIBE_RECORDS|ZTLF_PROTO_MESSAGE_HELLO_FLAG_SUBSCRIBE_PEERS|ZTLF_PROTO_MESSAGE_HELLO_FLAG_ANNOUNCE_THIS_PEER)

/* Message header prefixing every message: type, size, CRC32 */
ZTLF_PACKED_STRUCT(struct ZTLF_Message {
	uint16_t hdr;        /* TTTTSSSSSSSSSSSS: T == type, S == (message size - 1) (-1 means range is 1-4096) */
	uint16_t fletcher16; /* fletcher16 checksum of data after header */
});

#define ZTLF_Message_setHdr(m,t,s) { \
	const unsigned int _setHdrSTmp = ((unsigned int)(s)) - (sizeof(struct ZTLF_Message) + 1); \
	((uint8_t *)(m))[0] = (uint8_t)((t) << 4) | (uint8_t)(((_setHdrSTmp) >> 8) & 0xf); \
	((uint8_t *)(m))[1] = (uint8_t)(_setHdrSTmp); \
}
#define ZTLF_Message_type(m) (((const uint8_t *)(m))[0] >> 4)
#define ZTLF_Message_size(m) ((((unsigned int)(((const uint8_t *)(m))[0] & 0xf)) << 8) | ((unsigned int)(((const uint8_t *)(m))[1])))

ZTLF_PACKED_STRUCT(struct ZTLF_Message_Hello {
	uint16_t hdr;
	uint16_t fletcher16;

	uint8_t iv[16];
	uint8_t protoVersion;
	uint8_t protoFlags;
	uint64_t currentTime;
	uint32_t flags;
	uint8_t cipher;
	uint8_t publicKey[32];      /* length depends on cipher, but there's only one valid cipher right now */
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_OK {
	uint16_t hdr;
	uint16_t fletcher16;

	uint8_t ack[48];            /* SHA384(original hello packet | shared secret) */
	uint64_t helloTime;         /* time echoed from original hello */
	uint64_t currentTime;
	uint8_t version[4];
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_PeerInfo {
	uint16_t hdr;
	uint16_t fletcher16;

	uint8_t keyHash[48];        /* SHA384(publicKey) */
	uint8_t addressType;        /* 6 or 4 */
	uint8_t address[];          /* length depends on type: 6 (ip4, port) or 18 (ip6, port) */
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_Record {
	uint16_t hdr;
	uint16_t fletcher16;

	uint8_t record[];
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_RecordRequestByHash {
	uint16_t hdr;
	uint16_t fletcher16;

	uint8_t hash[32];
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_RecordQueryResult {
	uint16_t hdr;
	uint16_t fletcher16;

	uint32_t requestId;
	uint32_t resultNo;
	uint32_t totalResults;
	uint32_t flags;
	uint64_t weight[2];         /* 128-bit in little-endian quadword order (low, high) */

	uint8_t record[];
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_RecordQuery {
	uint16_t hdr;
	uint16_t fletcher16;

	uint32_t requestId;
	uint32_t maxResults;
	uint16_t flags;             /* flags indicate which keys are present */
	uint8_t keys[];             /* series of keys specified by flags */
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_Work {
	uint16_t hdr;
	uint16_t fletcher16;

	uint8_t workHash[48];
	uint8_t workAlgorithm;
	uint8_t work[];
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_WorkRequest {
	uint16_t hdr;
	uint16_t fletcher16;

	uint8_t workHash[48];
	uint8_t workAlgorithm;
	uint8_t work[];
});

#endif
