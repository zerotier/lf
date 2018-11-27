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

#ifndef ZTLF_PROTOCOL_H
#define ZTLF_PROTOCOL_H

#include "common.h"
#include "record.h"

#define ZTLF_PROTO_VERSION                                        0x00

#define ZTLF_PROTO_MESSAGE_TYPE_NOP                               0x00
#define ZTLF_PROTO_MESSAGE_TYPE_HELLO                             0x01
#define ZTLF_PROTO_MESSAGE_TYPE_OK                                0x02
#define ZTLF_PROTO_MESSAGE_TYPE_GOODBYE                           0x03
#define ZTLF_PROTO_MESSAGE_TYPE_PEER_INFO                         0x04
#define ZTLF_PROTO_MESSAGE_TYPE_RECORD                            0x05
#define ZTLF_PROTO_MESSAGE_TYPE_RECORD_REQUEST_BY_ID              0x06
#define ZTLF_PROTO_MESSAGE_TYPE_RECORD_REQUEST_BY_HASH            0x07

#define ZTLF_PROTO_CIPHER_C25519_AES256_CFB                       0x01

#define ZTLF_PROTO_GOODBYE_REASON_NONE                            0x00
#define ZTLF_PROTO_GOODBYE_REASON_TCP_ERROR                       0x01
#define ZTLF_PROTO_GOODBYE_REASON_SHUTDOWN                        0x02
#define ZTLF_PROTO_GOODBYE_REASON_DUPLICATE_LINK                  0x03
#define ZTLF_PROTO_GOODBYE_REASON_INVALID_MESSAGE                 0x04
#define ZTLF_PROTO_GOODBYE_REASON_UNSUPPORTED_PROTOCOL            0x05

/* Message header prefixing every message: type, size, CRC32 */
ZTLF_PACKED_STRUCT(struct ZTLF_Message {
	uint16_t hdr;        /* TTTTSSSSSSSSSSSS: T == type, S == inclusive message size - 1 (1-4096) */
	uint16_t fletcher16; /* fletcher16 checksum of data after header */
});

#define ZTLF_Message_setHdr(m,t,s) { \
	((uint8_t *)(m))[0] = (uint8_t)((t) << 4) | (uint8_t)(((s) >> 8) & 0xf); \
	((uint8_t *)(m))[1] = (uint8_t)(s); \
}
#define ZTLF_Message_type(m) (((const uint8_t *)(m))[0] >> 4)
#define ZTLF_Message_size(m) ((((unsigned int)(((const uint8_t *)(m))[0] & 0xf)) << 8) | ((unsigned int)(((const uint8_t *)(m))[1])))

ZTLF_PACKED_STRUCT(struct ZTLF_Message_Hello {
	uint16_t hdr;
	uint16_t fletcher16;

	uint8_t iv[16];

	/* Fields after the IV are encrypted with the network key using AES256-CFB and the first 16 bytes of SHA384(iv) as the IV. */
	uint8_t protoVersion;
	uint8_t protoFlags;
	uint64_t currentTime;
	uint64_t flags;
	uint8_t cipher;
	uint8_t publicKey[32]; /* length depends on cipher, but there's only one valid cipher right now */
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_OK {
	uint16_t hdr;
	uint16_t fletcher16;

	uint8_t ack[48];            /* SHA384(original hello packet | shared secret) */
	uint64_t helloTime;         /* time echoed from original hello */
	uint64_t currentTime;
	uint8_t version[4];
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_Goodbye {
	uint16_t hdr;
	uint16_t fletcher16;

	uint8_t reason;
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

	struct ZTLF_Record record;
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_RecordRequestByID {
	uint16_t hdr;
	uint32_t crc;

	uint8_t id[32];
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_RecordRequestByHash {
	uint16_t hdr;
	uint16_t fletcher16;

	uint8_t count;  /* maximum number of records to return */
	uint8_t hash[]; /* hash prefix of arbitrary length, up to 32 bytes */
});

#endif
