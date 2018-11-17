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

#define ZTLF_PROTO_MESSAGE_TYPE_HELLO                             0x00
#define ZTLF_PROTO_MESSAGE_TYPE_PEER_INFO                         0x01
#define ZTLF_PROTO_MESSAGE_TYPE_RECORD                            0x02 /* payload: record */
#define ZTLF_PROTO_MESSAGE_TYPE_RECORD_REQUEST_BEST_BY_ID         0x03
#define ZTLF_PROTO_MESSAGE_TYPE_RECORD_REQUEST_BY_HASH            0x04
#define ZTLF_PROTO_MESSAGE_TYPE_RECORD_REQUEST_BY_TIMESTAMP_RANGE 0x05
#define ZTLF_PROTO_MESSAGE_TYPE_SUBSCRIBE_TO_ID                   0x06
#define ZTLF_PROTO_MESSAGE_TYPE_SUBSCRIBE_TO_OWNER                0x07
#define ZTLF_PROTO_MESSAGE_TYPE_SUBSCRIBE_TO_ALL                  0x08

ZTLF_PACKED_STRUCT(struct ZTLF_Message_Hello {
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_PeerInfo {
	uint16_t protoVersion;
	uint16_t flags;
	uint8_t addressType; /* 6 or 4 */
	uint8_t addressProtocol; /* currently always 0 for plain TCP */
	uint8_t addressIp[16];
	uint16_t addressPort;
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_RecordRequestBestByID {
	uint8_t id[32];
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_RecordRequestByHash {
	uint8_t hash[32];
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_RecordRequestByTimestampRange {
	uint64_t start;
	uint64_t end;
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_SubscribeToID {
	uint8_t id[32];
});

ZTLF_PACKED_STRUCT(struct ZTLF_Message_SubscribeToOwner {
	uint8_t owner[32];
});

#endif
