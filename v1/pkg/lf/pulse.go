/*
 * Copyright (c)2019 ZeroTier, Inc.
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file in the project's root directory.
 *
 * Change Date: 2023-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2.0 of the Apache License.
 */
/****/

package lf

import (
	"crypto/sha256"
	"encoding/binary"
)

// PulseSize is the size of a pulse in bytes.
const PulseSize = 11

// Pulse encodes a pulse key and a 24-bit number of minutes that it represents.
type Pulse Blob

// Key returns the 64-bit pulse key
func (p Pulse) Key() uint64 {
	if len(p) != PulseSize {
		return 0
	}
	return binary.BigEndian.Uint64(p[0:8])
}

// Minutes returns the number of minutes represented by this pulse
func (p Pulse) Minutes() uint {
	if len(p) != PulseSize {
		return 0
	}
	minutes := uint(p[8]) << 16
	minutes |= uint(p[9]) << 8
	minutes |= uint(p[10])
	if minutes > RecordMaxPulseSpan {
		return RecordMaxPulseSpan
	}
	return minutes
}

// String returns this pulse in !base62 format.
func (p Pulse) String() string {
	return "!" + Base62Encode(p)
}

// Token returns the record PulseToken that should match this pulse.
// This evaluates the hash tree from its current value up to its final value.
func (p Pulse) Token() uint64 { return th64n(p.Key(), p.Minutes()) }

// NewPulse generates a pulse for a given record from its selectors, timestamp, and the owner's private key.
// Use 0 for minutes to generate a pulse token for a new record. The pulse token is the final hash in the pulse
// hash chain.
func NewPulse(owner *Owner, selectorNames [][]byte, selectorOrdinals []uint64, recordTimestamp uint64, minutes uint) (p Pulse, err error) {
	if owner.Private == nil {
		err = ErrPrivateKeyRequired
		return
	}

	if minutes > RecordMaxPulseSpan {
		err = ErrInvalidParameter
		return
	}

	var tmp [32]byte
	pulseTokenHasher := sha256.New()

	for i := 0; i < len(selectorNames); i++ {
		pulseTokenHasher.Write(selectorNames[i])
		if i < len(selectorOrdinals) {
			binary.BigEndian.PutUint64(tmp[0:8], selectorOrdinals[i])
			pulseTokenHasher.Write(tmp[0:8])
		}
	}

	binary.BigEndian.PutUint64(tmp[0:8], recordTimestamp)
	pulseTokenHasher.Write(tmp[0:8])

	ophash := owner.PrivateHash()
	pulseTokenHasher.Write(ophash[:])

	var pbuf [PulseSize]byte
	p = pbuf[:]
	binary.BigEndian.PutUint64(p[0:8], th64n(binary.BigEndian.Uint64(pulseTokenHasher.Sum(tmp[:0])), RecordMaxPulseSpan-minutes))
	p[8] = byte(minutes >> 16)
	p[9] = byte(minutes >> 8)
	p[10] = byte(minutes)

	return
}
