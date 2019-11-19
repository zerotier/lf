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

import "encoding/binary"

// PointerTTL is the global TTL for pointers (one year).
// After this time nodes may purge or refuse to replicate pointers.
const PointerTTL = 31536000

const (
	// PointerWorkAlgorithmNone indicates no proof of work.
	PointerWorkAlgorithmNone = RecordWorkAlgorithmNone

	// PointerWorkAlgorithmWharrgarbl indicates Wharrgarbl proof of work.
	PointerWorkAlgorithmWharrgarbl = RecordWorkAlgorithmWharrgarbl
)

// Pointer is a small ephemeral value that can be attached to a record.
// Pointers "hang" from specially constructed records and are not a part
// of the DAG. They are best-effort replicated, best-effort stored, and
// can be purged after PointerTTL. Records that can have pointers must
// end with a public key that is stored unmasked. Pointers inherit the
// maximum size constraints and work requirements of the records to which
// they are attached.
type Pointer struct {
	// RecordIDPrefix is the first 64 bits of the ID of this pointer's identity record containing its public key.
	// The ID is either a hash of the record's selectors or its hash if it has none. If multiple records
	// have this same ID prefix (collisions are possible) this is disambiguated by seeing which record's
	// embedded key successfully verifies this pointer's signature. This saves about 24 bytes of bandwidth per pointer.
	RecordIDPrefix [8]byte

	// WorkAlgorithm is the type of the Work field.
	WorkAlgorithm byte

	// SignatureAlgorithm is the algorithm used for this pointer's signatures.
	// The length and format of the public key are determined by the
	// algorithm. This is just where to look in the record's Value field.
	SignatureAlgorithm byte

	// Timestamp in SECONDS since epoch.
	Timestamp uint64

	// Value is the current value of this pointer.
	Value []byte

	// Signature of public key type, timestamp (as big-endian uint64), and value.
	Signature []byte

	// Work computed over public key type, timestamp, value, and signature.
	Work []byte
}

// PackedValue returns a blob with SignatureAlgorithm, Timestamp, Value, and Signature.
// Timestamp is as a full 64-bit big-endian int, not a varint.
func (p *Pointer) PackedValue() []byte {
	v := make([]byte, 11, 11+len(p.Value)+len(p.Signature))
	v[0] = p.SignatureAlgorithm
	binary.BigEndian.PutUint64(v[1:9], p.Timestamp)
	binary.BigEndian.PutUint16(v[9:11], uint16(len(p.Value)))
	v = append(v, p.Value...)
	v = append(v, p.Signature...)
	return v
}

// SetPackedValue sets this pointer's SignatureAlgorithm, Timestamp, Value, and Signature from a packed value.
// The format of packed values is constructed to make it trivial for third party software to handle.
func (p *Pointer) SetPackedValue(v []byte) error {
	if len(v) < 11 {
		return ErrInvalidParameter
	}
	p.SignatureAlgorithm = v[0]
	p.Timestamp = binary.BigEndian.Uint64(v[1:9])
	vl := int(binary.BigEndian.Uint16(v[9:11]))
	if vl > len(v) {
		return ErrInvalidParameter
	}
	p.Value = append(make([]byte, 0, vl), v[11:vl+11]...)
	v = v[vl+11:]
	if len(v) > 0 {
		p.Signature = append(make([]byte, 0, len(v)), v...)
	}
	return nil
}

func (p *Pointer) marshal() []byte {
	v := make([]byte, 8+2+10+10+len(p.Value)+len(p.Signature)+len(p.Work))
	copy(v[0:8], p.RecordIDPrefix[:])
	v[8] = p.WorkAlgorithm
	v[9] = p.SignatureAlgorithm
	i := 10 + binary.PutUvarint(v[10:], p.Timestamp)
	i += binary.PutUvarint(v[i:], uint64(len(p.Value)))
	copy(v[i:], p.Value)
	i += len(p.Value)
	copy(v[i:], p.Signature)
	i += len(p.Signature)
	copy(v[i:], p.Work)
	i += len(p.Work)
	return v[0:i]
}

func (p *Pointer) unmarshal(v []byte) error {
	if len(v) < 12 {
		return ErrInvalidObject
	}
	copy(p.RecordIDPrefix[:], v[0:8])
	p.WorkAlgorithm = v[8]
	p.SignatureAlgorithm = v[9]
	n, l := binary.Uvarint(v[10:])
	if l <= 0 {
		return ErrInvalidObject
	}
	p.Timestamp = n
	v = v[10+l:]
	n, l = binary.Uvarint(v[:])
	if l <= 0 {
		return ErrInvalidObject
	}
	v = v[l:]
	if n > uint64(len(v)) {
		return ErrInvalidObject
	}
	vsw := append(make([]byte, 0, len(v)), v...)
	p.Value = vsw[0:n]
	vsw = vsw[n:]
	workLen := 0
	switch p.WorkAlgorithm {
	case PointerWorkAlgorithmNone:
	case PointerWorkAlgorithmWharrgarbl:
		workLen = WharrgarblOutputSize
	default:
		return ErrRecordUnsupportedAlgorithm
	}
	if workLen > len(vsw) {
		return ErrInvalidObject
	}
	p.Signature = vsw[0 : len(vsw)-workLen]
	p.Work = vsw[len(vsw)-workLen:]
	return nil
}
