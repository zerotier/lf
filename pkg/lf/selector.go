/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c)2019-2021 ZeroTier, Inc.
 * https://www.zerotier.com/
 */

package lf

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"io"
)

// SelectorTypeBP160 is a 57-byte (serialized) selector built from the BrainpoolP160T1 small elliptic curve.
// This is a protocol constant and cannot be changed.
const SelectorTypeBP160 byte = 0 // valid range 0..15

// SelectorKeySize is the size of the sortable value used for database range queries.
const SelectorKeySize = 32

// Selector is a non-forgeable range queryable identifier for records.
// It can also rewind on request from the MC.
type Selector struct {
	Ordinal Ordinal `json:",omitempty"` // A plain text sortable field that can be used for range queries against secret selectors
	Claim   Blob    `json:",omitempty"` // 41-byte brainpoolP160t1 recoverable signature
}

// addOrdinalToHash adds a 128-bit ordinal to a 256-bit hash.
func addOrdinalToHash(h *[32]byte, ordinal *Ordinal) {
	a, b, c, d := binary.BigEndian.Uint64(h[0:8]), binary.BigEndian.Uint64(h[8:16]), binary.BigEndian.Uint64(h[16:24]), binary.BigEndian.Uint64(h[24:32])
	ob, oc, od := b, c, d
	d += binary.BigEndian.Uint64(ordinal[8:16])
	if d < od {
		c++
		if c < oc {
			b++
		}
	}
	c += binary.BigEndian.Uint64(ordinal[0:8])
	if c < oc {
		b++
		if b < ob {
			a++
		}
	}
	binary.BigEndian.PutUint64(h[0:8], a)
	binary.BigEndian.PutUint64(h[8:16], b)
	binary.BigEndian.PutUint64(h[16:24], c)
	binary.BigEndian.PutUint64(h[24:32], d)
}

// MakeSelectorKey obtains a sortable database/query key from a plain text name and ordinal.
func MakeSelectorKey(plainTextName []byte, plainTextOrdinal uint64) []byte {
	var prng seededPrng
	prng.seed(plainTextName)
	privateKey, err := ecdsa.GenerateKey(ECCCurveBrainpoolP160T1, &prng)
	if err != nil {
		panic(err)
	}

	key, _ := ECDSAHashPublicKey(&privateKey.PublicKey)

	var ord Ordinal
	ord.Set(plainTextOrdinal, plainTextName)
	addOrdinalToHash(&key, &ord)

	return key[:]
}

// NewSelectorFromBytes decodes a byte-serialized selector.
func NewSelectorFromBytes(b []byte) (s *Selector, err error) {
	s = new(Selector)
	err = s.unmarshalFrom(bytes.NewReader(b))
	return
}

// Bytes returns a byte-serialized version of this selector.
func (s *Selector) Bytes() []byte {
	var b bytes.Buffer
	_ = s.marshalTo(&b)
	return b.Bytes()
}

// claimKey recovers the public key from this selector's claim and the record body hash used to generate it.
func (s *Selector) claimKey(hash []byte) *ecdsa.PublicKey {
	sigHash := sha256.New()
	sigHash.Write(hash)
	sigHash.Write(s.Ordinal[:])
	var sigHashBuf [32]byte
	return ECDSARecover(ECCCurveBrainpoolP160T1, sigHash.Sum(sigHashBuf[:0]), s.Claim)
}

// isNamed returns true if this selector's plain text name matches the argument.
func (s *Selector) isNamed(hash, plainTextName []byte) bool {
	var prng seededPrng
	prng.seed(plainTextName)
	priv, err := ecdsa.GenerateKey(ECCCurveBrainpoolP160T1, &prng)
	if err != nil {
		return false
	}
	pub := s.claimKey(hash)
	return pub.X.Cmp(priv.PublicKey.X) == 0 && pub.Y.Cmp(priv.PublicKey.Y) == 0
}

// id returns the public key recovered from the claim signature or nil if there is an error.
func (s *Selector) id(hash []byte) []byte {
	pub := s.claimKey(hash)
	if pub != nil {
		pcomp, _ := ECDSACompressPublicKey(pub)
		return pcomp
	}
	return nil
}

// key returns the sortable and comparable database key for this selector.
func (s *Selector) key(hash []byte) []byte {
	pub := s.claimKey(hash)
	key, _ := ECDSAHashPublicKey(pub)
	addOrdinalToHash(&key, &s.Ordinal)
	return key[:]
}

func (s *Selector) marshalTo(out io.Writer) error {
	if len(s.Claim) != 41 {
		return ErrInvalidObject
	}
	// We can pack the last byte of the claim key into the first byte since
	// it's the key recovery index and will be 0 or 1. This saves one byte.
	if _, err := out.Write([]byte{SelectorTypeBP160 | (s.Claim[40] << 4)}); err != nil {
		return err
	}
	if _, err := out.Write(s.Ordinal[:]); err != nil {
		return err
	}
	if _, err := out.Write(s.Claim[0:40]); err != nil {
		return err
	}
	return nil
}

func (s *Selector) unmarshalFrom(in io.Reader) error {
	var t [1]byte
	if _, err := io.ReadFull(in, t[:]); err != nil {
		return err
	}
	if (t[0] & 0xf) != SelectorTypeBP160 {
		return ErrInvalidObject
	}
	if _, err := io.ReadFull(in, s.Ordinal[:]); err != nil {
		return err
	}
	var cl [41]byte
	if _, err := io.ReadFull(in, cl[0:40]); err != nil {
		return err
	}
	cl[40] = t[0] >> 4
	s.Claim = cl[:]
	return nil
}

func (s *Selector) set(plainTextName []byte, plainTextOrdinal uint64, hash []byte) {
	s.Ordinal.Set(plainTextOrdinal, plainTextName)

	var prng seededPrng
	prng.seed(plainTextName)
	priv, err := ecdsa.GenerateKey(ECCCurveBrainpoolP160T1, &prng)

	sigHash := sha256.New()
	sigHash.Write(hash)
	sigHash.Write(s.Ordinal[:])
	var sigHashBuf [32]byte
	cs, err := ECDSASignEmbedRecoveryIndex(priv, sigHash.Sum(sigHashBuf[:0]))
	if err != nil || len(cs) != 41 { // this would indicate a bug
		panic("ECDSA signature for selector generation failed!")
	}
	s.Claim = cs
}
