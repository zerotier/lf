/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * --
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial closed-source software that incorporates or links
 * directly against ZeroTier software without disclosing the source code
 * of your own application.
 */

package lf

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/sha3"
)

// SelectorTypeBP160 indicates a sortable selector built from the brainpoolP160t1 small elliptic curve.
// This is a protocol constant and cannot be changed.
const SelectorTypeBP160 byte = 0

// SelectorKeySize is the size of the sortable ordinal-modified hash used for DB queries and range queries.
// It's computed by adding the ordinal to the SHA512 hash of the deterministic selector public key.
// This is a protocol constant and cannot be changed.
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
	}
	if c < oc {
		b++
	}
	c += binary.BigEndian.Uint64(ordinal[0:8])
	if c < oc {
		b++
	}
	if b < ob {
		a++
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
	priv, err := ecdsa.GenerateKey(ECCCurveBrainpoolP160T1, &prng)
	if err != nil {
		panic(err)
	}

	var key [32]byte
	hasher := sha3.New256()
	hasher.Write(priv.PublicKey.X.Bytes())
	hasher.Write(priv.PublicKey.Y.Bytes())
	hasher.Sum(key[:0])

	var ord Ordinal
	ord.Set(plainTextOrdinal, plainTextName)
	addOrdinalToHash(&key, &ord)

	return key[:]
}

// claimKey recovers the public key from this selector's claim and the record body hash used to generate it.
func (s *Selector) claimKey(hash []byte) *ecdsa.PublicKey {
	sigHash := sha3.New256()
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
	var key [32]byte
	hasher := sha3.New256()
	hasher.Write(pub.X.Bytes())
	hasher.Write(pub.Y.Bytes())
	hasher.Sum(key[:0])
	addOrdinalToHash(&key, &s.Ordinal)
	return key[:]
}

func (s *Selector) marshalTo(out io.Writer) error {
	if len(s.Claim) != 41 {
		return ErrInvalidObject
	}
	if _, err := out.Write([]byte{SelectorTypeBP160}); err != nil {
		return err
	}
	if _, err := out.Write(s.Ordinal[:]); err != nil {
		return err
	}
	if _, err := out.Write(s.Claim); err != nil {
		return err
	}
	return nil
}

func (s *Selector) unmarshalFrom(in io.Reader) error {
	var t [1]byte
	if _, err := io.ReadFull(in, t[:]); err != nil {
		return err
	}
	if t[0] != SelectorTypeBP160 {
		return ErrInvalidObject
	}
	if _, err := io.ReadFull(in, s.Ordinal[:]); err != nil {
		return err
	}
	var cl [41]byte
	if _, err := io.ReadFull(in, cl[:]); err != nil {
		return err
	}
	s.Claim = cl[:]
	return nil
}

func newSelectorFromBytes(b []byte) (s *Selector, err error) {
	s = new(Selector)
	err = s.unmarshalFrom(bytes.NewReader(b))
	return
}

func (s *Selector) bytes() []byte {
	var b bytes.Buffer
	s.marshalTo(&b)
	return b.Bytes()
}

func (s *Selector) set(plainTextName []byte, plainTextOrdinal uint64, hash []byte) {
	s.Ordinal.Set(plainTextOrdinal, plainTextName)

	var prng seededPrng
	prng.seed(plainTextName)
	priv, err := ecdsa.GenerateKey(ECCCurveBrainpoolP160T1, &prng)

	sigHash := sha3.New256()
	sigHash.Write(hash)
	sigHash.Write(s.Ordinal[:])
	var sigHashBuf [32]byte
	cs, err := ECDSASignEmbedRecoveryIndex(priv, sigHash.Sum(sigHashBuf[:0]))
	if err != nil || len(cs) != 41 { // this would indicate a bug
		panic("ECDSA signature for selector generation failed!")
	}
	s.Claim = cs
}
