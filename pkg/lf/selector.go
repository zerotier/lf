/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/sha3"
)

// SelectorTypeBP160 indicates a sortable selector built from the brainpoolP160t1 small elliptic curve.
// This is a protocol constant and cannot be changed.
const SelectorTypeBP160 byte = 0 // valid range: 0..3

// SelectorMaxOrdinalSize is the maximum length of an ordinal.
// Functions will take larger ordinals but bytes to the left of this size are ignored.
// This is a protocol constant and cannot be changed.
const SelectorMaxOrdinalSize = 24

// SelectorKeySize is the size of the sortable ordinal-modified hash used for DB queries and range queries.
// It's computed by adding the ordinal to the SHA512 hash of the deterministic selector public key.
// This is a protocol constant and cannot be changed.
const SelectorKeySize = 32

// Selector is a non-forgeable range queryable identifier for records.
type Selector struct {
	Ordinal Blob `json:",omitempty"` // A plain text sortable field that can be used for range queries against secret selectors
	Claim   Blob `json:",omitempty"` // 41-byte brainpoolP160t1 recoverable signature
}

func addOrdinalToHash(h *[SelectorKeySize]byte, ordinal []byte) {
	if len(ordinal) > 0 {
		var ord [SelectorMaxOrdinalSize]byte
		if len(ordinal) > SelectorMaxOrdinalSize {
			copy(ord[:], ordinal[len(ordinal)-SelectorMaxOrdinalSize:])
		} else {
			copy(ord[SelectorMaxOrdinalSize-len(ordinal):], ordinal)
		}
		a, b, c, d := binary.BigEndian.Uint64(h[0:8]), binary.BigEndian.Uint64(h[8:16]), binary.BigEndian.Uint64(h[16:24]), binary.BigEndian.Uint64(h[24:32])
		ob, oc, od := b, c, d
		d += binary.BigEndian.Uint64(ord[16:24])
		if d < od {
			c++
		}
		c += binary.BigEndian.Uint64(ord[8:16])
		if c < oc {
			b++
		}
		b += binary.BigEndian.Uint64(ord[0:8])
		if b < ob {
			a++
		}
		binary.BigEndian.PutUint64(h[0:8], a)
		binary.BigEndian.PutUint64(h[8:16], b)
		binary.BigEndian.PutUint64(h[16:24], c)
		binary.BigEndian.PutUint64(h[24:32], d)
	}
}

// MakeSelectorKey obtains a sortable database key from a plain text name and ordinal.
func MakeSelectorKey(plainTextName, ordinal []byte) []byte {
	var prng seededPrng
	prng.seed(plainTextName)
	priv, err := ecdsa.GenerateKey(ECCCurveBrainpoolP160T1, &prng)
	if err != nil {
		panic(err)
	}

	var publicKeyHash [SelectorKeySize]byte
	pcomp, _ := ECDSACompressPublicKey(&priv.PublicKey)
	if pcomp != nil {
		publicKeyHash = sha256.Sum256(pcomp)
	}

	addOrdinalToHash(&publicKeyHash, ordinal)

	return publicKeyHash[:]
}

// claimKey recovers the public key from this selector's claim and the hash used to generate it.
func (s *Selector) claimKey(hash []byte) *ecdsa.PublicKey {
	sigHash := sha3.New256()
	sigHash.Write(hash)
	sigHash.Write(s.Ordinal)
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
	var publicKeyHash [SelectorKeySize]byte
	if pub != nil {
		pcomp, _ := ECDSACompressPublicKey(pub)
		if pcomp != nil {
			publicKeyHash = sha256.Sum256(pcomp)
		}
	}
	addOrdinalToHash(&publicKeyHash, s.Ordinal)
	return publicKeyHash[:]
}

func (s *Selector) marshalTo(out io.Writer) error {
	if len(s.Claim) != 41 {
		return ErrInvalidObject
	}
	if len(s.Ordinal) > SelectorMaxOrdinalSize || s.Claim[40] > 1 {
		return ErrInvalidObject
	}

	// This packs the ordinal length, selector type, and the last byte of the claim signature
	// into the first byte. The last byte of the claim signature holds either 0 or 1 to select
	// which key recovery index should be used. This saves a few bytes per selector which can
	// add up with records with multiple selectors.
	if _, err := out.Write([]byte{(byte(len(s.Ordinal)) << 3) | (SelectorTypeBP160 << 1) | s.Claim[40]}); err != nil {
		return err
	}
	if len(s.Ordinal) > 0 {
		if _, err := out.Write(s.Ordinal); err != nil {
			return err
		}
	}
	if _, err := out.Write(s.Claim[0:40]); err != nil {
		return err
	}

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

func (s *Selector) unmarshalFrom(in io.Reader) error {
	var typeOrdinalLenClaimSignatureRecoveryIndex [1]byte
	if _, err := io.ReadFull(in, typeOrdinalLenClaimSignatureRecoveryIndex[:]); err != nil {
		return err
	}
	if ((typeOrdinalLenClaimSignatureRecoveryIndex[0] >> 1) & 3) != SelectorTypeBP160 {
		return ErrInvalidObject
	}
	ordSize := uint(typeOrdinalLenClaimSignatureRecoveryIndex[0] >> 3)
	if ordSize > 0 {
		s.Ordinal = make([]byte, ordSize)
		if _, err := io.ReadFull(in, s.Ordinal); err != nil {
			return err
		}
	} else {
		s.Ordinal = nil
	}
	s.Claim = make([]byte, 41)
	if _, err := io.ReadFull(in, s.Claim[0:40]); err != nil {
		return err
	}
	s.Claim[40] = typeOrdinalLenClaimSignatureRecoveryIndex[0] & 1
	return nil
}

// set sets this selector to a given plain text name, ordinal, and record body hash.
// The hash supplied is the record's body hash. If this selector is not intended for range
// queries use nil for its ordinal.
func (s *Selector) set(plainTextName, ord, hash []byte) {
	if len(ord) > SelectorMaxOrdinalSize {
		s.Ordinal = make([]byte, SelectorMaxOrdinalSize)
		copy(s.Ordinal, ord[len(ord)-SelectorMaxOrdinalSize:])
	} else {
		s.Ordinal = ord
	}

	// Generate an ECDSA key pair deterministically using the plain text name. Note that
	// this depends on the ECDSA key generation algorithm. Go currently implements the
	// standard [NSA] A.2.1 algorithm. As long as this doesn't change we're fine. If it
	// does we'll have to copypasta the original [NSA] A.2.1 code.
	var prng seededPrng
	prng.seed(plainTextName)
	priv, err := ecdsa.GenerateKey(ECCCurveBrainpoolP160T1, &prng)

	// The hash we actually sign includes the ordinal so that ordinals, while publicly
	// visible, can't be forged without knowledge of the plain text name. Note that the
	// claim is based on a signature computed from the plain text name, so that is
	// a priori included too.
	sigHash := sha3.New256()
	sigHash.Write(hash)
	sigHash.Write(ord)
	var sigHashBuf [32]byte
	cs, err := ECDSASignEmbedRecoveryIndex(priv, sigHash.Sum(sigHashBuf[:0]))
	if err != nil || len(cs) != 41 { // this would indicate a bug
		panic("ECDSA signature for selector generation failed!")
	}
	s.Claim = cs
}
