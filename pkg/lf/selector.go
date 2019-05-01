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
	"crypto/sha512"
	"io"
	"math/big"
)

// SelectorTypeBP160 indicates a sortable selector built from the brainpoolP160t1 elliptic curve.
const SelectorTypeBP160 byte = 0 // valid range: 0..3

// SelectorMaxOrdinalSize is the maximum length of an ordinal.
// Functions will take larger ordinals but bytes to the left of this size are ignored.
// This is a protocol constant and cannot be changed.
const SelectorMaxOrdinalSize = 31

// SelectorKeySize is the size of the sortable ordinal-modified hash used for DB queries and range queries.
// It's computed by adding the ordinal to the SHA512 hash of the deterministic selector public key.
// This is a protocol constant and cannot be changed.
const SelectorKeySize = 64

// Selector is a non-forgeable range queryable identifier for records.
type Selector struct {
	Ordinal Blob     `json:",omitempty"` // A plain text sortable field that can be used for range queries against secret selectors
	Claim   [41]byte ``                  // 41-byte brainpoolP160t1 recoverable signature
}

func addOrdinalToHash(h *[64]byte, ordinal []byte) {
	var a, b big.Int
	a.Add(a.SetBytes(h[:]), b.SetBytes(ordinal))
	ab := a.Bytes()
	if len(ab) >= 64 {
		copy(h[:], ab[len(ab)-64:])
	} else {
		for i, j := 0, 64-len(ab); i < j; i++ {
			h[i] = 0
		}
		copy(h[0:64-len(ab)], ab)
	}
}

// MakeSelectorKey generates a masked selector database key from a plain text name.
// If this name is not used with range queries use zero for the ordinal. This function exists
// to allow selector database keys to be created separate from record creation if needed.
func MakeSelectorKey(plainTextName, ordinal []byte) []byte {
	if len(ordinal) > SelectorMaxOrdinalSize {
		ordinal = ordinal[len(ordinal)-SelectorMaxOrdinalSize:]
	}

	var prng seededPrng
	prng.seed(plainTextName)
	priv, err := ecdsa.GenerateKey(ECCCurveBrainpoolP160T1, &prng)
	if err != nil {
		panic(err)
	}

	var publicKeyHash [64]byte
	pcomp, _ := ECDSACompressPublicKey(&priv.PublicKey)
	if pcomp != nil {
		publicKeyHash = sha512.Sum512(pcomp)
	}

	addOrdinalToHash(&publicKeyHash, ordinal)

	return publicKeyHash[:]
}

// key returns the sortable and comparable database key for this selector.
// This must be supplied with the hash that was used in set() to perform ECDSA key recovery.
func (s *Selector) key(hash []byte) []byte {
	sigHash := sha256.New()
	sigHash.Write(hash)
	sigHash.Write(s.Ordinal)
	var sigHashBuf [32]byte
	pub := ECDSARecover(ECCCurveBrainpoolP160T1, sigHash.Sum(sigHashBuf[:0]), s.Claim[:])

	var publicKeyHash [64]byte
	if pub != nil {
		pcomp, _ := ECDSACompressPublicKey(pub)
		if pcomp != nil {
			publicKeyHash = sha512.Sum512(pcomp)
		}
	}

	addOrdinalToHash(&publicKeyHash, s.Ordinal)

	return publicKeyHash[:]
}

func (s *Selector) marshalTo(out io.Writer) error {
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
	sigHash := sha256.New()
	sigHash.Write(hash)
	sigHash.Write(ord)
	var sigHashBuf [32]byte
	cs, err := ECDSASignEmbedRecoveryIndex(priv, sigHash.Sum(sigHashBuf[:0]))
	if err != nil || len(cs) != len(s.Claim) { // this would indicate a bug
		panic("ECDSA signature for selector generation failed!")
	}
	copy(s.Claim[:], cs)
}
