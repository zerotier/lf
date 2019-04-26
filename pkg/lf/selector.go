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
	"encoding/binary"
	"io"
	"math/big"
)

// SelectorTypeBP160 indicates a sortable selector built from the brainpoolP160t1 elliptic curve.
const SelectorTypeBP160 byte = 0

// SelectorMaxOrdinalSize is the maximum length of an ordinal. The functions will take longer
// ordinals but characters to the left of the right-most 64 are ignored.
const SelectorMaxOrdinalSize = 64

// SelectorKeySize is the size of the sortable ordinal-modified hash used for DB queries and range queries.
// It's computed by adding the ordinal to the SHA512 hash of the deterministic selector public key.
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
func MakeSelectorKey(plainTextName []byte, ordinal []byte) []byte {
	if len(ordinal) > 64 {
		ordinal = ordinal[len(ordinal)-64:]
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
// The Record SelectorKey(n) method is a more convenient way to use this.
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

// marshalTo outputs this selector to a writer.
func (s *Selector) marshalTo(out io.Writer) error {
	if _, err := writeUVarint(out, uint64(len(s.Ordinal))); err != nil {
		return err
	}
	if _, err := out.Write(s.Ordinal); err != nil {
		return err
	}
	if _, err := out.Write([]byte{SelectorTypeBP160}); err != nil {
		return err
	}
	if _, err := out.Write(s.Claim[:]); err != nil {
		return err
	}
	return nil
}

// bytes returns this selector marshaled to a byte array.
func (s *Selector) bytes() []byte {
	var b bytes.Buffer
	s.marshalTo(&b)
	return b.Bytes()
}

// unmarshalFrom reads a selector from this input stream.
func (s *Selector) unmarshalFrom(in io.Reader) error {
	br := byteAndArrayReader{in}
	l, err := binary.ReadUvarint(&br)
	if err != nil {
		return err
	}
	if l > RecordMaxSize {
		return ErrRecordTooLarge
	}
	s.Ordinal = make([]byte, int(l))
	_, err = io.ReadFull(&br, s.Ordinal)
	if err != nil {
		return err
	}
	t, err := br.ReadByte()
	if err != nil {
		return err
	}
	if t != SelectorTypeBP160 {
		return ErrUnsupportedType
	}
	_, err = io.ReadFull(&br, s.Claim[:])
	return err
}

// set sets this selector to a given plain text name, ordinal, and record body hash.
// The hash supplied is the record's body hash. If this selector is not intended for range
// queries use nil for its ordinal.
func (s *Selector) set(plainTextName []byte, ord []byte, hash []byte) {
	if len(ord) > 64 {
		s.Ordinal = make([]byte, 64)
		copy(s.Ordinal, ord[len(ord)-64:])
	} else {
		s.Ordinal = ord
	}

	// Generate an ECDSA key pair deterministically using the plain text name. Note that
	// this depends on the ECDSA key generation algorithm. Go currently implements the
	// standard [NSA] A.2.1 algorithm. As long as this doesn't change we're fine. If it
	// does we'll have to copypasta the original [NSA] A.2.1 code. This is checked by
	// testing known selectors in selftest.go.
	var prng seededPrng
	prng.seed(plainTextName)
	priv, err := ecdsa.GenerateKey(ECCCurveBrainpoolP160T1, &prng)

	// The hash we actually sign includes the ordinal so that ordinals, while publicly
	// visible, can't be forged without knowledge of the plain text name.
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
