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
)

// SelectorTypeBP160 indicates a sortable selector built from the brainpoolP160t1 elliptic curve.
const SelectorTypeBP160 byte = 0

// Selector is a non-forgeable range queryable identifier for records.
type Selector struct {
	Ordinal Blob     `json:",omitempty"` // An ordinal value that can be used to perform range queries against selectors
	Claim   [41]byte ``                  // 41-byte brainpoolP160t1 recoverable signature
}

func addOrdinalToHash(h *[64]byte, ordinal []byte) {
	var carry byte
	for hi, oi := 63, len(ordinal)-1; hi >= 0; hi-- {
		var o byte
		if oi >= 0 {
			o = ordinal[oi]
			oi--
		} else if carry == 0 {
			break
		}

		b := h[hi]
		old := b
		b += o
		var c byte
		if b < old {
			c = 1
		}
		h[hi] = b + carry

		carry = c
	}
}

// MakeSelectorKey generates a masked selector database key from a plain text name.
// If this name is not used with range queries use zero for the ordinal. This function exists
// to allow selector database keys to be created separate from record creation if needed.
func MakeSelectorKey(plainTextName []byte, ordinal []byte) []byte {
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
	s.Ordinal = ord

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
