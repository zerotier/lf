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

//
// A selector is a sortable token created from a name and an ordinal that defines sort order. A selector consists
// of an ECDSA signature of a record's body (body hash) and the ordinal signed by a key pair created deterministically
// from a plain text name. The selector key itself is the public key (which can be recovered from this signature)
// followed by the ordinal, making it sortable.
//
// The purpose of this exotic construction is to simultaneously mask and prove knowledge of a selector's name. It is
// not possible (without breaking a modest size ECC key) to create a selector for a given name without knowing that
// name and selectors do not reveal the names from which they were created.
//
// This prevents a type of DOS or application level attack where an attacker could "claim" record IDs for records
// not yet created by an application. It also means that selector names can be treated as secrets if desired and if
// they are kept secret records cannot be created with them by anyone who doesn't know them.
//

// SelectorTypeBP160 indicates a sortable selector built from the brainpoolP160t1 elliptic curve.
const SelectorTypeBP160 byte = 0

// Selector is a non-forgeable range queryable identifier for records.
type Selector struct {
	Ordinal Blob    // An ordinal value that can be used to perform range queries against selectors
	Claim   Blob328 // 41-byte brainpoolP160t1 recoverable signature
}

func addOrdinalToHash(h *[32]byte, ordinal []byte) {
	var carry byte
	for hi, oi := 31, len(ordinal)-1; hi >= 0; hi-- {
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

	var publicKeyHash [32]byte
	pcomp, _ := ECDSACompressPublicKey(&priv.PublicKey)
	if pcomp != nil {
		publicKeyHash = sha3.Sum256(pcomp)
	}

	addOrdinalToHash(&publicKeyHash, ordinal)

	return publicKeyHash[:]
}

// key returns the sortable and comparable database key for this selector.
// This must be supplied with the hash that was used in set() to perform key recovery.
// The Record SelectorKey(n) method is a more convenient way to use this.
func (s *Selector) key(hash []byte) []byte {
	sigHash := sha256.New()
	sigHash.Write(hash)
	sigHash.Write(s.Ordinal)
	var sigHashBuf [32]byte
	pub := ECDSARecover(ECCCurveBrainpoolP160T1, sigHash.Sum(sigHashBuf[:0]), s.Claim[:])

	var publicKeyHash [32]byte
	if pub != nil {
		pcomp, _ := ECDSACompressPublicKey(pub)
		if pcomp != nil {
			publicKeyHash = sha3.Sum256(pcomp)
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
		return ErrorRecordTooLarge
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
		return ErrorUnsupportedType
	}
	_, err = io.ReadFull(&br, s.Claim[:])
	return err
}

// set sets this selector to a given plain text name, ordinal, and record body hash.
// The hash supplied is the record's body hash. If this selector is not intended for range
// queries use zero for its ordinal.
func (s *Selector) set(plainTextName []byte, ord []byte, hash []byte) {
	s.Ordinal = ord

	var prng seededPrng
	prng.seed(plainTextName)
	priv, err := ecdsa.GenerateKey(ECCCurveBrainpoolP160T1, &prng)

	sigHash := sha256.New()
	sigHash.Write(hash)
	sigHash.Write(ord)
	var sigHashBuf [32]byte
	cs, err := ECDSASignEmbedRecoveryIndex(priv, sigHash.Sum(sigHashBuf[:0]))
	if err != nil {
		panic(err)
	}
	if len(cs) != len(s.Claim) {
		panic("claim signature size is not correct")
	}
	copy(s.Claim[:], cs)
}
