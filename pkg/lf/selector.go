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

// sha384csprng is a Reader that acts as a random source for generating ECDSA key pairs deterministically.
type sha384csprng struct {
	s384 [48]byte
	n    int
}

func (prng sha384csprng) Read(b []byte) (int, error) {
	for i := 0; i < len(b); i++ {
		b[i] = prng.s384[prng.n]
		prng.n++
		b[i] ^= prng.s384[prng.n] // make sure you can't infer CSPRNG state from output, though this probably doesn't matter for our use case
		prng.n++
		if prng.n == 48 {
			prng.s384 = sha512.Sum384(prng.s384[:])
			prng.n = 0
		}
	}
	return len(b), nil
}

// SelectorTypeBP160 indicates a sortable selector built from the brainpoolP160t1 elliptic curve.
const SelectorTypeBP160 byte = 0

// Selector is a non-forgeable range queryable identifier for records.
type Selector struct {
	Ordinal uint64   // An ordinal value that can be used to perform range queries against selectors
	Claim   [41]byte // 40-byte brainpoolP160t1 signature with additional byte of recovery information
}

// MakeSelectorKey generates a masked selector database key from a plain text name.
// If this name is not used with range queries use zero for the ordinal. This function exists
// to allow selector database keys to be created separate from record creation if needed.
func MakeSelectorKey(plainTextName []byte, ord uint64) []byte {
	priv, err := ecdsa.GenerateKey(ECCCurveBrainpoolP160T1, &sha384csprng{s384: sha512.Sum384(plainTextName), n: 0})
	if err != nil {
		panic(err)
	}
	ck, _ := ECDSACompressPublicKey(&priv.PublicKey)
	var o [8]byte
	binary.BigEndian.PutUint64(o[:], ord)
	return append(ck, o[:]...)
}

// Key returns the sortable and comparable database key for this selector.
// This must be supplied with the hash that was used in Set() to perform key recovery.
// The Record SelectorKey(n) method is a more convenient way to use this.
func (s *Selector) Key(hash []byte) []byte {
	var obytes [8]byte
	binary.BigEndian.PutUint64(obytes[:], s.Ordinal)
	sigHash := sha256.New()
	sigHash.Write(hash)
	sigHash.Write(obytes[:])
	var sigHashBuf [32]byte
	pub := ECDSARecover(ECCCurveBrainpoolP160T1, sigHash.Sum(sigHashBuf[:0]), s.Claim[:])
	if pub == nil {
		return obytes[:]
	}
	pcomp, err := ECDSACompressPublicKey(pub)
	if err != nil {
		return obytes[:]
	}
	return append(pcomp, obytes[:]...)
}

// MarshalTo outputs this selector to a writer.
func (s *Selector) MarshalTo(out io.Writer) error {
	out.Write([]byte{SelectorTypeBP160})
	writeUVarint(out, s.Ordinal)
	if _, err := out.Write(s.Claim[:]); err != nil {
		return err
	}
	return nil
}

// Bytes returns this selector marshaled to a byte array.
func (s *Selector) Bytes() []byte {
	var b bytes.Buffer
	s.MarshalTo(&b)
	return b.Bytes()
}

// UnmarshalFrom reads a selector from this input stream.
func (s *Selector) UnmarshalFrom(in io.Reader) error {
	br := byteAndArrayReader{r: in}
	selType, err := br.ReadByte()
	if err != nil {
		return err
	}
	if selType != SelectorTypeBP160 {
		return ErrorUnsupportedType
	}
	s.Ordinal, err = binary.ReadUvarint(&br)
	if err != nil {
		return err
	}
	_, err = io.ReadFull(&br, s.Claim[:])
	return err
}

// Set sets this selector to a given plain text name, ordinal, and record body hash.
// The hash supplied is the record's body hash. If this selector is not intended for range
// queries use zero for its ordinal.
func (s *Selector) Set(plainTextName []byte, ord uint64, hash []byte) {
	s.Ordinal = ord

	priv, err := ecdsa.GenerateKey(ECCCurveBrainpoolP160T1, &sha384csprng{s384: sha512.Sum384(plainTextName), n: 0})

	var obytes [8]byte
	binary.BigEndian.PutUint64(obytes[:], ord)
	sigHash := sha256.New()
	sigHash.Write(hash)
	sigHash.Write(obytes[:])
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
