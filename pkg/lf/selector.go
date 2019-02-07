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
// A selector consists of a public key from a key pair deterministically generated from the selector's plain text name,
// a 64-bit ordinal that can be used for range queries, and a signature. The signature signs the record to which this
// selector is attached, its key, and its ordinal. The purpose of this signature system is to prove knowledge of the
// selector's plain text name without actually revealing it, making selector names private unless explicitly revealed.
// This makes it easier to build secure apps that rely on private identifiers and also protects the network against a
// class of denial of service or application data corrupting attacks where an attacker naively creates bogus records with
// overlapping keys without actually knowing what the keys really are. The curve used for selector claim sigantures is
// small, making that a really determined attacker may be able to forge one, but it's big enough that the cost of such
// an attack would outweigh its modest result (assuming LF based apps are well designed). Much larger ECC curves are
// used for more important security roles in the LF system.
type Selector struct {
	Ordinal        uint64   // An ordinal value that can be used to perform range queries against selectors
	ClaimKey       [21]byte // 21-byte brainpoolP160t1 public key
	ClaimSignature [40]byte // 40-byte brainpoolP160t1 signature
}

// MakeSelectorKey generates a masked selector database key from a plain text name.
// If this name is not used with range queries use zero for the ordinal. This function exists
// to allow selector database keys to be created separate from record creation if needed.
func MakeSelectorKey(plainTextName []byte, ord uint64) []byte {
	priv, err := ecdsa.GenerateKey(&ECCCurveBrainpoolP160T1, &sha384csprng{s384: sha512.Sum384(plainTextName), n: 0})
	if err != nil {
		panic(err)
	}
	ck, _ := ECDSACompressPublicKeyWithID(&priv.PublicKey, SelectorTypeBP160)
	var o [8]byte
	binary.BigEndian.PutUint64(o[:], ord)
	return append(ck, o[:]...)
}

// Key returns the sortable opaque key used to store this selector in a database.
// It consists of the claim key followed by the ordinal as a big-endian 64-bit integer.
func (s *Selector) Key() (k []byte) {
	k = make([]byte, 29)
	copy(k[0:21], s.ClaimKey[:])
	binary.BigEndian.PutUint64(k[21:29], s.Ordinal)
	return
}

// MarshalTo outputs this selector to a writer.
func (s *Selector) MarshalTo(out io.Writer) error {
	writeUVarint(out, s.Ordinal)
	if _, err := out.Write(s.ClaimKey[:]); err != nil {
		return err
	}
	if _, err := out.Write(s.ClaimSignature[:]); err != nil {
		return err
	}
	return nil
}

// Bytes returns this selector marshaled to a byte array.
func (s *Selector) Bytes() []byte {
	var b bytes.Buffer
	b.Grow(40 + 21 + 8)
	s.MarshalTo(&b)
	return b.Bytes()
}

// UnmarshalFrom reads a selector from this input stream.
func (s *Selector) UnmarshalFrom(in io.Reader) error {
	br := byteAndArrayReader{r: in}
	ord, err := binary.ReadUvarint(&br)
	if err != nil {
		return err
	}
	s.Ordinal = ord
	s.ClaimKey[0], err = br.ReadByte()
	if err != nil {
		return err
	}
	if (s.ClaimKey[0] >> 1) != SelectorTypeBP160 {
		return ErrorUnsupportedType
	}
	_, err = br.Read(s.ClaimKey[1:])
	if err != nil {
		return err
	}
	_, err = br.Read(s.ClaimSignature[:])
	return err
}

// Claim initializes and signs this selector for a given record.
// The hash supplied is the record's body hash. If this selector is not intended for range
// queries use zero for its ordinal.
func (s *Selector) Claim(plainTextName []byte, ord uint64, hash []byte) {
	s.Ordinal = ord

	priv, err := ecdsa.GenerateKey(&ECCCurveBrainpoolP160T1, &sha384csprng{s384: sha512.Sum384(plainTextName), n: 0})
	if err != nil {
		panic(err)
	}
	ck, _ := ECDSACompressPublicKeyWithID(&priv.PublicKey, SelectorTypeBP160)
	if len(ck) != len(s.ClaimKey) {
		panic("claim key compression failed")
	}
	copy(s.ClaimKey[:], ck)

	sigHash := sha256.New()
	sigHash.Write(hash)
	sigHash.Write(ck)
	var obytes [8]byte
	binary.BigEndian.PutUint64(obytes[:], ord)
	sigHash.Write(obytes[:])
	var sigHashBuf [32]byte
	cs, err := ECDSASign(priv, sigHash.Sum(sigHashBuf[:0]))
	if err != nil {
		panic(err)
	}
	if len(cs) != len(s.ClaimSignature) {
		panic("claim signature size is not correct")
	}
	copy(s.ClaimSignature[:], cs)
}

// VerifyClaim verifies that the creator of this selector knew its plain text name when it was attached to its record.
func (s *Selector) VerifyClaim(hash []byte) bool {
	pub, err := ECDSADecompressPublicKey(&ECCCurveBrainpoolP160T1, s.ClaimKey[:])
	if err != nil {
		return false
	}
	sigHash := sha256.New()
	sigHash.Write(hash)
	sigHash.Write(s.ClaimKey[:])
	var obytes [8]byte
	binary.BigEndian.PutUint64(obytes[:], s.Ordinal)
	sigHash.Write(obytes[:])
	var sigHashBuf [32]byte
	return ECDSAVerify(pub, sigHash.Sum(sigHashBuf[:0]), s.ClaimSignature[:])
}
