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
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
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
	Ordinal uint64   // An ordinal value that can be used to perform range queries against selectors
	Claim   [41]byte // 41-byte brainpoolP160t1 recoverable signature
}

type selectorInternalJSON struct {
	Ordinal uint64
	Claim   Blob
}

// MarshalJSON encodes this Selector as a JSON object using Blob to encode the claim.
func (s *Selector) MarshalJSON() ([]byte, error) {
	str := fmt.Sprintf("{\"Ordinal\":%d,\"Claim\":\"\\b%s\"}", s.Ordinal, base64.StdEncoding.EncodeToString(s.Claim[:]))
	return []byte(str), nil
}

// UnmarshalJSON decodes this Selector as a JSON object.
func (s *Selector) UnmarshalJSON(j []byte) error {
	var tmp selectorInternalJSON
	err := json.Unmarshal(j, &tmp)
	if err != nil {
		return err
	}
	s.Ordinal = tmp.Ordinal
	if len(tmp.Claim) == len(s.Claim) {
		copy(s.Claim[:], tmp.Claim)
	}
	return nil
}

// MakeSelectorKey generates a masked selector database key from a plain text name.
// If this name is not used with range queries use zero for the ordinal. This function exists
// to allow selector database keys to be created separate from record creation if needed.
func MakeSelectorKey(plainTextName []byte, ord uint64) []byte {
	var prng seededPrng
	prng.seed(plainTextName)
	priv, err := ecdsa.GenerateKey(ECCCurveBrainpoolP160T1, &prng)
	if err != nil {
		panic(err)
	}
	ck, _ := ECDSACompressPublicKey(&priv.PublicKey)
	var o [8]byte
	binary.BigEndian.PutUint64(o[:], ord)
	return append(ck, o[:]...)
}

// key returns the sortable and comparable database key for this selector.
// This must be supplied with the hash that was used in Set() to perform key recovery.
// The Record SelectorKey(n) method is a more convenient way to use this.
func (s *Selector) key(hash []byte) []byte {
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

// marshalTo outputs this selector to a writer.
func (s *Selector) marshalTo(out io.Writer) error {
	out.Write([]byte{SelectorTypeBP160})
	writeUVarint(out, s.Ordinal)
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

// set sets this selector to a given plain text name, ordinal, and record body hash.
// The hash supplied is the record's body hash. If this selector is not intended for range
// queries use zero for its ordinal.
func (s *Selector) set(plainTextName []byte, ord uint64, hash []byte) {
	s.Ordinal = ord

	var prng seededPrng
	prng.seed(plainTextName)
	priv, err := ecdsa.GenerateKey(ECCCurveBrainpoolP160T1, &prng)

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
