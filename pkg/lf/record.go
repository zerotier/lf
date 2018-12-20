/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/binary"
	"io"
	"math/rand"

	"golang.org/x/crypto/ed25519"
)

// Record value encryption algorithm IDs (range 0-3)
const (
	RecordValueEncryptionAlgorithmNone      = byte(0)
	RecordValueEncryptionAlgorithmAES256CFB = byte(1)
)

// Record work algorithm IDs (range 0-3)
const (
	RecordWorkAlgorithmNone       = byte(0)
	RecordWorkAlgorithmWharrgarbl = byte(1)
)

// Record signature algorithm IDs (range 0-3) (no "none" here since there must be signatures)
const (
	RecordSignatureAlgorithmEd25519 = byte(0)
)

// Record meta-data field types (range 0-15) and sizes
const (
	RecordMetaDataTypeNone        = byte(0)
	RecordMetaDataTypeChangeOwner = byte(1)
	RecordMetaDataTypeSelectorID  = byte(2)
)

// Record flag bits
const (
	RecordFlagValueDeflated = uint64(0x1)
)

// RecordMaxLinkCount is the maximum number of links one record can have to previous records (cannot be changed).
const RecordMaxLinkCount = 31

// RecordDesiredLinks is how many links records should have (can be increased).
const RecordDesiredLinks = 3

// RecordMaxTimeDrift is the maximum number of seconds in the future (vs. local time) a record may be before it is rejected.
const RecordMaxTimeDrift = uint64(10)

// RecordMaxValueSize is the maximum size of a value (cannot easily be changed, protocol maximum: 2047).
const RecordMaxValueSize = 512

// RecordWharrgarblMemory is the memory size that should be used for Wharrgarbl PoW.
// This is large enough to perform well up to relatively big record sizes. It'll still work for
// really huge ones of course, but performance starts to drop a bit. It can be increased and could
// be made configurable in the future if ever needed.
const RecordWharrgarblMemory = uint(1024 * 1024 * 256) // 256mb

// RecordMinSize is the minimum possible size of a serialized record (real records will always be bigger but never smaller).
const RecordMinSize = 71 // ID + owner + timestamp + TTL + flags + algorithms + link count and value length + meta-data types

// RecordMaxSize is the maximum possible record size supported by LF (cannot be changed).
const RecordMaxSize = 65535

// Record is an entry in the LF key/value store.
// The Data field contains the real record data. The rest of these fields are expansions
// to make the record much easier to access.
type Record struct {
	Data []byte `msgpack:"D"`

	// Expanded record fields
	Hash                      [32]byte  `msgpack:"H"`                      // Shandwich256(Data)
	ID                        [32]byte  `msgpack:"ID"`                     // Public key (or hash thereof) derived from the record's plain text key
	Owner                     [32]byte  `msgpack:"O"`                      // Public key (or hash thereof) of the record's owner
	Timestamp                 uint64    `msgpack:"T"`                      // Timestamp in SECONDS since epoch, also doubles as revision ID
	TTL                       uint64    `msgpack:"TTL"`                    // Time to live in SECONDS since epoch
	Flags                     uint64    `msgpack:"F"`                      // Flags setting various record attributes
	Value                     []byte    `msgpack:"V"`                      // Record data payload (encrypted if encryption algorithm is non-zero)
	ValueEncryptionAlgorithm  byte      `msgpack:"VEA"`                    // Encryption algorithm for record data
	WorkAlgorithm             byte      `msgpack:"WA"`                     // Work algorithm used to "pay" for record
	OwnerSignatureAlgorithm   byte      `msgpack:"OSA"`                    // Signature algorithm used to sign record by owner
	IDClaimSignatureAlgorithm byte      `msgpack:"IDCSA"`                  // Signature algorithm used to prove knowledge of plain text key (and selectors)
	Links                     []byte    `msgpack:"L" json:",omitempty"`    // Hashes of older records (size is always a multiple of 32 bytes)
	ChangeOwner               []byte    `msgpack:"CO" json:",omitempty"`   // New owner to inherit previous owner's record set weights
	SelectorIDs               [2][]byte `msgpack:"SIDs" json:",omitempty"` // Sel0 ID, Sel1 ID (if present)
	WorkHash                  [64]byte  `msgpack:"WH"`                     // Hash of everything up to proof of work on which PoW operates
	Work                      []byte    `msgpack:"W"`                      // Output of work algorithm
	SigningHash               [64]byte  `msgpack:"SH"`                     // Hash of record and work that is signed by owner and claim signatures
	OwnerSignature            []byte    `msgpack:"OS"`                     // Signature of record by owner
	IDClaimSignature          []byte    `msgpack:"IDCS"`                   // Signature of record data by signing key derived from plain text record key
	SelectorSignatures        [2][]byte `msgpack:"SS" json:",omitempty"`   // Proof of knowledge signatures for selectors, if present
}

// RecordWharrgarblCost computes the cost in Wharrgarbl difficulty for a record whose total size is the supplied number of bytes.
func RecordWharrgarblCost(bytes int) uint32 {
	//
	// This function was figured out by:
	//
	// (1) Empirically sampling difficulty vs time.
	// (2) Using Microsoft Excel to fit the curve to a power function, yielding: d =~ 1.739 * b^1.5605
	// (3) Figuring out an integer based function that approximates this power function relatively well for our plausible input range.
	//
	// An integer only algorithm is used to avoid FPU inconsistencies across systems.
	//
	// This function provides a relatively linear relationship between average Wharrgarbl time
	// and the number of bytes (total) in a record.
	//
	b := uint64(bytes * 2) // this adjusts the overall magnitude without affecting the curve's shape
	c := (uint64(integerSqrtRounded(uint32(b))) * b * uint64(3)) - (b * 8)
	if c > 0xffffffff { // sanity check, no record gets this big
		return 0xffffffff
	}
	return uint32(c)
}

// RecordDeriveID derives a blinded public ID from a plain-text key.
// This is done automatically when creating a record either step-by-step or with NewRecord().
// This function can be used to get the ID of a record based on its plain text key for querying
// or other purposes.
func RecordDeriveID(key []byte) (id [32]byte, privateKey []byte) {
	s512 := sha512.Sum512(key)
	copy(id[0:32], s512[0:32])
	privateKey = ed25519.NewKeyFromSeed(s512[0:32])
	return
}

// packMainSection serializes into the supplied buffer up to the point where the record's contents are hashed for proof of work, signatures, etc.
func (r *Record) packMainSection(b *bytes.Buffer) error {
	if len(r.Value) > RecordMaxValueSize {
		return ErrorRecordValueTooLarge
	}

	b.Write(r.ID[:])
	b.Write(r.Owner[:])
	writeUVarint(b, r.Timestamp)
	writeUVarint(b, r.TTL)
	writeUVarint(b, r.Flags)

	linkCount := len(r.Links) / 32
	if (linkCount*32) != len(r.Links) || linkCount > RecordMaxLinkCount {
		return ErrorRecordLinksInvalid
	}
	linkCountAndValueSize := (linkCount << 11) | (len(r.Value) & 0x7ff)
	b.WriteByte(byte(linkCountAndValueSize>>8) & 0xff)
	b.WriteByte(byte(linkCountAndValueSize & 0xff))

	b.Write(r.Value)
	b.Write(r.Links)

	if ((r.ValueEncryptionAlgorithm | r.WorkAlgorithm | r.OwnerSignatureAlgorithm | r.IDClaimSignatureAlgorithm) & 0xfc) != 0 {
		return ErrorRecordAlgorithmTypeInvalid
	}
	b.WriteByte((r.ValueEncryptionAlgorithm << 6) | (r.WorkAlgorithm << 4) | (r.OwnerSignatureAlgorithm << 2) | r.IDClaimSignatureAlgorithm)

	var mdc uint
	var mdt [2]byte
	var md [2][]byte
	if len(r.ChangeOwner) == 32 {
		mdt[0] = RecordMetaDataTypeChangeOwner
		md[0] = r.ChangeOwner
		mdc++
	}
	for si := range r.SelectorIDs {
		if len(r.SelectorIDs[si]) > 0 {
			if mdc >= 2 {
				return ErrorRecordOnlyTwoMetaDataSlots
			}
			if len(r.SelectorIDs[si]) != 32 {
				return ErrorRecordInvalid
			}
			mdt[mdc] = RecordMetaDataTypeSelectorID
			md[mdc] = r.SelectorIDs[si]
		}
	}

	b.WriteByte((mdt[0] << 4) | mdt[1])
	for i := 0; i < 2; i++ {
		switch mdt[i] {
		case RecordMetaDataTypeNone:
		case RecordMetaDataTypeChangeOwner:
			b.Write(md[i])
		case RecordMetaDataTypeSelectorID:
			b.Write(md[i])
		default:
			writeUVarint(b, uint64(len(md[i]))) // support future additions with size for flexibility
			b.Write(md[i])
		}
	}

	return nil
}

func (r *Record) setValue(key, value []byte, encrypt bool) error {
	r.Flags &= ^RecordFlagValueDeflated

	if len(value) == 0 {
		r.Value = nil
		return nil
	}

	v := value
	if len(value) > 32 {
		var cb bytes.Buffer
		cw, err := flate.NewWriter(&cb, flate.BestCompression)
		if err == nil {
			_, err = cw.Write(value)
			if err == nil {
				cw.Close()
				if cb.Len() < len(value) {
					v = cb.Bytes()
					r.Flags |= RecordFlagValueDeflated
				}
			}
		}
	}
	if len(v) > RecordMaxValueSize {
		return ErrorRecordValueTooLarge
	}

	r.Value = make([]byte, len(v))
	if encrypt {
		var iv [16]byte
		binary.BigEndian.PutUint64(iv[0:8], r.Timestamp)
		copy(iv[8:16], r.Owner[0:8]) // every owner+timestamp combo is unique since timestamp is also revision, thus unique IV
		s512 := sha512.Sum512(key)
		c, _ := aes.NewCipher(s512[32:64]) // first 32 bytes are used to derive ID, second 32 are used to encrypt value
		cfb := cipher.NewCFBEncrypter(c, iv[:])
		cfb.XORKeyStream(r.Value, v)
		r.ValueEncryptionAlgorithm = RecordValueEncryptionAlgorithmAES256CFB
	} else {
		copy(r.Value, v)
		r.ValueEncryptionAlgorithm = RecordValueEncryptionAlgorithmNone
	}
	return nil
}

// NewRecord creates a new record.
// This can be a time consuming operation due to proof of work. The skipWork paramter
// allows work to be skipped. This generates a record that wouldn't be valid on a live
// network but can be used for e.g. database self-test or record encode/decode self-test.
func NewRecord(key, value, links []byte, ts, ttl uint64, encryptValue bool, changeOwner []byte, selectors [][]byte, ownerPrivateKey []byte, skipWork bool) (*Record, error) {
	var r Record

	if len(ownerPrivateKey) != 64 {
		return nil, ErrorInvalidPrivateKey
	}
	if len(selectors) > 2 || (len(changeOwner) == 32 && len(selectors) > 1) {
		return nil, ErrorRecordOnlyTwoMetaDataSlots
	}
	if len(changeOwner) > 0 && len(changeOwner) != 32 {
		return nil, ErrorInvalidParameter
	}

	id, idClaimPrivateKey := RecordDeriveID(key)
	r.ID = id
	copy(r.Owner[:], ownerPrivateKey[32:64])
	r.Timestamp = ts
	r.TTL = ttl
	r.setValue(key, value, encryptValue)
	r.WorkAlgorithm = RecordWorkAlgorithmWharrgarbl
	r.OwnerSignatureAlgorithm = RecordSignatureAlgorithmEd25519
	r.IDClaimSignatureAlgorithm = RecordSignatureAlgorithmEd25519
	linkCount := len(links) / 32
	if linkCount > 0 {
		r.Links = make([]byte, 32*linkCount)
		copy(r.Links, links[0:len(r.Links)])
	}

	if len(changeOwner) == 32 {
		var co [32]byte
		r.ChangeOwner = co[:]
		copy(r.ChangeOwner, changeOwner)
	}

	var selectorClaimPrivateKeys [2][]byte
	for si := range selectors {
		sid, pk := RecordDeriveID(selectors[si])
		r.SelectorIDs[si] = sid[:]
		selectorClaimPrivateKeys[si] = pk
	}

	b := bytes.NewBuffer(make([]byte, 0, len(r.Value)+len(r.Links)+512))
	err := r.packMainSection(b)
	if err != nil {
		return nil, err
	}

	r.WorkHash = sha512.Sum512(b.Bytes())
	if skipWork {
		rand.Read(r.Work[:])
	} else {
		work, workIterations := Wharrgarbl(r.WorkHash[:], RecordWharrgarblCost(b.Len()+WharrgarblOutputSize+(64*(2+len(selectors)))), RecordWharrgarblMemory)
		if workIterations == 0 {
			return nil, ErrorWharrgarblFailed
		}
		r.Work = work[:]
	}
	b.Write(r.Work[:])

	r.SigningHash = sha512.Sum512(append(r.WorkHash[:], r.Work[:]...))

	r.OwnerSignature = ed25519.Sign(ownerPrivateKey, r.SigningHash[:])
	b.Write(r.OwnerSignature)

	r.IDClaimSignature = ed25519.Sign(idClaimPrivateKey[:], r.SigningHash[:])
	b.Write(r.IDClaimSignature)

	for i := range selectorClaimPrivateKeys {
		if len(selectorClaimPrivateKeys[i]) == 64 {
			r.SelectorSignatures[i] = ed25519.Sign(selectorClaimPrivateKeys[i], r.SigningHash[:])
			b.Write(r.SelectorSignatures[i])
		}
	}

	r.Data = b.Bytes()
	r.Hash = Shandwich256(r.Data)

	return &r, nil
}

// GetValue retrieves the plain text value from this record, performing decompression and decryption as needed.
// The plain text key for the record must be supplied if the record's value is encrypted. Otherwise the result
// will be invalid and undefined. If you want to check that a key is correct, use RecordDeriveID and then compare
// the resulting ID with the one in the record.
func (r *Record) GetValue(key []byte) ([]byte, error) {
	var pt []byte

	if r.ValueEncryptionAlgorithm == RecordValueEncryptionAlgorithmNone {
		pt = r.Value
	} else if r.ValueEncryptionAlgorithm == RecordValueEncryptionAlgorithmAES256CFB {
		var iv [16]byte
		binary.BigEndian.PutUint32(iv[0:4], uint32(r.Timestamp))
		copy(iv[4:16], r.Owner[0:12])
		s512 := sha512.Sum512(key)
		c, _ := aes.NewCipher(s512[32:64])
		cfb := cipher.NewCFBDecrypter(c, iv[:])
		pt = make([]byte, len(r.Value))
		cfb.XORKeyStream(pt, r.Value)
	} else {
		return nil, ErrorRecordAlgorithmTypeInvalid
	}

	if (r.Flags & RecordFlagValueDeflated) != 0 {
		inf := flate.NewReader(bytes.NewReader(pt))
		var infb bytes.Buffer
		_, err := io.Copy(&infb, inf)
		if err != nil {
			return nil, err
		}
		return infb.Bytes(), nil
	}

	return pt, nil
}

// Unpack deserializes a packed record and fills the record's fields.
// If data is nil/empty, the record's Data field is used. If data is not nil it is used and
// the record's Data field is set to a copy of the supplied slice.
func (r *Record) Unpack(data []byte) (err error) {
	defer func() {
		e := recover()
		if e != nil {
			err = ErrorTrappedPanic{e}
		}
	}()

	if len(data) > 0 {
		r.Data = make([]byte, len(data))
		copy(r.Data, data)
	}
	data = r.Data
	if len(data) < RecordMinSize {
		return ErrorRecordTooSmall
	}
	if len(data) > RecordMaxSize {
		return ErrorRecordTooLarge
	}

	r.Hash = Shandwich256(data)
	copy(r.ID[:], data[0:32])
	copy(r.Owner[:], data[32:64])
	dr := bytes.NewReader(data[64:])
	r.Timestamp, err = binary.ReadUvarint(dr)
	if err != nil {
		return
	}
	r.TTL, err = binary.ReadUvarint(dr)
	if err != nil {
		return
	}
	r.Flags, err = binary.ReadUvarint(dr)
	if err != nil {
		return
	}

	var tmp byte
	tmp, err = dr.ReadByte()
	if err != nil {
		return
	}
	linkCountAndValueSize := uint(tmp) << 8
	tmp, err = dr.ReadByte()
	if err != nil {
		return
	}
	linkCountAndValueSize |= uint(tmp)
	linkCount := (linkCountAndValueSize >> 11) & 31 // 31 == RecordMaxLinkCount, so no extra checking needed
	valueSize := linkCountAndValueSize & 0x7ff
	if valueSize > RecordMaxValueSize {
		return ErrorRecordValueTooLarge
	}

	r.Value = make([]byte, valueSize)
	_, err = io.ReadFull(dr, r.Value)
	if err != nil {
		return
	}

	r.Links = make([]byte, linkCount*32)
	_, err = io.ReadFull(dr, r.Links)
	if err != nil {
		return
	}

	tmp, err = dr.ReadByte()
	if err != nil {
		return
	}
	r.ValueEncryptionAlgorithm = (tmp >> 6) & 3
	r.WorkAlgorithm = (tmp >> 4) & 3
	r.OwnerSignatureAlgorithm = (tmp >> 2) & 3
	r.IDClaimSignatureAlgorithm = tmp & 3

	tmp, err = dr.ReadByte()
	if err != nil {
		return
	}
	var mdt [2]byte
	mdt[0] = (tmp >> 4) & 0xf
	mdt[1] = tmp & 0xf
	var selCount uint
	r.ChangeOwner = nil
	r.SelectorIDs[0] = nil
	r.SelectorIDs[1] = nil
	for i := 0; i < 2; i++ {
		switch mdt[i] {
		case RecordMetaDataTypeNone:
		case RecordMetaDataTypeChangeOwner:
			if len(r.ChangeOwner) == 0 {
				r.ChangeOwner = make([]byte, 32)
				io.ReadFull(dr, r.ChangeOwner)
			}
		case RecordMetaDataTypeSelectorID:
			r.SelectorIDs[selCount] = make([]byte, 32)
			io.ReadFull(dr, r.SelectorIDs[selCount])
			selCount++
		default:
			var skip uint64
			skip, err = binary.ReadUvarint(dr)
			if err != nil {
				return
			}
			err = readSkip(dr, int(skip))
			if err != nil {
				return
			}
		}
	}

	r.WorkHash = sha512.Sum512(data[0 : int(dr.Size())-dr.Len()])

	switch r.WorkAlgorithm {
	case RecordWorkAlgorithmNone:
	case RecordWorkAlgorithmWharrgarbl:
		_, err = io.ReadFull(dr, r.Work[:])
		if err != nil {
			return
		}
	default:
		return ErrorRecordWorkTypeInvalid
	}

	r.SigningHash = sha512.Sum512(append(r.WorkHash[:], r.Work[:]...))

	if r.OwnerSignatureAlgorithm == RecordSignatureAlgorithmEd25519 {
		r.OwnerSignature = make([]byte, 64)
		_, err = io.ReadFull(dr, r.OwnerSignature)
		if err != nil {
			return
		}
	} else {
		return ErrorRecordSignatureTypeInvalid
	}

	if r.IDClaimSignatureAlgorithm == RecordSignatureAlgorithmEd25519 {
		r.IDClaimSignature = make([]byte, 64)
		_, err = io.ReadFull(dr, r.IDClaimSignature)
		if err != nil {
			return
		}
		for s := uint(0); s < selCount; s++ {
			r.SelectorSignatures[s] = make([]byte, 32)
			_, err = io.ReadFull(dr, r.SelectorSignatures[s])
			if err != nil {
				return
			}
		}
	} else {
		return ErrorRecordSignatureTypeInvalid
	}

	return nil
}

// Verify checks signatures and proof of work, returning nil if everything is okay.
// This does not check second-order rules such as those involving timestamps. That code is in
// AddRecord in node.go.
func (r *Record) Verify() error {
	if r.OwnerSignatureAlgorithm != RecordSignatureAlgorithmEd25519 || !ed25519.Verify(r.Owner[:], r.SigningHash[:], r.OwnerSignature) {
		return ErrorRecordOwnerSignatureCheckFailed
	}
	if r.WorkAlgorithm != RecordWorkAlgorithmWharrgarbl || WharrgarblVerify(r.Work[:], r.WorkHash[:]) < RecordWharrgarblCost(len(r.Data)) {
		return ErrorRecordInsufficientWork
	}
	if r.IDClaimSignatureAlgorithm != RecordSignatureAlgorithmEd25519 || !ed25519.Verify(r.ID[:], r.SigningHash[:], r.IDClaimSignature) {
		return ErrorRecordClaimSignatureCheckFailed
	}
	for si := range r.SelectorIDs {
		if len(r.SelectorIDs[si]) == 32 {
			if !ed25519.Verify(r.SelectorIDs[si], r.SigningHash[:], r.SelectorSignatures[si]) {
				return ErrorRecordClaimSignatureCheckFailed
			}
		}
	}
	return nil
}
