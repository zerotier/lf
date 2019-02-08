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
	"crypto/elliptic"
	secrand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"
)

var (
	b1_0 = []byte{0x00}
	b1_1 = []byte{0x01}
)

// recordWharrgarblMemory is the default amount of memory to use for Wharrgarbl momentum-type PoW.
const recordWharrgarblMemory = 1024 * 1024 * 384 // 384mb

// recordMaxSize is a global maximum record size (binary serialized length).
// This is more or less a sanity limit to prevent malloc overflow attacks and similar things.
const recordMaxSize = 65536

// RecordWorkAlgorithmNone indicates no work algorithm (not allowed on main network but can exist in testing or private networks that are CA-only).
const RecordWorkAlgorithmNone byte = 0

// RecordWorkAlgorithmWharrgarbl indicates the Wharrgarbl momentum-like proof of work algorithm.
const RecordWorkAlgorithmWharrgarbl byte = 1

// RecordOwnerTypeP384 is a NIST P-384 point compressed public key (valid types can be from 0 to 63).
const RecordOwnerTypeP384 byte = 0

// recordBody represents the main body of a record including its value, owner public keys, etc.
// It's included as part of Record but separated since in record construction we want to treat it as a separate element.
type recordBody struct {
	Value       []byte // Record value
	Owner       []byte // Owner of this record (public key with type)
	Certificate []byte // Hash of exact record containing certificate for this owner (if CAs are enabled)
	Links       []byte // Links to previous records' hashes (size is a multiple of 32 bytes, link count is size / 32)
	Timestamp   uint64 // Timestamp (and revision ID) in SECONDS since Unix epoch
}

func (rb *recordBody) unmarshalFrom(r io.Reader) error {
	rr := byteAndArrayReader{r}

	flags, err := rr.ReadByte()

	l, err := binary.ReadUvarint(&rr)
	if err != nil {
		return err
	}
	if l > recordMaxSize {
		return ErrorRecordInvalid
	}
	rb.Value = make([]byte, uint(l))
	_, err = io.ReadFull(&rr, rb.Value)
	if err != nil {
		return err
	}

	l, err = binary.ReadUvarint(&rr)
	if err != nil {
		return err
	}
	if l > recordMaxSize {
		return ErrorRecordInvalid
	}
	rb.Owner = make([]byte, uint(l))
	_, err = io.ReadFull(&rr, rb.Owner)
	if err != nil {
		return err
	}

	if (flags & 0x01) != 0 {
		var cert [32]byte
		_, err = io.ReadFull(&rr, cert[:])
		if err != nil {
			return err
		}
		rb.Certificate = cert[:]
	} else {
		rb.Certificate = nil
	}

	l, err = binary.ReadUvarint(&rr)
	if err != nil {
		return err
	}
	l *= 32
	if l > recordMaxSize {
		return ErrorRecordInvalid
	}
	rb.Links = make([]byte, uint(l))
	_, err = io.ReadFull(&rr, rb.Links)

	rb.Timestamp, err = binary.ReadUvarint(&rr)
	if err != nil {
		return err
	}

	return nil
}

func (rb *recordBody) marshalTo(w io.Writer) error {
	var flags [1]byte
	if len(rb.Certificate) == 32 {
		flags[0] |= 0x01
	}

	if _, err := w.Write(flags[:]); err != nil {
		return err
	}

	if _, err := writeUVarint(w, uint64(len(rb.Value))); err != nil {
		return err
	}
	if _, err := w.Write(rb.Value); err != nil {
		return err
	}

	if _, err := writeUVarint(w, uint64(len(rb.Owner))); err != nil {
		return err
	}
	if _, err := w.Write(rb.Owner); err != nil {
		return err
	}

	if len(rb.Certificate) == 32 {
		if _, err := w.Write(rb.Certificate); err != nil {
			return err
		}
	}

	if len(rb.Links) >= 32 {
		linkCount := len(rb.Links) / 32
		if _, err := writeUVarint(w, uint64(linkCount)); err != nil {
			return err
		}
		if _, err := w.Write(rb.Links[0 : linkCount*32]); err != nil {
			return err
		}
	} else {
		if _, err := w.Write(b1_0); err != nil {
			return nil
		}
	}

	_, err := writeUVarint(w, rb.Timestamp)
	return err
}

func (rb *recordBody) sizeBytes() uint {
	var wc countingWriter
	rb.marshalTo(&wc)
	return uint(wc)
}

// signingHash computes a hash for use in record signing.
// This doesn't just hash Bytes(). It uses a different encoding and hashes the value
// separately. This is done to make it possible in the future to store only value hashes
// but still be able to authenticate records, which could allow the size of the data store
// to get trimmed down a bit by discarding actual values for very old records.
func (rb *recordBody) signingHash() [32]byte {
	h := sha512.New()
	vh := Shandwich256(rb.Value)
	h.Write(vh[:])
	h.Write(b1_0)
	h.Write(rb.Owner)
	h.Write(b1_0)
	h.Write(rb.Links)
	h.Write(b1_0)
	binary.BigEndian.PutUint64(vh[0:8], rb.Timestamp) // this just re-uses vh[] as a temp buffer
	h.Write(vh[0:8])
	h.Write(b1_0)
	var s512buf [64]byte
	return Shandwich256FromSha512(h.Sum(s512buf[:]))
}

// LinkCount returns the number of links, which is just short for len(Links)/32
func (rb *recordBody) LinkCount() int { return (len(rb.Links) / 32) }

// Record combines the record body with one or more selectors, work, and a signature.
// A record should not be modified once created. It should be treated as a read-only value.
type Record struct {
	recordBody

	Selectors     []Selector // Things that can be used to find the record
	Work          []byte     // Proof of work computed on sha256(Body Signing Hash | Selectors) with work cost based on size of body and selectors
	WorkAlgorithm byte       // Proof of work algorithm
	Signature     []byte     // Signature of sha256(sha256(Body Signing Hash | Selectors) | Work | WorkAlgorithm)

	data []byte    // Cached raw data
	hash *[32]byte // Cached hash
	id   *[32]byte // Cached ID
}

// UnmarshalFrom deserializes this record from a reader.
func (r *Record) UnmarshalFrom(rdr io.Reader) error {
	rr := byteAndArrayReader{rdr}

	hdrb, err := rr.ReadByte()
	if err != nil {
		return err
	}
	if hdrb != 0 {
		return ErrorRecordInvalid
	}

	if err = r.recordBody.unmarshalFrom(&rr); err != nil {
		return err
	}

	selCount, err := binary.ReadUvarint(rr)
	if err != nil {
		return err
	}
	if selCount > (recordMaxSize / 64) {
		return ErrorRecordInvalid
	}
	r.Selectors = make([]Selector, uint(selCount))
	for i := 0; i < len(r.Selectors); i++ {
		err = r.Selectors[i].UnmarshalFrom(rr)
		if err != nil {
			return err
		}
	}

	walg, err := rr.ReadByte()
	if err != nil {
		return err
	}
	if walg == RecordWorkAlgorithmWharrgarbl {
		var work [WharrgarblOutputSize]byte
		if _, err = io.ReadFull(&rr, work[:]); err != nil {
			return err
		}
		r.Work = work[:]
	} else if walg != RecordWorkAlgorithmNone {
		return ErrorRecordUnsupportedAlgorithm
	}
	r.WorkAlgorithm = walg

	siglen, err := binary.ReadUvarint(&rr)
	if err != nil {
		return err
	}
	if siglen > recordMaxSize {
		return ErrorRecordInvalid
	}
	r.Signature = make([]byte, uint(siglen))
	if _, err = io.ReadFull(&rr, r.Signature); err != nil {
		return err
	}

	r.data = nil
	r.hash = nil
	r.id = nil

	return nil
}

// MarshalTo writes this record in serialized form to the supplied writer.
func (r *Record) MarshalTo(w io.Writer) error {
	if len(r.data) > 0 { // just send cached data if present since this is faster
		_, err := w.Write(r.data)
		return err
	}

	// Record begins with a reserved version/type byte, currently 0
	if _, err := w.Write(b1_0); err != nil {
		return err
	}

	if err := r.recordBody.marshalTo(w); err != nil {
		return err
	}

	if _, err := writeUVarint(w, uint64(len(r.Selectors))); err != nil {
		return err
	}
	for i := 0; i < len(r.Selectors); i++ {
		if err := r.Selectors[i].MarshalTo(w); err != nil {
			return err
		}
	}

	// Work algorithm specifies work size
	if _, err := w.Write([]byte{r.WorkAlgorithm}); err != nil {
		return err
	}
	if _, err := w.Write(r.Work); err != nil {
		return err
	}

	if _, err := writeUVarint(w, uint64(len(r.Signature))); err != nil {
		return err
	}
	if _, err := w.Write(r.Signature); err != nil {
		return err
	}

	return nil
}

// Bytes returns a byte serialized record.
// The returned slice should not be modified since it's cached internally in Record to
// make multiple calls to Bytes() faster.
func (r *Record) Bytes() []byte {
	if len(r.data) == 0 {
		var buf bytes.Buffer
		r.MarshalTo(&buf)
		r.data = buf.Bytes()
	}
	return r.data
}

// SizeBytes returns the serialized size of this record.
func (r *Record) SizeBytes() uint {
	var cr countingWriter
	r.MarshalTo(&cr)
	return uint(cr)
}

// Hash returns Shandwich256(record Bytes()).
// This is the main record hash used for record linking.
func (r *Record) Hash() *[32]byte {
	if r.hash == nil {
		s512 := sha512.New()
		r.MarshalTo(s512)
		var h512buf [64]byte
		h512 := s512.Sum(h512buf[:0])
		h := Shandwich256FromSha512(h512[:])
		r.hash = &h
	}
	return r.hash
}

// Score returns this record's work score, which is algorithm dependent.
// The returned value is scaled to the range of uint32 so that future algorithms can coexist with or at least
// be comparable relative to current ones.
func (r *Record) Score() uint32 {
	switch r.WorkAlgorithm {
	case RecordWorkAlgorithmNone:
		return 1
	case RecordWorkAlgorithmWharrgarbl:
		return RecordWharrgarblScore(WharrgarblGetDifficulty(r.Work))
	}
	return 0
}

// ID returns a sha256 hash of all this record's selector database keys in their specified order.
// If the record has no selectors the ID is just its hash.
func (r *Record) ID() *[32]byte {
	if r.id == nil {
		if len(r.Selectors) == 0 {
			return r.Hash()
		}
		var id [32]byte
		h := sha256.New()
		for i := 0; i < len(r.Selectors); i++ {
			h.Write(r.Selectors[i].Key())
		}
		h.Sum(id[:0])
		r.id = &id
	}
	return r.id
}

// Validate checks this record's signatures and other attributes and returns an error or nil if there is no problem.
func (r *Record) Validate() (err error) {
	defer func() {
		e := recover()
		if e != nil {
			err = fmt.Errorf("caught panic validating record: %v", e)
		}
	}()

	if len(r.recordBody.Owner) == 0 {
		return ErrorRecordOwnerSignatureCheckFailed
	}

	selectorClaimSigningHash := r.recordBody.signingHash()
	workHashBytes := make([]byte, 0, 32+(len(r.Selectors)*128))
	workHashBytes = append(workHashBytes, selectorClaimSigningHash[:]...)
	workBillableBytes := r.recordBody.sizeBytes()
	for i := 0; i < len(r.Selectors); i++ {
		sb := r.Selectors[i].Bytes()
		workHashBytes = append(workHashBytes, sb...)
		workBillableBytes += uint(len(sb))

		if !r.Selectors[i].VerifyClaim(selectorClaimSigningHash[:]) {
			return ErrorRecordSelectorClaimCheckFailed
		}

		sb = append(sb, selectorClaimSigningHash[:]...)
		selectorClaimSigningHash = sha256.Sum256(sb)
	}
	workHash := sha256.Sum256(workHashBytes)

	if r.WorkAlgorithm != RecordWorkAlgorithmWharrgarbl {
		return ErrorRecordInsufficientWork
	}
	if WharrgarblVerify(r.Work, workHash[:]) < RecordWharrgarblCost(workBillableBytes) {
		return ErrorRecordInsufficientWork
	}

	pubKey, err := ECDSADecompressPublicKey(elliptic.P384(), r.recordBody.Owner) // the curve type is in the least significant bits of owner but right now there's only one allowed
	if err != nil {
		return ErrorRecordOwnerSignatureCheckFailed
	}
	finalHash := sha256.New()
	finalHash.Write(workHash[:])
	finalHash.Write(r.Work)
	finalHash.Write([]byte{r.WorkAlgorithm})
	var hb [32]byte
	if !ECDSAVerify(pubKey, finalHash.Sum(hb[:0]), r.Signature) {
		return ErrorRecordOwnerSignatureCheckFailed
	}

	return nil
}

// RecordWharrgarblCost computes the cost in Wharrgarbl difficulty for a record of a given number of "billable" bytes.
func RecordWharrgarblCost(bytes uint) uint32 {
	//
	// This function was figured out by:
	//
	// (1) Empirically sampling difficulty vs time.
	// (2) Using Microsoft Excel to fit the curve to a power function.
	// (3) Figuring out an integer based function that approximates this power function.
	//
	// An integer only algorithm is used to avoid FPU inconsistencies across systems.
	//
	// This function provides a relatively linear relationship between average Wharrgarbl time
	// and the number of bytes (total) in a record.
	//
	if bytes <= 1 { // byte counts <= 1 break the calculation (no real record is this small anyway)
		return 1
	}
	if bytes > recordMaxSize { // sanity check, shouldn't ever happen
		bytes = recordMaxSize
	}
	b := uint64(bytes * 4)
	c := (uint64(integerSqrtRounded(uint32(b))) * b * uint64(3)) - (b * 8)
	if c > 0xffffffff { // sanity check, no record gets this big
		return 0xffffffff
	}
	return uint32(c)
}

// RecordWharrgarblScore computes a score approximately scaled to uint32_max based on a Wharrgarbl cost value from a piece of work.
// This is used by Record's Score() method.
func RecordWharrgarblScore(cost uint32) uint32 {
	if cost >= 0x17e00000 {
		return 0xffffda7f
	}
	if cost <= 1 {
		return 0x0000000a
	}
	// The max cost that will ever be returned by RecordWharrgarblCost is 0x17e00000. The max
	// value of a 32-bit integer divided by this is 10.722513086508705. This approximately
	// scales the cost of a record to a value from 0 to approximately uint32_max. The max is
	// actually 0xffffda7f, which is close enough.
	return ((cost * 10) + ((cost / 10000) * 7225))
}

// GenerateOwner creates a new record owner, returning its packed public key and fully expanded private key.
// The packed public key is packed using ECCCompressPublicKeyWithID to embed an algorithm ID to support
// different curves or entirely different algorithms in the future. This public key should be used directly
// as the owner field in records. The private key is required to sign records.
func GenerateOwner() ([]byte, *ecdsa.PrivateKey) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), secrand.Reader)
	if err != nil {
		panic(err)
	}
	pub, err := ECDSACompressPublicKey(&priv.PublicKey)
	if err != nil {
		panic(err)
	}
	pub[0] |= RecordOwnerTypeP384 << 2 // we can use the lower 6 bits of the first byte for a type
	return pub, priv
}

// GetOwnerPublicKey gets a comrpessed and properly ID-embedded owner public key from a private key that includes its public portion.
func GetOwnerPublicKey(k *ecdsa.PrivateKey) ([]byte, error) {
	if k == nil || k.Params().Name != "P-384" {
		return nil, ErrorUnsupportedCurve
	}
	pub, err := ECDSACompressPublicKey(&k.PublicKey)
	if err != nil {
		return nil, err
	}
	pub[0] |= RecordOwnerTypeP384 << 2 // we can use the lower 6 bits of the first byte for a type
	return pub, nil
}

// NewRecordStart creates an incomplete record with its body and selectors filled out but no work or final signature.
// This can be used to do the first step of a three-phase record creation process with the next two phases being NewRecordAddWork
// and NewRecordComplete. This is useful of record creation needs to be split among systems or participants.
func NewRecordStart(value []byte, links [][]byte, plainTextSelectorNames [][]byte, selectorOrdinals []uint64, owner []byte, ts uint64) (r *Record, workHash [32]byte, workBillableBytes uint, err error) {
	if len(value) > recordMaxSize {
		err = ErrorInvalidParameter
		return
	}

	r = new(Record)

	if len(value) > 0 {
		r.recordBody.Value = append(r.recordBody.Value, value...)
	}
	r.recordBody.Owner = append(r.recordBody.Owner, owner...)
	if len(links) > 0 {
		r.recordBody.Links = make([]byte, 0, 32*len(links))
		for i := 0; i < len(links); i++ {
			r.recordBody.Links = append(r.recordBody.Links, links[i]...)
		}
	}
	r.recordBody.Timestamp = ts

	workBillableBytes = r.recordBody.sizeBytes()

	workHasher := sha256.New()
	selectorClaimSigningHash := r.recordBody.signingHash()
	workHasher.Write(selectorClaimSigningHash[:])
	if len(plainTextSelectorNames) > 0 {
		r.Selectors = make([]Selector, len(plainTextSelectorNames))
		for i := 0; i < len(plainTextSelectorNames); i++ {
			r.Selectors[i].Claim(plainTextSelectorNames[i], selectorOrdinals[i], selectorClaimSigningHash[:])

			sb := r.Selectors[i].Bytes()
			workBillableBytes += uint(len(sb))
			workHasher.Write(sb)

			sb = append(sb, selectorClaimSigningHash[:]...)
			selectorClaimSigningHash = sha256.Sum256(sb)
		}
	}

	workHasher.Sum(workHash[:0])

	return
}

// NewRecordDoWork is a convenience method for doing the work to add to a record.
// This can obviously be a time and memory intensive function.
func NewRecordDoWork(workHash []byte, workBillableBytes uint, workAlgorithm byte) (work []byte, err error) {
	if workAlgorithm != RecordWorkAlgorithmNone {
		if workAlgorithm == RecordWorkAlgorithmWharrgarbl {
			w, iter := Wharrgarbl(workHash, RecordWharrgarblCost(workBillableBytes), recordWharrgarblMemory)
			if iter == 0 {
				err = ErrorWharrgarblFailed
				return
			}
			work = w[:]
		} else {
			err = ErrorInvalidParameter
		}
	}
	return
}

// NewRecordAddWork adds work to a record created with NewRecordStart and returns the same record with work and the signing hash to be signed by the owner.
func NewRecordAddWork(incompleteRecord *Record, workHash []byte, work []byte, workAlgorithm byte) (r *Record, signingHash [32]byte, err error) {
	r = incompleteRecord
	r.Work = work
	r.WorkAlgorithm = workAlgorithm
	tmp := make([]byte, len(workHash)+len(work)+1)
	copy(tmp, workHash)
	copy(tmp[len(workHash):], work)
	tmp[len(tmp)-1] = workAlgorithm
	signingHash = sha256.Sum256(tmp)
	return
}

// NewRecordComplete completes a record created with NewRecordStart after work is added with NewRecordAddWork by signing it with the owner's private key.
func NewRecordComplete(incompleteRecord *Record, signingHash []byte, ownerPrivate *ecdsa.PrivateKey) (r *Record, err error) {
	r = incompleteRecord
	if ownerPrivate.Curve.Params().Name != "P-384" {
		return nil, ErrorUnsupportedCurve
	}
	r.Signature, err = ECDSASign(ownerPrivate, signingHash)
	if r.SizeBytes() > recordMaxSize {
		return nil, ErrorRecordTooLarge
	}
	return
}

// NewRecord is a shortcut to running all incremental record creation functions.
// Obviously this is time and memory intensive due to proof of work required to "pay" for this record.
func NewRecord(value []byte, links [][]byte, plainTextSelectorNames [][]byte, selectorOrdinals []uint64, owner []byte, ts uint64, workAlgorithm byte, ownerPrivate *ecdsa.PrivateKey) (r *Record, err error) {
	var wh, sh [32]byte
	var wb uint
	r, wh, wb, err = NewRecordStart(value, links, plainTextSelectorNames, selectorOrdinals, owner, ts)
	if err != nil {
		return
	}
	w, err := NewRecordDoWork(wh[:], wb, workAlgorithm)
	if err != nil {
		return
	}
	r, sh, err = NewRecordAddWork(r, wh[:], w, workAlgorithm)
	if err != nil {
		return
	}
	r, err = NewRecordComplete(r, sh[:], ownerPrivate)
	return
}

// NewRecordFromBytes deserializes a record from a byte array.
func NewRecordFromBytes(b []byte) (r *Record, err error) {
	r = new(Record)
	err = r.UnmarshalFrom(bytes.NewReader(b))
	return
}
