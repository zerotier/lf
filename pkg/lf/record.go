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

	// This nonce is included in the hash used to derive a key for value masking encryption
	// to make it different from other uses of that plain text key.
	recordValueMaskKeyHashNonce = []byte("LFKeyForValueMasking")
)

// RecordMaxSize is a global maximum record size (binary serialized length).
const RecordMaxSize = 65536

// RecordWorkAlgorithmNone indicates no work algorithm (not allowed on main network).
const RecordWorkAlgorithmNone byte = 0

// RecordWorkAlgorithmWharrgarbl indicates the Wharrgarbl momentum-like proof of work algorithm.
const RecordWorkAlgorithmWharrgarbl byte = 1

// RecordOwnerTypeP384 is a NIST P-384 point compressed public key.
const RecordOwnerTypeP384 byte = 1

// RecordWharrgarblMemory is the memory size that should be used for Wharrgarbl PoW.
// This is large enough to perform well up to relatively big record sizes. It'll still work for
// really huge ones of course, but performance starts to drop a bit. It can be increased and could
// be made configurable in the future if ever needed.
const RecordWharrgarblMemory = 1024 * 1024 * 384 // 384mb

// RecordBody represents the main body of a record including its value, owner public keys, etc.
type RecordBody struct {
	Value     []byte // Record value
	Owner     []byte // Owner of this record
	Links     []byte // Links to previous records' hashes (size is a multiple of 32 bytes, link count is size / 32)
	Timestamp uint64 // Timestamp (and revision ID) in SECONDS since Unix epoch
}

// UnmarshalFrom deserializes this record body from a reader.
func (rb *RecordBody) UnmarshalFrom(r io.Reader) error {
	rr := byteAndArrayReader{r}

	l, err := binary.ReadUvarint(&rr)
	if err != nil {
		return err
	}
	if l > RecordMaxSize {
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
	if l > RecordMaxSize {
		return ErrorRecordInvalid
	}
	rb.Owner = make([]byte, uint(l))
	_, err = io.ReadFull(&rr, rb.Owner)
	if err != nil {
		return err
	}

	l, err = binary.ReadUvarint(&rr)
	if err != nil {
		return err
	}
	l *= 32
	if l > RecordMaxSize {
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

// MarshalTo writes this record body in serialized form to the given writer.
func (rb *RecordBody) MarshalTo(w io.Writer) error {
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

// LinkCount returns the number of links, which is just short for len(Links)/32
func (rb *RecordBody) LinkCount() int {
	return (len(rb.Links) / 32)
}

// Bytes returns a compact byte array serialized RecordBody.
func (rb *RecordBody) Bytes() []byte {
	var buf bytes.Buffer
	rb.MarshalTo(&buf)
	return buf.Bytes()
}

// SizeBytes returns the size of the result of Bytes().
func (rb *RecordBody) SizeBytes() uint {
	var wc countingWriter
	rb.MarshalTo(&wc)
	return uint(wc)
}

// SigningHash computes a hash for use in record signing.
// This does something a bit different from just hashing Bytes(). This is because we want
// to hash a hash of the value rather than the literal value. This would allow nodes in the
// future to potentially forget the content of very old records but preserve enough of their
// meta-data to allow signature verification. It's also just a little bit faster.
func (rb *RecordBody) SigningHash() [32]byte {
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

// Record contains all the elements of a complete (unmarshaled) record.
// Note that records should be considered const structures. They shouldn't be modified
// directly but instead should be generated by the NewRecord functions.
type Record struct {
	Body          RecordBody // Main record body with value and other tasty stuff
	Selectors     []Selector // Things that can be used to find the record
	Work          []byte     // Proof of work computed on sha256(Body Signing Hash | Selectors) with work cost based on size of body and selectors
	WorkAlgorithm byte       // Proof of work algorithm
	Signature     []byte     // Signature of sha256(sha256(Body Signing Hash | Selectors) | Work | WorkAlgorithm)

	data []byte    // Cached data
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

	if err = r.Body.UnmarshalFrom(&rr); err != nil {
		return err
	}

	selCount, err := binary.ReadUvarint(rr)
	if err != nil {
		return err
	}
	if selCount > (RecordMaxSize / 64) {
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
	if walg != RecordWorkAlgorithmWharrgarbl {
		return ErrorRecordUnsupportedAlgorithm
	}
	var work [WharrgarblOutputSize]byte
	if _, err = io.ReadFull(&rr, work[:]); err != nil {
		return err
	}
	r.Work = work[:]
	r.WorkAlgorithm = walg

	siglen, err := binary.ReadUvarint(&rr)
	if err != nil {
		return err
	}
	if siglen > RecordMaxSize {
		return ErrorRecordInvalid
	}
	r.Signature = make([]byte, uint(siglen))
	if _, err = io.ReadFull(&rr, r.Signature); err != nil {
		return err
	}

	return nil
}

// MarshalTo writes this record in serialized form to the supplied writer.
func (r *Record) MarshalTo(w io.Writer) error {
	// Record begins with a reserved version/type byte, currently 0
	if _, err := w.Write(b1_0); err != nil {
		return err
	}

	if err := r.Body.MarshalTo(w); err != nil {
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

// Hash returns Shandwich256(record Bytes()).
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

// SizeBytes returns the serialized size of this record.
func (r *Record) SizeBytes() uint {
	var cr countingWriter
	r.MarshalTo(&cr)
	return uint(cr)
}

// Score returns this record's work score, which is algorithm dependent.
func (r *Record) Score() uint32 {
	switch r.WorkAlgorithm {
	case RecordWorkAlgorithmNone:
		return 1
	case RecordWorkAlgorithmWharrgarbl:
		return WharrgarblGetDifficulty(r.Work)
	}
	return 0
}

// ID returns a sha256 hash of all this record's selector database keys (selector hashed name and ordinal) in their specified order.
func (r *Record) ID() *[32]byte {
	if r.id == nil {
		var id [32]byte
		var sk [32]byte
		h := sha256.New()
		for i := 0; i < len(r.Selectors); i++ {
			sk = r.Selectors[i].Key()
			h.Write(sk[:])
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

	if len(r.Body.Owner) == 0 {
		return ErrorRecordOwnerSignatureCheckFailed
	}

	bodySigningHash := r.Body.SigningHash()
	workHashBytes := make([]byte, 0, 32+(len(r.Selectors)*128))
	workHashBytes = append(workHashBytes, bodySigningHash[:]...)
	workBillableBytes := r.Body.SizeBytes()
	for i := 0; i < len(r.Selectors); i++ {
		sb := r.Selectors[i].Bytes()
		workHashBytes = append(workHashBytes, sb...)
		workBillableBytes += uint(len(sb))
		if !r.Selectors[i].VerifyHash(bodySigningHash[:]) {
			return ErrorRecordSelectorClaimCheckFailed
		}
	}
	workHash := sha256.Sum256(workHashBytes)

	if r.WorkAlgorithm != RecordWorkAlgorithmWharrgarbl {
		return ErrorRecordInsufficientWork
	}
	if WharrgarblVerify(r.Work, workHash[:]) < RecordWharrgarblCost(workBillableBytes) {
		return ErrorRecordInsufficientWork
	}

	pubKey, err := ECDSADecompressPublicKey(elliptic.P384(), r.Body.Owner) // the curve type is in the least significant bits of owner but right now there's only one allowed
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
	b := uint64(bytes * 4)
	c := (uint64(integerSqrtRounded(uint32(b))) * b * uint64(3)) - (b * 8)
	if c > 0xffffffff { // sanity check, no record gets this big
		return 0xffffffff
	}
	return uint32(c)
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
	pub, err := ECDSACompressPublicKeyWithID(&priv.PublicKey, RecordOwnerTypeP384)
	if err != nil {
		panic(err)
	}
	return pub, priv
}

// GetOwnerPublicKey gets a comrpessed and properly ID-embedded owner public key from a private key that includes its public portion.
func GetOwnerPublicKey(k *ecdsa.PrivateKey) ([]byte, error) {
	if k == nil || k.Params().Name != "P-384" {
		return nil, ErrorUnsupportedCurve
	}
	return ECDSACompressPublicKeyWithID(&k.PublicKey, RecordOwnerTypeP384)
}

// NewRecordStart creates an incomplete record with its body and selectors filled out but no work or final signature.
// This can be used to do the first step of a three-phase record creation process with the next two phases being NewRecordAddWork
// and NewRecordComplete. This is useful of record creation needs to be split among systems or participants.
func NewRecordStart(value []byte, links [][]byte, plainTextSelectorNames [][]byte, selectorOrdinals []uint64, owner []byte, ts uint64) (r *Record, workHash [32]byte, workBillableBytes uint, err error) {
	if len(value) > RecordMaxSize {
		err = ErrorInvalidParameter
		return
	}

	r = new(Record)

	if len(value) > 0 {
		r.Body.Value = append(r.Body.Value, value...)
	}
	r.Body.Owner = append(r.Body.Owner, owner...)
	if len(links) > 0 {
		r.Body.Links = make([]byte, 0, 32*len(links))
		for i := 0; i < len(links); i++ {
			r.Body.Links = append(r.Body.Links, links[i]...)
		}
	}

	r.Body.Timestamp = ts

	bodySigningHash := r.Body.SigningHash()
	workBillableBytes = r.Body.SizeBytes()

	workHasher := sha256.New()
	workHasher.Write(bodySigningHash[:])

	if len(plainTextSelectorNames) > 0 {
		r.Selectors = make([]Selector, len(plainTextSelectorNames))
		for i := 0; i < len(plainTextSelectorNames); i++ {
			r.Selectors[i].Set(plainTextSelectorNames[i], selectorOrdinals[i], bodySigningHash[:])
			sb := r.Selectors[i].Bytes()
			workBillableBytes += uint(len(sb))
			workHasher.Write(sb)
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
			w, iter := Wharrgarbl(workHash, RecordWharrgarblCost(workBillableBytes), RecordWharrgarblMemory)
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
	if r.SizeBytes() > RecordMaxSize {
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
