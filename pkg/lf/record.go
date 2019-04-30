/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"gopkg.in/kothar/brotli-go.v0/dec"

	"gopkg.in/kothar/brotli-go.v0/enc"

	"golang.org/x/crypto/sha3"
)

var (
	b1_0 = []byte{0x00}
	b1_1 = []byte{0x01}

	brotliParams = func() (bp *enc.BrotliParams) {
		bp = enc.NewBrotliParams()
		bp.SetQuality(11)
		bp.SetMode(enc.GENERIC)
		return
	}()
)

const (
	recordBodyFlagHasCertificate  byte = 0x01
	recordBodyFlagValueMasked     byte = 0x02
	recordBodyFlagValueCompressed byte = 0x04
)

// RecordDefaultWharrgarblMemory is the default amount of memory to use for Wharrgarbl momentum-type PoW.
const RecordDefaultWharrgarblMemory = 1024 * 1024 * 512

// RecordMaxSize is a global maximum record size (binary serialized length).
// This is more or less a sanity limit to prevent malloc overflow attacks and similar things.
const RecordMaxSize = 65536

// RecordWorkAlgorithmNone indicates no work algorithm (not allowed on main network but can exist in testing or private networks that are CA-only).
const RecordWorkAlgorithmNone byte = 0

// RecordWorkAlgorithmWharrgarbl indicates the Wharrgarbl momentum-like proof of work algorithm.
const RecordWorkAlgorithmWharrgarbl byte = 1

// recordBody represents the main body of a record including its value, owner public keys, etc.
// It's included as part of Record but separated since in record construction we want to treat it as a separate element.
type recordBody struct {
	Value           Blob       `json:",omitempty"` // Record value (possibly masked and/or compressed, use GetValue() to get)
	Owner           Blob       `json:",omitempty"` // Owner of this record (owner public bytes)
	Certificate     *[32]byte  `json:",omitempty"` // Hash (256-bit) of exact record containing certificate for this owner (if CAs are enabled)
	Links           [][32]byte `json:",omitempty"` // Links to previous records' hashes
	Timestamp       uint64     ``                  // Timestamp (and revision ID) in SECONDS since Unix epoch
	ValueMasked     bool       ``                  // If true, value is encrypted with a masking key
	ValueCompressed bool       ``                  // If true, value is compressed (within encrypted envelope)
}

func (rb *recordBody) unmarshalFrom(r io.Reader) error {
	rr := byteAndArrayReader{r}

	flags, err := rr.ReadByte()

	l, err := binary.ReadUvarint(&rr)
	if err != nil {
		return err
	}
	if l > 0 {
		if l > RecordMaxSize {
			return ErrRecordInvalid
		}
		rb.Value = make([]byte, uint(l))
		_, err = io.ReadFull(&rr, rb.Value)
		if err != nil {
			return err
		}
	} else {
		rb.Value = nil
	}

	l, err = binary.ReadUvarint(&rr)
	if err != nil {
		return err
	}
	if l > 0 {
		if l > RecordMaxSize {
			return ErrRecordInvalid
		}
		rb.Owner = make([]byte, uint(l))
		_, err = io.ReadFull(&rr, rb.Owner)
		if err != nil {
			return err
		}
	} else {
		rb.Owner = nil
	}

	if (flags & recordBodyFlagHasCertificate) != 0 {
		var cert [32]byte
		_, err = io.ReadFull(&rr, cert[:])
		if err != nil {
			return err
		}
		rb.Certificate = &cert
	} else {
		rb.Certificate = nil
	}

	l, err = binary.ReadUvarint(&rr)
	if err != nil {
		return err
	}
	if l > 0 {
		if (l * 32) > RecordMaxSize {
			return ErrRecordInvalid
		}
		rb.Links = make([][32]byte, uint(l))
		for i := 0; i < len(rb.Links); i++ {
			_, err = io.ReadFull(&rr, rb.Links[i][:])
			if err != nil {
				return err
			}
		}
	} else {
		rb.Links = nil
	}

	rb.Timestamp, err = binary.ReadUvarint(&rr)
	if err != nil {
		return err
	}

	rb.ValueMasked = (flags & recordBodyFlagValueMasked) != 0
	rb.ValueCompressed = (flags & recordBodyFlagValueCompressed) != 0

	return nil
}

func (rb *recordBody) marshalTo(w io.Writer, hashAsProxyForValue bool) error {
	var flags [1]byte
	if rb.Certificate != nil {
		flags[0] |= recordBodyFlagHasCertificate
	}
	if rb.ValueMasked {
		flags[0] |= recordBodyFlagValueMasked
	}
	if rb.ValueCompressed {
		flags[0] |= recordBodyFlagValueCompressed
	}
	if _, err := w.Write(flags[:]); err != nil {
		return err
	}

	if hashAsProxyForValue {
		h := sha3.Sum256(rb.Value)
		if _, err := w.Write(h[:]); err != nil {
			return err
		}
	} else {
		if _, err := writeUVarint(w, uint64(len(rb.Value))); err != nil {
			return err
		}
		if _, err := w.Write(rb.Value); err != nil {
			return err
		}
	}

	if _, err := writeUVarint(w, uint64(len(rb.Owner))); err != nil {
		return err
	}
	if _, err := w.Write(rb.Owner); err != nil {
		return err
	}

	if rb.Certificate != nil {
		if _, err := w.Write(rb.Certificate[:]); err != nil {
			return err
		}
	}

	if _, err := writeUVarint(w, uint64(len(rb.Links))); err != nil {
		return err
	}
	for i := 0; i < len(rb.Links); i++ {
		if _, err := w.Write(rb.Links[i][:]); err != nil {
			return err
		}
	}

	_, err := writeUVarint(w, rb.Timestamp)
	return err
}

func (rb *recordBody) signingHash() (hb [32]byte) {
	h := NewShandwich256()
	rb.marshalTo(h, true)
	h.Sum(hb[:0])
	return
}

func (rb *recordBody) sizeBytes() uint {
	var wc countingWriter
	rb.marshalTo(&wc, false)
	return uint(wc)
}

// GetValue unmasks and possibly decompresses this record's value.
// Nil is returned if the value is empty.
func (rb *recordBody) GetValue(maskingKey []byte) ([]byte, error) {
	if len(rb.Value) == 0 {
		return nil, nil
	}

	var unmaskedValue []byte
	if rb.ValueMasked {
		unmaskedValue = make([]byte, len(rb.Value))
		var cfbIv [16]byte
		binary.BigEndian.PutUint64(cfbIv[0:8], rb.Timestamp)
		if len(rb.Owner) >= 8 {
			copy(cfbIv[8:16], rb.Owner[0:8])
		}
		maskingKeyH := sha256.Sum256(maskingKey)
		c, _ := aes.NewCipher(maskingKeyH[:])
		cipher.NewCFBDecrypter(c, cfbIv[:]).XORKeyStream(unmaskedValue, rb.Value)
	} else {
		unmaskedValue = rb.Value
	}

	if rb.ValueCompressed {
		return dec.DecompressBuffer(unmaskedValue, make([]byte, 0, len(unmaskedValue)+(len(unmaskedValue)/3)))
	}
	return unmaskedValue, nil
}

// Record combines the record body with one or more selectors, work, and a signature.
// A record should not be modified once created. It should be treated as a read-only value.
type Record struct {
	recordBody

	Selectors     []Selector `json:",omitempty"` // Things that can be used to find the record
	Work          Blob       `json:",omitempty"` // Proof of work computed on sha3-256(Body Signing Hash | Selectors) with work cost based on size of body and selectors
	WorkAlgorithm byte       ``                  // Proof of work algorithm
	Signature     Blob       `json:",omitempty"` // Signature of sha3-256(sha3-256(Body Signing Hash | Selectors) | Work | WorkAlgorithm)

	selectorKeys [][]byte // Cached selector keys
}

// UnmarshalFrom deserializes this record from a reader.
// The special error ErrorRecordMarkedIgnore indicates a record whose first bytes have
// been overwritten by 0xff followed by a 32-bit length. This can be used to mark a record
// to be ignored in a flat file without having to rewrite the entire file to delete it.
func (r *Record) UnmarshalFrom(rdr io.Reader) error {
	rr := byteAndArrayReader{rdr}

	if err := r.recordBody.unmarshalFrom(&rr); err != nil {
		return err
	}

	selCount, err := binary.ReadUvarint(rr)
	if err != nil {
		return err
	}
	if selCount > (RecordMaxSize / 64) {
		return ErrRecordInvalid
	}
	r.Selectors = make([]Selector, uint(selCount))
	for i := 0; i < len(r.Selectors); i++ {
		err = r.Selectors[i].unmarshalFrom(rr)
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
		return ErrRecordUnsupportedAlgorithm
	}
	r.WorkAlgorithm = walg

	siglen, err := binary.ReadUvarint(&rr)
	if err != nil {
		return err
	}
	if siglen > RecordMaxSize {
		return ErrRecordInvalid
	}
	r.Signature = make([]byte, uint(siglen))
	if _, err = io.ReadFull(&rr, r.Signature); err != nil {
		return err
	}

	r.selectorKeys = nil

	return nil
}

// MarshalTo writes this record in serialized form to the supplied writer.
// If hashAsProxyForValue is true a hash of the value is substituted for the actual value.
// This results in a byte stream that can't be unmarshaled and is for hashing. The hash
// of the value is used in place of the value for hashing records to permit obsolete values
// to eventually be dropped from storage. This also allows any "pee in the pool attacks"
// like storing CP in the DAG to be mitigated via some kind of local blacklist.
func (r *Record) MarshalTo(w io.Writer, hashAsProxyForValue bool) error {
	if err := r.recordBody.marshalTo(w, hashAsProxyForValue); err != nil {
		return err
	}

	if _, err := writeUVarint(w, uint64(len(r.Selectors))); err != nil {
		return err
	}
	for i := 0; i < len(r.Selectors); i++ {
		if err := r.Selectors[i].marshalTo(w); err != nil {
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
	var buf bytes.Buffer
	buf.Grow(len(r.Value) + 256)
	r.MarshalTo(&buf, false)
	return buf.Bytes()
}

// Hash returns Shandwich256(Bytes()).
// This is the main record hash used for record linking. Note that it's not a straight
// hash of the record's bytes by a hash of the record with the (raw unmasked) value
// replaced by the value's hash.
func (r *Record) Hash() (hb [32]byte) {
	h := NewShandwich256()
	r.MarshalTo(h, true)
	h.Sum(hb[:0])
	return
}

// Score returns this record's work score, which is algorithm dependent.
// The returned value is scaled to the range of uint32 so that future algorithms can coexist with or at least
// be comparable relative to current ones.
func (r *Record) Score() uint32 {
	switch r.WorkAlgorithm {
	case RecordWorkAlgorithmNone:
		return 1
	case RecordWorkAlgorithmWharrgarbl:
		return recordWharrgarblScore(WharrgarblGetDifficulty(r.Work))
	}
	return 0
}

// SelectorKey returns the selector key for a given selector at a given index in []Selectors.
// This is easier than getting the record body hash and calling the selector's Key method and
// also caches keys for faster retrieval later.
func (r *Record) SelectorKey(selectorIndex int) []byte {
	if selectorIndex < len(r.Selectors) {
		if len(r.selectorKeys) != len(r.Selectors) {
			r.selectorKeys = make([][]byte, len(r.Selectors))
			selectorClaimSigningHash := r.recordBody.signingHash()
			for si := range r.Selectors {
				r.selectorKeys[si] = r.Selectors[si].key(selectorClaimSigningHash[:])
			}
		}
		return r.selectorKeys[selectorIndex]
	}
	return nil
}

// ID returns a Shandwich256 hash of all this record's selector database keys sorted in ascending order.
// If the record has no selectors the ID is just its hash.
func (r *Record) ID() (id [32]byte) {
	if len(r.Selectors) == 0 {
		return r.Hash()
	}

	var selectorKeys [][]byte
	for i := range r.Selectors {
		selectorKeys = append(selectorKeys, r.SelectorKey(i))
	}
	sort.Slice(selectorKeys, func(a, b int) bool { return bytes.Compare(selectorKeys[a], selectorKeys[b]) < 0 })

	h := NewShandwich256()
	for i := 0; i < len(selectorKeys); i++ {
		h.Write(selectorKeys[i])
	}
	h.Sum(id[:0])
	return
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
		return ErrRecordOwnerSignatureCheckFailed
	}

	selectorClaimSigningHash := r.recordBody.signingHash()
	workBillableBytes := r.recordBody.sizeBytes()
	workHasher := sha3.New256()
	workHasher.Write(selectorClaimSigningHash[:])
	for i := 0; i < len(r.Selectors); i++ {
		sb := r.Selectors[i].bytes()
		workHasher.Write(sb)
		workBillableBytes += uint(len(sb))
	}
	var workHash [32]byte
	workHasher.Sum(workHash[:0])

	switch r.WorkAlgorithm {
	case RecordWorkAlgorithmNone:
	case RecordWorkAlgorithmWharrgarbl:
		if WharrgarblVerify(r.Work, workHash[:]) < recordWharrgarblCost(workBillableBytes) {
			return ErrRecordInsufficientWork
		}
	default:
		return ErrRecordInsufficientWork
	}

	owner, err := NewOwnerFromBytes(r.recordBody.Owner)
	if err != nil {
		return ErrRecordOwnerSignatureCheckFailed
	}
	finalHash := sha3.New256()
	finalHash.Write(workHash[:])
	finalHash.Write(r.Work)
	finalHash.Write([]byte{r.WorkAlgorithm})
	var hb [32]byte
	if !owner.Verify(finalHash.Sum(hb[:0]), r.Signature) {
		return ErrRecordOwnerSignatureCheckFailed
	}

	return nil
}

// recordWharrgarblCost computes the cost in Wharrgarbl difficulty for a record of a given number of "billable" bytes.
func recordWharrgarblCost(bytes uint) uint32 {
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
	if bytes < 4 { // small byte counts break the calculation (no real record is this small anyway)
		return uint32(bytes) + 1
	}
	if bytes > RecordMaxSize { // sanity check, shouldn't ever happen
		bytes = RecordMaxSize
	}
	b := uint64(bytes * 3)
	c := (uint64(integerSqrtRounded(uint32(b))) * b * uint64(3)) - (b * 8)
	if c > 0xffffffff { // sanity check, no record gets this big
		return 0xffffffff
	}
	return uint32(c)
}

// recordWharrgarblScore computes a score approximately scaled to uint32_max based on a Wharrgarbl cost value from a piece of work.
func recordWharrgarblScore(cost uint32) uint32 {
	if cost > 0x0f7b0000 { // RecordWharrgarblCost(RecordMaxSize)
		return 0xffffa8db
	}
	if cost < 1 {
		return 1
	}
	return ((cost * 16) + ((cost / 10000) * 5369))
}

// NewRecordStart creates an incomplete record with its body and selectors filled out but no work or final signature.
// This can be used to do the first step of a three-phase record creation process with the next two phases being NewRecordAddWork
// and NewRecordComplete. This is useful of record creation needs to be split among systems or participants.
func NewRecordStart(value []byte, links [][32]byte, maskingKey []byte, plainTextSelectorNames [][]byte, selectorOrdinals [][]byte, ownerPublic, certificateRecordHash []byte, ts uint64) (r *Record, workHash [32]byte, workBillableBytes uint, err error) {
	if len(value) > RecordMaxSize {
		err = ErrInvalidParameter
		return
	}

	r = new(Record)

	if len(value) > 0 {
		// Attempt compression for values of non-trivial size.
		if len(value) > 32 {
			var valueCompr []byte
			valueCompr, err = enc.CompressBuffer(brotliParams, value, make([]byte, 0, len(value)+4))
			if err == nil && len(valueCompr) < len(value) {
				value = valueCompr
				r.recordBody.ValueCompressed = true
			}
		}

		// Encrypt with AES256-CFB using the timestamp and owner for IV.
		if len(maskingKey) > 0 {
			var cfbIv [16]byte
			binary.BigEndian.PutUint64(cfbIv[0:8], ts)
			if len(ownerPublic) >= 8 {
				copy(cfbIv[8:16], ownerPublic[0:8])
			}
			maskingKeyH := sha256.Sum256(maskingKey)
			c, _ := aes.NewCipher(maskingKeyH[:])
			valueMasked := make([]byte, len(value))
			cipher.NewCFBEncrypter(c, cfbIv[:]).XORKeyStream(valueMasked, value)
			r.recordBody.Value = valueMasked
			r.recordBody.ValueMasked = true
		} else {
			r.recordBody.Value = append(r.recordBody.Value, value...)
		}
	}

	r.recordBody.Owner = append(r.recordBody.Owner, ownerPublic...)
	if len(certificateRecordHash) == 32 {
		var cert [32]byte
		copy(cert[:], certificateRecordHash)
		r.recordBody.Certificate = &cert
	}

	if len(links) > 0 {
		r.recordBody.Links = make([][32]byte, 0, len(links))
		for i := 0; i < len(links); i++ {
			r.recordBody.Links = append(r.recordBody.Links, links[i])
		}
	}

	r.recordBody.Timestamp = ts

	workBillableBytes = r.recordBody.sizeBytes()
	selectorClaimSigningHash := r.recordBody.signingHash()
	workHasher := sha3.New256()
	workHasher.Write(selectorClaimSigningHash[:])
	if len(plainTextSelectorNames) > 0 {
		r.Selectors = make([]Selector, len(plainTextSelectorNames))
		for i := 0; i < len(plainTextSelectorNames); i++ {
			r.Selectors[i].set(plainTextSelectorNames[i], selectorOrdinals[i], selectorClaimSigningHash[:])
			sb := r.Selectors[i].bytes()
			workBillableBytes += uint(len(sb))
			workHasher.Write(sb)
		}
	}

	workHasher.Sum(workHash[:0])

	return
}

// NewRecordDoWork is a convenience method for doing the work to add to a record.
// This can obviously be a time and memory intensive function.
func NewRecordDoWork(workHash []byte, workBillableBytes uint, workFunction *Wharrgarblr, workCostOverride uint32) (work []byte, err error) {
	if workFunction != nil {
		if workCostOverride == 0 {
			workCostOverride = recordWharrgarblCost(workBillableBytes)
		}
		w, iter := workFunction.Compute(workHash, workCostOverride)
		if iter == 0 {
			err = ErrWharrgarblFailed
			return
		}
		work = w[:]
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
	signingHash = sha3.Sum256(tmp)
	return
}

// NewRecordComplete completes a record created with NewRecordStart after work is added with NewRecordAddWork by signing it with the owner's private key.
func NewRecordComplete(incompleteRecord *Record, signingHash []byte, owner *Owner) (r *Record, err error) {
	r = incompleteRecord
	r.Signature, err = owner.Sign(signingHash)
	r.selectorKeys = nil
	return
}

// NewRecord is a shortcut to running all incremental record creation functions.
// Obviously this is time and memory intensive due to proof of work required to "pay" for this record.
func NewRecord(value []byte, links [][32]byte, maskingKey []byte, plainTextSelectorNames [][]byte, selectorOrdinals [][]byte, certificateRecordHash []byte, ts uint64, workFunction *Wharrgarblr, workCostOverride uint32, owner *Owner) (r *Record, err error) {
	var wh, sh [32]byte
	var wb uint
	r, wh, wb, err = NewRecordStart(value, links, maskingKey, plainTextSelectorNames, selectorOrdinals, owner.Bytes(), certificateRecordHash, ts)
	if err != nil {
		return
	}
	w, err := NewRecordDoWork(wh[:], wb, workFunction, workCostOverride)
	if err != nil {
		return
	}
	workAlgorithm := RecordWorkAlgorithmNone
	if workFunction != nil {
		workAlgorithm = RecordWorkAlgorithmWharrgarbl
	}
	r, sh, err = NewRecordAddWork(r, wh[:], w, workAlgorithm)
	if err != nil {
		return
	}
	r, err = NewRecordComplete(r, sh[:], owner)
	return
}

// NewRecordFromBytes deserializes a record from a byte array.
func NewRecordFromBytes(b []byte) (r *Record, err error) {
	r = new(Record)
	err = r.UnmarshalFrom(bytes.NewReader(b))
	return
}
