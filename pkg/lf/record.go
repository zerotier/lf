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
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"sort"

	"golang.org/x/crypto/sha3"
	brotlidec "gopkg.in/kothar/brotli-go.v0/dec"
	brotlienc "gopkg.in/kothar/brotli-go.v0/enc"
)

var (
	b1_0 = []byte{0x00}
	b1_1 = []byte{0x01}

	brotliParams = func() (bp [2]*brotlienc.BrotliParams) {
		bp[0] = brotlienc.NewBrotliParams()
		bp[0].SetQuality(11)
		bp[0].SetMode(brotlienc.TEXT)
		bp[1] = brotlienc.NewBrotliParams()
		bp[1].SetQuality(11)
		bp[1].SetMode(brotlienc.GENERIC)
		return
	}()
)

const (
	recordBodyFlagHasCertificate byte = 0x01
	recordBodyFlagHasType        byte = 0x02

	recordValueFlagBrotliCompressed uint32 = 0x80000000

	// RecordDefaultWharrgarblMemory is the default amount of memory to use for Wharrgarbl momentum-type PoW.
	RecordDefaultWharrgarblMemory = 1024 * 1024 * 512

	// RecordMaxSize is a global maximum record size (binary serialized length).
	// This is a protocol constant and can't be changed.
	RecordMaxSize = 65536

	// RecordMaxLinks is the maximum number of links a valid record can have.
	// This is a protocol constant and can't be changed.
	RecordMaxLinks = 255

	// RecordMaxSelectors is a sanity limit on the number of selectors.
	// This is a protocol constant and can't be changed.
	RecordMaxSelectors = 16

	// RecordWorkAlgorithmNone indicates no work algorithm (not allowed on main network but can exist in testing or private networks that are CA-only).
	// This is a protocol constant and can't be changed.
	RecordWorkAlgorithmNone byte = 0

	// RecordWorkAlgorithmWharrgarbl indicates the Wharrgarbl momentum-like proof of work algorithm.
	// This is a protocol constant and can't be changed.
	RecordWorkAlgorithmWharrgarbl byte = 1

	// RecordTypeDatum records are normal user data records (this is the default if unspecified).
	// This is a protocol constant and can't be changed.
	RecordTypeDatum byte = 0

	// RecordTypeGenesis indicates a genesis record containing possible network config updates (if any are amendable).
	// This is a protocol constant and can't be changed.
	RecordTypeGenesis byte = 1

	// RecordTypeCertificate records contain an x509 certificate.
	// This is a protocol constant and can't be changed.
	RecordTypeCertificate byte = 2

	// RecordTypeCommentary records contain commentary about other records in the DAG.
	// This is a protocol constant and can't be changed.
	RecordTypeCommentary byte = 3
)

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

//////////////////////////////////////////////////////////////////////////////

// recordBody represents the main body of a record including its value, owner public keys, etc.
// It's included as part of Record but separated since in record construction we want to treat it as a separate element.
type recordBody struct {
	Value       Blob       `json:",omitempty"` // Record value (possibly masked and/or compressed, use GetValue() to get)
	Owner       OwnerBlob  `json:",omitempty"` // Owner of this record (owner public bytes) in @base58string format
	Certificate *HashBlob  `json:",omitempty"` // Hash (256-bit) of exact record containing certificate for this owner (if CAs are enabled)
	Links       []HashBlob `json:",omitempty"` // Links to previous records' hashes
	Timestamp   uint64     ``                  // Timestamp (and revision ID) in SECONDS since Unix epoch
	Type        *byte      `json:",omitempty"` // Record type byte, RecordTypeDatum (0) if nil
}

func (rb *recordBody) unmarshalFrom(r io.Reader) error {
	rr := byteAndArrayReader{r}

	flags, err := rr.ReadByte()
	if err != nil {
		return err
	}

	if (flags & recordBodyFlagHasType) != 0 {
		rtype, err := rr.ReadByte()
		if err != nil {
			return err
		}
		if rtype != 0 {
			rb.Type = &rtype
		}
	}

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
		var cert HashBlob
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
		rb.Links = make([]HashBlob, uint(l))
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

	return nil
}

func (rb *recordBody) marshalTo(w io.Writer, hashAsProxyForValue bool) error {
	var flags [2]byte
	if rb.Certificate != nil {
		flags[0] |= recordBodyFlagHasCertificate
	}
	if rb.Type != nil && *rb.Type != 0 {
		flags[0] |= recordBodyFlagHasType
		flags[1] = *rb.Type
		if _, err := w.Write(flags[0:2]); err != nil {
			return err
		}
	} else {
		if _, err := w.Write(flags[0:1]); err != nil {
			return err
		}
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
// Nil is returned if the value is empty. ErrIncorrectKey is returned if the masking
// key is not correct.
func (rb *recordBody) GetValue(maskingKey []byte) ([]byte, error) {
	if len(rb.Value) < 4 {
		return nil, nil
	}

	if len(maskingKey) == 0 {
		maskingKey = rb.Owner
	}

	var unmaskedValue []byte
	unmaskedValue = make([]byte, len(rb.Value))
	var cfbIv [16]byte
	binary.BigEndian.PutUint64(cfbIv[0:8], rb.Timestamp)
	if len(rb.Owner) >= 8 {
		copy(cfbIv[8:16], rb.Owner[0:8])
	}
	maskingKeyH := sha3.Sum256(maskingKey)
	c, _ := aes.NewCipher(maskingKeyH[:])
	cipher.NewCFBDecrypter(c, cfbIv[:]).XORKeyStream(unmaskedValue, rb.Value)
	flagsAndCrc := binary.BigEndian.Uint32(unmaskedValue[0:4])
	if (crc32.ChecksumIEEE(unmaskedValue[4:]) & 0x0fffffff) != (flagsAndCrc & 0x0fffffff) {
		return nil, ErrIncorrectKey
	}
	unmaskedValue = unmaskedValue[4:]

	if (flagsAndCrc & recordValueFlagBrotliCompressed) != 0 {
		return brotlidec.DecompressBuffer(unmaskedValue, make([]byte, 0, len(unmaskedValue)+(len(unmaskedValue)/3)))
	}
	return unmaskedValue, nil
}

// GetType is a shortcut to both checking Type for nil and getting its value if not.
func (rb *recordBody) GetType() byte {
	if rb.Type == nil {
		return RecordTypeDatum
	}
	return *rb.Type
}

//////////////////////////////////////////////////////////////////////////////

// Record combines the record body with one or more selectors, work, and a signature.
// A record should not be modified once created. It should be treated as a read-only value.
type Record struct {
	recordBody

	Selectors     []Selector `json:",omitempty"` // Things that can be used to find the record
	Work          Blob       `json:",omitempty"` // Proof of work computed on sha3-256(Body Signing Hash | Selectors) with work cost based on size of body and selectors
	WorkAlgorithm byte       ``                  // Proof of work algorithm
	Signature     Blob       `json:",omitempty"` // Signature of sha3-256(sha3-256(Body Signing Hash | Selectors) | Work | WorkAlgorithm)

	selectorKeys [][]byte  // memoized selector keys
	hash         *[32]byte // memoized hash
}

// UnmarshalFrom deserializes this record from a reader.
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
	r.hash = nil

	return nil
}

// MarshalTo writes this record in serialized form to the supplied writer.
// If hashAsProxyForValue is true a hash of the value is substituted for the actual value.
// This results in a byte stream that can't be unmarshaled and is used for computing
// record hashes.
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

// SizeBytes is a faster shortcut for len(Bytes())
func (r *Record) SizeBytes() int {
	var c countingWriter
	r.MarshalTo(&c, false)
	return int(c)
}

// Hash returns Shandwich256(Bytes()).
// This is the main record hash used for record linking. Note that it's not a straight
// hash of the record's bytes by a hash of the record with the (raw unmasked) value
// replaced by the value's hash.
func (r *Record) Hash() (hb [32]byte) {
	if r.hash != nil {
		copy(hb[:], r.hash[:])
		return
	}
	h := NewShandwich256()
	r.MarshalTo(h, true)
	h.Sum(hb[:0])
	r.hash = &hb
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
	if selectorIndex >= 0 && selectorIndex < len(r.Selectors) {
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

// SelectorIs returns true if the selector with the given index has the given plain text key.
// Note that this is computationally a little more expensive than you'd think given how selectors work.
func (r *Record) SelectorIs(plainTextKey []byte, selectorIndex int) bool {
	if selectorIndex >= 0 && selectorIndex < len(r.Selectors) {
		selectorClaimSigningHash := r.recordBody.signingHash()
		return r.Selectors[selectorIndex].isNamed(selectorClaimSigningHash[:], plainTextKey)
	}
	return false
}

// ID returns SHA3-256(selector keys) where selector keys are sorted in ascending order.
// If there are no selectors in this record, its ID is equal to its hash.
func (r *Record) ID() (id [32]byte) {
	if len(r.Selectors) == 0 {
		return r.Hash()
	}

	var selectorKeys [][]byte
	for i := range r.Selectors {
		selectorKeys = append(selectorKeys, r.SelectorKey(i))
	}
	sort.Slice(selectorKeys, func(a, b int) bool { return bytes.Compare(selectorKeys[a], selectorKeys[b]) < 0 })

	h := sha3.New256()
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

// NewRecordStart creates an incomplete record with its body and selectors filled out but no work or final signature.
// This can be used to do the first step of a three-phase record creation process with the next two phases being NewRecordAddWork
// and NewRecordComplete. This is useful of record creation needs to be split among systems or participants.
func NewRecordStart(recordType byte, value []byte, links [][32]byte, maskingKey []byte, plainTextSelectorNames [][]byte, selectorOrdinals [][]byte, owner, certificateRecordHash []byte, ts uint64) (r *Record, workHash [32]byte, workBillableBytes uint, err error) {
	r = new(Record)

	if len(value) > 0 {
		// Attempt compression for values of non-trivial size.
		var flags uint32
		if len(value) > 24 {
			bestOutput := value
			for _, bp := range brotliParams { // tries both GENERIC and TEXT brotli parameters
				var cout []byte
				cout, err = brotlienc.CompressBuffer(bp, value, make([]byte, 0, len(value)+4))
				if err == nil && len(cout) > 0 && len(cout) < len(bestOutput) {
					bestOutput = cout
				}
			}
			if len(bestOutput) < len(value) {
				value = bestOutput
				flags = recordValueFlagBrotliCompressed
			}
		}

		// Encrypt with AES256-CFB using the timestamp and owner for IV. A CRC32 is
		// included so users can tell if their masking key is correct. Note that this
		// CRC32 is not used for real authentication. That happens via the owner's
		// signature of the whole record.
		var cfbIv [16]byte
		binary.BigEndian.PutUint64(cfbIv[0:8], ts)
		if len(owner) >= 8 { // sanity check
			copy(cfbIv[8:16], owner[0:8])
		}
		if len(maskingKey) == 0 {
			maskingKey = owner // all records are masked, use owner if no key given
		}
		maskingKeyH := sha3.Sum256(maskingKey)
		c, _ := aes.NewCipher(maskingKeyH[:])
		cfb := cipher.NewCFBEncrypter(c, cfbIv[:])
		valueMasked := make([]byte, 4+len(value))
		binary.BigEndian.PutUint32(valueMasked[0:4], (crc32.ChecksumIEEE(value)&0x0fffffff)|flags) // most significant 4 bits are used for flags
		cfb.XORKeyStream(valueMasked[0:4], valueMasked[0:4])
		cfb.XORKeyStream(valueMasked[4:], value)
		r.recordBody.Value = valueMasked
	}

	r.recordBody.Owner = append(r.recordBody.Owner, owner...)
	if len(certificateRecordHash) == 32 {
		var cert HashBlob
		copy(cert[:], certificateRecordHash)
		r.recordBody.Certificate = &cert
	}

	if len(links) > 0 {
		r.recordBody.Links = make([]HashBlob, 0, len(links))
		for i := 0; i < len(links); i++ {
			r.recordBody.Links = append(r.recordBody.Links, links[i])
		}
		sort.Slice(r.recordBody.Links, func(a, b int) bool { return bytes.Compare(r.recordBody.Links[a][:], r.recordBody.Links[b][:]) < 0 })
	}

	r.recordBody.Timestamp = ts

	if recordType != 0 {
		r.Type = &recordType
	}

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
func NewRecordDoWork(workHash []byte, workBillableBytes uint, workFunction *Wharrgarblr) (work []byte, err error) {
	if workFunction != nil {
		w, iter := workFunction.Compute(workHash, recordWharrgarblCost(workBillableBytes))
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
	return
}

// NewRecord is a shortcut to running all incremental record creation functions.
// Obviously this is time and memory intensive due to proof of work required to "pay" for this record.
func NewRecord(recordType byte, value []byte, links [][32]byte, maskingKey []byte, plainTextSelectorNames [][]byte, selectorOrdinals [][]byte, certificateRecordHash []byte, ts uint64, workFunction *Wharrgarblr, owner *Owner) (r *Record, err error) {
	var wh, sh [32]byte
	var wb uint
	r, wh, wb, err = NewRecordStart(recordType, value, links, maskingKey, plainTextSelectorNames, selectorOrdinals, owner.Bytes(), certificateRecordHash, ts)
	if err != nil {
		return
	}
	w, err := NewRecordDoWork(wh[:], wb, workFunction)
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
