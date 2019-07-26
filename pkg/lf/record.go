/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * --
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial closed-source software that incorporates or links
 * directly against ZeroTier software without disclosing the source code
 * of your own application.
 */

package lf

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

var (
	b1_0 = []byte{0x00}
	b1_1 = []byte{0x01}
)

const (
	// Flags are protocol constants and can't be changed. Bits are reserved as
	// follows:
	//   0-4   - boolean flags
	//   4-8   - link count (0...15)
	//   8-12  - record type (0...15)
	//  12-63  - reserved for future use
	recordBodyFlagHasValue      uint64 = 0x1
	recordBodyFlagHasPulseToken uint64 = 0x2
	recordBodyFlagValueIsHash   uint64 = 0x4

	// Record value compression types are protocol constants. Range must be 0-3.
	recordValueCompressionNone   = 0
	recordValueCompressionBrotli = 1

	// recordNoWorkScore is the score of records that don't have work (certificate authorized).
	// This is a protocol constant and can't be changed.
	recordNoWorkScore = 0x000fffff

	// RecordDefaultWharrgarblMemory is the default amount of memory to use for Wharrgarbl momentum-type PoW.
	RecordDefaultWharrgarblMemory = 1024 * 1024 * 512

	// RecordMaxSize is a global maximum record size (binary serialized length).
	// This is a protocol constant and can't be changed.
	RecordMaxSize = 65536

	// RecordMaxLinks is the maximum number of links a valid record can have.
	// This is a protocol constant and can't be changed. (It must also fit in 3 bits.)
	RecordMaxLinks = 15

	// RecordMaxSelectors is a sanity limit on the number of selectors.
	// This is a protocol constant and can't be changed.
	RecordMaxSelectors = 15

	// RecordMaxPulseSpan is the maximum number of minutes after a record's timestamp that pulses can be applied.
	// This is a protocol constant and can't be changed.
	RecordMaxPulseSpan = 525600

	// RecordWorkAlgorithmNone indicates no work algorithm.
	// This is a protocol constant and can't be changed.
	RecordWorkAlgorithmNone = 0

	// RecordWorkAlgorithmWharrgarbl indicates the Wharrgarbl momentum-like proof of work algorithm.
	// This is a protocol constant and can't be changed.
	RecordWorkAlgorithmWharrgarbl = 1

	// RecordTypeDatum records are normal user data records (this is the default if unspecified).
	// This is a protocol constant and can't be changed.
	RecordTypeDatum = 0

	// RecordTypeGenesis indicates a genesis record containing possible network config updates (if any are amendable).
	// This is a protocol constant and can't be changed.
	RecordTypeGenesis = 1

	// RecordTypeCommentary records contain commentary about other records in the DAG.
	// This is a protocol constant and can't be changed.
	RecordTypeCommentary = 2

	// RecordTypeCertificate records contain an x509 certificate.
	// This is a protocol constant and can't be changed.
	RecordTypeCertificate = 3

	// RecordTypeCRL contains a DER encoded x509 CRL.
	// This is a protocol constant and can't be changed.
	RecordTypeCRL = 4

	// RecordTypeDelete is a record that hides all other records by the same owner.
	// This is a protocol constant and can't be changed.
	RecordTypeDelete = 15 // reserved, not implemented yet

	// RecordCertificateMaskingKey is the masking key for certs and CRLs (used as byte array).
	// This is a protocol constant and can't be changed.
	RecordCertificateMaskingKey = "lfCertificate"
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

// makeMaskingCipher initializes AES256-CFB using various bits of record material.
// If maskingKey is nil, selectorNames[0] is used if present. If both are nil/empty
// then the masking key is based only on the timestamp and the owner.
func makeMaskingCipher(maskingKey, ownerPublic []byte, selectorNames [][]byte, timestamp uint64, decrypt bool) cipher.Stream {
	var tsb [8]byte
	binary.BigEndian.PutUint64(tsb[:], timestamp)
	maskingHasher := sha512.New384()
	maskingHasher.Write(tsb[:])
	if len(maskingKey) == 0 {
		if len(selectorNames) > 0 {
			maskingHasher.Write(selectorNames[0])
		}
	} else {
		maskingHasher.Write(maskingKey)
	}
	maskingHasher.Write(ownerPublic)
	var maskingKeyBits [48]byte
	maskingHasher.Sum(maskingKeyBits[:0])
	c, _ := aes.NewCipher(maskingKeyBits[0:32])
	if decrypt {
		return cipher.NewCFBDecrypter(c, maskingKeyBits[32:48])
	}
	return cipher.NewCFBEncrypter(c, maskingKeyBits[32:48])
}

//////////////////////////////////////////////////////////////////////////////

// recordBody represents the main body of a record including its value, owner public keys, etc.
// It's included as part of Record but separated since in record construction we want to treat it as a separate element.
type recordBody struct {
	Value      Blob        `json:",omitempty"` // Record value (possibly masked and/or compressed, use GetValue() to get)
	ValueHash  Blob        `json:",omitempty"` // Normally empty, but contains SHA384(Value) if this is an abbreviated record
	Owner      OwnerPublic `json:",omitempty"` // Owner of this record
	Links      []HashBlob  `json:",omitempty"` // Links to previous records' hashes
	Timestamp  uint64      ``                  // Timestamp (and revision ID) in SECONDS since Unix epoch
	PulseToken uint64      ``                  // Pulse token (endpoint of TH64 hash chain)
	Type       int         ``                  // Record type ID

	sigHash *[48]byte
}

func (rb *recordBody) unmarshalFrom(r io.Reader) error {
	rr := byteAndArrayReader{r}

	flags, err := binary.ReadUvarint(&rr)
	if err != nil {
		return err
	}

	if (flags & recordBodyFlagHasValue) != 0 {
		if (flags & recordBodyFlagValueIsHash) != 0 {
			var vh [48]byte
			_, err = io.ReadFull(&rr, vh[:])
			if err != nil {
				return err
			}
			rb.Value = nil
			rb.ValueHash = vh[:]
		} else {
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
			rb.ValueHash = nil
		}
	} else {
		rb.Value = nil
		rb.ValueHash = nil
	}

	l, err := binary.ReadUvarint(&rr)
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

	linkCount := int((flags >> 4) & 0xf)
	if linkCount > 0 {
		rb.Links = make([]HashBlob, linkCount)
		for i := 0; i < linkCount; i++ {
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

	if (flags & recordBodyFlagHasPulseToken) != 0 {
		var pt [8]byte
		_, err = io.ReadFull(&rr, pt[:])
		if err != nil {
			return err
		}
		rb.PulseToken = binary.BigEndian.Uint64(pt[:])
	} else {
		rb.PulseToken = 0
	}

	rb.Type = int((flags >> 8) & 0xf)

	rb.sigHash = nil

	return nil
}

func (rb *recordBody) marshalTo(w io.Writer, hashAsProxyForValue bool) error {
	if len(rb.Links) > 0xf || rb.Type < 0 || rb.Type > 0xf {
		return ErrRecordInvalid
	}

	flags := (uint64(len(rb.Links)) << 4) | (uint64(rb.Type) << 8)
	if len(rb.Value) > 0 {
		flags |= recordBodyFlagHasValue
	}
	if len(rb.ValueHash) == 48 {
		flags |= recordBodyFlagHasValue
		hashAsProxyForValue = true
	}
	if rb.PulseToken != 0 {
		flags |= recordBodyFlagHasPulseToken
	}
	if hashAsProxyForValue {
		flags |= recordBodyFlagValueIsHash
	}
	if _, err := writeUVarint(w, flags); err != nil {
		return err
	}

	if len(rb.Value) > 0 {
		if hashAsProxyForValue {
			if len(rb.ValueHash) == 48 {
				if _, err := w.Write(rb.ValueHash); err != nil {
					return err
				}
			} else {
				h := sha512.Sum384(rb.Value)
				if _, err := w.Write(h[:]); err != nil {
					return err
				}
			}
		} else {
			if _, err := writeUVarint(w, uint64(len(rb.Value))); err != nil {
				return err
			}
			if _, err := w.Write(rb.Value); err != nil {
				return err
			}
		}
	}

	if _, err := writeUVarint(w, uint64(len(rb.Owner))); err != nil {
		return err
	}
	if _, err := w.Write(rb.Owner); err != nil {
		return err
	}

	for i := 0; i < len(rb.Links); i++ {
		if _, err := w.Write(rb.Links[i][:]); err != nil {
			return err
		}
	}

	_, err := writeUVarint(w, rb.Timestamp)

	if rb.PulseToken != 0 {
		var pt [8]byte
		binary.BigEndian.PutUint64(pt[:], rb.PulseToken)
		if _, err := w.Write(pt[:]); err != nil {
			return err
		}
	}

	return err
}

func (rb *recordBody) signingHash() (hb [48]byte) {
	if rb.sigHash == nil {
		s384 := sha512.New384()
		rb.marshalTo(s384, true)
		s384.Sum(hb[:0])
		rb.sigHash = &hb
		return
	}
	hb = *rb.sigHash
	return
}

func (rb *recordBody) sizeBytes() uint {
	var wc countingWriter
	rb.marshalTo(&wc, false)
	return uint(wc)
}

// GetValue unmasks and possibly decompresses this record's value.
// A masking key is always needed. The default for new records where no masking key is
// explicitly specified is the plain text name of the first selector or the owner if
// there are no selectors. If nil is given here for a masking key, the owner is used.
func (rb *recordBody) GetValue(maskingKey []byte) ([]byte, error) {
	if len(rb.Value) < 2 {
		return nil, nil
	}

	unmaskedValue := make([]byte, len(rb.Value))
	makeMaskingCipher(maskingKey, rb.Owner, nil, rb.Timestamp, true).XORKeyStream(unmaskedValue, rb.Value)
	flagsAndCrc := (uint16(unmaskedValue[0]) << 8) | uint16(unmaskedValue[1])
	if (flagsAndCrc >> 2) != (crc16(unmaskedValue[2:]) >> 2) {
		return nil, ErrIncorrectKey
	}
	unmaskedValue = unmaskedValue[2:]

	if (flagsAndCrc & 3) == recordValueCompressionBrotli {
		return BrotliDecompress(unmaskedValue, RecordMaxSize)
	}
	return unmaskedValue, nil
}

// ValueDataSize returns the size of the value minus CRC16 overhead.
// This is the number that's used to check to see if records are below the network's max value size.
// Checking against just len(Value) excludes records whose payload is exactly the maximum
// and that are not compressable.
func (rb *recordBody) ValueDataSize() int {
	if len(rb.Value) <= 2 {
		return 0
	}
	return len(rb.Value) - 2
}

//////////////////////////////////////////////////////////////////////////////

// Record combines the record body with one or more selectors, work, and a signature.
// A record should not be modified once created. It should be treated as a read-only value.
type Record struct {
	recordBody

	Selectors     []Selector `json:",omitempty"` // Things that can be used to find the record
	Work          Blob       `json:",omitempty"` // Proof of work "paying" for this record
	WorkAlgorithm int        ``                  // Proof of work algorithm
	Signature     Blob       `json:",omitempty"` // Signature of record (including work) by owner

	hash, id *[32]byte
}

// UnmarshalFrom deserializes this record from a reader.
func (r *Record) UnmarshalFrom(rdr io.Reader) error {
	rr := byteAndArrayReader{rdr}

	if err := r.recordBody.unmarshalFrom(&rr); err != nil {
		return err
	}

	selCountAndWorkAlg, err := rr.ReadByte()
	if err != nil {
		return err
	}

	selCount := int(selCountAndWorkAlg & 0xf)
	r.Selectors = make([]Selector, selCount)
	for i := 0; i < selCount; i++ {
		err = r.Selectors[i].unmarshalFrom(rr)
		if err != nil {
			return err
		}
	}

	r.WorkAlgorithm = int(selCountAndWorkAlg >> 4)
	switch r.WorkAlgorithm {
	case RecordWorkAlgorithmNone:
		r.Work = nil
	case RecordWorkAlgorithmWharrgarbl:
		var work [WharrgarblOutputSize]byte
		if _, err = io.ReadFull(&rr, work[:]); err != nil {
			return err
		}
		r.Work = work[:]
	default:
		return ErrRecordUnsupportedAlgorithm
	}

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

	r.hash = nil
	r.id = nil

	return nil
}

// MarshalTo writes this record in serialized form to the supplied writer.
// If hashAsProxyForValue is true SHA384(value) is stored in the stream instead
// of the actual value. These streams can't (currently) be unmarshaled and are
// only used to compute further hashes.
func (r *Record) MarshalTo(w io.Writer, hashAsProxyForValue bool) error {
	if len(r.Selectors) > 0xf || r.WorkAlgorithm < 0 || r.WorkAlgorithm > 0xf {
		return ErrRecordInvalid
	}
	if err := r.recordBody.marshalTo(w, hashAsProxyForValue); err != nil {
		return err
	}

	if _, err := w.Write([]byte{byte(len(r.Selectors)) | byte(r.WorkAlgorithm<<4)}); err != nil {
		return err
	}

	for i := 0; i < len(r.Selectors); i++ {
		if err := r.Selectors[i].marshalTo(w); err != nil {
			return err
		}
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

// NewRecordFromBytes deserializes a record from a byte array.
func NewRecordFromBytes(b []byte) (r *Record, err error) {
	r = new(Record)
	err = r.UnmarshalFrom(bytes.NewReader(b))
	return
}

// Bytes returns a byte serialized record
func (r *Record) Bytes() []byte {
	var buf bytes.Buffer
	buf.Grow(len(r.Value) + 256)
	r.MarshalTo(&buf, false)
	return buf.Bytes()
}

// SizeBytes is a faster shortcut for len(Bytes()) that just serializes to a counting writer.
func (r *Record) SizeBytes() int {
	var c countingWriter
	r.MarshalTo(&c, false)
	return int(c)
}

// Hash returns the record hash used for individual record identification and linking.
// The hash computed is sha256(in | sha512(in)) where in is the record with its value
// replaced by the sha384() hash of its value. This replacement is to allow future
// nodes to drop old record values from storage but still compute proper hashes for all
// records in the entire DAG.
func (r *Record) Hash() (hb [32]byte) {
	if r.hash != nil {
		hb = *r.hash
		return
	}

	s256 := sha256.New()
	s512 := sha512.New()
	r.MarshalTo(io.MultiWriter(s256, s512), true)

	var s512buf [64]byte
	s256.Write(s512.Sum(s512buf[:0]))

	s256.Sum(hb[:0])
	r.hash = &hb
	return
}

// HashString returns =hash where hash is base62 encoded.
func (r *Record) HashString() string {
	h := r.Hash()
	return "=" + Base62Encode(h[:])
}

// Score returns this record's work score scaled to be work algorithm independent.
func (r *Record) Score() uint32 {
	switch r.WorkAlgorithm {
	case RecordWorkAlgorithmWharrgarbl:
		return recordWharrgarblScore(WharrgarblGetDifficulty(r.Work))
	}
	return recordNoWorkScore
}

// SelectorKey returns the selector key for a given selector at a given index in []Selectors.
func (r *Record) SelectorKey(selectorIndex int) []byte {
	if selectorIndex >= 0 && selectorIndex < len(r.Selectors) {
		recordBodyHash := r.recordBody.signingHash()
		return r.Selectors[selectorIndex].key(recordBodyHash[:])
	}
	return nil
}

// SelectorIs returns true if the selector with the given index has the given plain text key.
// Note that this is computationally a little more expensive than you'd think given how selectors work.
func (r *Record) SelectorIs(plainTextKey []byte, selectorIndex int) bool {
	if selectorIndex >= 0 && selectorIndex < len(r.Selectors) {
		recordBodyHash := r.recordBody.signingHash()
		return r.Selectors[selectorIndex].isNamed(recordBodyHash[:], plainTextKey)
	}
	return false
}

// ID returns SHA256(selector IDs) where selector IDs are the recovered selector public keys.
// If there are no selectors in this record, its ID is equal to its hash.
func (r *Record) ID() (id [32]byte) {
	if r.id != nil {
		copy(id[:], r.id[:])
		return
	}
	if len(r.Selectors) == 0 {
		id = r.Hash()
		return
	}
	recordBodyHash := r.recordBody.signingHash()
	h := sha256.New()
	for i := 0; i < len(r.Selectors); i++ {
		h.Write(r.Selectors[i].id(recordBodyHash[:]))
	}
	h.Sum(id[:0])
	r.id = &id
	return
}

// Validate this record structurally and validates its cryptographic signatures.
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

	if len(r.Selectors) > RecordMaxSelectors {
		return ErrRecordTooManySelectors
	}

	if len(r.Links) > RecordMaxLinks {
		return ErrRecordTooManyLinks
	}
	for i := 1; i < len(r.Links); i++ {
		if bytes.Compare(r.Links[i-1][:], r.Links[i][:]) >= 0 {
			return ErrRecordInvalidLinks
		}
	}

	if r.SizeBytes() > RecordMaxSize {
		return ErrRecordTooLarge
	}

	workHash, _ := r.workHash()
	signingHasher := sha512.New384()
	signingHasher.Write(workHash)
	signingHasher.Write(r.Work)
	signingHasher.Write([]byte{byte(r.WorkAlgorithm)})
	var hb [48]byte
	owner := Owner{Public: r.recordBody.Owner}
	if !owner.Verify(signingHasher.Sum(hb[:0]), r.Signature) {
		return ErrRecordOwnerSignatureCheckFailed
	}

	return nil
}

// ValidateWork checks that this record's work is enough to "pay" for it.
// Note that this doesn't check whether work is needed, just that it is sufficient.
// It returns false for WorkAlgorithmNone as well as if there is simply not enough work.
func (r *Record) ValidateWork() bool {
	workHash, workBillableBytes := r.workHash()
	switch r.WorkAlgorithm {
	case RecordWorkAlgorithmWharrgarbl:
		if WharrgarblVerify(r.Work, workHash[:]) >= recordWharrgarblCost(workBillableBytes) {
			return true
		}
	}
	return false
}

// WorkHash returns a 384-bit hash used to compute and verify PoW and also the number of billable bytes for PoW.
func (r *Record) workHash() ([]byte, uint) {
	recordBodyHash := r.recordBody.signingHash()
	workBillableBytes := r.recordBody.sizeBytes()
	workHasher := sha512.New384()
	workHasher.Write(recordBodyHash[:])
	for i := 0; i < len(r.Selectors); i++ {
		sb := r.Selectors[i].Bytes()
		workHasher.Write(sb)
		workBillableBytes += uint(len(sb))
	}
	var wh [48]byte
	return workHasher.Sum(wh[:0]), workBillableBytes
}

//////////////////////////////////////////////////////////////////////////////

// RecordBuilder allows records to be built in multiple steps.
// This could be used in the future to support record building across different nodes
// if we ever need that.
type RecordBuilder struct {
	record            *Record
	workHash          Blob
	workBillableBytes uint
}

// Start begins creating a new record, resetting RecordBuilder if it contains any old state.
func (rb *RecordBuilder) Start(recordType int, value []byte, links [][32]byte, maskingKey []byte, selectorNames [][]byte, selectorOrdinals []uint64, ownerPublic []byte, pulseToken, timestamp uint64) error {
	rb.record = new(Record)
	rb.workHash = nil
	rb.workBillableBytes = 0

	if recordType < 0 || recordType > 0xf || len(links) > 0xf {
		return ErrInvalidParameter
	}
	if timestamp == 0 {
		timestamp = TimeSec()
	}

	if len(value) > 0 {
		compressionType := uint16(recordValueCompressionNone)
		if len(value) > 24 {
			cout, err := BrotliCompress(value, make([]byte, 0, len(value)+4))
			if err == nil && len(cout) > 0 && len(cout) < len(value) {
				value = cout
				compressionType = uint16(recordValueCompressionBrotli)
			}
		}

		cfb := makeMaskingCipher(maskingKey, ownerPublic, selectorNames, timestamp, false)
		valueMasked := make([]byte, 2+len(value))
		binary.BigEndian.PutUint16(valueMasked[0:2], (crc16(value)&0xfffc)|compressionType)
		cfb.XORKeyStream(valueMasked[0:2], valueMasked[0:2])
		cfb.XORKeyStream(valueMasked[2:], value)
		rb.record.recordBody.Value = valueMasked
	}

	rb.record.recordBody.Owner = ownerPublic
	if len(links) > 0 {
		rb.record.recordBody.Links = make([]HashBlob, 0, len(links))
		for i := 0; i < len(links); i++ {
			rb.record.recordBody.Links = append(rb.record.recordBody.Links, links[i])
		}
		sort.Slice(rb.record.recordBody.Links, func(a, b int) bool {
			return bytes.Compare(rb.record.recordBody.Links[a][:], rb.record.recordBody.Links[b][:]) < 0
		})
	}
	rb.record.recordBody.Timestamp = timestamp
	rb.record.recordBody.PulseToken = pulseToken
	rb.record.recordBody.Type = recordType

	// Billable bytes equals the total serialized bytes of the record body plus the record's selectors' serialized sizes.
	rb.workBillableBytes = rb.record.recordBody.sizeBytes()

	// The work hash combines the record body hash with all the record's selectors. The final signing
	// hash is computed from this hash followed by the work itself (if any).
	workHasher := sha512.New384()

	recordBodyHash := rb.record.recordBody.signingHash()
	workHasher.Write(recordBodyHash[:])
	if len(selectorNames) > 0 {
		rb.record.Selectors = make([]Selector, len(selectorNames))
		for i := 0; i < len(selectorNames); i++ {
			rb.record.Selectors[i].set(selectorNames[i], selectorOrdinals[i], recordBodyHash[:])
			sb := rb.record.Selectors[i].Bytes()
			rb.workBillableBytes += uint(len(sb))
			workHasher.Write(sb)
		}
	}
	var workHashBuf [48]byte
	rb.workHash = workHasher.Sum(workHashBuf[:0])

	return nil
}

// AddWork actually computes the work and sets the Work field in the RecordBuilder.
// This doesn't need to be called if there is no work to be done, e.g. an auth signature only record.
// The minWorkFunctionDifficulty parameter can be used if you want to do extra work to altruistically
// add work to the DAG. Otherwise it should be zero.
func (rb *RecordBuilder) AddWork(workFunction *Wharrgarblr, minWorkFunctionDifficulty uint32) error {
	if workFunction != nil {
		diff := recordWharrgarblCost(rb.workBillableBytes)
		if diff < minWorkFunctionDifficulty {
			diff = minWorkFunctionDifficulty
		}
		w, iter := workFunction.Compute(rb.workHash, diff)
		if iter == 0 {
			return ErrWharrgarblFailed
		}
		rb.record.Work = w[:]
		rb.record.WorkAlgorithm = RecordWorkAlgorithmWharrgarbl
	}
	return nil
}

// Complete computes the signing hash, signs the record, and returns a pointer to completed record on success.
// It must be supplied with an Owner containing a full private key as well as public information.
func (rb *RecordBuilder) Complete(owner *Owner) (*Record, error) {
	signingHasher := sha512.New384()
	signingHasher.Write(rb.workHash)
	signingHasher.Write(rb.record.Work)
	signingHasher.Write([]byte{byte(rb.record.WorkAlgorithm)})
	var signingHash [48]byte
	signingHasher.Sum(signingHash[:0])
	var err error
	rb.record.Signature, err = owner.Sign(signingHash[:])
	if err != nil {
		return nil, err
	}
	return rb.record, nil
}

// NewRecord is a shortcut to running all incremental record creation functions.
func NewRecord(recordType int, value []byte, links [][32]byte, maskingKey []byte, selectorNames [][]byte, selectorOrdinals []uint64, timestamp uint64, workFunction *Wharrgarblr, owner *Owner) (*Record, error) {
	pulseToken, err := NewPulse(owner, selectorNames, selectorOrdinals, timestamp, 0)
	if err != nil {
		return nil, err
	}
	var rb RecordBuilder
	err = rb.Start(recordType, value, links, maskingKey, selectorNames, selectorOrdinals, owner.Public, pulseToken.Key(), timestamp)
	if err != nil {
		return nil, err
	}
	err = rb.AddWork(workFunction, 0)
	if err != nil {
		return nil, err
	}
	return rb.Complete(owner)
}
