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
	"crypto/ecdsa"
	"crypto/elliptic"
	secrand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"io"
)

var (
	b1_0 = []byte{0x00}
	b1_1 = []byte{0x01}

	recordValueMaskKeyHashNonce = []byte("LFKeyForValueMaskingEncryption")
)

// RecordMaxFieldSize is a sanity limit for record field sizes used in deserialization.
// Real records never get this big, but this prevents a malformed record from causing an out
// of memory error.
const RecordMaxFieldSize = 65536

// RecordHashSize is the number of bytes in a record hash (Shandwich256).
const RecordHashSize = 32

// Note that maximum value for any of the algorithm IDs should be capped at 15, which is
// far more than we ought to ever need.

// RecordValueEncryptionAlgorithmNone indicates that the value is not masked.
const RecordValueEncryptionAlgorithmNone = byte(0)

// RecordValueEncryptionAlgorithmAES256CFB indicates AES256-CFB masking encryption for value.
const RecordValueEncryptionAlgorithmAES256CFB = byte(1)

// RecordSelectorAlgorithmS112 is the 64-bit suffix sortable selector algorithm with SecP112 claim signatures.
const RecordSelectorAlgorithmS112 = byte(1)

// RecordWorkAlgorithmNone indicates no work algorithm (not allowed on main network).
const RecordWorkAlgorithmNone = byte(0)

// RecordWorkAlgorithmWharrgarbl indicates the Wharrgarbl momentum-like proof of work algorithm.
const RecordWorkAlgorithmWharrgarbl = byte(1)

// RecordDesiredLinks is the number of links records should have.
const RecordDesiredLinks = 3

// RecordOwnerTypeP384 is a NIST P-384 point compressed public key.
const RecordOwnerTypeP384 = byte(1)

// RecordWharrgarblMemory is the memory size that should be used for Wharrgarbl PoW.
// This is large enough to perform well up to relatively big record sizes. It'll still work for
// really huge ones of course, but performance starts to drop a bit. It can be increased and could
// be made configurable in the future if ever needed.
const RecordWharrgarblMemory = uint(1024 * 1024 * 256) // 256mb

// RecordBody represents the main body of a record including its value, owner public keys, etc.
type RecordBody struct {
	Value                    []byte // Value (may be encrypted and/or compressed, use Open() to get plain text value)
	Owner                    []byte // Owner of this record
	Links                    []byte // Links to previous records' hashes (size is a multiple of 32 bytes, link count is size / 32)
	Timestamp                uint64 // Timestamp (and revision ID) in SECONDS since Unix epoch
	ValueEncryptionAlgorithm byte   // Encryption algorithm used to mask value
	ValueCompression         bool   // If true, value is deflate compressed.
}

// ReadFrom deserializes this record body from a reader.
func (rb *RecordBody) ReadFrom(r io.Reader) error {
	rr := byteAndArrayReader{r}

	hdrb, err := rr.ReadByte()
	if err != nil {
		return err
	}

	l, err := binary.ReadUvarint(&rr)
	if err != nil {
		return err
	}
	if l > RecordMaxFieldSize {
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
	if l > RecordMaxFieldSize {
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
	if l > RecordMaxFieldSize {
		return ErrorRecordInvalid
	}
	rb.Links = make([]byte, uint(l))
	_, err = io.ReadFull(&rr, rb.Links)

	rb.Timestamp, err = binary.ReadUvarint(&rr)
	if err != nil {
		return err
	}

	rb.ValueEncryptionAlgorithm = hdrb & 0xf
	rb.ValueCompression = (hdrb & 0x10) != 0

	return nil
}

// WriteTo writes this record body in serialized form to the given writer.
func (rb *RecordBody) WriteTo(w io.Writer) error {
	hdrb := rb.ValueEncryptionAlgorithm // 4-bit algorithm field
	if rb.ValueCompression {
		hdrb |= 0x10 // compression flag
	}
	if _, err := w.Write([]byte{hdrb}); err != nil {
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

// Bytes returns a compact byte array serialized RecordBody.
func (rb *RecordBody) Bytes() []byte {
	var buf bytes.Buffer
	rb.WriteTo(&buf)
	return buf.Bytes()
}

// SizeBytes returns the size of the result of Bytes().
func (rb *RecordBody) SizeBytes() uint {
	var wc CountingWriter
	rb.WriteTo(&wc)
	return uint(wc)
}

// SigningHash computes a hash for use in record signing.
// This does something a bit different from just hashing Bytes(). This is because we want
// to hash a hash of the value rather than the literal value. This would allow nodes in the
// future to potentially forget the content of very old records but preserve enough of their
// meta-data to allow signature verification.
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
	if rb.ValueCompression {
		h.Write(b1_1)
	} else {
		h.Write(b1_0)
	}
	h.Write([]byte{rb.ValueEncryptionAlgorithm})
	h.Write(b1_0)
	var s512buf [64]byte
	return Shandwich256FromSha512(h.Sum(s512buf[:]))
}

// RecordSelector is a hashed plain text key that doubles as a public key and an associated proof of knowledge signature.
type RecordSelector struct {
	Selector  []byte // Public masked identifier derived from plain text key
	Claim     []byte // Signature of message with public key embedded in selector or other proof of knowledge of plain text key
	Algorithm byte   // Algorithm used for claim signature
}

// ReadFrom reads this record selector from the provided reader.
func (rs *RecordSelector) ReadFrom(r io.Reader) error {
	var alg [1]byte
	if _, err := io.ReadFull(r, alg[:]); err != nil {
		return err
	}
	if alg[0] != RecordSelectorAlgorithmS112 {
		return ErrorRecordUnsupportedAlgorithm
	}
	buf := make([]byte, 32+ECCCurveSecP112R1SignatureSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	rs.Selector = buf[0:32]
	rs.Claim = buf[32:]
	rs.Algorithm = RecordSelectorAlgorithmS112
	return nil
}

// WriteTo writes this RecordSelector in serialized form to the supplied writer.
func (rs *RecordSelector) WriteTo(w io.Writer) error {
	if _, err := w.Write([]byte{rs.Algorithm}); err != nil { // algorithm implies size of selector and claim
		return err
	}
	if _, err := w.Write(rs.Selector); err != nil {
		return err
	}
	if _, err := w.Write(rs.Claim); err != nil {
		return err
	}
	return nil
}

// Bytes returns a byte serialized selector.
func (rs *RecordSelector) Bytes() []byte {
	var buf bytes.Buffer
	rs.WriteTo(&buf)
	return buf.Bytes()
}

// SizeBytes returns how large the result of Bytes() would be.
func (rs *RecordSelector) SizeBytes() uint {
	return uint(len(rs.Selector) + len(rs.Claim) + 1)
}

// VerifyHash verifies a hash with this selector's public key component to prove the creator's knowledge of the plain text key.
func (rs *RecordSelector) VerifyHash(hash []byte) bool {
	if len(rs.Selector) != 32 {
		return false
	}
	pk, err := ECCDecompressPublicKey(&ECCCurveSecP112R1, rs.Selector[17:])
	if pk == nil || err != nil {
		return false
	}
	return ECDSAVerify(pk, hash, rs.Claim)
}

// Record contains all the elements of a complete (unmarshaled) record.
type Record struct {
	Body          RecordBody       // Main record body
	Selectors     []RecordSelector // Record selectors with claim signatures computed against body's signing hash
	Work          []byte           // Proof of work computed on sha256(Body Signing Hash | Selectors) with work cost based on size of body and selectors
	WorkAlgorithm byte             // Proof of work algorithm
	Signature     []byte           // Signature of sha256(sha256(Body Signing Hash | Selectors) | Work | WorkAlgorithm)
}

// ReadFrom deserializes this record from a reader.
func (r *Record) ReadFrom(rdr io.Reader) error {
	rr := byteAndArrayReader{rdr}

	hdrb, err := rr.ReadByte()
	if err != nil {
		return err
	}
	if hdrb != 0 {
		return ErrorRecordInvalid
	}

	if err = r.Body.ReadFrom(&rr); err != nil {
		return err
	}

	selCount, err := binary.ReadUvarint(rr)
	if err != nil {
		return err
	}
	if selCount > (RecordMaxFieldSize / 64) {
		return ErrorRecordInvalid
	}
	r.Selectors = make([]RecordSelector, uint(selCount))
	for i := 0; i < len(r.Selectors); i++ {
		err = r.Selectors[i].ReadFrom(rr)
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
	if siglen > RecordMaxFieldSize {
		return ErrorRecordInvalid
	}
	r.Signature = make([]byte, uint(siglen))
	if _, err = io.ReadFull(&rr, r.Signature); err != nil {
		return err
	}

	return nil
}

// WriteTo writes this record in serialized form to the supplied writer.
func (r *Record) WriteTo(w io.Writer) error {
	// Record begins with a reserved version/type byte, currently 0
	if _, err := w.Write(b1_0); err != nil {
		return err
	}

	if err := r.Body.WriteTo(w); err != nil {
		return err
	}

	if _, err := writeUVarint(w, uint64(len(r.Selectors))); err != nil {
		return err
	}
	for i := 0; i < len(r.Selectors); i++ {
		if err := r.Selectors[i].WriteTo(w); err != nil {
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
func (r *Record) Bytes() []byte {
	var buf bytes.Buffer
	r.WriteTo(&buf)
	return buf.Bytes()
}

// SizeBytes returns the serialized size of this record.
func (r *Record) SizeBytes() uint {
	var cr CountingWriter
	r.WriteTo(&cr)
	return uint(cr)
}

// sha512csprng is a Reader that acts as a random source for generating ECDSA key pairs from repeated hashing of a seed.
type sha512csprng struct {
	s512 [64]byte
	n    int
}

func (prng sha512csprng) Read(b []byte) (int, error) {
	for i := 0; i < len(b); i++ {
		b[i] = prng.s512[prng.n]
		prng.n++
		if prng.n == 64 {
			prng.s512 = sha512.Sum512(prng.s512[:])
			prng.n = 0
		}
	}
	return len(b), nil
}

// RecordDeriveSelector deterministically generates a selector from a plain text selector key.
// The current algorithm creates a 32 byte selector from a sha256 hash of the first (len-8) bytes of
// the plain text key, adds the last 8 bytes as a big-endian 64-bit integer to the first 9 bytes of
// the hash to make it range queryable by plain text key, and then overwrites the last 15 bytes of the hash
// with a small 112-bit prime field elliptic curve public key derived from a sha512 hash of the plain
// text key. This small key can then be used to generate small claim signatures to defend against the
// naive key collision attack. The sortability part of the algorithm is skipped for plain text keys
// shorter than 16 bytes. Those are just sha256 hashed and then combined with a public key.
func RecordDeriveSelector(plainTextKey []byte) (selector []byte, privateKey *ecdsa.PrivateKey) {
	var sel [32]byte
	if len(plainTextKey) >= 16 {
		sel = sha256.Sum256(plainTextKey[0 : len(plainTextKey)-8])
		if sel[0] == 0xff {
			sel[0] = 0 // preserve proper sort order if 64-bit addition wraps and we have to carry into the lowest byte
		}
		orderingPrefix := binary.BigEndian.Uint64(sel[1:9])
		originalOrderingPrefix := orderingPrefix
		orderingPrefix += binary.BigEndian.Uint64(plainTextKey[len(plainTextKey)-8:])
		if orderingPrefix < originalOrderingPrefix {
			sel[0]++
		}
		binary.BigEndian.PutUint64(sel[1:9], orderingPrefix)
	} else {
		sel = sha256.Sum256(plainTextKey)
	}

	var err error
	rng := sha512csprng{s512: sha512.Sum512(plainTextKey), n: 0}
	privateKey, err = ecdsa.GenerateKey(&ECCCurveSecP112R1, &rng)
	if err != nil {
		panic(err)
	}
	cpub, err := ECCCompressPublicKey(&(privateKey.PublicKey))
	if err != nil {
		panic(err)
	}
	sel[17] &= 0xfe
	sel[17] |= (cpub[0] - 2) // use only one bit for compressed public key even/odd parity
	copy(sel[18:], cpub[1:15])

	selector = sel[:]
	return
}

// RecordWharrgarblCost computes the cost in Wharrgarbl difficulty for a record of a given number of "billable" bytes.
func RecordWharrgarblCost(bytes uint) uint32 {
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

// NewRecordOwner creates a new record owner, returning its packed public key and fully expanded private key.
// The packed public key is packed using ECCCompressPublicKeyWithID to embed an algorithm ID to support
// different curves or entirely different algorithms in the future.
func NewRecordOwner() ([]byte, *ecdsa.PrivateKey) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), secrand.Reader)
	if err != nil {
		panic(err)
	}
	pub, err := ECCCompressPublicKeyWithID(&priv.PublicKey, RecordOwnerTypeP384)
	if err != nil {
		panic(err)
	}
	return pub, priv
}

// NewRecordStart creates an incomplete record with its body and selectors filled out but no work or final signature.
// This can be used to do the first step of a three-phase record creation process with the next two phases being NewRecordAddWork
// and NewRecordComplete. This is useful of record creation needs to be split among systems or participants.
func NewRecordStart(value []byte, links [][]byte, plainTextSelectors [][]byte, maskValue bool, owner []byte, ts uint64) (r *Record, workHash [32]byte, workBillableBytes uint, err error) {
	r = new(Record)

	if len(value) > 0 {
		if len(value) > 128 {
			var dbuf bytes.Buffer
			def, err := flate.NewWriter(&dbuf, flate.BestCompression)
			if err != nil {
				panic(err)
			}
			def.Write(value)
			def.Close()
			if dbuf.Len() < len(value) {
				value = dbuf.Bytes()
				r.Body.ValueCompression = true
			}
		}

		if maskValue {
			if len(plainTextSelectors) == 0 {
				err = ErrorInvalidParameter
			}

			var kbuf [32]byte
			kh := sha256.New()
			kh.Write(recordValueMaskKeyHashNonce)
			kh.Write(plainTextSelectors[0])
			key := kh.Sum(kbuf[:0])

			var iv [16]byte
			binary.BigEndian.PutUint64(iv[0:8], ts)
			if len(owner) >= 8 {
				copy(iv[8:16], owner[len(owner)-8:])
			}

			c, _ := aes.NewCipher(key[:])
			cfb := cipher.NewCFBEncrypter(c, iv[:])
			r.Body.Value = make([]byte, len(value))
			cfb.XORKeyStream(r.Body.Value, value)

			r.Body.ValueEncryptionAlgorithm = RecordValueEncryptionAlgorithmAES256CFB
		} else {
			r.Body.Value = append(r.Body.Value, value...)
			r.Body.ValueEncryptionAlgorithm = RecordValueEncryptionAlgorithmNone
		}
	}

	r.Body.Owner = append(r.Body.Owner, owner...)

	if len(links) > 0 {
		r.Body.Links = make([]byte, 0, 32*len(links))
		for i := 0; i < len(links); i++ {
			r.Body.Links = append(r.Body.Links, links[i]...)
		}
	}

	r.Body.Timestamp = ts

	signingHash := r.Body.SigningHash()
	workBillableBytes = r.Body.SizeBytes()
	workHashBytes := make([]byte, 0, 1024)
	workHashBytes = append(workHashBytes, signingHash[:]...)

	if len(plainTextSelectors) > 0 {
		r.Selectors = make([]RecordSelector, len(plainTextSelectors))
		for i := 0; i < len(plainTextSelectors); i++ {
			var pk *ecdsa.PrivateKey
			r.Selectors[i].Selector, pk = RecordDeriveSelector(plainTextSelectors[i])
			r.Selectors[i].Claim, err = ECDSASign(pk, signingHash[:])
			if err != nil {
				panic(err)
			}
			r.Selectors[i].Algorithm = RecordSelectorAlgorithmS112
			sb := r.Selectors[i].Bytes()
			workBillableBytes += uint(len(sb))
			workHashBytes = append(workHashBytes, sb...)
		}
	}

	workHash = sha256.Sum256(workHashBytes)

	return
}

// NewRecordDoWork is a convenience method for doing the work to add to a record.
// This can obviously be a time and memory intensive function.
func NewRecordDoWork(workHash []byte, workBillableBytes uint) (work []byte, workAlgorithm byte, err error) {
	w, iter := Wharrgarbl(workHash, RecordWharrgarblCost(workBillableBytes), RecordWharrgarblMemory)
	if iter == 0 {
		err = ErrorWharrgarblFailed
		return
	}
	work = w[:]
	workAlgorithm = RecordWorkAlgorithmWharrgarbl
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
	r.Signature, err = ECDSASign(ownerPrivate, signingHash)
	return
}

// NewRecord is a shortcut to running all incremental record creation functions.
// Obviously this is time and memory intensive due to proof of work required to "pay" for this record.
func NewRecord(value []byte, links [][]byte, plainTextSelectors [][]byte, maskValue bool, owner []byte, ts uint64, ownerPrivate *ecdsa.PrivateKey) (r *Record, err error) {
	var wh, sh [32]byte
	var wb uint
	r, wh, wb, err = NewRecordStart(value, links, plainTextSelectors, maskValue, owner, ts)
	if err != nil {
		return
	}
	w, wa, err := NewRecordDoWork(wh[:], wb)
	if err != nil {
		return
	}
	r, sh, err = NewRecordAddWork(r, wh[:], w, wa)
	if err != nil {
		return
	}
	r, err = NewRecordComplete(r, sh[:], ownerPrivate)
	return
}
