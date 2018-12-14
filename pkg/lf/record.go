package lf

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

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

// Record meta-data field types (range 0-15)
const (
	RecordMetaDataTypeNone        = byte(0)
	RecordMetaDataTypeChangeOwner = byte(1)
	RecordMetaDataTypeSelector    = byte(2)
)

// Record flag bits
const (
	RecordFlagValueDeflated = uint64(0x1)
)

// RecordMaxLinkCount is the maximum number of links one record can have to previous records.
const RecordMaxLinkCount = 31

// RecordMaxValueSize is the maximum size of a value (protocol maximum: 2047)
const RecordMaxValueSize = 512

// RecordWharrgarblMemory is the memory size that should be used for Wharrgarbl PoW.
const RecordWharrgarblMemory = uint(1024 * 1024 * 512)

// RecordMinSize is the minimum possible size of a serialized record (real records will always be bigger but never smaller).
const RecordMinSize = 32 + // ID
	32 + // owner
	1 + // timestamp (min varint)
	1 + // TTL (min varint)
	1 + // flags (min varint)
	1 + // bit-packed algorithms
	2 + // bit-packed link count and value length
	1 // bit-packed meta-data types

// RecordMetaData is an optional record field
type RecordMetaData struct {
	Type  byte
	Value []byte
}

// Record is an entry in the LF key/value store. Many of its fields should be updated through methods, not directly.
type Record struct {
	Data                      []byte            // Binary serialized Record data for storage and transport
	Hash                      [32]byte          // Shandwich256(Packed), updated by Pack() or Unpack()
	PlainTextKey              []byte            // Record's plain text key or nil/empty if not known
	IDClaimPrivateKey         [64]byte          // Ed25519 private key derived from PlainTextKey (public is actually last 32 bytes)
	ID                        [32]byte          // Public key (or hash thereof) derived from the record's plain text key
	Owner                     [32]byte          // Public key (or hash thereof) of the record's owner
	Timestamp                 uint64            // Timestamp in SECONDS since epoch, also doubles as revision ID
	TTL                       uint64            // Time to live in SECONDS since epoch
	Flags                     uint64            // Flags setting various record attributes
	Value                     []byte            // Record data payload (encrypted if encryption algorithm is set)
	Links                     []byte            // Hashes of older records (size is always a multiple of 32 bytes)
	MetaData                  [2]RecordMetaData // Up to two optional fields
	Work                      []byte            // Work created by work algorithm
	IDClaimSignature          []byte            // Signature of record data by signing key derived from plain text record key
	OwnerSignature            []byte            // Signature of record by owner
	ValueEncryptionAlgorithm  byte              // Encryption algorithm for record data
	WorkAlgorithm             byte              // Work algorithm used to "pay" for record
	OwnerSignatureAlgorithm   byte              // Signature algorithm used to sign record by owner
	IDClaimSignatureAlgorithm byte              // Signature algorithm used to prove knowledge of plain text key
}

// RecordWharrgarblCost computes the cost in Wharrgarbl difficulty for a record whose total size is the supplied number of bytes.
func RecordWharrgarblCost(bytes int) uint32 {
	// This function was figured out by:
	//
	// (1) Sampling difficulty vs time.
	// (2) Using Microsoft Excel to fit the curve, yielding: d =~ 1.739*b^1.5605
	// (3) Figuring out an integer based equation that approximates this for our input range.
	//
	// It's an integer algorithm using a rounded integer square root to avoid FPU inconsistencies
	// across different systems. Any FPU inconsistencies could make nodes disagree about costs.
	b := uint64(bytes * 2) // this adjusts the overall magnitude without affecting the curve's shape
	c := (uint64(IntegerSqrtRounded(uint32(b))) * b * uint64(3)) - (b * 8)
	if c > 0xffffffff { // sanity check, no record gets this big
		return 0xffffffff
	}
	return uint32(c)
}

// packMainSection serializes into the supplied buffer up to the point where the record's contents are hashed for proof of work, signatures, etc.
func (r *Record) packMainSection(b *bytes.Buffer) error {
	if len(r.Value) > RecordMaxValueSize {
		return errors.New("record value too large")
	}
	b.Write(r.ID[:])
	b.Write(r.Owner[:])
	writeUVarint(b, r.Timestamp)
	writeUVarint(b, r.TTL)
	writeUVarint(b, r.Flags)
	if ((r.ValueEncryptionAlgorithm | r.WorkAlgorithm | r.OwnerSignatureAlgorithm | r.IDClaimSignatureAlgorithm) & 0xfc) != 0 {
		return errors.New("at least one algorithm type field is out of range (range: 2 bits, 0-3)")
	}
	b.WriteByte((r.ValueEncryptionAlgorithm << 6) | (r.WorkAlgorithm << 4) | (r.OwnerSignatureAlgorithm << 2) | r.IDClaimSignatureAlgorithm)
	linkCount := len(r.Links) / 32
	if (linkCount * 32) != len(r.Links) {
		return errors.New("size of Links must be a multiple of 32")
	}
	if linkCount > RecordMaxLinkCount {
		return errors.New("too many links")
	}
	linkCountAndValueSize := (linkCount << 11) | (len(r.Value) & 0x7ff)
	b.WriteByte(byte(linkCountAndValueSize>>8) & 0xff)
	b.WriteByte(byte(linkCountAndValueSize & 0xff))
	b.WriteByte(((r.MetaData[0].Type & 0xf) << 4) | (r.MetaData[1].Type & 0xf))
	b.Write(r.Value)
	b.Write(r.Links)
	for i := 0; i < 2; i++ {
		if r.MetaData[i].Type != RecordMetaDataTypeNone {
			if r.MetaData[i].Type == RecordMetaDataTypeChangeOwner || r.MetaData[i].Type == RecordMetaDataTypeSelector {
				if len(r.MetaData[i].Value) == 32 {
					b.WriteByte(32) // technically a varint but 32 can be written as a single byte
					b.Write(r.MetaData[i].Value)
				} else {
					return errors.New("meta-data value length invalid for meta-data type")
				}
			} else {
				return errors.New("unrecognized meta-data type")
			}
		}
	}
	return nil
}

// SetPlainTextKey sets the PlainTextKey, IDClaimPrivateKey, ID, and IDClaimSignatureAlgorithm fields from a plain text record key.
// The ID field is the public key derived from a key pair generated deterministically from the plain
// text key. It's used to sign records to prove knowledge of the (secret) plain text key to prevent
// forgery pollution attacks.
func (r *Record) SetPlainTextKey(key []byte) {
	r.PlainTextKey = make([]byte, len(key))
	copy(r.PlainTextKey, key)
	s512 := sha512.Sum512(key)
	priv := ed25519.NewKeyFromSeed(s512[0:32])
	copy(r.IDClaimPrivateKey[:], priv)
	copy(r.ID[:], priv[32:64])
	r.IDClaimSignatureAlgorithm = RecordSignatureAlgorithmEd25519
}

// SetValue sets this record's Value field to a copy of the supplied value.
// If encrypt is true PlainTextKey must be set and will be used to perform identity-based encryption
// of the value. Value encryption is the default in LF and makes values secret unless their
// corresponding plain text key is known. An attempt will be made to compress the value as well and
// if this results in a size reduction the RecordFlagValueDeflated flag will be set and the value
// will be compressed.
func (r *Record) SetValue(value []byte, encrypt bool) error {
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
		return errors.New("record value is too large even after compression")
	}

	r.Value = make([]byte, len(v))
	if encrypt {
		if len(r.PlainTextKey) == 0 {
			return errors.New("cannot encrypt value without plain text key")
		}
		var iv [16]byte
		binary.BigEndian.PutUint64(iv[0:8], r.Timestamp)
		copy(iv[8:16], r.Owner[0:8]) // every owner+timestamp combo is unique since timestamp is also revision, thus unique IV
		s512 := sha512.Sum512(r.PlainTextKey)
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

// NewRecord is a shortcut to configure, add proof of work, and seal a record. The only external
// ingredient needed from a node is enough links. The timestamp (ts) and TTL are in seconds, not
// milliseconds. The owner private key must be a 64-byte ed25519 private key since this is currently
// the only signature algorithm supported.
func NewRecord(key, value, links []byte, ts, ttl uint64, encryptValue bool, ownerPrivateKey []byte) (*Record, error) {
	var r Record

	if len(ownerPrivateKey) != 64 {
		return nil, errors.New("invalid ed25519 owner private key")
	}
	r.SetPlainTextKey(key)
	copy(r.Owner[:], ownerPrivateKey[32:64])
	r.Timestamp = ts
	r.TTL = ttl
	err := r.SetValue(value, encryptValue)
	if err != nil {
		return nil, err
	}

	workHash, cost, err := r.WorkHash()
	if err != nil {
		return nil, err
	}
	work, workIterations := Wharrgarbl(workHash[:], cost, RecordWharrgarblMemory)
	if workIterations == 0 {
		return nil, errors.New("unknown error computing proof of work (0 returned for iterations)")
	}

	err = r.Seal(work[:], ownerPrivateKey)
	if err != nil {
		return nil, err
	}

	return &r, nil
}

// GetValue retrieves the plain text value from this record, decompressing and/or decrypting as needed.
func (r *Record) GetValue(plainTextKey []byte) ([]byte, error) {
	var dec []byte
	if r.ValueEncryptionAlgorithm == RecordValueEncryptionAlgorithmNone {
		dec = r.Value
	} else if r.ValueEncryptionAlgorithm == RecordValueEncryptionAlgorithmAES256CFB {
		ptk := r.PlainTextKey
		if len(plainTextKey) > 0 {
			ptk = plainTextKey
		} else {
			if !bytes.Equal(r.IDClaimPrivateKey[32:64], r.ID[0:32]) {
				return nil, errors.New("no plain text key supplied or set in the record, cannot unmask value")
			}
		}

		var iv [16]byte
		binary.BigEndian.PutUint32(iv[0:4], uint32(r.Timestamp))
		copy(iv[4:16], r.Owner[0:12])
		s512 := sha512.Sum512(ptk)

		c, _ := aes.NewCipher(s512[32:64])
		cfb := cipher.NewCFBDecrypter(c, iv[:])
		dec = make([]byte, len(r.Value))
		cfb.XORKeyStream(dec, r.Value)
	} else {
		return nil, errors.New("unrecognized value encryption algorithm")
	}

	if (r.Flags & RecordFlagValueDeflated) != 0 {
		inf := flate.NewReader(bytes.NewReader(dec))
		var infb bytes.Buffer
		_, err := io.Copy(&infb, inf)
		if err != nil {
			return nil, err
		}
		return infb.Bytes(), nil
	}
	return dec, nil
}

// Unpack deserializes a packed record and fills the record's fields.
// If data is nil/empty, the record's Data field is used. If data is not nil it is used and
// the record's Data field is set to a copy of the supplied slice. If validate is true signatures
// and proof of work will be checked for validity.
func (r *Record) Unpack(data []byte, validate bool) (err error) {
	defer func() {
		e := recover()
		if e != nil {
			err = fmt.Errorf("trapped unexpected error: %s", e)
		}
	}()

	if len(data) == 0 {
		data = r.Data
	} else {
		r.Data = make([]byte, len(data))
		copy(r.Data, data)
	}
	r.Hash = Shandwich256(r.Data)

	if len(r.Data) < RecordMinSize {
		return errors.New("record too small")
	}
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
	//b.WriteByte((r.ValueEncryptionAlgorithm << 6) | (r.WorkAlgorithm << 4) | (r.IDClaimSignatureAlgorithm << 2) | r.OwnerSignatureAlgorithm)
	tmp, err := dr.ReadByte()
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
	linkCountAndValueSize := uint(tmp) << 8
	tmp, err = dr.ReadByte()
	if err != nil {
		return
	}
	linkCountAndValueSize |= uint(tmp)
	linkCount := (linkCountAndValueSize >> 11) & 31
	valueSize := linkCountAndValueSize & 0x7ff
	if valueSize > RecordMaxValueSize {
		return errors.New("record value too large")
	}
	tmp, err = dr.ReadByte()
	if err != nil {
		return
	}
	r.MetaData[0].Type = (tmp >> 4) & 0xf
	r.MetaData[1].Type = tmp & 0xf

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

	for i := 0; i < 2; i++ {
		if r.MetaData[i].Type != RecordMetaDataTypeNone {
			var mdl uint64
			mdl, err = binary.ReadUvarint(dr)
			if err != nil {
				return
			}
			if (mdl > uint64(len(data))) || ((r.MetaData[i].Type == RecordMetaDataTypeChangeOwner || r.MetaData[i].Type == RecordMetaDataTypeSelector) && (mdl != 32)) {
				return errors.New("meta-data size invalid")
			}
			r.MetaData[i].Value = make([]byte, uint(mdl))
			_, err = io.ReadFull(dr, r.MetaData[i].Value)
			if err != nil {
				return
			}
		}
	}

	switch r.WorkAlgorithm {
	case RecordWorkAlgorithmNone:
	case RecordWorkAlgorithmWharrgarbl:
		r.Work = make([]byte, WharrgarblProofOfWorkSize)
		_, err = io.ReadFull(dr, r.Work)
		if err != nil {
			return
		}
	default:
		return errors.New("unrecognized work type")
	}

	switch r.OwnerSignatureAlgorithm {
	case RecordSignatureAlgorithmEd25519:
		r.OwnerSignature = make([]byte, 64)
		_, err = io.ReadFull(dr, r.Work)
		if err != nil {
			return
		}
	default:
		return errors.New("unrecognized signature type")
	}

	switch r.IDClaimSignatureAlgorithm {
	case RecordSignatureAlgorithmEd25519:
		r.IDClaimSignature = make([]byte, 64)
		_, err = io.ReadFull(dr, r.Work)
		if err != nil {
			return
		}
	default:
		return errors.New("unrecognized signature type")
	}

	// Check whether plain text key in Record (if present) matches record's ID and null out if not.
	if !bytes.Equal(r.IDClaimPrivateKey[32:64], r.ID[0:32]) {
		r.PlainTextKey = nil
	}

	return nil
}

// WorkHash serializes (without modifying Data) this record up to the point where it should receive proof of work, then returns SHA512(partially serialized record).
// This also computes and returns the work requirement for the Wharrgarbl proof of work function, currently the only one.
func (r *Record) WorkHash() (h [64]byte, wharrgarblCost uint32, err error) {
	b := bytes.NewBuffer(make([]byte, 0, 512))
	err = r.packMainSection(b)
	bb := b.Bytes()
	wharrgarblCost = RecordWharrgarblCost(len(bb))
	h = sha512.Sum512(bb)
	return
}

// Seal completes a record by adding work, signing it with the ID claim key, and then signing it with the owner key.
// It sets the Data and Hash fields to the result of final record serialization and signing. Note that the ID claim private
// key must be set, so SetPlainTextKey must be called before this.
func (r *Record) Seal(work []byte, ownerPrivateKey []byte) error {
	if r.WorkAlgorithm == RecordWorkAlgorithmWharrgarbl && len(work) != WharrgarblProofOfWorkSize {
		return errors.New("work size is not valid")
	}
	if !bytes.Equal(r.IDClaimPrivateKey[32:64], r.ID[0:32]) {
		return errors.New("ID claim private key is not initialized, call SetPlainTextKey before Seal")
	}
	if r.OwnerSignatureAlgorithm == RecordSignatureAlgorithmEd25519 && len(ownerPrivateKey) != 64 {
		return errors.New("invalid owner private key")
	}

	b := bytes.NewBuffer(make([]byte, 0, 512))
	err := r.packMainSection(b)
	if err != nil {
		return err
	}

	workHash := sha512.Sum512(b.Bytes())
	b.Write(work)
	r.Work = make([]byte, len(work))
	copy(r.Work, work)

	// Signing hash is the hash of the work hash and the work. This makes it easy to both generate work
	// and sign a record remotely. A remote only needs to know the work hash and it can do PoW, append
	// it, hash again, then sign with the owner key.
	sigHash := sha512.Sum512(append(workHash[:], work...))
	r.OwnerSignature = ed25519.Sign(ownerPrivateKey, sigHash[:])
	b.Write(r.OwnerSignature)

	// Finally the record is signed by the ID claim key, proving that the plain text key is known.
	r.IDClaimSignature = ed25519.Sign(r.IDClaimPrivateKey[:], b.Bytes())
	b.Write(r.IDClaimSignature)

	r.Data = b.Bytes()
	r.Hash = Shandwich256(r.Data)
	return nil
}
