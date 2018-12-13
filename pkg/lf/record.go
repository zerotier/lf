package lf

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/binary"
	"errors"
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

// Record signature algorithm IDs (range 0-3)
const (
	RecordSignatureAlgorithmNone    = byte(0)
	RecordSignatureAlgorithmEd25519 = byte(1)
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
	IDClaimSignatureAlgorithm byte              // Signature algorithm used to prove knowledge of plain text key
	OwnerSignatureAlgorithm   byte              // Signature algorithm used to sign record by owner
}

// RecordWharrgarblCost computes the cost in Wharrgarbl difficulty for a record whose total size is the supplied number of bytes.
func RecordWharrgarblCost(bytes int) uint32 {
	// This function was figured out by:
	//
	// (1) Using the -W option to model difficulty for a target time appreciation curve.
	// (2) Using Microsoft Excel to fit the curve, yielding: d =~ 1.739*b^1.5605
	// (3) Figuring out an integer based equation that approximates this for our input range.
	//
	// It's an integer algorithm using a rounded integer square root to avoid FPU inconsistencies
	// across different systems. Any FPU inconsistencies could make nodes disagree about costs.
	if bytes <= 64 {
		return 1024 // minimum work
	}
	c := (uint64(IntegerSqrtRounded(uint32(bytes))) * uint64(bytes) * uint64(3)) - uint64(bytes*8)
	if c > 0xffffffff {
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
	if ((r.ValueEncryptionAlgorithm | r.WorkAlgorithm | r.IDClaimSignatureAlgorithm | r.OwnerSignatureAlgorithm) & 0xfc) != 0 {
		return errors.New("at least one algorithm type field is out of range (range: 2 bits, 0-3)")
	}
	b.WriteByte((r.ValueEncryptionAlgorithm << 6) | (r.WorkAlgorithm << 4) | (r.IDClaimSignatureAlgorithm << 2) | r.OwnerSignatureAlgorithm)
	linkCount := len(r.Links) / 32
	if (linkCount * 32) != len(r.Links) {
		return errors.New("size of Links must be a multiple of 32")
	}
	if linkCount > RecordMaxLinkCount {
		return errors.New("too many links")
	}
	linkCountAndValueSize := (linkCount << 11) | len(r.Value)
	b.WriteByte(byte(linkCountAndValueSize>>8) & 0xff)
	b.WriteByte(byte(linkCountAndValueSize & 0xff))
	b.WriteByte(((r.MetaData[0].Type & 15) << 4) | (r.MetaData[1].Type & 15))
	b.Write(r.Value)
	b.Write(r.Links)
	for i := 0; i < 2; i++ {
		if r.MetaData[i].Type != RecordMetaDataTypeNone {
			b.Write(r.MetaData[i].Value)
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
	var v []byte
	var cb bytes.Buffer
	cw, err := flate.NewWriter(&cb, flate.BestCompression)
	if err == nil {
		_, err = cw.Write(value)
		if err == nil {
			cw.Close()
			if cb.Len() < len(value) {
				v = cb.Bytes()
				r.Flags |= RecordFlagValueDeflated
			} else {
				v = value
			}
		} else {
			v = value
		}
	} else {
		v = value
	}
	if len(v) > RecordMaxValueSize {
		return errors.New("record value is too large even after compression")
	}
	r.Value = make([]byte, len(v))
	if encrypt && len(r.PlainTextKey) > 0 {
		var iv [16]byte
		binary.BigEndian.PutUint32(iv[0:4], uint32(r.Timestamp))
		copy(iv[4:16], r.Owner[0:12])
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
// the record's Data field is set to a copy of the supplied slice.
func (r *Record) Unpack(data []byte) error {
	if len(data) == 0 {
		data = r.Data
	} else {
		r.Data = make([]byte, len(data))
		copy(r.Data, data)
	}
	r.Hash = Shandwich256(r.Data)

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

	b := bytes.NewBuffer(make([]byte, 0, 512))
	err := r.packMainSection(b)
	if err != nil {
		return err
	}

	workHash := sha512.Sum512(b.Bytes())
	b.Write(work)

	// Signing hash is the hash of the work hash and the work. This makes it easy to both generate work
	// and sign a record remotely. A remote only needs to know the work hash and it can do PoW, append
	// it, hash again, then sign with the owner key.
	sigHash := sha512.Sum512(append(workHash[:], work...))

	sig := ed25519.Sign(r.IDClaimPrivateKey[:], sigHash[:])
	b.Write(sig)

	if r.OwnerSignatureAlgorithm == RecordSignatureAlgorithmEd25519 && len(ownerPrivateKey) != 64 {
		return errors.New("invalid owner private key")
	}
	sig = ed25519.Sign(ownerPrivateKey, sigHash[:])
	b.Write(sig)

	r.Data = b.Bytes()
	r.Hash = Shandwich256(r.Data)
	return nil
}
