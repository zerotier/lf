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

// Record is an entry in the LF key/value store. Many of its fields should be updated through methods, not directly.
// The Data field contains raw record data. The other fields are filled in when records are created or by Unpack
// and exist for more convenient access.
type Record struct {
	// Hidden fields memo-izing private keys and such
	plainTextKey      []byte    // Record's plain text key or nil/empty if not known
	idClaimPrivateKey [64]byte  // Ed25519 private key derived from PlainTextKey (public is actually last 32 bytes)
	selPrivateKeys    [2][]byte // Ed25519 private keys for selectors

	// Exported fields for use by outside code or sending via the API.
	Data                      []byte    `msgpack:"D"`                      // Binary serialized raw Record data for storage and transport
	Hash                      [32]byte  `msgpack:"H"`                      // Shandwich256(Data)
	ID                        [32]byte  `msgpack:"ID"`                     // Public key (or hash thereof) derived from the record's plain text key
	Owner                     [32]byte  `msgpack:"O"`                      // Public key (or hash thereof) of the record's owner
	SelectorIDs               [2][]byte `msgpack:"SIDs" json:",omitempty"` // Sel0 ID, Sel1 ID (if present)
	Timestamp                 uint64    `msgpack:"T"`                      // Timestamp in SECONDS since epoch, also doubles as revision ID
	TTL                       uint64    `msgpack:"TTL"`                    // Time to live in SECONDS since epoch
	Flags                     uint64    `msgpack:"F"`                      // Flags setting various record attributes
	Value                     []byte    `msgpack:"V"`                      // Record data payload (encrypted if encryption algorithm is non-zero)
	Links                     []byte    `msgpack:"L" json:",omitempty"`    // Hashes of older records (size is always a multiple of 32 bytes)
	ChangeOwner               []byte    `msgpack:"CO" json:",omitempty"`   // New owner to inherit previous owner's record set weights, if present
	Work                      []byte    `msgpack:"W" json:",omitempty"`    // Work created by work algorithm
	OwnerSignature            []byte    `msgpack:"OS"`                     // Signature of record by owner
	IDClaimSignature          []byte    `msgpack:"IDCS"`                   // Signature of record data by signing key derived from plain text record key
	SelectorSignatures        [2][]byte `msgpack:"SS" json:",omitempty"`   // Proof of knowledge signatures for selectors, if present
	SigningHash               [64]byte  `msgpack:"SH"`                     // Signing hash to make signature verification easy
	ValueEncryptionAlgorithm  byte      `msgpack:"VEA"`                    // Encryption algorithm for record data
	WorkAlgorithm             byte      `msgpack:"WA"`                     // Work algorithm used to "pay" for record
	OwnerSignatureAlgorithm   byte      `msgpack:"OSA"`                    // Signature algorithm used to sign record by owner
	IDClaimSignatureAlgorithm byte      `msgpack:"IDCSA"`                  // Signature algorithm used to prove knowledge of plain text key (and selectors)
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

	b.Write(r.Value)
	b.Write(r.Links)

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
				return errors.New("only two meta-data slots are available, allowing two selectors or one change in owner and one selector")
			}
			if len(r.SelectorIDs[si]) != 32 {
				return errors.New("invalid selector ID")
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

// SetPlainTextKey sets the PlainTextKey, IDClaimPrivateKey, ID, and IDClaimSignatureAlgorithm fields from a plain text record key.
// The ID field is the public key derived from a key pair generated deterministically from the plain
// text key. It's used to sign records to prove knowledge of the (secret) plain text key to prevent
// forgery pollution attacks.
func (r *Record) SetPlainTextKey(key []byte) {
	r.plainTextKey = make([]byte, len(key))
	copy(r.plainTextKey, key)
	s512 := sha512.Sum512(key)
	priv := ed25519.NewKeyFromSeed(s512[0:32])
	copy(r.idClaimPrivateKey[:], priv)
	copy(r.ID[:], priv[32:64])
	r.IDClaimSignatureAlgorithm = RecordSignatureAlgorithmEd25519
}

// AddSelector adds a selector to this record.
// The first selector will be sel0, the second sel1, so order matters. Records with a change in ownership
// can only have one selector due to there being only space for two meta-data items in a record.
func (r *Record) AddSelector(sel []byte) error {
	for si := range r.SelectorIDs {
		if len(r.SelectorIDs[si]) != 32 {
			if len(r.ChangeOwner) == 32 && si > 0 {
				return errors.New("records with an ownership change can only have one selector")
			}
			var sid [32]byte
			sid, r.selPrivateKeys[si] = RecordDeriveID(sel)
			r.SelectorIDs[si] = sid[:]
			return nil
		}
	}
	return errors.New("no space for more selectors")
}

// SetValue sets this record's Value field to a copy of the supplied value.
// If encrypt is true plainTextKey must be set and will be used to perform identity-based encryption
// of the value. Value encryption is the default in LF and makes values secret unless their
// corresponding plain text key is known. An attempt will be made to compress the value as well and
// if this results in a size reduction the RecordFlagValueDeflated flag will be set and the value
// will be compressed.
func (r *Record) SetValue(value []byte, encrypt bool) error {
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
		return errors.New("record value is too large even after compression")
	}

	r.Value = make([]byte, len(v))
	if encrypt {
		if len(r.plainTextKey) == 0 {
			return errors.New("cannot encrypt value without known plain text key")
		}
		var iv [16]byte
		binary.BigEndian.PutUint64(iv[0:8], r.Timestamp)
		copy(iv[8:16], r.Owner[0:8]) // every owner+timestamp combo is unique since timestamp is also revision, thus unique IV
		s512 := sha512.Sum512(r.plainTextKey)
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
func NewRecord(key, value, links []byte, ts, ttl uint64, encryptValue bool, changeOwner []byte, selectors [][]byte, ownerPrivateKey []byte) (*Record, error) {
	var r Record

	if len(ownerPrivateKey) != 64 {
		return nil, errors.New("invalid ed25519 owner private key")
	}
	if len(selectors) > 2 || (len(changeOwner) == 32 && len(selectors) > 1) {
		return nil, errors.New("record supports two meta-data fields for either two selectors or one ownership change and one selector")
	}

	r.SetPlainTextKey(key)
	for si := range selectors {
		err := r.AddSelector(selectors[si])
		if err != nil {
			return nil, err
		}
	}
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

// GetValue retrieves the plain text value from this record, performing decompression and decryption as needed.
// If plainTextKey is not supplied this will use the hidden plainTextKey field in the record, if non-nil and correct.
// Note that neither is needed if this record's value is not encrypted.
func (r *Record) GetValue(plainTextKey []byte) ([]byte, error) {
	var dec []byte
	if r.ValueEncryptionAlgorithm == RecordValueEncryptionAlgorithmNone {
		dec = r.Value
	} else if r.ValueEncryptionAlgorithm == RecordValueEncryptionAlgorithmAES256CFB {
		ptk := r.plainTextKey
		if len(plainTextKey) > 0 {
			ptk = plainTextKey
		} else {
			if !bytes.Equal(r.idClaimPrivateKey[32:64], r.ID[0:32]) {
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
	linkCount := (linkCountAndValueSize >> 11) & 31 // 31 == RecordMaxLinkCount, so no extra checking needed
	valueSize := linkCountAndValueSize & 0x7ff
	if valueSize > RecordMaxValueSize {
		return errors.New("record value too large")
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
			if len(r.selPrivateKeys[selCount]) != 64 && !bytes.Equal(r.selPrivateKeys[selCount][32:64], r.SelectorIDs[selCount][0:32]) {
				r.selPrivateKeys[selCount] = nil // nil out cached private keys if they don't match IDs
			}
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

	workHash := sha512.Sum512(data[0 : int(dr.Size())-dr.Len()])

	switch r.WorkAlgorithm {
	case RecordWorkAlgorithmNone:
		r.Work = nil
	case RecordWorkAlgorithmWharrgarbl:
		r.Work = make([]byte, WharrgarblProofOfWorkSize)
		_, err = io.ReadFull(dr, r.Work)
		if err != nil {
			return
		}
	default:
		return errors.New("unrecognized work type")
	}

	r.SigningHash = sha512.Sum512(append(workHash[:], r.Work...))

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
		// This also sets the type of any selector ID signatures...
		for s := uint(0); s < selCount; s++ {
			r.SelectorSignatures[s] = make([]byte, 32)
			_, err = io.ReadFull(dr, r.SelectorSignatures[s])
			if err != nil {
				return
			}
		}
	default:
		return errors.New("unrecognized signature type")
	}

	if !bytes.Equal(r.idClaimPrivateKey[32:64], r.ID[0:32]) {
		r.plainTextKey = nil // nil out cached plain text key if it doesn't match ID
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

// Seal completes a record by adding work and signing it by the owner and by keys that prove knowledge of blind IDs.
// It sets the Data and Hash fields to the result of final record serialization and signing.
func (r *Record) Seal(work []byte, ownerPrivateKey []byte) error {
	if r.WorkAlgorithm == RecordWorkAlgorithmWharrgarbl && len(work) != WharrgarblProofOfWorkSize {
		return errors.New("work size is not valid")
	}
	if !bytes.Equal(r.idClaimPrivateKey[32:64], r.ID[0:32]) {
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

	// Sign by owner
	r.OwnerSignature = ed25519.Sign(ownerPrivateKey, sigHash[:])
	b.Write(r.OwnerSignature)

	// Sign with ID private key to prove knowledge of blind plain text key.
	r.IDClaimSignature = ed25519.Sign(r.idClaimPrivateKey[:], sigHash[:])
	b.Write(r.IDClaimSignature)

	// Sign with private keys for selectors to prove knowledge of blind selector keys.
	for i := range r.selPrivateKeys {
		if i >= 2 || len(r.selPrivateKeys[i]) != 64 {
			return errors.New("invalid selector private key(s)")
		}
		r.SelectorSignatures[i] = ed25519.Sign(r.selPrivateKeys[i], sigHash[:])
		b.Write(r.SelectorSignatures[i])
	}

	r.Data = b.Bytes()
	r.Hash = Shandwich256(r.Data)
	return nil
}
