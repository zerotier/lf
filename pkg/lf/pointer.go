package lf

import (
	"encoding/binary"
	"io"
)

// PointerTTL is the global TTL for pointers (one year).
// After this time nodes may purge or refuse to replicate pointers.
const PointerTTL = 31536000

const (
	// PointerWorkAlgorithmNone indicates no proof of work.
	PointerWorkAlgorithmNone = RecordWorkAlgorithmNone

	// PointerWorkAlgorithmWharrgarbl indicates Wharrgarbl proof of work.
	PointerWorkAlgorithmWharrgarbl = RecordWorkAlgorithmWharrgarbl
)

// Pointer is a small ephemeral value that can be attached to a record.
// It must be signed by a public key that is embedded in the record and is
// part of the record value's clear text region (not masked). Pointers are
// ephemeral, not guaranteed to be stored for longer than a set maximum TTL,
// and are replicated using a best-effort replication algorithm. They are
// not a part of the DAG.
type Pointer struct {
	// RecordIDPrefix is the first 64 bits of the ID of this pointer's identity record containing its public key.
	// The ID is either a hash of the record's selectors or its hash if it has none. If multiple records
	// have this same ID prefix (collisions are possible) this is disambiguated by seeing which record's
	// embedded key successfully verifies this pointer's signature.
	RecordIDPrefix [8]byte

	// Timestamp in SECONDS since epoch.
	Timestamp uint64

	// Value is the current value of this pointer.
	Value []byte

	// PublicKeyType is the algorithm used for this pointer's signatures.
	// The length and format of the public key are determined by the
	// algorithm. This is just where to look in the record's Value field.
	PublicKeyType byte

	// Signature of this pointer with the identity record's public key.
	Signature []byte

	// WorkAlgorithm is the type of the Work field.
	WorkAlgorithm byte

	// Work to "pay" for this pointer.
	Work []byte
}

func (p *Pointer) marshalTo(w io.Writer) error {
	var tmp [10]byte
	if _, err := w.Write(p.RecordIDPrefix[:]); err != nil {
		return err
	}
	if _, err := w.Write(tmp[0:binary.PutUvarint(tmp[:],p.Timestamp)]); err != nil {
		return err
	}
	if _, err := w.Write(tmp[0:binary.PutUvarint(tmp[:],uint64(len(p.Value)))]); err != nil {
		return err
	}
	if _, err := w.Write(p.Value); err != nil {
		return err
	}
	if _, err := w.Write([]byte{p.PublicKeyType}); err != nil {
		return err
	}
	if _, err := w.Write(tmp[0:binary.PutUvarint(tmp[:],uint64(len(p.Signature)))]); err != nil {
		return err
	}
	if _, err := w.Write(p.Signature); err != nil {
		return err
	}
	if _, err := w.Write([]byte{p.WorkAlgorithm}); err != nil {
		return err
	}
	if _, err := w.Write(p.Work); err != nil {
		return err
	}
	if _, err := w.Write([]byte{0}); err != nil { // length of any additional fields
		return err
	}
	return nil
}

func (p *Pointer) unmarshalFrom(r io.Reader) error {
	var err error
	rr := byteAndArrayReader{r}
	if _, err := io.ReadFull(&rr,p.RecordIDPrefix[:]); err != nil {
		return err
	}
	p.Timestamp, err = binary.ReadUvarint(&rr)
	if err != nil {
		return err
	}
	vl, err := binary.ReadUvarint(&rr)
	if vl > RecordMaxSize {
		return ErrRecordInvalid
	}
	p.Value = make([]byte,int(vl))
	if _, err := io.ReadFull(&rr,p.Value); err != nil {
		return err
	}
	p.PublicKeyType, err = rr.ReadByte()
	if err != nil {
		return err
	}
	sl, err := binary.ReadUvarint(&rr)
	if sl > RecordMaxSize {
		return ErrRecordInvalid
	}
	p.Signature = make([]byte,int(sl))
	if _, err := io.ReadFull(&rr,p.Signature); err != nil {
		return err
	}
	p.WorkAlgorithm, err = rr.ReadByte()
	switch p.WorkAlgorithm {
	case PointerWorkAlgorithmNone:
	case PointerWorkAlgorithmWharrgarbl:
		var ww [WharrgarblOutputSize]byte
		if _, err := io.ReadFull(&rr,ww[:]); err != nil {
			return err
		}
		p.Work = ww[:]
	default:
		return ErrUnsupportedType
	}
	additionalBytes, err := rr.ReadByte()
	if err != nil {
		return err
	}
	if additionalBytes > 0 {
		var tmp [256]byte
		if _, err := io.ReadFull(&rr,tmp[0:int(additionalBytes)]); err != nil {
			return err
		}
	}
	return nil
}
