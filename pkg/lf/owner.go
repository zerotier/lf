/*
 * Copyright (c)2019 ZeroTier, Inc.
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file in the project's root directory.
 *
 * Change Date: 2023-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2.0 of the Apache License.
 */
/****/

package lf

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"strings"
	"time"

	"golang.org/x/crypto/ed25519"
)

// OwnerTypeNistP224 indicates an owner based on the NIST P-224 elliptic curve.
// Total record overhead for this type is 70 bytes.
const OwnerTypeNistP224 byte = 1

// OwnerTypeNistP384 indicates an owner based on the NIST P-384 elliptic curve.
// Total record overhead for this type is 120 bytes.
const OwnerTypeNistP384 byte = 2

// OwnerTypeEd25519 is an owner using the popular ed25519 Edwards elliptic curve.
// Total record overhead for this type is 96 bytes.
const OwnerTypeEd25519 byte = 3

// OwnerPrivatePEMType is the type string that should be used for PEM-encoding owner private keys.
const OwnerPrivatePEMType = "LF OWNER PRIVATE KEY"

// Length of public part of owner for each type. Right now this length is used
// to determine the type. If we add another 32-byte type in the future we'll
// probably make it 33 bytes and preface it or something.
const (
	ownerLenP224    = 14
	ownerLenP384    = 24
	ownerLenEd25519 = 32
)

// PassphraseToOwnerAndMaskingKey generates both an owner and a masking key from a secret string.
func PassphraseToOwnerAndMaskingKey(passphrase string) (*Owner, []byte) {
	pp := []byte(passphrase)
	mkh := sha256.Sum256(pp)
	mkh = sha256.Sum256(mkh[:]) // double hash to ensure difference from seededprng
	owner, err := NewOwnerFromSeed(OwnerTypeNistP384, pp)
	if err != nil {
		panic(err)
	}
	return owner, mkh[:]
}

// OwnerTypeFromString converts a canonical string name to an owner type, returning OwnerTypeNistP224 if not recognized.
func OwnerTypeFromString(typeString string) byte {
	switch strings.TrimSpace(strings.ToLower(typeString)) {
	case "p224", "p-224":
		return OwnerTypeNistP224
	case "p384", "p-384":
		return OwnerTypeNistP384
	case "ed25519":
		return OwnerTypeEd25519
	}
	return OwnerTypeNistP224
}

// OwnerPublic is a byte array that serializes to an @owner base62-encoded string.
type OwnerPublic []byte

// NewOwnerPublicFromString decodes a @base62 owner public name.
func NewOwnerPublicFromString(b62 string) (OwnerPublic, error) {
	if len(b62) < 1 {
		return nil, ErrInvalidParameter
	}
	if b62[0] == '@' {
		return Base62Decode(b62[1:]), nil
	}
	return nil, ErrInvalidParameter
}

// NewOwnerPublicFromECDSAPublicKey creates an OwnerPublic derived from an ECDSA public key.
func NewOwnerPublicFromECDSAPublicKey(pub *ecdsa.PublicKey) (OwnerPublic, error) {
	if pub == nil || pub.Curve == nil {
		return nil, ErrInvalidParameter
	}
	var oh []byte
	var err error
	switch pub.Curve.Params().Name {
	case "P-224":
		oh, err = internalOwnerHashECDSA(OwnerTypeNistP224, pub)
	case "P-384":
		oh, err = internalOwnerHashECDSA(OwnerTypeNistP384, pub)
	default:
		return nil, ErrUnsupportedCurve
	}
	if err != nil {
		return nil, err
	}
	return OwnerPublic(oh), nil
}

// String returns @base62 owner
func (o OwnerPublic) String() string { return "@" + Base62Encode(o) }

// Type returns the type of this owner or 0 if the owner is not initialized.
func (o OwnerPublic) Type() byte {
	switch len(o) {
	case 14:
		return OwnerTypeNistP224
	case 24:
		return OwnerTypeNistP384
	case 32:
		return OwnerTypeEd25519
	}
	return 0
}

// TypeString returns a human-readable Owner type.
func (o OwnerPublic) TypeString() string {
	switch len(o) {
	case 14:
		return "p224"
	case 24:
		return "p384"
	case 32:
		return "ed25519"
	}
	return ""
}

// MarshalJSON returns this blob marshaled as a @owner base62-encoded string.
func (o OwnerPublic) MarshalJSON() ([]byte, error) {
	return []byte("\"@" + Base62Encode(o) + "\""), nil
}

// UnmarshalJSON unmarshals this blob from a JSON array or string
func (o *OwnerPublic) UnmarshalJSON(j []byte) error {
	if len(j) == 0 {
		*o = nil
		return nil
	}

	// Default is @base62string
	var err error
	var str string
	err = json.Unmarshal(j, &str)
	if err == nil {
		if len(str) > 0 && str[0] == '@' {
			*o = Base62Decode(str[1:])
			return nil
		}
		err = errors.New("base62 string not prefixed by @ (for owner)")
	}

	// Byte arrays are also accepted
	var bb []byte
	if json.Unmarshal(j, &bb) != nil {
		return err
	}
	*o = bb
	return nil
}

// Owner represents an entity capable of creating LF records.
type Owner struct {
	// Private is *ecdsa.PrivateKey for ECDSA modes and *ed25519.PrivateKey for ed25519.
	// It will be nil if this owner holds a public key only.
	Private interface{}

	// Public is the value placed in Owner in records.
	// Its exact nature varies by owner key type. For ed25519 it's the 256-bit public
	// key itself. For ECDSA it's a hash of the key to save space and verification
	// happens by running ECESA key recovery and checking the result against this hash.
	Public OwnerPublic
}

func internalOwnerHashECDSA(ownerType byte, pub *ecdsa.PublicKey) ([]byte, error) {
	hh, err := ECDSAHashPublicKey(pub)
	if err != nil {
		return nil, err
	}
	if ownerType == OwnerTypeNistP224 {
		return hh[0:14], nil // matches 112-bit security provided by P-224
	}
	return hh[0:24], nil // matches 192-bit security provided by P-384
}

func internalNewOwner(ownerType byte, prng io.Reader) (*Owner, error) {
	var curve elliptic.Curve
	switch ownerType {

	// These two subsequently fall out of the switch statement
	case OwnerTypeNistP224:
		curve = elliptic.P224()
	case OwnerTypeNistP384:
		curve = elliptic.P384()

	case OwnerTypeEd25519:
		var seed [ed25519.SeedSize]byte
		_, err := io.ReadFull(prng, seed[:])
		if err != nil {
			return nil, err
		}
		priv := ed25519.NewKeyFromSeed(seed[:])
		return &Owner{Private: &priv, Public: OwnerPublic(priv[32:])}, nil

	default:
		return nil, ErrInvalidParameter
	}

	priv, err := ecdsa.GenerateKey(curve, prng)
	if err != nil {
		return nil, err
	}
	oh, err := internalOwnerHashECDSA(ownerType, &priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Owner{Private: priv, Public: oh}, nil
}

// NewOwnerFromECDSAPrivateKey creates an owner from an ECDSA private key with either the P224 or the P384 curve.
func NewOwnerFromECDSAPrivateKey(key *ecdsa.PrivateKey) (*Owner, error) {
	var ownerType byte
	switch key.Curve.Params().Name {
	case "P-224":
		ownerType = OwnerTypeNistP224
	case "P-384":
		ownerType = OwnerTypeNistP384
	default:
		return nil, ErrUnsupportedCurve
	}
	oh, err := internalOwnerHashECDSA(ownerType, &key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Owner{Private: key, Public: oh}, nil
}

// NewOwnerFromSeed creates a new owner whose key pair is generated using deterministic randomness from the given seed.
func NewOwnerFromSeed(ownerType byte, seed []byte) (*Owner, error) {
	var prng seededPrng
	prng.seed(seed)
	return internalNewOwner(ownerType, &prng)
}

// NewOwner creates a random new owner key pair.
func NewOwner(ownerType byte) (*Owner, error) { return internalNewOwner(ownerType, secureRandom) }

// NewOwnerFromPrivateBytes deserializes both private and public portions from the result of PrivateBytes() or PrivatePEM().
// Whether it's DER or PEM is auto-detected based on the presence of "-----BEGIN LF OWNER PRIVATE KEY-----" in the data.
func NewOwnerFromPrivateBytes(b []byte) (*Owner, error) {
	if len(b) == 0 {
		return nil, ErrInvalidPrivateKey
	}

	if strings.Contains(string(b), "-----BEGIN LF OWNER PRIVATE KEY-----") {
		pb, _ := pem.Decode(b)
		if pb != nil && pb.Type == OwnerPrivatePEMType {
			b = pb.Bytes
		}
	}

	switch b[0] {

	case OwnerTypeNistP224, OwnerTypeNistP384:
		priv, err := x509.ParseECPrivateKey(b[1:])
		if err != nil {
			return nil, err
		}
		var ownerType byte
		switch priv.Curve.Params().Name {
		case "P-224":
			ownerType = OwnerTypeNistP224
		case "P-384":
			ownerType = OwnerTypeNistP384
		default:
			return nil, ErrUnsupportedCurve
		}
		oh, err := internalOwnerHashECDSA(ownerType, &priv.PublicKey)
		if err != nil {
			return nil, err
		}
		return &Owner{Private: priv, Public: oh}, nil

	case OwnerTypeEd25519:
		if len(b) != 65 {
			return nil, ErrInvalidPrivateKey
		}
		var priv2 [64]byte
		var priv ed25519.PrivateKey
		priv = priv2[:]
		copy(priv, b[1:])
		return &Owner{Private: &priv, Public: OwnerPublic(priv[32:])}, nil
	}

	return nil, ErrInvalidPrivateKey
}

// PrivateBytes returns this owner serialized with both public and private key parts.
func (o *Owner) PrivateBytes() ([]byte, error) {
	if o.Private == nil {
		return nil, ErrPrivateKeyRequired
	}
	switch len(o.Public) {

	case ownerLenP224, ownerLenP384:
		priv, err := x509.MarshalECPrivateKey(o.Private.(*ecdsa.PrivateKey))
		if err != nil {
			return nil, err
		}
		if len(o.Public) == ownerLenP224 {
			return append([]byte{OwnerTypeNistP224}, priv...), nil
		}
		return append([]byte{OwnerTypeNistP384}, priv...), nil

	case ownerLenEd25519:
		return append([]byte{OwnerTypeEd25519}, *(o.Private.(*ed25519.PrivateKey))...), nil

	default:
		return nil, ErrInvalidObject
	}
}

// PrivatePEM is a shortcut to PEM encode PrivateBytes().
func (o *Owner) PrivatePEM() ([]byte, error) {
	pb, err := o.PrivateBytes()
	if err != nil {
		return nil, err
	}
	pemHdrs := make(map[string]string)
	pemHdrs["Type"] = o.TypeString()
	pemHdrs["Public"] = o.Public.String()
	return pem.EncodeToMemory(&pem.Block{Type: OwnerPrivatePEMType, Headers: pemHdrs, Bytes: pb}), nil
}

// String returns @base62 encoded Public.
func (o *Owner) String() string { return o.Public.String() }

// Type returns the type of this owner or 0 if the owner is not initialized.
func (o *Owner) Type() byte { return o.Public.Type() }

// TypeString returns a human-readable Owner type.
func (o *Owner) TypeString() string { return o.Public.TypeString() }

// PrivateHash returns sha256(raw private key)
func (o *Owner) PrivateHash() (h [32]byte) {
	if o.Private != nil {
		switch len(o.Public) {
		case ownerLenP224, ownerLenP384:
			priv, _ := o.Private.(*ecdsa.PrivateKey)
			if priv == nil {
				return
			}
			h = sha256.Sum256(priv.D.Bytes())
		case ownerLenEd25519:
			priv, _ := o.Private.(*ed25519.PrivateKey)
			if priv == nil {
				return
			}
			h = sha256.Sum256(*priv)
		default:
			return
		}
	}
	return
}

// Sign signs a hash (typically 32 bytes) with this key pair.
// ErrorPrivateKeyRequired is returned if the private key is not present or invalid.
func (o *Owner) Sign(hash []byte) ([]byte, error) {
	if o.Private == nil {
		return nil, ErrPrivateKeyRequired
	}
	switch len(o.Public) {
	case ownerLenP224, ownerLenP384:
		return ECDSASign(o.Private.(*ecdsa.PrivateKey), hash)
	case ownerLenEd25519:
		return ed25519.Sign(*(o.Private.(*ed25519.PrivateKey)), hash), nil
	default:
		return nil, ErrInvalidObject
	}
}

// Verify verifies a message hash and a signature against this owner's public key.
func (o *Owner) Verify(hash, sig []byte) (verdict bool) {
	switch len(o.Public) {
	case ownerLenP224:
		k0, k1 := ECDSARecoverBoth(elliptic.P224(), hash, sig)
		oh, _ := internalOwnerHashECDSA(OwnerTypeNistP224, k0)
		if bytes.Equal(oh, o.Public) {
			verdict = true
		} else {
			oh, _ = internalOwnerHashECDSA(OwnerTypeNistP224, k1)
			verdict = bytes.Equal(oh, o.Public)
		}

	case ownerLenP384:
		k0, k1 := ECDSARecoverBoth(elliptic.P384(), hash, sig)
		oh, _ := internalOwnerHashECDSA(OwnerTypeNistP384, k0)
		if bytes.Equal(oh, o.Public) {
			verdict = true
		} else {
			oh, _ = internalOwnerHashECDSA(OwnerTypeNistP384, k1)
			verdict = bytes.Equal(oh, o.Public)
		}

	case ownerLenEd25519:
		verdict = ed25519.Verify([]byte(o.Public), hash, sig)

	default:
		verdict = false
	}
	return
}

// CreateCSR creates a CSR (certificate signing request) for an Owner.
// The owner must contain its Private key. Currently only P224 and P384 type
// owners can have CSRs generated for them. When GoLang x509 gets EDDSA support
// then support for ed25519 CSRs will be added. The supplied subject is used
// as a template but its SerialNumber will always be set to the Base62 encoded
// owner public value (minus the leading @).
func (o *Owner) CreateCSR(subject *pkix.Name) ([]byte, error) {
	if o.Private == nil {
		return nil, ErrPrivateKeyRequired
	}
	var sa x509.SignatureAlgorithm
	switch o.Type() {
	case OwnerTypeNistP224:
		sa = x509.ECDSAWithSHA256
	case OwnerTypeNistP384:
		sa = x509.ECDSAWithSHA384
	default:
		return nil, ErrUnsupportedType
	}
	tmpl := x509.CertificateRequest{
		SignatureAlgorithm: sa,
		Subject:            *subject,
	}
	tmpl.Subject.SerialNumber = Base62Encode(o.Public)
	return x509.CreateCertificateRequest(secureRandom, &tmpl, o.Private)
}

// CreateOwnerCertificate generates a certificate for an owner from an owner CSR.
// The CSR is validated and the auth certificate is checked to ensure that it has
// the proper key usage flags.
func CreateOwnerCertificate(recordLinks [][32]byte, recordWorkFunction *Wharrgarblr, recordOwner *Owner, ownerCertificateRequest *x509.CertificateRequest, ttl time.Duration, authCertificate *x509.Certificate, authPrivateKey interface{}) (*Record, error) {
	err := ownerCertificateRequest.CheckSignature()
	if err != nil {
		return nil, err
	}

	if !authCertificate.IsCA || (authCertificate.KeyUsage|x509.KeyUsageCertSign) == 0 {
		return nil, errors.New("auth certificate is not a root or intermediate CA certificate")
	}

	var randomSerial [32]byte
	_, _ = secureRandom.Read(randomSerial[:])
	now := time.Now().UTC()
	cert, err := x509.CreateCertificate(secureRandom, &x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes(randomSerial[:]),
		Subject:               ownerCertificateRequest.Subject,
		NotBefore:             now,
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}, authCertificate, authCertificate.PublicKey, authPrivateKey)
	if err != nil {
		return nil, err
	}

	nowSec := uint64(now.Unix())
	return NewRecord(RecordTypeCertificate, cert, recordLinks, []byte(RecordCertificateMaskingKey), nil, nil, nowSec, recordWorkFunction, recordOwner)
}
