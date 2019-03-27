package lf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	secrand "crypto/rand"
	"crypto/x509"
	"io"

	"golang.org/x/crypto/ed25519"
)

// OwnerTypeNil represents an invalid or uninitialized owner type.
const OwnerTypeNil = 0

// OwnerTypeEd25519 represents an owner using Ed25519 signatures (this is the default).
const OwnerTypeEd25519 = 1

// OwnerTypeNistP384 represents an owner using ECDSA signatures over ECC curve NIST P-384 (for NSA Suite B users).
const OwnerTypeNistP384 = 2

// Owner represents a key pair that can own and sign LF records.
type Owner struct {
	publicBytes  []byte
	privateBytes []byte
	privateECDSA *ecdsa.PrivateKey // an ECDSA private key if this owner happens to be of that type
}

func newOwnerIntl(ownerType int, prng io.Reader) (*Owner, error) {
	switch ownerType {
	case OwnerTypeEd25519:
		pub, priv, err := ed25519.GenerateKey(prng)
		if err != nil {
			return nil, err
		}
		return &Owner{
			publicBytes:  pub,
			privateBytes: append([]byte{byte(OwnerTypeEd25519)}, priv...),
			privateECDSA: nil,
		}, nil
	case OwnerTypeNistP384:
		priv, err := ecdsa.GenerateKey(elliptic.P384(), prng)
		if err != nil {
			return nil, err
		}
		privBytes, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			return nil, err
		}
		pubBytes, err := ECDSACompressPublicKey(&priv.PublicKey)
		if err != nil {
			return nil, err
		}
		pubBytes[0] |= byte(OwnerTypeNistP384) << 2 // pack owner type into unused most significant 6 bits of compressed key
		return &Owner{
			publicBytes:  pubBytes,
			privateBytes: append([]byte{byte(OwnerTypeNistP384)}, privBytes...),
			privateECDSA: priv,
		}, nil
	}
	return nil, ErrInvalidParameter
}

// NewOwnerFromSeed creates a new owner whose key pair is generated using deterministic randomness from the given seed.
// Most users will want OwnerTypeEd25519. Only those that need ECDSA with NSA Suite B crypto will want to use OwnerTypeNistP384.
func NewOwnerFromSeed(ownerType int, seed []byte) (*Owner, error) {
	var prng seededPrng
	prng.seed(seed)
	return newOwnerIntl(ownerType, &prng)
}

// NewOwner creates a new owner key pair.
// Most users will want OwnerTypeEd25519. Only those that need ECDSA with NSA Suite B crypto will want to use OwnerTypeNistP384.
func NewOwner(ownerType int) (*Owner, error) { return newOwnerIntl(ownerType, secrand.Reader) }

// NewOwnerFromBytes creates a new Owner object from a set of public Owner bytes (as returned by Bytes()).
func NewOwnerFromBytes(publicBytes []byte) (*Owner, error) {
	o := &Owner{
		publicBytes:  publicBytes,
		privateBytes: nil,
		privateECDSA: nil,
	}
	if o.Type() != OwnerTypeNil {
		return o, nil
	}
	return nil, ErrInvalidParameter
}

// NewOwnerFromPrivateBytes creates a new Owner object from a set of private key bytes.
// The public key is included of course.
func NewOwnerFromPrivateBytes(privateBytes []byte) (*Owner, error) {
	if len(privateBytes) == 0 {
		return nil, ErrInvalidParameter
	}
	switch privateBytes[0] {
	case OwnerTypeEd25519:
		if len(privateBytes) == 65 {
			return &Owner{
				publicBytes:  privateBytes[33:],
				privateBytes: privateBytes,
				privateECDSA: nil,
			}, nil
		}
		return nil, ErrInvalidParameter
	case OwnerTypeNistP384:
		priv, err := x509.ParseECPrivateKey(privateBytes[1:])
		if err != nil {
			return nil, err
		}
		if priv.Curve.Params().Name != "P-384" {
			return nil, ErrUnsupportedCurve
		}
		pub, err := ECDSACompressPublicKey(&priv.PublicKey)
		if err != nil {
			return nil, err
		}
		return &Owner{
			publicBytes:  pub,
			privateBytes: privateBytes,
			privateECDSA: priv,
		}, nil
	}
	return nil, ErrInvalidParameter
}

// Type returns this owner's type.
func (o *Owner) Type() int {
	if len(o.publicBytes) == 32 {
		return OwnerTypeEd25519
	}
	if len(o.publicBytes) > 32 && (o.publicBytes[0]>>2) == OwnerTypeNistP384 {
		return OwnerTypeNistP384
	}
	return OwnerTypeNil
}

// HasPrivate returns true if this owner object includes its private key component.
func (o *Owner) HasPrivate() bool {
	return len(o.privateBytes) > 0
}

// Bytes returns this owner's public key bytes.
// This is the literal value placed in a Record for its owner.
func (o *Owner) Bytes() []byte {
	return o.publicBytes
}

// PrivateBytes returns this owner's private key bytes prefixed by the owner type.
func (o *Owner) PrivateBytes() []byte {
	return o.privateBytes
}

// Sign signs a hash (typically 32 bytes) with this key pair.
// ErrorPrivateKeyRequired is returned if the private key is not present or invalid.
func (o *Owner) Sign(hash []byte) ([]byte, error) {
	if len(o.privateBytes) == 0 {
		return nil, ErrPrivateKeyRequired
	}
	switch o.privateBytes[0] {
	case OwnerTypeEd25519:
		if len(o.privateBytes) != 65 {
			return nil, ErrInvalidParameter
		}
		return ed25519.Sign(o.privateBytes[1:], hash), nil
	case OwnerTypeNistP384:
		if o.privateECDSA == nil {
			priv, err := x509.ParseECPrivateKey(o.privateBytes[1:])
			if err != nil {
				return nil, err
			}
			if priv.Curve.Params().Name != "P-384" {
				return nil, ErrUnsupportedCurve
			}
			o.privateECDSA = priv
			return ECDSASign(priv, hash)
		}
	}
	return nil, ErrPrivateKeyRequired
}

// Verify verifies a message hash and a signature against this owner's public key.
func (o *Owner) Verify(hash, sig []byte) bool {
	if len(o.publicBytes) == 0 {
		return false
	}
	if len(o.publicBytes) == 32 {
		return ed25519.Verify(o.publicBytes, hash, sig)
	}
	if len(o.publicBytes) > 32 && (o.publicBytes[0]>>2) == OwnerTypeNistP384 {
		pub, err := ECDSADecompressPublicKey(elliptic.P384(), o.publicBytes[1:])
		if err != nil {
			return false
		}
		return ECDSAVerify(pub, hash, sig)
	}
	return false
}
