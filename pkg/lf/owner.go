/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"io"
	"math/big"

	"golang.org/x/crypto/ed25519"
)

// OwnerTypeNil represents an invalid or uninitialized owner type.
const OwnerTypeNil = 0

// OwnerTypeEd25519 represents an owner using Ed25519 signatures (this is the default).
const OwnerTypeEd25519 = 1

// OwnerTypeNistP384 represents an owner using ECDSA signatures over ECC curve NIST P-384.
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
func NewOwner(ownerType int) (*Owner, error) { return newOwnerIntl(ownerType, secureRandom) }

// NewOwnerFromBytes creates a new Owner object from a set of public Owner bytes (as returned by Bytes()).
func NewOwnerFromBytes(publicBytes []byte) (*Owner, error) {
	if len(publicBytes) == 0 {
		return nil, ErrInvalidPublicKey
	}
	o := &Owner{
		publicBytes:  publicBytes,
		privateBytes: nil,
		privateECDSA: nil,
	}
	if o.Type() != OwnerTypeNil {
		return o, nil
	}
	return nil, ErrInvalidPublicKey
}

// newOwnerFromP384 creates a new P-384 owner (public keys only) from a NIST P-384 public key.
func newOwnerFromP384(pubX, pubY *big.Int) (*Owner, error) {
	pubBytes, err := ECCCompressPublicKey(elliptic.P384(), pubX, pubY)
	if err != nil {
		return nil, err
	}
	pubBytes[0] |= byte(OwnerTypeNistP384) << 2 // pack owner type into unused most significant 6 bits of compressed key
	return &Owner{
		publicBytes:  pubBytes,
		privateBytes: nil,
		privateECDSA: nil,
	}, nil
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
		pubBytes, err := ECDSACompressPublicKey(&priv.PublicKey)
		if err != nil {
			return nil, err
		}
		pubBytes[0] |= byte(OwnerTypeNistP384) << 2 // pack owner type into unused most significant 6 bits of compressed key
		return &Owner{
			publicBytes:  pubBytes,
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
func (o *Owner) HasPrivate() bool { return len(o.privateBytes) > 0 }

// Bytes returns this owner's public key bytes.
// This is the literal value placed in a Record for its owner.
func (o *Owner) Bytes() []byte { return o.publicBytes }

// PrivateBytes returns this owner's private key bytes prefixed by the owner type.
func (o *Owner) PrivateBytes() []byte { return o.privateBytes }

// getPrivateECDSA returns the private ECDSA key for this owner if it is of that type.
// This returns nil for owners using ed25519 or any other non-ECDSA algorithm.
func (o *Owner) getPrivateECDSA() *ecdsa.PrivateKey {
	if o.privateECDSA == nil {
		if len(o.privateBytes) == 0 || o.privateBytes[0] != OwnerTypeNistP384 {
			return nil
		}
		priv, err := x509.ParseECPrivateKey(o.privateBytes[1:])
		if err != nil {
			return nil
		}
		o.privateECDSA = priv
	}
	return o.privateECDSA
}

// publicECDSA returns the public ECDSA key for this owner if it is of that type.
// This return snil for owners using ed25519 or any other non-ECDSA algorithm.
func (o *Owner) publicECDSA() *ecdsa.PublicKey {
	if o.Type() == OwnerTypeNistP384 {
		pub, err := ECDSADecompressPublicKey(elliptic.P384(), o.publicBytes)
		if err != nil {
			return nil
		}
		return pub
	}
	return nil
}

// rawPublicKeyBytes is a shortcut to decoding this owner's public key and encoding it as a byte array.
// This returns nil if there is a problem or the owner object is not initialized.
func (o *Owner) rawPublicKeyBytes() []byte {
	if len(o.publicBytes) == 32 {
		return o.publicBytes
	}
	pubec := o.publicECDSA()
	if pubec != nil {
		comp, err := ECDSACompressPublicKey(pubec)
		if err == nil {
			return comp
		}
	}
	return nil
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
		priv := o.getPrivateECDSA()
		if priv == nil {
			return nil, ErrInvalidPrivateKey
		}
		return ECDSASign(priv, hash)
	}
	return nil, ErrPrivateKeyRequired
}

// Verify verifies a message hash and a signature against this owner's public key.
func (o *Owner) Verify(hash, sig []byte) bool {
	if len(o.publicBytes) == 0 {
		return false
	}
	if len(o.publicBytes) == 32 { // we assume 32-byte publics are ed25519
		return ed25519.Verify(o.publicBytes, hash, sig)
	}
	pub := o.publicECDSA()
	if pub == nil {
		return false
	}
	return ECDSAVerify(pub, hash, sig)
}
