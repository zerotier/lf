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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"

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

// OwnerPublic is a byte array that serializes to an @owner base62-encoded string.
type OwnerPublic []byte

// NewOwnerPublicFromString decodes a @base62 owner public name.
func NewOwnerPublicFromString(b62 string) (OwnerPublic, error) {
	if len(b62) < 1 {
		return nil, ErrInvalidParameter
	}
	if b62[0] == '@' {
		return OwnerPublic(Base62Decode(b62[1:])), nil
	}
	return nil, ErrInvalidParameter
}

// String returns @base62 owner
func (b OwnerPublic) String() string {
	return "@" + Base62Encode(b)
}

// MarshalJSON returns this blob marshaled as a @owner base62-encoded string.
func (b OwnerPublic) MarshalJSON() ([]byte, error) {
	return []byte("\"@" + Base62Encode(b) + "\""), nil
}

// UnmarshalJSON unmarshals this blob from a JSON array or string
func (b *OwnerPublic) UnmarshalJSON(j []byte) error {
	if len(j) == 0 {
		*b = nil
		return nil
	}

	// Default is @base62string
	var err error
	var str string
	err = json.Unmarshal(j, &str)
	if err == nil {
		if len(str) > 0 && str[0] == '@' {
			*b = Base62Decode(str[1:])
			return nil
		}
		err = errors.New("base62 string not prefixed by @ (for owner)")
	}

	// Byte arrays are also accepted
	var bb []byte
	if json.Unmarshal(j, &bb) != nil {
		return err
	}
	*b = bb
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
	return &Owner{Private: priv, Public: OwnerPublic(oh)}, nil
}

// NewOwnerFromSeed creates a new owner whose key pair is generated using deterministic randomness from the given seed.
func NewOwnerFromSeed(ownerType byte, seed []byte) (*Owner, error) {
	var prng seededPrng
	prng.seed(seed)
	return internalNewOwner(ownerType, &prng)
}

// NewOwner creates a random new owner key pair.
func NewOwner(ownerType byte) (*Owner, error) { return internalNewOwner(ownerType, secureRandom) }

// NewOwnerFromPrivateBytes deserializes both private and public portions from the result of PrivateBytes().
func NewOwnerFromPrivateBytes(b []byte) (*Owner, error) {
	if len(b) == 0 {
		return nil, ErrInvalidPrivateKey
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
		return append([]byte{OwnerTypeEd25519}, (*(o.Private.(*ed25519.PrivateKey)))...), nil

	default:
		return nil, ErrInvalidObject
	}
}

// String returns @base62 encoded Public.
func (o *Owner) String() string { return "@" + Base62Encode(o.Public) }

// Type returns the type of this owner or 0 if the owner is not initialized.
func (o *Owner) Type() byte {
	switch len(o.Public) {
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
func (o Owner) TypeString() string {
	switch len(o.Public) {
	case 14:
		return "p224"
	case 24:
		return "p384"
	case 32:
		return "ed25519"
	}
	return ""
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
