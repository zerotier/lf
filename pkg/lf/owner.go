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
	"io"

	"golang.org/x/crypto/sha3"
)

// OwnerTypeNistP224 indicates an owner based on the NIST P-224 elliptic curve.
const OwnerTypeNistP224 byte = 1

// OwnerTypeNistP384 indicates an owner based on the NIST P-384 elliptic curve.
const OwnerTypeNistP384 byte = 2

// Owner represents an entity capable of creating LF records.
type Owner struct {
	Private *ecdsa.PrivateKey
	Public  []byte
}

func internalOwnerHashECDSA(ownerType byte, pub *ecdsa.PublicKey) []byte {
	h := sha3.New224()
	h.Write(pub.X.Bytes())
	h.Write(pub.Y.Bytes())
	var tmp [28]byte
	hh := h.Sum(tmp[:0])
	if ownerType == OwnerTypeNistP224 {
		return hh[0:14] // P-224 provides 112-bit security
	}
	return hh[0:24] // P-384 provides 192-bit security
}

func internalNewOwner(ownerType byte, prng io.Reader) (*Owner, error) {
	var curve elliptic.Curve
	switch ownerType {
	case OwnerTypeNistP224:
		curve = elliptic.P224()
	case OwnerTypeNistP384:
		curve = elliptic.P384()
	default:
		return nil, ErrInvalidParameter
	}

	priv, err := ecdsa.GenerateKey(curve, prng)
	if err != nil {
		return nil, err
	}
	return &Owner{Private: priv, Public: internalOwnerHashECDSA(ownerType, &priv.PublicKey)}, nil
}

// NewOwnerFromSeed creates a new owner whose key pair is generated using deterministic randomness from the given seed.
func NewOwnerFromSeed(ownerType byte, seed []byte) (*Owner, error) {
	var prng seededPrng
	prng.seed(seed)
	return internalNewOwner(ownerType, &prng)
}

// NewOwner creates a random new owner key pair.
func NewOwner(ownerType byte) (*Owner, error) { return internalNewOwner(ownerType, secureRandom) }

// NewOwnerFromPublicKey creates a public-only owner from a public key.
func NewOwnerFromPublicKey(k *ecdsa.PublicKey) (*Owner, error) {
	var ownerType byte
	switch k.Curve.Params().Name {
	case "P-256":
		ownerType = OwnerTypeNistP224
	case "P-384":
		ownerType = OwnerTypeNistP384
	default:
		return nil, ErrUnsupportedCurve
	}
	return &Owner{Private: nil, Public: internalOwnerHashECDSA(ownerType, k)}, nil
}

// NewOwnerFromPrivateBytes deserializes both private and public portions from the result of PrivateBytes().
func NewOwnerFromPrivateBytes(b []byte) (*Owner, error) {
	priv, err := x509.ParseECPrivateKey(b)
	if err != nil {
		return nil, err
	}
	var ownerType byte
	switch priv.Curve.Params().Name {
	case "P-256":
		ownerType = OwnerTypeNistP224
	case "P-384":
		ownerType = OwnerTypeNistP384
	default:
		return nil, ErrUnsupportedCurve
	}
	return &Owner{Private: priv, Public: internalOwnerHashECDSA(ownerType, &priv.PublicKey)}, nil
}

// PrivateBytes returns this owner serialized with both public and private key parts.
func (o *Owner) PrivateBytes() ([]byte, error) {
	if o.Private == nil {
		return nil, ErrPrivateKeyRequired
	}
	return x509.MarshalECPrivateKey(o.Private)
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
	}
	return 0
}

// Sign signs a hash (typically 32 bytes) with this key pair.
// ErrorPrivateKeyRequired is returned if the private key is not present or invalid.
func (o *Owner) Sign(hash []byte) ([]byte, error) {
	if o.Private == nil {
		return nil, ErrPrivateKeyRequired
	}
	return ECDSASign(o.Private, hash)
}

// Verify verifies a message hash and a signature against this owner's public key.
func (o *Owner) Verify(hash, sig []byte) (verdict bool) {
	switch len(o.Public) {
	case 14:
		k0, k1 := ECDSARecoverBoth(elliptic.P224(), hash, sig)
		if bytes.Equal(internalOwnerHashECDSA(OwnerTypeNistP224, k0), o.Public) {
			verdict = true
		} else {
			verdict = bytes.Equal(internalOwnerHashECDSA(OwnerTypeNistP224, k1), o.Public)
		}
	case 24:
		k0, k1 := ECDSARecoverBoth(elliptic.P384(), hash, sig)
		if bytes.Equal(internalOwnerHashECDSA(OwnerTypeNistP384, k0), o.Public) {
			verdict = true
		} else {
			verdict = bytes.Equal(internalOwnerHashECDSA(OwnerTypeNistP384, k1), o.Public)
		}
	default:
		verdict = false
	}
	return
}
