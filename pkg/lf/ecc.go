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

// NOTE: the way point compression, public key hashing, and several other
// things are done here are parts of the protocol spec and can't easily be
// changed.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"math/big"
)

// SignatureAlgorithmNone is no signature algorithm.
const SignatureAlgorithmNone byte = 0

// SignatureAlgorithmECDSANistP224 is ECDSA with the NIST P-224 curve
const SignatureAlgorithmECDSANistP224 byte = 1

// SignatureAlgorithmECDSANistP384 is ECDSA with the NIST P-384 curve
const SignatureAlgorithmECDSANistP384 byte = 2

// SignatureAlgorithmEDDSAEd25519 is EDDSA with the Ed25519 curve
const SignatureAlgorithmEDDSAEd25519 byte = 3

// SignatureAlgorithmECDSABP160 is ECDSA with the BrainpoolP160T1 curve
const SignatureAlgorithmECDSABP160 byte = 4

// SignatureAlgorithmECDSANistP224PublicKeySize is the size of a compressed NIST P-224 key.
const SignatureAlgorithmECDSANistP224PublicKeySize = 29

// SignatureAlgorithmECDSANistP384PublicKeySize is the size of a compressed NIST P-384 key.
const SignatureAlgorithmECDSANistP384PublicKeySize = 49

// SignatureAlgorithmEDDSAEd25519PublicKeySize is the size of an Ed25519 public key.
const SignatureAlgorithmEDDSAEd25519PublicKeySize = 32

// SignatureAlgorithmECDSABP160PublicKeySize is the size of a BrainpoolP160T1 public key.
const SignatureAlgorithmECDSABP160PublicKeySize = 21

var (
	// ECCCurveBrainpoolP160T1 is a very small elliptic curve used only for selector claim signatures.
	ECCCurveBrainpoolP160T1 = func() elliptic.Curve {
		var c elliptic.CurveParams
		c.Name = "brainpoolP160t1"
		c.P, _ = new(big.Int).SetString("E95E4A5F737059DC60DFC7AD95B3D8139515620F", 16)
		c.N, _ = new(big.Int).SetString("E95E4A5F737059DC60DF5991D45029409E60FC09", 16)
		c.B, _ = new(big.Int).SetString("7A556B6DAE535B7B51ED2C4D7DAA7A0B5C55F380", 16)
		c.Gx, _ = new(big.Int).SetString("B199B13B9B34EFC1397E64BAEB05ACC265FF2378", 16)
		c.Gy, _ = new(big.Int).SetString("ADD6718B7C7C1961F0991B842443772152C9E0AD", 16)
		c.BitSize = 160
		return &c
	}()
)

// ECCCompressPublicKey compresses a naked elliptic curve public key denoted by X and Y components.
// Identifiers can be safely shoved into the most significant six bits of the first byte though this
// results in a non-standard-looking compressed ECC point.
func ECCCompressPublicKey(curve elliptic.Curve, kx, ky *big.Int) ([]byte, error) {
	x := kx.Bytes()
	bits := curve.Params().BitSize
	x2 := make([]byte, (bits/8)+(bits%8)+1)
	if len(x) >= len(x2) {
		return nil, ErrInvalidPublicKey
	}
	copy(x2[len(x2)-len(x):], x)
	x = x2
	x[0] = byte(2 + ky.Bit(0)) // 2 for even, 3 for odd
	return x, nil
}

// ECCDecompressPublicKey decompresses a public key.
// This won't work for Koblitz curves. Note that the most significant 6 bits of the first byte are
// ignored and therefore can be used to store curve or other type IDs.
func ECCDecompressPublicKey(c elliptic.Curve, data []byte) (*big.Int, *big.Int, error) {
	if len(data) < 2 {
		return nil, nil, ErrInvalidPublicKey
	}
	var x, y, a, ax big.Int
	params := c.Params()
	x.SetBytes(data[1:])
	y.Exp(&x, big3, params.P)
	a.Sub(params.P, big3)
	ax.Mul(&x, &a)
	ax.Mod(&ax, params.P)
	y.Add(&y, &ax)
	y.Mod(&y, params.P)
	y.Add(&y, params.B)
	y.Mod(&y, params.P)
	if y.ModSqrt(&y, params.P) == nil {
		return nil, nil, ErrInvalidPublicKey
	}
	if y.Bit(0) != uint(data[0]&1) { // even or odd?
		y.Sub(params.P, &y)
	}
	return &x, &y, nil
}

// ECDHAgree performs elliptic curve Diffie-Hellman key agreement and returns the sha256 digest of the resulting shared key.
// This is just a simple wrapper function for clarity and brevity.
func ECDHAgree(c elliptic.Curve, pubX, pubY *big.Int, privateKey []byte) ([32]byte, error) {
	if !c.IsOnCurve(pubX, pubY) {
		return [32]byte{}, ErrInvalidPublicKey
	}
	x, _ := c.ScalarMult(pubX, pubY, privateKey)
	return sha256.Sum256(x.Bytes()), nil
}

// ECDHAgreeECDSA is a version of ECDHAgree that takes an ECDSA-wrapped private and uses its curve parameter.
// It's a shortcut for using privateKey.D.Bytes() as the private.
func ECDHAgreeECDSA(pubX, pubY *big.Int, privateKey *ecdsa.PrivateKey) ([32]byte, error) {
	if !privateKey.Curve.IsOnCurve(pubX, pubY) {
		return [32]byte{}, ErrInvalidPublicKey
	}
	x, _ := privateKey.Curve.ScalarMult(pubX, pubY, privateKey.D.Bytes())
	return sha256.Sum256(x.Bytes()), nil
}

// ECDSAHashPublicKey computes sha256(in | sha512(in)) over X, Y, and the curve name.
func ECDSAHashPublicKey(pub *ecdsa.PublicKey) (hb [32]byte, err error) {
	params := pub.Params()
	curveSize := (params.BitSize >> 3) + (params.BitSize & 3)

	xb, yb := pub.X.Bytes(), pub.Y.Bytes()
	if len(xb) > curveSize || len(yb) > curveSize {
		err = ErrInvalidPublicKey
		return
	}
	buf := make([]byte, curveSize*2, (curveSize*2)+32)
	copy(buf[curveSize-len(xb):], xb)
	copy(buf[len(buf)-len(yb):], yb)
	buf = append(buf, []byte(params.Name)...)

	s256 := sha256.New()
	s256.Write(buf)
	s512 := sha512.Sum512(buf)
	s256.Write(s512[:])
	s256.Sum(hb[:0])
	return
}

// ECDSACompressPublicKey compresses an ECDSA public key using standard ECC point compression for prime curves.
// This is just a convenience wrapper around ECCCompressPublicKey() for DSA public keys.
func ECDSACompressPublicKey(key *ecdsa.PublicKey) ([]byte, error) {
	return ECCCompressPublicKey(key.Curve, key.X, key.Y)
}

// ECDSADecompressPublicKey is a convenience wrapper around ECCDecompressPublicKey to generate an ECDSA public key object.
func ECDSADecompressPublicKey(c elliptic.Curve, data []byte) (*ecdsa.PublicKey, error) {
	x, y, err := ECCDecompressPublicKey(c, data)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{Curve: c, X: x, Y: y}, nil
}

// ECDSASign signs a message hash with an ECDSA key pair, returning a byte packed signature.
// The returned signature consists of the two integers from the ECDSA signature (r and s)
// packed into a fixed byte array of ECDSASignatureSize bytes. This is simpler and more
// compact than ASN.1 but assumes that the verifier knows the curve.
func ECDSASign(key *ecdsa.PrivateKey, hash []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(secureRandom, key, hash)
	if err != nil {
		return nil, err
	}
	rb, sb := r.Bytes(), s.Bytes()

	orderSize := key.Params().N.BitLen()
	if (orderSize & 7) != 0 {
		orderSize = (orderSize / 8) + 1
	} else {
		orderSize /= 8
	}
	sig := make([]byte, orderSize*2)

	copy(sig[orderSize-len(rb):], rb)
	copy(sig[orderSize+(orderSize-len(sb)):], sb)

	return sig, nil
}

// ECDSASignEmbedRecoveryIndex creates a signature that also contains information required by ECDSARecover.
func ECDSASignEmbedRecoveryIndex(key *ecdsa.PrivateKey, hash []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(secureRandom, key, hash)
	if err != nil {
		return nil, err
	}

	var rindex byte
	pub := ecdsaRecoverPublicKey(key.Curve, r, s, hash, 1)
	if pub != nil && pub.X.Cmp(key.X) == 0 && pub.Y.Cmp(key.Y) == 0 {
		rindex = 1
	} // else rindex must be 0, can only be 0 or 1 for the curves we use

	rb, sb := r.Bytes(), s.Bytes()

	orderSize := key.Params().N.BitLen()
	if (orderSize & 7) != 0 {
		orderSize = (orderSize / 8) + 1
	} else {
		orderSize /= 8
	}
	sig := make([]byte, (orderSize*2)+1)

	copy(sig[orderSize-len(rb):], rb)
	copy(sig[orderSize+(orderSize-len(sb)):], sb)
	sig[len(sig)-1] = rindex

	return sig, nil
}

// ECDSAVerify verifies a hash with a packed signature of the type created by ECDSASign().
func ECDSAVerify(publicKey *ecdsa.PublicKey, hash, signature []byte) bool {
	params := publicKey.Curve.Params()
	orderSize := params.N.BitLen()
	if (orderSize & 7) != 0 {
		orderSize = (orderSize / 8) + 1
	} else {
		orderSize /= 8
	}

	if len(signature) != orderSize*2 {
		return false
	}

	var r, s big.Int
	r.SetBytes(signature[0:orderSize])
	s.SetBytes(signature[orderSize:])
	return ecdsa.Verify(publicKey, hash, &r, &s)
}

// ECDSARecover recovers the public key from an ECDSA signature and the hash that was signed using ECDSASignEmbedRecoveryIndex.
// This returns nil if the recovery operation fails for some reason.
func ECDSARecover(curve elliptic.Curve, hash, signature []byte) *ecdsa.PublicKey {
	params := curve.Params()

	orderSize := params.N.BitLen()
	if (orderSize & 7) != 0 {
		orderSize = (orderSize / 8) + 1
	} else {
		orderSize /= 8
	}
	if len(signature) != orderSize*2+1 {
		return nil
	}

	var r, s big.Int
	r.SetBytes(signature[0:orderSize])
	s.SetBytes(signature[orderSize : len(signature)-1])
	return ecdsaRecoverPublicKey(curve, &r, &s, hash, uint(signature[len(signature)-1]))
}

// ECDSARecoverBoth recovers both potential keys from a signature without an embedded recovery index.
func ECDSARecoverBoth(curve elliptic.Curve, hash, signature []byte) (*ecdsa.PublicKey, *ecdsa.PublicKey) {
	params := curve.Params()

	orderSize := params.N.BitLen()
	if (orderSize & 7) != 0 {
		orderSize = (orderSize / 8) + 1
	} else {
		orderSize /= 8
	}
	if len(signature) != int(orderSize*2) {
		return nil, nil
	}

	var r, s big.Int
	r.SetBytes(signature[0:orderSize])
	s.SetBytes(signature[orderSize:len(signature)])
	return ecdsaRecoverPublicKey(curve, &r, &s, hash, 0), ecdsaRecoverPublicKey(curve, &r, &s, hash, 1)
}

// ecdsaRecoverPublicKey contains the actual guts of the ECDSA key recovery from signature algorithm
func ecdsaRecoverPublicKey(c elliptic.Curve, r, s *big.Int, hash []byte, iter uint) *ecdsa.PublicKey {
	curve := c.Params()
	var rx, iterBE, threeX, ry, e, invr, invrS big.Int

	rx.Mul(curve.N, iterBE.SetInt64(int64(iter/2)))
	rx.Add(&rx, r)
	if rx.Cmp(curve.P) != -1 {
		return nil
	}

	ry.Mul(&rx, &rx)
	ry.Mul(&ry, &rx)
	threeX.Lsh(&rx, 1)
	threeX.Add(&threeX, &rx)
	ry.Sub(&ry, &threeX)
	ry.Add(&ry, curve.B)
	ry.Mod(&ry, curve.P)
	ry.ModSqrt(&ry, curve.P)
	if ry.Bit(0) != iter&1 {
		ry.Neg(&ry)
		ry.Mod(&ry, curve.P)
	}

	orderBits := curve.N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}
	e.SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		e.Rsh(&e, uint(excess))
	}

	invr.ModInverse(r, curve.N)
	invrS.Mul(&invr, s)
	invrS.Mod(&invrS, curve.N)
	srx, sry := c.ScalarMult(&rx, &ry, invrS.Bytes())
	e.Neg(&e)
	e.Mod(&e, curve.N)
	e.Mul(&e, &invr)
	e.Mod(&e, curve.N)
	minuseGx, minuseGy := c.ScalarBaseMult(e.Bytes())
	qx, qy := c.Add(srx, sry, minuseGx, minuseGy)
	return &ecdsa.PublicKey{
		Curve: c,
		X:     qx,
		Y:     qy,
	}
}
