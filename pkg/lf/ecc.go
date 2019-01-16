/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	secrand "crypto/rand"
	"math/big"
)

var (
	// ECCCurveSecP112R1 is a tiny elliptic curve for use in claim signatures.
	// This is not used for security critical things like owner signatures, just to make dumb key collision DOS attacks hard
	// by allowing selectors to prove knowledge of their masked plain text keys.
	ECCCurveSecP112R1 = func() elliptic.CurveParams {
		var secp112r1 elliptic.CurveParams
		secp112r1.Name = "secp112r1"
		secp112r1.P, _ = new(big.Int).SetString("00db7c2abf62e35e668076bead208b", 16) // Prime
		secp112r1.N, _ = new(big.Int).SetString("00db7c2abf62e35e7628dfac6561c5", 16) // Order
		secp112r1.B, _ = new(big.Int).SetString("659ef8ba043916eede8911702b22", 16)   // B
		secp112r1.Gx, _ = new(big.Int).SetString("09487239995a5ee76b55f9c2f098", 16)  // Generator X
		secp112r1.Gy, _ = new(big.Int).SetString("a89ce5af8724c0a23e0e0ff77500", 16)  // Generator Y
		secp112r1.BitSize = 112
		return secp112r1
	}()

	// ECCCurveSecP112R1SignatureSize is the size of a byte packed (not ASN.1) signature from ECCCurveSecP112R1.
	ECCCurveSecP112R1SignatureSize = ECDSASignatureSize(&ECCCurveSecP112R1)

	bigInt3 = big.NewInt(3)
)

// Size of compressed public keys for different ECDSA curves.
const (
	ECCSecP112R1CompressedPublicKeySize = 15
	ECCP224CompressedPublicKeySize      = 29
	ECCP256CompressedPublicKeySize      = 33
	ECCP384CompressedPublicKeySize      = 49
	ECCP521CompressedPublicKeySize      = 67
)

// ECCCompressPublicKey compresses an ECC public key using standard ECC point compression for prime curves.
func ECCCompressPublicKey(key *ecdsa.PublicKey) ([]byte, error) {
	x := key.X.Bytes()
	bits := key.Curve.Params().BitSize
	x2 := make([]byte, (bits/8)+(bits%8)+1)
	if len(x) >= len(x2) {
		return nil, ErrorInvalidPublicKey
	}
	copy(x2[len(x2)-len(x):], x)
	x = x2
	x[0] = byte(2 + key.Y.Bit(0)) // 2 for even, 3 for odd
	return x, nil
}

// ECCCompressPublicKeyWithID uses a slightly different encoding for the first parity byte to allow an ID to be packed with no extra space.
// The ID may be up to 7 bits in size (0..127). This deviates a little from the compressed point standard which always sets bit 0x02 to indicate
// compression, so it should be used in roles where compression is always assumed.
func ECCCompressPublicKeyWithID(key *ecdsa.PublicKey, algorithmID byte) ([]byte, error) {
	c, err := ECCCompressPublicKey(key)
	if err != nil {
		return nil, err
	}
	if len(c) == 0 {
		return nil, ErrorInvalidPublicKey
	}
	c[0] = (c[0] & 1) | (algorithmID << 1) // translate 2/3 even/odd parity to 0/1 and then stuff ID in most significant 7 bits
	return c, nil
}

// ECCDecompressPublicKey decompresses a public key.
// This won't work for Koblitz curves. It will work with compressed keys created with ECCCompressPublicKeyWithID().
func ECCDecompressPublicKey(c elliptic.Curve, data []byte) (*ecdsa.PublicKey, error) {
	var x, y, a, ax big.Int
	params := c.Params()
	x.SetBytes(data[1:])
	y.Exp(&x, bigInt3, params.P)
	a.Sub(params.P, bigInt3)
	ax.Mul(&x, &a)
	ax.Mod(&ax, params.P)
	y.Add(&y, &ax)
	y.Mod(&y, params.P)
	y.Add(&y, params.B)
	y.Mod(&y, params.P)
	if y.ModSqrt(&y, params.P) == nil {
		return nil, ErrorInvalidPublicKey
	}
	if y.Bit(0) != uint(data[0]&1) { // even or odd?
		y.Sub(params.P, &y)
	}
	return &ecdsa.PublicKey{
		Curve: c,
		X:     &x,
		Y:     &y,
	}, nil
}

// ECDSASignatureSize returns the maximum packed binary signature size for a given curve.
func ECDSASignatureSize(curve *elliptic.CurveParams) uint {
	// ECDSA signatures consist of two integers from 0 to the order (N) of the curve.
	orderSize := uint(curve.N.BitLen())
	if (orderSize & 7) != 0 {
		orderSize = (orderSize / 8) + 1
	} else {
		orderSize /= 8
	}
	return orderSize * 2
}

// ECDSASign signs a message hash with an ECDSA key pair, returning a byte packed signature.
// The returned signature consists of the two integers from the ECDSA signature (r and s)
// packed into a fixed byte array of ECDSASignatureSize bytes. This is simpler and more
// compact than ASN.1 but assumes that the verifier knows the curve.
func ECDSASign(key *ecdsa.PrivateKey, hash []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(secrand.Reader, key, hash)
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

	copy(sig, rb)
	copy(sig[orderSize:], sb)

	return sig, nil
}

// ECDSAVerify verifies a hash with a packed signature of the type created by ECDSASign().
func ECDSAVerify(key *ecdsa.PublicKey, hash []byte, signature []byte) bool {
	if key == nil || key.Curve == nil || key.X == nil || key.Y == nil {
		return false
	}

	orderSize := key.Params().N.BitLen()
	if (orderSize & 7) != 0 {
		orderSize = (orderSize / 8) + 1
	} else {
		orderSize /= 8
	}

	if len(signature) != int(orderSize*2) {
		return false
	}

	var r, s big.Int
	r.SetBytes(signature[0:orderSize])
	s.SetBytes(signature[orderSize:])

	return ecdsa.Verify(key, hash, &r, &s)
}
