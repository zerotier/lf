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
	secrand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"math/big"
)

var (
	// ECCCurveBrainpoolP160T1 is a 160-bit elliptic curve used for selectors and their claim signatures.
	// This curve is used for selector claim signatures to prevent a form of denial of service attack. It's
	// not used in really security-critical areas like owner and CA signatures or transport security.
	ECCCurveBrainpoolP160T1 = func() elliptic.CurveParams {
		var c elliptic.CurveParams
		c.Name = "brainpoolP160t1"
		c.P, _ = new(big.Int).SetString("E95E4A5F737059DC60DFC7AD95B3D8139515620F", 16)
		c.N, _ = new(big.Int).SetString("E95E4A5F737059DC60DF5991D45029409E60FC09", 16)
		c.B, _ = new(big.Int).SetString("7A556B6DAE535B7B51ED2C4D7DAA7A0B5C55F380", 16)
		c.Gx, _ = new(big.Int).SetString("B199B13B9B34EFC1397E64BAEB05ACC265FF2378", 16)
		c.Gy, _ = new(big.Int).SetString("ADD6718B7C7C1961F0991B842443772152C9E0AD", 16)
		c.BitSize = 160
		return c
	}()

	bigInt3 = big.NewInt(3)
)

// ECCCompressPublicKey compresses a naked elliptic curve public key denoted by X and Y components.
func ECCCompressPublicKey(curve elliptic.Curve, kx, ky *big.Int) ([]byte, error) {
	x := kx.Bytes()
	bits := curve.Params().BitSize
	x2 := make([]byte, (bits/8)+(bits%8)+1)
	if len(x) >= len(x2) {
		return nil, ErrorInvalidPublicKey
	}
	copy(x2[len(x2)-len(x):], x)
	x = x2
	x[0] = byte(2 + ky.Bit(0)) // 2 for even, 3 for odd
	return x, nil
}

// ECCDecompressPublicKey decompresses a public key.
// This won't work for Koblitz curves but will work with ECDSA curves compressed with the slightly alternate ECDSACompressPublicKeyWithID() function.
func ECCDecompressPublicKey(c elliptic.Curve, data []byte) (*big.Int, *big.Int, error) {
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
		return nil, nil, ErrorInvalidPublicKey
	}
	if y.Bit(0) != uint(data[0]&1) { // even or odd?
		y.Sub(params.P, &y)
	}
	return &x, &y, nil
}

// ECCAgree performs elliptic curve Diffie-Hellman key agreement and returns the sha256 digest of the resulting shared key.
// This is just a simple wrapper function for clarity and brevity.
func ECCAgree(c elliptic.Curve, pubX, pubY *big.Int, priv []byte) ([32]byte, error) {
	x, _ := c.ScalarMult(pubX, pubY, priv)
	return sha256.Sum256(x.Bytes()), nil
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

// ECDSACompressPublicKeyWithID uses a slightly different encoding for the first parity byte to allow an ID to be packed with no extra space.
// The ID may be up to 7 bits in size (0..127). This deviates a little from the compressed point standard which always sets bit 0x02 to indicate
// compression, so it should be used in roles where compression is always assumed.
func ECDSACompressPublicKeyWithID(key *ecdsa.PublicKey, algorithmID byte) ([]byte, error) {
	c, err := ECDSACompressPublicKey(key)
	if err != nil {
		return nil, err
	}
	if len(c) == 0 {
		return nil, ErrorInvalidPublicKey
	}
	c[0] = (c[0] & 1) | (algorithmID << 1) // translate 2/3 even/odd parity to 0/1 and then stuff ID in most significant 7 bits
	return c, nil
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

	copy(sig[orderSize-len(rb):], rb)
	copy(sig[orderSize+(orderSize-len(sb)):], sb)

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

// ECDSAMarshalPEM creates a plain text PEM-encoded X.509 ECDSA private key (includes public).
func ECDSAMarshalPEM(key *ecdsa.PrivateKey) []byte {
	bin, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: bin,
	})
}

// ECDSAUnmarshalPEM unmarshals a PEM-encoded X.509 ECDSA private key.
// Non-PEM parts of data are ignored.
func ECDSAUnmarshalPEM(data []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(data)
	if blk.Type != "EC PRIVATE KEY" {
		return nil, ErrorUnsupportedType
	}
	return x509.ParseECPrivateKey(blk.Bytes)
}
