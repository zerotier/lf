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
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"

	"golang.org/x/crypto/sha3"
)

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

	bigInt3 = big.NewInt(3)
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
	y.Exp(&x, bigInt3, params.P)
	a.Sub(params.P, bigInt3)
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

// ECDHAgree performs elliptic curve Diffie-Hellman key agreement and returns the sha3-256 digest of the resulting shared key.
// This is just a simple wrapper function for clarity and brevity.
func ECDHAgree(c elliptic.Curve, pubX, pubY *big.Int, priv []byte) ([32]byte, error) {
	if !c.IsOnCurve(pubX, pubY) {
		return [32]byte{}, ErrInvalidPublicKey
	}
	x, _ := c.ScalarMult(pubX, pubY, priv)
	return sha3.Sum256(x.Bytes()), nil
}

// ECDHAgreeECDSA is a version of ECDHAgree that takes an ECDSA-wrapped private and uses its curve parameter.
// It's a shortcut for using priv.D.Bytes() as the private.
func ECDHAgreeECDSA(pubX, pubY *big.Int, priv *ecdsa.PrivateKey) ([32]byte, error) {
	if !priv.Curve.IsOnCurve(pubX, pubY) {
		return [32]byte{}, ErrInvalidPublicKey
	}
	x, _ := priv.Curve.ScalarMult(pubX, pubY, priv.D.Bytes())
	return sha3.Sum256(x.Bytes()), nil
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

	if len(signature) != int(orderSize*2) {
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
	if len(signature) != int(orderSize*2)+1 {
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
