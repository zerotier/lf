/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"crypto/aes"
	"crypto/sha256"
	"crypto/sha512"
)

// Shandwich256 computes a 256-bit compound hash using SHA512, SHA256, and AES.
// This is designed to provide an extremely future-proof hash function resistant to even full breaks
// of any single algorithm. Its name comes from the use of SHA on both sides with AES keyed from the
// hidden middle state.
func Shandwich256(in []byte) (out [32]byte) {
	s512 := sha512.Sum512(in)
	s256 := sha256.Sum256(s512[:])
	c, _ := aes.NewCipher(s512[0:32])
	c.Encrypt(out[0:16], s256[0:16])
	c.Encrypt(out[16:32], s256[16:32])
	for i := 0; i < 32; i++ {
		out[i] ^= s256[i]
	}
	return
}

// Shandwich256FromSha512 computes Shandwich256 starting from a pre-existing SHA512 hash of an input.
// This is useful if you want to instantiate SHA512 and hash from a stream and then compute a final
// hash at the end.
func Shandwich256FromSha512(s512 []byte) (out [32]byte) {
	s256 := sha256.Sum256(s512[:])
	c, _ := aes.NewCipher(s512[0:32])
	c.Encrypt(out[0:16], s256[0:16])
	c.Encrypt(out[16:32], s256[16:32])
	for i := 0; i < 32; i++ {
		out[i] ^= s256[i]
	}
	return
}
