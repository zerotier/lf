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
	"hash"

	"golang.org/x/crypto/sha3"
)

// Shandwich256 uses AES to combine the results of SHA256 and SHA3-256 to yield a very future-proof hash.
func Shandwich256(in []byte) (h [32]byte) {
	h = sha256.Sum256(in)
	hs3 := sha3.Sum256(in)
	c, _ := aes.NewCipher(hs3[:])
	c.Encrypt(h[0:16], h[0:16])
	c.Encrypt(h[16:32], h[16:32])
	return
}

// Shandwich256Hasher is a hash.Hash implementation for Shandwich256.
type Shandwich256Hasher [2]hash.Hash

// NewShandwich256 creates a new hash.Hash that implements Shandwich256.
func NewShandwich256() *Shandwich256Hasher { return &Shandwich256Hasher{sha256.New(), sha3.New256()} }

// Write hashes in[]
func (h *Shandwich256Hasher) Write(in []byte) (int, error) {
	h[0].Write(in)
	h[1].Write(in)
	return len(in), nil
}

// Reset resets this instance to be used again.
func (h *Shandwich256Hasher) Reset() {
	h[0].Reset()
	h[1].Reset()
}

// Size returns the size of Sum()'s output.
func (h *Shandwich256Hasher) Size() int { return 32 }

// BlockSize returns the block size of one of the two hashes and isn't that meaningful here.
func (h *Shandwich256Hasher) BlockSize() int { return h[0].BlockSize() } // not really correct but nothing in our code cares about this

// Sum computes the 256-bit Shandwich256 sum of the current input.
func (h *Shandwich256Hasher) Sum(b []byte) []byte {
	h256 := h[0].Sum(b)
	var hs3 [32]byte
	h[1].Sum(hs3[:0])
	c, _ := aes.NewCipher(hs3[:])
	c.Encrypt(h256[0:16], h256[0:16])
	c.Encrypt(h256[16:32], h256[16:32])
	return h256
}
