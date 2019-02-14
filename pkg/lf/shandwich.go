/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/sha3"
)

// Shandwich256 uses sha256 to combine the outputs of sha512 and sha3-512 for a very future-proof 256-bit hash.
// This is used to compute record identity hashes and in a few other critical spots where changing the hash
// function would be painful and disruptive. It provides a very future-proof hash where a significant break of either
// SHA2-512 or SHA3 would be relatively inconsequential since an attacker would have to successfully attack both.
// A major break of SHA2-256 would also not matter much since we just use it to combine outputs in a nonlinear way.
func Shandwich256(in []byte) (h [32]byte) {
	h0 := sha512.Sum512(in)
	h1 := sha3.Sum512(in)
	combiner := sha256.New()
	combiner.Write(h0[:])
	combiner.Write(h1[:])
	combiner.Sum(h[:0])
	return
}

type shandwich256Hasher [2]hash.Hash

// NewShandwich256 creates a new hash.Hash that implements Shandwich256.
func NewShandwich256() hash.Hash { return &shandwich256Hasher{sha512.New(), sha3.New512()} }

func (h *shandwich256Hasher) Write(in []byte) (int, error) {
	h[0].Write(in)
	h[1].Write(in)
	return len(in), nil
}

func (h *shandwich256Hasher) Reset() {
	h[0].Reset()
	h[1].Reset()
}

func (h *shandwich256Hasher) Size() int { return 32 }

func (h *shandwich256Hasher) BlockSize() int { return h[0].BlockSize() } // not really correct but nothing in our code cares about this

func (h *shandwich256Hasher) Sum(b []byte) []byte {
	var hbuf [128]byte
	combined := sha256.Sum256(h[1].Sum(h[0].Sum(hbuf[:0])))
	return append(b, combined[:]...)
}
