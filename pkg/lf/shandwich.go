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
	"crypto/aes"
	"crypto/sha256"
	"hash"
	"hash/fnv"
)

// Shandwich256 combines AES and SHA-256 for a more future-proof 256-bit hash.
func Shandwich256(in []byte) (h [32]byte) {
	h2 := fnv.New128a()
	h2.Write(in)
	var tmp [16]byte
	c, _ := aes.NewCipher(h2.Sum(tmp[:0]))
	h = sha256.Sum256(in)
	c.Encrypt(h[0:16], h[0:16])
	c.Encrypt(h[16:32], h[16:32])
	return
}

// Shandwich256Hasher is a hash.Hash implementation for Shandwich256.
type Shandwich256Hasher [2]hash.Hash

// NewShandwich256 creates a new hash.Hash that implements Shandwich256.
func NewShandwich256() *Shandwich256Hasher { return &Shandwich256Hasher{sha256.New(), fnv.New128a()} }

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

// BlockSize returns the block size of SHA-256.
func (h *Shandwich256Hasher) BlockSize() int { return sha256.BlockSize }

// Sum computes the 256-bit Shandwich256 sum of the current input.
func (h *Shandwich256Hasher) Sum(b []byte) []byte {
	var tmp [16]byte
	c, _ := aes.NewCipher(h[1].Sum(tmp[:0]))
	h256 := h[0].Sum(b)
	c.Encrypt(h256[0:16], h256[0:16])
	c.Encrypt(h256[16:32], h256[16:32])
	return h256
}
