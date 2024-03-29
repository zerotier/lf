/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c)2019-2021 ZeroTier, Inc.
 * https://www.zerotier.com/
 */

package lf

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
)

// seededPrng is a deterministic cryptographic random Reader used to generate key pairs from specific seeds.
// This is used in various places to generate deterministic cryptographically strong random number sequences
// from known seeds. It's basically just AES-CTR. Its design should be considered a protocol constant.
type seededPrng struct {
	i uint
	c cipher.Block
	b [16]byte
	n [16]byte
}

func (s *seededPrng) seed(b []byte) {
	k := sha256.Sum256(b)
	k[8]++ // defensive precaution in case the same 'key' is used elsewhere to initialize AES from SHA256
	s.i = 16
	s.c, _ = aes.NewCipher(k[:])
	for i := range s.n {
		s.n[i] = 0
	}
}

func (s *seededPrng) Read(b []byte) (int, error) {
	for i := 0; i < len(b); i++ {
		if s.i == 16 {
			s.i = 0
			for j := 0; j < 16; j++ {
				s.n[j]++
				if s.n[j] != 0 {
					break
				}
			}
			s.c.Encrypt(s.b[:], s.n[:])
		}
		b[i] = s.b[s.i]
		s.i++
	}
	return len(b), nil
}
