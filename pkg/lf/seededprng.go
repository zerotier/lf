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
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"sync"
)

// seededPrng is a deterministic cryptographic random Reader used to generate key pairs from specific seeds.
// This is effectively part of Selector and Owner and its spec is therefore a protocol constant.
// Note that the seeds in this case are themselves secrets, so you don't have to worry much here about
// a known-seed attack scenario. The only goal is to generate a random stream from a seed in a reproducible
// and strongly random way.
type seededPrng struct {
	l sync.Mutex
	c cipher.Block
	n uint64
	i uint
	b [16]byte
}

func (s *seededPrng) seed(b []byte) {
	k := sha256.Sum256(b)
	k[0] ^= k[1] // perturb hash slightly to ensure uniqueness of this AES key vs any other use of the same seed
	s.c, _ = aes.NewCipher(k[:])
	s.n = 0
	s.i = 16
}

func (s *seededPrng) Read(b []byte) (int, error) {
	var tmp [16]byte
	s.l.Lock()
	for i := 0; i < len(b); i++ {
		if s.i == 16 {
			s.i = 0
			binary.LittleEndian.PutUint64(tmp[0:8], s.n)
			s.n++
			s.c.Encrypt(s.b[:], tmp[:])
		}
		b[i] = s.b[s.i]
		s.i++
	}
	s.l.Unlock()
	return len(b), nil
}
