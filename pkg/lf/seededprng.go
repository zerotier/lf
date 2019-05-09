/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
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
	lock sync.Mutex
	c    cipher.Block
	n    uint64
	i    uint
	b    [16]byte
}

func (s *seededPrng) seed(b []byte) {
	k := sha256.Sum256(b)
	s.c, _ = aes.NewCipher(k[:])
	s.n = 0
	s.i = 16
}

func (s *seededPrng) Read(b []byte) (int, error) {
	var tmp [16]byte
	s.lock.Lock()
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
	s.lock.Unlock()
	return len(b), nil
}
