package lf

import (
	"crypto/sha512"

	"golang.org/x/crypto/sha3"
)

// seededPrng is a deterministic cryptographic random Reader used to generate key pairs from specific seeds.
// This is used for seeded mode in the owner API and for selector creation from plain text names.
type seededPrng struct {
	state [64]byte
	block [64]byte
	i     int
}

func (s *seededPrng) seed(b []byte) {
	s.state = sha3.Sum512(b)
	s.block = sha512.Sum512(s.state[:])
	s.i = 0
}

func (s *seededPrng) Read(b []byte) (int, error) {
	for k := 0; k < len(b); k++ {
		b[k] = s.block[s.i]
		s.i++
		if s.i == 64 {
			s.i = 0
			s.state = sha3.Sum512(s.state[:])
			s.block = sha512.Sum512(s.state[:])
		}
	}
	return len(b), nil
}
