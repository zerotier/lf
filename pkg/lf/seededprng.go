package lf

import (
	"crypto/sha256"
	"crypto/sha512"
	"sync"
)

// seededPrng is a deterministic cryptographic random Reader used to generate key pairs from specific seeds.
type seededPrng struct {
	lock  sync.Mutex
	state [64]byte // private state
	buf   [32]byte // public buffer filled from state
	i     uint
}

func (s *seededPrng) seed(b []byte) {
	s.lock.Lock()
	s.state = sha512.Sum512(b)
	s.buf = sha256.Sum256(s.state[:])
	s.i = 0
	s.lock.Unlock()
}

func (s *seededPrng) Read(b []byte) (int, error) {
	s.lock.Lock()
	for i := 0; i < len(b); i++ {
		if s.i == 32 {
			s.i = 0
			s.state = sha512.Sum512(s.state[:])
			s.buf = sha256.Sum256(s.state[:])
		}
		b[i] = s.buf[s.i]
		s.i++
	}
	s.lock.Unlock()
	return len(b), nil
}
