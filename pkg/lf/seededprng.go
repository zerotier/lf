package lf

import (
	"crypto/aes"
	"crypto/cipher"

	"golang.org/x/crypto/sha3"
)

// seededPrng is a deterministic cryptographic random Reader used to generate key pairs from specific seeds.
type seededPrng struct {
	c cipher.Block
	b [16]byte
	i int
}

func (s *seededPrng) seed(b []byte) {
	sk := sha3.Sum384(b)
	s.c, _ = aes.NewCipher(sk[16:48])
	s.c.Encrypt(s.b[:], sk[0:16])
	s.i = 0
}

func (s *seededPrng) Read(b []byte) (int, error) {
	i := s.i
	for k := 0; k < len(b); k++ {
		b[k] = s.b[i]
		i++
		if i == 15 {
			i = 0
			s.c.Encrypt(s.b[:], s.b[:])
		}
	}
	s.i = i
	return len(b), nil
}
