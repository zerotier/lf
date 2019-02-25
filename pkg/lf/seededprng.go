package lf

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

// seededPrng is a deterministic cryptographic random Reader used to generate key pairs from specific seeds.
type seededPrng struct {
	c cipher.Block
	n uint64
	b [16]byte
	i int
}

func (s *seededPrng) seed(b []byte) {
	sk := sha3.Sum384(b)
	s.c, _ = aes.NewCipher(sk[0:32])
	s.n = binary.BigEndian.Uint64(sk[32:40])
	s.i = 16
}

func (s *seededPrng) Read(b []byte) (int, error) {
	var tmp [16]byte
	i := s.i
	for k := 0; k < len(b); k++ {
		if i == 16 {
			i = 0
			s.n++
			binary.BigEndian.PutUint64(tmp[0:8], s.n)
			s.c.Encrypt(s.b[:], tmp[:])
		}
		b[k] = s.b[i]
		i++
	}
	s.i = i
	return len(b), nil
}
