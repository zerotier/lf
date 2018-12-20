package lf

import (
	"crypto/aes"
	"crypto/sha512"
)

// Shandwich256 computes a 256-bit compound hash using SHA512, SHA384, and AES.
// This is designed to provide an extremely future-proof hash function resistant to even full breaks
// of either SHA-2 or AES. Its name comes from the use of SHA on both sides with AES keyed from the
// hidden middle state.
func Shandwich256(in []byte) (out [32]byte) {
	s512 := sha512.Sum512(in)
	s384 := sha512.Sum384(s512[:])
	c, _ := aes.NewCipher(s512[0:32])
	c.Encrypt(out[0:16], s384[0:16])
	c.Encrypt(out[16:32], s384[16:32])
	for i := 0; i < 32; i++ {
		out[i] ^= s384[i]
	}
	return
}

// Shandwich256FromSha512 computes Shandwich256 starting from a pre-existing SHA512 hash of an input.
func Shandwich256FromSha512(s512 []byte) (out [32]byte) {
	s384 := sha512.Sum384(s512[:])
	c, _ := aes.NewCipher(s512[0:32])
	c.Encrypt(out[0:16], s384[0:16])
	c.Encrypt(out[16:32], s384[16:32])
	for i := 0; i < 32; i++ {
		out[i] ^= s384[i]
	}
	return
}
