package lf

import (
	"crypto/aes"
	"crypto/sha512"
)

// Shandwich256 computes a compound hash using SHA512, SHA384, and AES
// This is designed to provide what will hopefully be an ultimately future-proof hash resistant to breaks
// of either SHA-2 or AES (but not both). The function's name comes from the use of the middle hash to
// key AES for use on the final outer hash.
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
