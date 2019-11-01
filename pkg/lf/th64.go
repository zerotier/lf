/*
 * Copyright (c)2019 ZeroTier, Inc.
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file in the project's root directory.
 *
 * Change Date: 2023-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2.0 of the Apache License.
 */
/****/

package lf

import (
	"crypto/aes"
	"encoding/binary"
	"unsafe"
)

// AES for AES-MMO with an arbitrary random 128-bit key.
var th64Aes, _ = aes.NewCipher([]byte{1, 200, 16, 93, 99, 101, 16, 4, 99, 202, 255, 254, 22, 17, 42, 173})

// th64 computes a tiny 64-bit hash using AES in a simple Matyas-Meyer-Oseas construction.
// See: https://en.wikipedia.org/wiki/One-way_compression_function#Matyas–Meyer–Oseas
func th64(i uint64) uint64 {
	var in, out [16]byte
	binary.LittleEndian.PutUint64(in[0:8], i)
	th64Aes.Encrypt(out[:], in[:])
	return binary.LittleEndian.Uint64(out[0:8]) ^ binary.LittleEndian.Uint64(out[8:16]) ^ i
}

// th64n performs TH64 count times and is a bit faster than just repeatedly calling TH64.
func th64n(i uint64, count uint) uint64 {
	var in, out [2]uint64
	inb := ((*[16]byte)(unsafe.Pointer(&in)))[:]
	outb := ((*[16]byte)(unsafe.Pointer(&out)))[:]
	binary.LittleEndian.PutUint64(inb[0:8], i)
	for k := uint(0); k < count; k++ {
		th64Aes.Encrypt(outb, inb)
		in[0] ^= out[0] ^ out[1]
	}
	return binary.LittleEndian.Uint64(inb[0:8])
}
