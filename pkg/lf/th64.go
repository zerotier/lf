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
	"encoding/binary"
	"unsafe"
)

var th64Aes, _ = aes.NewCipher([]byte{1, 200, 16, 93, 99, 101, 16, 4, 99, 202, 255, 254, 22, 17, 42, 173})

// TH64 computes a tiny 64-bit hash using AES in Matyas-Meyer-Oseas mode.
// See: https://en.wikipedia.org/wiki/One-way_compression_function#Matyas–Meyer–Oseas
func TH64(i uint64) uint64 {
	var in, out [16]byte
	binary.LittleEndian.PutUint64(in[0:8], i)
	th64Aes.Encrypt(out[:], in[:])
	return (binary.LittleEndian.Uint64(out[0:8]) ^ binary.LittleEndian.Uint64(out[8:16]) ^ i)
}

// TH64N performs TH64 count times and is a bit faster than just repeatedly calling TH64.
func TH64N(i uint64, count int) uint64 {
	var in, out [16]byte
	binary.LittleEndian.PutUint64(in[0:8], i)
	for k := 0; k < count; k++ {
		th64Aes.Encrypt(out[:], in[:])
		*((*uint64)(unsafe.Pointer(&in[0]))) ^= *((*uint64)(unsafe.Pointer(&out[0]))) ^ *((*uint64)(unsafe.Pointer(&out[8])))
	}
	return binary.LittleEndian.Uint64(in[0:8])
}
