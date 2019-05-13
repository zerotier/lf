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
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"sort"
	"unsafe"
)

// OrdinalSize is the size of an ordinal in bytes.
const OrdinalSize = 16

// Ordinal is the somewhat-blinded (via a randomized substitution cipher) sortable/comparable part of a selector.
type Ordinal [16]byte

// MarshalJSON returns this blob marshaled as a \bbase62-encoded string (like a non-UTF8 Blob).
func (b *Ordinal) MarshalJSON() ([]byte, error) {
	return []byte("\"\\b" + Base62Encode(b[:]) + "\""), nil
}

// UnmarshalJSON unmarshals this blob from a JSON array or string
func (b *Ordinal) UnmarshalJSON(j []byte) error {
	if len(j) == 0 {
		for i := range b {
			b[i] = 0
		}
		return nil
	}

	var err error
	var bb []byte

	// Default is \bbase62string
	var str string
	err = json.Unmarshal(j, &str)
	if err == nil {
		if len(str) > 0 && str[0] == '\b' {
			bb = Base62Decode(str[1:])
		} else {
			bb = []byte(str) // be consistent with Blob even though an ordinal won't satisfy this that often
		}
	}

	// Byte arrays are also accepted
	if err != nil {
		if json.Unmarshal(j, &bb) != nil {
			return err
		}
	}

	i := 0
	for i < len(bb) && i < 16 {
		b[i] = bb[i]
		i++
	}
	for i < 16 {
		b[i] = 0
		i++
	}
	return nil
}

func ordinalMakeAlphabet(alphabet *[2048]uint16, key []byte) {
	keyHash := sha256.Sum256(key)
	c, _ := aes.NewCipher(keyHash[:])

	// Generate 8 unique alphabets of 256 16-bit values that are unique and sorted in ascending order.
	// Each unique alphabet "stripe" corresponds to one byte of the ordinal.
	for stripeNo := 0; stripeNo < 8; stripeNo++ {
		var cin [16]byte
		cin[15] = byte(stripeNo)

	tryNext:
		for {
			stripe := alphabet[256*stripeNo : 256*(stripeNo+1)]

			// Generate a random 16-bit alphabet for this stripe of the overall alphabet.
			stripeBytes := (*[512]byte)(unsafe.Pointer(&stripe[0]))
			for stripeBlockNo := 0; stripeBlockNo < 32; stripeBlockNo++ {
				cin[14] = byte(stripeBlockNo)
				c.Encrypt(stripeBytes[16*stripeBlockNo:16*(stripeBlockNo+1)], cin[:])
			}

			// Sort this alphabet in ascending word order.
			sort.Slice(stripe, func(a, b int) bool { return stripe[a] < stripe[b] })

			// If every word in this alphabet stripe is not unique, we increment the AES input's least
			// significant 64 bits and try again. This is deterministic from the key, so we'll get
			// the same alphabet every time for a given key.
			for i := 1; i < 256; i++ {
				if stripe[i] == stripe[i-1] {
					for i := 0; i < 8; i++ {
						cin[i]++
						if cin[i] != 0 {
							break
						}
					}
					continue tryNext
				}
			}
			break
		}
	}
}

// Set sets this ordinal to a sortable value computed from a 64-bit plain text integer using a random set of alphabets generated from the key.
func (b *Ordinal) Set(value uint64, key []byte) {
	var alphabet [2048]uint16
	ordinalMakeAlphabet(&alphabet, key)
	var vb [8]byte
	binary.BigEndian.PutUint64(vb[:], value)
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint16(b[2*i:2*(i+1)], alphabet[(i*256)+int(vb[i])])
	}
}
