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
)

// OrdinalSize is the size of an ordinal in bytes.
const OrdinalSize = 16

// Ordinal is the sortable/comparable part of a selector.
// It consists of a 64-bit integer masked using a simple order-preserving keyed hash.
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

// Set sets this ordinal to a sortable masked value that hides the original value (to some degree).
func (b *Ordinal) Set(value uint64, key []byte) {
	kh := sha256.Sum256(key)
	kh[0]++ // make sure this is never the same AES key as seededPrng just to be safe
	c, _ := aes.NewCipher(kh[:])
	for i := range kh {
		kh[i] = 0
	}
	c.Encrypt(kh[0:16], kh[0:16])
	c.Encrypt(kh[16:32], kh[16:32])
	hi := 0
	for vi := 0; vi < 8; vi++ {
		vb := uint(value >> 56)
		value <<= 8
		col := uint16(kh[hi])
		hi++
		if hi == 32 {
			c.Encrypt(kh[0:16], kh[0:16])
			c.Encrypt(kh[16:32], kh[16:32])
			hi = 0
		}
		for i := uint(0); i < vb; i++ {
			col += 1 + uint16(kh[hi])
			hi++
			if hi == 32 {
				c.Encrypt(kh[0:16], kh[0:16])
				c.Encrypt(kh[16:32], kh[16:32])
				hi = 0
			}
		}
		binary.BigEndian.PutUint16(b[2*vi:2*(vi+1)], col)
	}
}
