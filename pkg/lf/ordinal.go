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
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"math/big"
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

var bigInt0 = big.NewInt(0)

// Set sets this ordinal to a sortable masked value that hides the original value (to some degree).
// This is basically an order preserving keyed hash. If the values are sequential or nearly so,
// an attacker could guess them after collecting a number of these. Where this helps is in
// protecting the privacy of non-sequential ordinals that might be something a user wants
// to keep secret (e.g. a ZeroTier node address or network ID). In that case guessing the ordinal
// would be quite difficult. Sequential ordinals are typically not private information anyway.
func (b *Ordinal) Set(value uint64, key []byte) {
	var bi, bit big.Int

	keyHash := md5.Sum(key) // MD5's issues don't matter here -- we just want 128 pseudorandom bits
	bi.SetBytes(keyHash[:])

	for i := 0; i < 16; i++ {
		keyHash[i] = ^keyHash[i]
	}
	keyHash[0] &= 0x0f
	bit.SetBytes(keyHash[:])

	for i := 0; i < 64; i++ {
		bit.Rsh(&bit, 1)
		if (value >> 63) != 0 {
			bi.Add(&bi, &bit)
		}
		value <<= 1
	}

	if bit.Rsh(&bit, 1).Cmp(bigInt0) > 0 {
		binary.BigEndian.PutUint64(keyHash[0:8], value)
		keyHash = md5.Sum(keyHash[:]) // generate a random 64-bit int based on key + value
		var tmp big.Int
		bi.Add(&bi, tmp.Mod(tmp.SetUint64(binary.BigEndian.Uint64(keyHash[0:8])), &bit))
	}

	bb := bi.Bytes()
	for i, j := 0, 16-len(bb); i < j; i++ {
		b[i] = 0
	}
	copy(b[16-len(bb):], bb[:])
}
