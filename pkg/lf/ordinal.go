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
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"runtime"
	"sort"
	"sync"
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

var ordinalAlphabetPool = sync.Pool{
	New: func() interface{} {
		return make([]uint32, 16384, 16384)
	},
}

func ordinal32to16(valueMaskedToColumn uint64, columnValue uint32, kk int, keyHash *[64]byte) uint {
	var rnb [16]byte
	c, _ := aes.NewCipher(keyHash[16*kk : 16*(kk+1)])

	alphabet := ordinalAlphabetPool.Get().([]uint32)
	_ = alphabet[16383]

	for {
	StartOver:
		for {
			c.Encrypt(rnb[:], rnb[:])
			rangeSize := uint32(0xffffffff / 16384)
			last := binary.LittleEndian.Uint32(rnb[:]) % rangeSize
			alphabet[0] = last
			for i := 1; i < 16384; i++ {
				rni := i & 3
				if rni == 0 {
					c.Encrypt(rnb[:], rnb[:])
				}
				rangeSize = ^last / uint32(16384-i)
				if rangeSize == 0 {
					continue StartOver
				}
				last = (binary.LittleEndian.Uint32(rnb[rni<<2:]) % rangeSize) + last + 1
				alphabet[i] = last
			}
			break
		}

		for i := 1; i < 16384; i++ {
			ai := alphabet[i]
			diff := ai - alphabet[i-1]
			if diff < 16 || diff > ai {
				alphabet[i] += 0x00000010
			}
		}

		if alphabet[16383] > alphabet[0] {
			base := sort.Search(16384, func(a int) bool { return alphabet[a] >= columnValue })
			if base > 0 {
				base--
			}

			rv := alphabet[base]
			var rvRangePerStep uint32
			if base == 16383 {
				rvRangePerStep = ^rv
			} else {
				rvRangePerStep = alphabet[base+1] - rv
			}
			rvRangePerStep >>= 2 // /4

			ordinalAlphabetPool.Put(alphabet)
			return uint(base<<2) + uint((columnValue-rv)/rvRangePerStep)
		}
	}
}

func ordinal16to32(wg *sync.WaitGroup, valueMaskedToColumn uint64, columnValue uint, kk int, keyHash *[64]byte, result *[4]uint32) {
	var rnb [16]byte
	c, _ := aes.NewCipher(keyHash[16*kk : 16*(kk+1)])

	alphabet := ordinalAlphabetPool.Get().([]uint32)
	_ = alphabet[16383]

	for {
		// This generates random numbers in ascending order. It generates a
		// somewhat skewed distribution, but we don't really care. It's
		// good enough for this use case.
	StartOver:
		for {
			c.Encrypt(rnb[:], rnb[:])
			rangeSize := uint32(0xffffffff / 16384)
			last := binary.LittleEndian.Uint32(rnb[:]) % rangeSize
			alphabet[0] = last
			for i := 1; i < 16384; i++ {
				rni := i & 3
				if rni == 0 {
					c.Encrypt(rnb[:], rnb[:])
				}
				rangeSize = ^last / uint32(16384-i)
				if rangeSize == 0 {
					continue StartOver
				}
				last = (binary.LittleEndian.Uint32(rnb[rni<<2:]) % rangeSize) + last + 1
				alphabet[i] = last
			}
			break
		}

		// Make sure all values have a gap of at least 16.
		for i := 1; i < 16384; i++ {
			ai := alphabet[i]
			diff := ai - alphabet[i-1]
			if diff < 16 || diff > ai {
				alphabet[i] += 0x00000010
			}
		}

		if alphabet[16383] > alphabet[0] {
			base := columnValue >> 2

			rv := alphabet[base]
			var rvRangePerStep uint32
			if base == 16383 {
				rvRangePerStep = ^rv
			} else {
				rvRangePerStep = alphabet[base+1] - rv
			}
			rvRangePerStep >>= 2 // /4

			rv += rvRangePerStep * uint32(columnValue&3)
			binary.LittleEndian.PutUint64(rnb[0:8], valueMaskedToColumn)
			c.Encrypt(rnb[:], rnb[:])
			rv += binary.LittleEndian.Uint32(rnb[:]) % rvRangePerStep

			result[kk] = rv

			ordinalAlphabetPool.Put(alphabet)
			if wg != nil {
				wg.Done()
			}
			return
		}
	}
}

// Set sets this ordinal to a sortable masked value that hides the original value (somewhat).
func (b *Ordinal) Set(value uint64, key []byte) {
	var result [4]uint32

	keyHash := sha512.Sum512(key)

	switch runtime.NumCPU() {
	case 0, 1:
		ordinal16to32(nil, 0, uint((value>>48)&0xffff), 0, &keyHash, &result)
		ordinal16to32(nil, value&0xffff000000000000, uint((value>>32)&0xffff), 1, &keyHash, &result)
		ordinal16to32(nil, value&0xffffffff00000000, uint((value>>16)&0xffff), 2, &keyHash, &result)
		ordinal16to32(nil, value&0xffffffffffff0000, uint(value&0xffff), 3, &keyHash, &result)
	case 2, 3:
		var wg sync.WaitGroup
		wg.Add(2)
		go ordinal16to32(&wg, 0, uint((value>>48)&0xffff), 0, &keyHash, &result)
		ordinal16to32(nil, value&0xffff000000000000, uint((value>>32)&0xffff), 1, &keyHash, &result)
		go ordinal16to32(&wg, value&0xffffffff00000000, uint((value>>16)&0xffff), 2, &keyHash, &result)
		ordinal16to32(nil, value&0xffffffffffff0000, uint(value&0xffff), 3, &keyHash, &result)
		wg.Wait()
	default:
		var wg sync.WaitGroup
		wg.Add(3)
		go ordinal16to32(&wg, 0, uint((value>>48)&0xffff), 0, &keyHash, &result)
		go ordinal16to32(&wg, value&0xffff000000000000, uint((value>>32)&0xffff), 1, &keyHash, &result)
		go ordinal16to32(&wg, value&0xffffffff00000000, uint((value>>16)&0xffff), 2, &keyHash, &result)
		ordinal16to32(nil, value&0xffffffffffff0000, uint(value&0xffff), 3, &keyHash, &result)
		wg.Wait()
	}

	binary.BigEndian.PutUint32(b[0:4], result[0])
	binary.BigEndian.PutUint32(b[4:8], result[1])
	binary.BigEndian.PutUint32(b[8:12], result[2])
	binary.BigEndian.PutUint32(b[12:16], result[3])
}

// Get reverses Set and returns the original 64-bit ordinal.
func (b *Ordinal) Get(key []byte) (v uint64) {
	// This one can't be parallelized since each computation depends on the previous one.
	keyHash := sha512.Sum512(key)
	v = uint64(ordinal32to16(0, binary.BigEndian.Uint32(b[0:4]), 0, &keyHash)) << 48
	v |= uint64(ordinal32to16(v, binary.BigEndian.Uint32(b[4:8]), 1, &keyHash)) << 32
	v |= uint64(ordinal32to16(v, binary.BigEndian.Uint32(b[8:12]), 2, &keyHash)) << 16
	v |= uint64(ordinal32to16(v, binary.BigEndian.Uint32(b[12:16]), 3, &keyHash))
	return
}
