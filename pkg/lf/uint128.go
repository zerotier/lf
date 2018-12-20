package lf

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

// Uint128 is a big-endian 128-bit value that JSON serializes to a four-element array of 32-bit hex numbers.
type Uint128 [4]uint32

// MarshalJSON encodes this Uint128 as an array of four 32-bit integers.
func (b *Uint128) MarshalJSON() ([]byte, error) {
	s := make([]byte, 1, 64)
	s[0] = '['
	s = strconv.AppendUint(s, uint64((*b)[0]), 10)
	s = append(s, ',')
	s = strconv.AppendUint(s, uint64((*b)[1]), 10)
	s = append(s, ',')
	s = strconv.AppendUint(s, uint64((*b)[2]), 10)
	s = append(s, ',')
	s = strconv.AppendUint(s, uint64((*b)[3]), 10)
	s = append(s, ']')
	return s, nil
}

// Hex returns a 32-character hex representation of this Uint128.
func (b *Uint128) Hex() string {
	return fmt.Sprintf("%.8x%.8x%.8x%.8x", (*b)[0], (*b)[1], (*b)[2], (*b)[3])
}

// SetHex sets this Uint128 to a hex value.
func (b *Uint128) SetHex(h string) error {
	i := 3
	for len(h) >= 8 && i >= 0 {
		i64, err := strconv.ParseUint(h[len(h)-8:], 16, 64)
		if err != nil {
			return err
		}
		(*b)[i] = uint32(i64)
		i--
		h = h[0 : len(h)-8]
	}
	if len(h) > 0 && i >= 0 {
		i64, err := strconv.ParseUint(h, 16, 64)
		if err != nil {
			return err
		}
		(*b)[i] = uint32(i64)
		i--
	}
	for i >= 0 {
		(*b)[i] = 0
	}
	return nil
}

// Set sets this 128-bit value to the value specified by two 64-bit ints: the most significant and least significant quadword.
func (b *Uint128) Set(msq, lsq uint64) {
	(*b)[0] = uint32(msq >> 32)
	(*b)[1] = uint32(msq)
	(*b)[2] = uint32(lsq >> 32)
	(*b)[3] = uint32(lsq)
}

// Less returns true if this value is less than another 128-bit value.
func (b *Uint128) Less(i *Uint128) bool {
	if (*b)[0] < (*i)[0] {
		return true
	} else if (*b)[0] == (*i)[0] {
		if (*b)[1] < (*i)[1] {
			return true
		} else if (*b)[1] == (*i)[1] {
			if (*b)[2] < (*i)[2] {
				return true
			} else if (*b)[2] == (*i)[2] {
				return (*b)[3] < (*i)[3]
			}
		}
	}
	return false
}

// Bytes returns this 128-bit value as a 16 byte array in big-endian byte order.
func (b *Uint128) Bytes() (i [16]byte) {
	binary.BigEndian.PutUint32(i[0:4], (*b)[0])
	binary.BigEndian.PutUint32(i[4:8], (*b)[1])
	binary.BigEndian.PutUint32(i[8:12], (*b)[2])
	binary.BigEndian.PutUint32(i[12:16], (*b)[3])
	return
}

// Uint64 returns the least significant 64 bits in this Uint128.
func (b *Uint128) Uint64() uint64 {
	return ((uint64((*b)[2]) << 32) | uint64((*b)[3]))
}
