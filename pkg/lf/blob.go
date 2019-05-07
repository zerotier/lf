/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"encoding/json"
	"errors"
)

var hexChars = [16]byte{48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102}

// Blob is a byte array that serializes to a string.
type Blob []byte

// MarshalJSON returns this blob marshaled as a string.
func (b Blob) MarshalJSON() ([]byte, error) {
	ba := make([]byte, 1, len(b)*2)
	ba[0] = 34
	for _, c := range b {
		switch c {
		case 8:
			ba = append(ba, 92, 98) // \b
		case 9:
			ba = append(ba, 92, 116) // \t
		case 10:
			ba = append(ba, 92, 110) // \n
		case 12:
			ba = append(ba, 92, 102) // \f
		case 13:
			ba = append(ba, 92, 114) // \r
		case 34:
			ba = append(ba, 92, 34) // \"
		case 47:
			ba = append(ba, 92, 47) // \/
		case 92:
			ba = append(ba, 92, 92) // \\
		default:
			if c >= 32 && c <= 126 {
				ba = append(ba, c)
			} else {
				ba = append(ba, 92, 117, 48, 48, hexChars[c>>4], hexChars[c&0xf]) // \u00xx
			}
		}
	}
	ba = append(ba, 34)
	return ba, nil
}

// UnmarshalJSON unmarshals this blob from a string or byte array.
func (b *Blob) UnmarshalJSON(j []byte) error {
	var s string
	err := json.Unmarshal(j, &s)
	if err == nil {
		bb := make([]byte, 0, len(s))
		for _, c := range s {
			bb = append(bb, byte(c))
		}
		*b = bb
	}

	// Byte arrays are also accepted
	var bb []byte
	if json.Unmarshal(j, &bb) != nil {
		return err
	}
	*b = bb
	return nil
}

//////////////////////////////////////////////////////////////////////////////

// OwnerBlob is a byte array that serializes to an @owner base58-encoded string.
type OwnerBlob []byte

// MarshalJSON returns this blob marshaled as a @owner base58-encoded string.
func (b OwnerBlob) MarshalJSON() ([]byte, error) {
	return []byte("\"@" + Base58Encode(b) + "\""), nil
}

// UnmarshalJSON unmarshals this blob from a JSON array or string
func (b *OwnerBlob) UnmarshalJSON(j []byte) error {
	if len(j) == 0 {
		*b = nil
		return nil
	}

	// Default is @base58string
	var err error
	var str string
	err = json.Unmarshal(j, &str)
	if err == nil {
		if len(str) > 1 && str[0] == '@' {
			*b, err = Base58Decode(str[1:])
			if err == nil {
				return nil
			}
		} else {
			err = errors.New("base58 string not prefixed by @ (for owner)")
		}
	}

	// Byte arrays are also accepted
	var bb []byte
	if json.Unmarshal(j, &bb) != nil {
		return err
	}
	*b = bb
	return nil
}

//////////////////////////////////////////////////////////////////////////////

// HashBlob is a 32-byte array that serializes to a =hash base58-encoded string.
type HashBlob [32]byte

// MarshalJSON returns this blob marshaled as a byte array or a string
func (b *HashBlob) MarshalJSON() ([]byte, error) {
	return []byte("\"=" + Base58Encode(b[:]) + "\""), nil
}

// UnmarshalJSON unmarshals this blob from a JSON array or string
func (b *HashBlob) UnmarshalJSON(j []byte) error {
	if len(j) == 0 {
		for i := range b {
			b[i] = 0
		}
		return nil
	}

	var err error
	var bb []byte

	// Default is =base58string
	var str string
	err = json.Unmarshal(j, &str)
	if err == nil {
		if len(str) > 1 && str[0] == '=' {
			bb, err = Base58Decode(str[1:])
		} else {
			err = errors.New("base58 string not prefixed by = (for exact record hash)")
		}
	}

	// Byte arrays are also accepted
	if err != nil {
		if json.Unmarshal(j, &bb) != nil {
			return err
		}
	}

	i := 0
	for i < len(bb) && i < 32 {
		b[i] = bb[i]
		i++
	}
	for i < 32 {
		b[i] = 0
		i++
	}
	return nil
}
