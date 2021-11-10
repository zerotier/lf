/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c)2019-2021 ZeroTier, Inc.
 * https://www.zerotier.com/
 */

package lf

import (
	"bytes"
	"errors"
)

// Base62Alphabet is the alphabet used for LF's Base62 encoding.
const Base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var base62Encoding, _ = newBaseXEncoding(Base62Alphabet)

type baseXEncoding struct {
	base        int
	alphabet    []rune
	alphabetMap map[rune]int
}

func newBaseXEncoding(alphabet string) (*baseXEncoding, error) {
	runes := []rune(alphabet)
	runeMap := make(map[rune]int)
	for i := 0; i < len(runes); i++ {
		if _, ok := runeMap[runes[i]]; ok {
			return nil, errors.New("bad alphabet")
		}
		runeMap[runes[i]] = i
	}
	return &baseXEncoding{
		base:        len(runes),
		alphabet:    runes,
		alphabetMap: runeMap,
	}, nil
}

func (e *baseXEncoding) encode(source []byte) string {
	if len(source) == 0 {
		return ""
	}
	digits := []int{0}
	for i := 0; i < len(source); i++ {
		carry := int(source[i])
		for j := 0; j < len(digits); j++ {
			carry += digits[j] << 8
			digits[j] = carry % e.base
			carry = carry / e.base
		}
		for carry > 0 {
			digits = append(digits, carry%e.base)
			carry = carry / e.base
		}
	}
	var res bytes.Buffer
	for k := 0; source[k] == 0 && k < len(source)-1; k++ {
		res.WriteRune(e.alphabet[0])
	}
	for q := len(digits) - 1; q >= 0; q-- {
		res.WriteRune(e.alphabet[digits[q]])
	}
	return res.String()
}

func (e *baseXEncoding) decode(source string) []byte {
	if len(source) == 0 {
		return nil
	}
	runes := []rune(source)
	decodedBytes := []byte{0}
	for i := 0; i < len(source); i++ {
		value, ok := e.alphabetMap[runes[i]]
		if ok { // ignore non-base characters
			carry := value
			for j := 0; j < len(decodedBytes); j++ {
				carry += int(decodedBytes[j]) * e.base
				decodedBytes[j] = byte(carry & 0xff)
				carry >>= 8
			}
			for carry > 0 {
				decodedBytes = append(decodedBytes, byte(carry&0xff))
				carry >>= 8
			}
		}
	}
	for k := 0; runes[k] == e.alphabet[0] && k < len(runes)-1; k++ {
		decodedBytes = append(decodedBytes, 0)
	}
	for i, j := 0, len(decodedBytes)-1; i < j; i, j = i+1, j-1 {
		decodedBytes[i], decodedBytes[j] = decodedBytes[j], decodedBytes[i]
	}
	return decodedBytes
}

// Base62Encode encodes a byte array in base62 form
func Base62Encode(in []byte) string { return base62Encoding.encode(in) }

// Base62Decode decodes a base62 string into a byte array, ignoring non-base62 characters
func Base62Decode(in string) []byte { return base62Encoding.decode(in) }
