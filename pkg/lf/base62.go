/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"bytes"
	"errors"
)

var base62Encoding, _ = newBaseXEncoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")

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

func (e *baseXEncoding) decode(source string) ([]byte, error) {
	if len(source) == 0 {
		return []byte{}, nil
	}
	runes := []rune(source)
	bytes := []byte{0}
	for i := 0; i < len(source); i++ {
		value, ok := e.alphabetMap[runes[i]]
		if ok { // ignore non-base characters
			carry := int(value)
			for j := 0; j < len(bytes); j++ {
				carry += int(bytes[j]) * e.base
				bytes[j] = byte(carry & 0xff)
				carry >>= 8
			}
			for carry > 0 {
				bytes = append(bytes, byte(carry&0xff))
				carry >>= 8
			}
		}
	}
	for k := 0; runes[k] == e.alphabet[0] && k < len(runes)-1; k++ {
		bytes = append(bytes, 0)
	}
	for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}
	return bytes, nil
}

// Base62Encode encodes a byte array in base62 form
func Base62Encode(in []byte) string { return base62Encoding.encode(in) }

// Base62Decode decodes a base62 string into a byte array, ignoring all non-base62 characters
func Base62Decode(in string) ([]byte, error) { return base62Encoding.decode(in) }
