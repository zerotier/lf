package lf

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
)

// Blob is a byte array that JSON serializes to something more user-friendly than just always a base64 blob.
type Blob []byte

var jsonEmptyStr = []byte("\"\"")

// MarshalJSON returns this blob as a JSON object.
func (b Blob) MarshalJSON() ([]byte, error) {
	if len(b) == 0 {
		return jsonEmptyStr, nil
	}
	var s strings.Builder
	s.WriteRune('"')
	for _, c := range b {
		if (c <= 31 && c != 9 && c != 10 && c != 13) || c >= 127 {
			// String is binary, so output as either an array (for short values) or base64 (for longer values)
			var sb strings.Builder
			if len(b) <= 32 {
				sb.WriteRune('[')
				sb.WriteString(strconv.FormatUint(uint64(b[0]), 10))
				for i := 1; i < len(b); i++ {
					sb.WriteRune(',')
					sb.WriteString(strconv.FormatUint(uint64(b[i]), 10))
				}
				sb.WriteRune(']')
				return []byte(sb.String()), nil
			}
			sb.WriteString("\"\\b")
			sb.WriteString(base64.StdEncoding.EncodeToString(b))
			sb.WriteRune('"')
			return []byte(sb.String()), nil
		}

		switch c {
		case 9:
			s.WriteString("\\t")
		case 10:
			s.WriteString("\\n")
		case 13:
			s.WriteString("\\t")
		case 34:
			s.WriteString("\\\"")
		case 92:
			s.WriteString("\\\\")
		default:
			s.WriteRune(rune(c))
		}
	}
	s.WriteRune('"')
	return []byte(s.String()), nil
}

// UnmarshalJSON unmarshals this blob from a JSON array, string, or base64 string prefixed by a backspace (ascii 8, string "\b").
func (b *Blob) UnmarshalJSON(j []byte) error {
	if len(j) == 0 {
		*b = []byte{}
		return nil
	}
	var str string
	err := json.Unmarshal(j, &str)
	if err != nil {
		var arr []int
		err = json.Unmarshal(j, &arr)
		if err != nil {
			return err
		}
		*b = make([]byte, len(arr))
		for i := range arr {
			(*b)[i] = byte(arr[i])
		}
		return nil
	}
	if str[0] == 8 && len(str) > 1 {
		*b, err = base64.StdEncoding.DecodeString(str[1:])
		return err
	}
	*b = []byte(str)
	return nil
}

// Blob256 is a 256-bit / 32 byte Blob that always serializes to a JSON array.
type Blob256 [32]byte

// MarshalJSON returns this blob as a JSON object.
func (b *Blob256) MarshalJSON() ([]byte, error) {
	var s strings.Builder
	s.WriteRune('[')
	s.WriteString(strconv.FormatUint(uint64(b[0]), 10))
	for i := 1; i < 32; i++ {
		s.WriteRune(',')
		s.WriteString(strconv.FormatUint(uint64(b[i]), 10))
	}
	s.WriteRune(']')
	return []byte(s.String()), nil
}

// UnmarshalJSON unmarshals this Blob256, supporting all the formats supported by Blob.
func (b *Blob256) UnmarshalJSON(j []byte) error {
	var b2 Blob
	err := b2.UnmarshalJSON(j)
	if err != nil {
		return err
	}
	if len(b2) >= 32 {
		copy(b[:], b2[0:32])
	} else {
		copy(b[:], b2)
		for i := len(b2); i < 32; i++ {
			b[i] = 0
		}
	}
	return nil
}
