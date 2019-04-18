package lf

import (
	"encoding/json"
	"strings"
)

var jsonEmptyStr = []byte("\"\"")
var emptyBytes = []byte{}
var jsonHexChars = []rune{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}

// binToJSONString escapes non-printable characters to generate a JSON string containing any binary data.
func binToJSONString(b []byte, s *strings.Builder) {
	for _, c := range b {
		switch c {
		case '\\', '"', '/':
			s.WriteRune('\\')
			s.WriteByte(c)
		case '\b':
			s.WriteRune('\\')
			s.WriteRune('b')
		case '\t':
			s.WriteRune('\\')
			s.WriteRune('t')
		case '\n':
			s.WriteRune('\\')
			s.WriteRune('n')
		case '\f':
			s.WriteRune('\\')
			s.WriteRune('f')
		case '\r':
			s.WriteRune('\\')
			s.WriteRune('r')
		default:
			if c <= 31 || c >= 127 {
				s.WriteRune('\\')
				s.WriteRune('u')
				s.WriteRune('0')
				s.WriteRune('0')
				s.WriteRune(jsonHexChars[c>>4])
				s.WriteRune(jsonHexChars[c&0xf])
			} else {
				s.WriteByte(c)
			}
		}
	}
}

// Blob is a byte array that JSON serializes to an escaped string instead of Base64.
type Blob []byte

// MarshalJSON returns this blob as a JSON object.
func (b Blob) MarshalJSON() ([]byte, error) {
	if len(b) == 0 {
		return jsonEmptyStr, nil
	}
	var s strings.Builder
	s.WriteRune('"')
	binToJSONString(b, &s)
	s.WriteRune('"')
	return []byte(s.String()), nil
}

// UnmarshalJSON unmarshals this blob from a JSON array, string, or base64 string prefixed by a backspace (ascii 8, string "\b").
func (b *Blob) UnmarshalJSON(j []byte) error {
	var str string
	err := json.Unmarshal(j, &str)
	if err != nil {
		return err
	}
	bb := make([]byte, 0, len(str))
	for _, r := range str {
		bb = append(bb, byte(r&0xff))
	}
	*b = bb
	return nil
}
