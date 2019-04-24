package lf

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Blob is a byte array that JSON serializes to an array and accepts deserialization from string or array.
type Blob []byte

// MarshalJSON returns this blob marshaled as a byte array or a string
func (b Blob) MarshalJSON() ([]byte, error) {
	var sb strings.Builder
	sb.WriteRune('[')
	for i := 0; i < len(b); i++ {
		if i != 0 {
			sb.WriteRune(',')
		}
		sb.WriteString(strconv.FormatUint(uint64(b[i]), 10))
	}
	sb.WriteRune(']')
	return []byte(sb.String()), nil
}

// UnmarshalJSON unmarshals this blob from a JSON array or string
func (b *Blob) UnmarshalJSON(j []byte) error {
	if len(j) == 0 {
		*b = []byte{}
		return nil
	}

	// Blobs are accepted by LF as UTF-8 strings.
	if j[0] == '"' {
		var str string
		if json.Unmarshal(j, &str) == nil {
			*b = []byte(str)
			return nil
		}
	}

	// ... or as arrays
	var bb []byte
	err := json.Unmarshal(j, &bb)
	if err == nil {
		*b = bb
		return nil
	}

	return err
}
