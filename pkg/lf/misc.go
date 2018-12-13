package lf

import (
	"io"
	"time"
)

// TimeMs returns the time in milliseconds since epoch.
func TimeMs() uint64 { return uint64(time.Now().UnixNano()) / uint64(1000000) }

// TimeMsToTime converts a time in milliseconds since epoch to a Go native time.Time structure.
func TimeMsToTime(ms uint64) time.Time { return time.Unix(int64(ms/1000), int64((ms%1000)*1000000)) }

// byteAndArrayReader wraps io.Reader to also make it support io.ByteReader because you can't read a varint from a Reader because derp
type byteAndArrayReader struct{ r io.Reader }

func (mr byteAndArrayReader) Read(p []byte) (int, error) { return mr.r.Read(p) }

func (mr byteAndArrayReader) ReadByte() (byte, error) {
	var tmp [1]byte
	_, err := io.ReadFull(mr.r, tmp[:])
	return tmp[0], err
}
