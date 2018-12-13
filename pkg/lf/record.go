package lf

// #cgo LDFLAGS: -L../../internal/libZTLF -lZTLF -lsqlite3
// #include "../../internal/libZTLF/record.h"
import "C"
import (
	"fmt"
	"unsafe"
)

// RecordMinSize is the minimum size of a packed raw record in bytes
const RecordMinSize = C.ZTLF_RECORD_MIN_SIZE

// RecordMaxSize is the maximum size of a packed raw record in bytes
const RecordMaxSize = C.ZTLF_RECORD_MAX_SIZE

// ExpandedRecord contains the data in a record in a more convenient to access form
type ExpandedRecord C.struct_ZTLF_ExpandedRecord

// Record contains a version of a global key/value pair in LF
type Record struct {
	data    []uint8         // Raw packed record (struct ZTLF_Record)
	details *ExpandedRecord // Expanded record details for more convenient access
}

// Expand fills the details field with expanded and more conveniently accessable record information.
func (r *Record) Expand() error {
	r.details = new(ExpandedRecord)
	cerr := C.ZTLF_Record_Expand((*C.struct_ZTLF_ExpandedRecord)(r.details), (*C.struct_ZTLF_Record)(unsafe.Pointer(&(r.data[0]))), _Ctype_uint(len(r.data)))
	if cerr != 0 {
		return fmt.Errorf("ZTLF_Record_Expand failed: %d", cerr)
	}
	return nil
}
