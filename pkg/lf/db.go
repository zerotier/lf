package lf

// #cgo CFLAGS: -O3
// #cgo LDFLAGS: -lsqlite3
// #include "./native/db.h"
// #include "./native/db.c"
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

// DB is an instance of the LF database that stores records and manages record weights and linkages.
type db C.struct_ZTLF_DB

func (db *db) open(path string) error {
	cerr := C.ZTLF_DB_Open((*C.struct_ZTLF_DB)(db), C.CString(path))
	if cerr != 0 {
		return fmt.Errorf("Database open failed: %d", cerr)
	}
	return nil
}

func (db *db) close() {
	C.ZTLF_DB_Close((*C.struct_ZTLF_DB)(db))
}

func (db *db) putRecord(r *Record) error {
	if len(r.Data) < RecordMinSize {
		return errors.New("record too short")
	}

	var changeOwner, sel0, sel1 unsafe.Pointer
	for i := 0; i < len(r.MetaData); i++ {
		switch r.MetaData[i].Type {
		case RecordMetaDataTypeChangeOwner:
			if uintptr(changeOwner) == 0 && len(r.MetaData[i].Value) == 32 {
				changeOwner = unsafe.Pointer(&(r.MetaData[i].Value[0]))
			}
		case RecordMetaDataTypeSelector:
			if len(r.MetaData[i].Value) == 32 {
				if uintptr(sel0) == 0 {
					sel0 = unsafe.Pointer(&(r.MetaData[i].Value[0]))
				} else if uintptr(sel1) == 0 {
					sel1 = unsafe.Pointer(&(r.MetaData[i].Value[0]))
				}
			}
		}
	}

	var links unsafe.Pointer
	lc := len(r.Links) / 32
	if lc > 0 {
		links = unsafe.Pointer(&(r.Links[0]))
	}

	var score uint32
	if r.WorkAlgorithm == RecordMetaDataTypeChangeOwner {
		if len(r.Work) == WharrgarblProofOfWorkSize {
			score = WharrgarblGetDifficulty(r.Work)
		} else {
			return errors.New("invalid proof of work")
		}
	} else {
		score = 1
	}

	cerr := C.ZTLF_DB_PutRecord(
		(*C.struct_ZTLF_DB)(db),
		unsafe.Pointer(&(r.Data[0])),
		_Ctype_uint(len(r.Data)),
		unsafe.Pointer(&(r.ID)),
		unsafe.Pointer(&(r.Owner)),
		unsafe.Pointer(&(r.Hash)),
		_Ctype_ulonglong(r.Timestamp),
		_Ctype_ulonglong(r.TTL),
		_Ctype_uint(score),
		changeOwner,
		sel0,
		sel1,
		links,
		_Ctype_uint(lc))
	if cerr != 0 {
		return fmt.Errorf("error %d", cerr)
	}

	return nil
}
