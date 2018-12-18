package lf

// #cgo CFLAGS: -O3
// #cgo LDFLAGS: -lsqlite3
// #include "./native/db.h"
// #include "./native/db.c"
// extern int ztlfDBInternalGetMatchingCCallback(int64_t,int64_t,uint64_t,uint64_t,void *,void *,void *,uint64_t,uint64_t,unsigned long);
// static inline void ZTLF_DB_GetMatching_fromGo(struct ZTLF_DB *db,const void *id,const void *owner,const void *sel0,const void *sel1,unsigned long arg) { ZTLF_DB_GetMatching(db,id,owner,sel0,sel1,&ztlfDBInternalGetMatchingCCallback,arg); }
import "C"
import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sort"
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

	var changeOwner, sel0, sel1, links unsafe.Pointer
	if len(r.ChangeOwner) == 32 {
		changeOwner = unsafe.Pointer(&(r.ChangeOwner[0]))
	}
	for i := range r.SelectorIDs {
		if uintptr(sel0) == 0 {
			sel0 = unsafe.Pointer(&(r.SelectorIDs[i][0]))
		} else {
			sel1 = unsafe.Pointer(&(r.SelectorIDs[i][0]))
		}
	}
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
		C.uint(len(r.Data)),
		unsafe.Pointer(&(r.ID)),
		unsafe.Pointer(&(r.Owner)),
		unsafe.Pointer(&(r.Hash)),
		C.ulonglong(r.Timestamp),
		C.ulonglong(r.TTL),
		C.uint(score),
		changeOwner,
		sel0,
		sel1,
		links,
		C.uint(lc))
	if cerr != 0 {
		return fmt.Errorf("error %d", cerr)
	}

	return nil
}

func (db *db) getMatching(id, owner, sel0, sel1 []byte) (rd []APIRecordDetail) {
	var idP, ownerP, sel0P, sel1P unsafe.Pointer
	var doffdlen []uintptr

	if len(id) == 32 {
		idP = unsafe.Pointer(&(id[0]))
	}
	if len(owner) == 32 {
		ownerP = unsafe.Pointer(&(owner[0]))
	}
	if len(sel0) == 32 {
		sel0P = unsafe.Pointer(&(sel0[0]))
	}
	if len(sel1) == 32 {
		sel1P = unsafe.Pointer(&(sel1[0]))
	}

	// This stuff is defined in db-native-callbacks.go
	dbGetMatchingStateInstanceLock.Lock()
	dbGetMatchingStateInstance.byIDOwner = make(map[[64]byte]*dbGetMatchingStateByIDOwner)

	runtime.LockOSThread()
	C.ZTLF_DB_GetMatching_fromGo((*C.struct_ZTLF_DB)(db), idP, ownerP, sel0P, sel1P, C.ulong(0))
	runtime.UnlockOSThread()

	now := TimeSec()
	for _, info := range dbGetMatchingStateInstance.byIDOwner {
		if info.exp > now {
			rd = append(rd, APIRecordDetail{})
			w := rd[len(rd)-1].Weight[:]
			binary.BigEndian.PutUint64(w[0:8], info.weightH)
			binary.BigEndian.PutUint64(w[8:16], info.weightL)
			doffdlen = append(doffdlen, uintptr(info.doff), uintptr(info.dlen))
		}
	}

	dbGetMatchingStateInstance.byIDOwner = nil
	dbGetMatchingStateInstanceLock.Unlock()

	for i, j := 0, 0; i < len(rd); i++ {
		doff := doffdlen[j]
		j++
		dlen := doffdlen[j]
		j++
		rd[i].Record.Data = make([]byte, uint(dlen))
		ok := C.ZTLF_DB_GetRecordData((*C.struct_ZTLF_DB)(db), C.ulonglong(doff), unsafe.Pointer(&(rd[i].Record.Data[0])), C.uint(dlen))
		if int(ok) == 0 { // unlikely, sanity check
			// TODO: log probable database corruption
			rd = nil
			break
		} else {
			if rd[i].Record.Unpack(nil, false) != nil { // same... would indicate a bad record in DB
				// TODO: log probable database corruption
				rd = nil
				break
			}
		}
	}

	sort.Slice(rd, func(i, j int) bool {
		if bytes.Equal(rd[i].Record.ID[:], rd[j].Record.ID[:]) {
			return bytes.Compare(rd[i].Weight[:], rd[j].Weight[:]) > 0
		}
		return rd[i].Record.Timestamp > rd[j].Record.Timestamp
	})

	return
}

func (db *db) stats() (recordCount, dataSize uint64) {
	C.ZTLF_DB_Stats((*C.struct_ZTLF_DB)(db), (*C.ulonglong)(unsafe.Pointer(&recordCount)), (*C.ulonglong)(unsafe.Pointer(&dataSize)))
	return
}

func (db *db) crc64() uint64 {
	return uint64(C.ZTLF_DB_CRC64((*C.struct_ZTLF_DB)(db)))
}
