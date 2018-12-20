/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

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
	"runtime"
	"sort"
	"strconv"
	"unsafe"
)

// DB is an instance of the LF database that stores records and manages record weights and linkages.
type db C.struct_ZTLF_DB

func (db *db) open(path string) error {
	var errbuf [2048]byte
	cerr := C.ZTLF_DB_Open((*C.struct_ZTLF_DB)(db), C.CString(path), (*C.char)(unsafe.Pointer(&(errbuf[0]))), 2047)
	if cerr != 0 {
		errstr := "unknown or I/O level error " + strconv.FormatInt(int64(cerr), 10)
		if cerr > 0 {
			var eos = 0
			for eos < len(errbuf) {
				if errbuf[eos] == 0 {
					errstr = string(errbuf[0:eos])
					break
				}
				eos++
			}
		}
		return ErrorDatabase{int(cerr), "open failed (" + errstr + ")"}
	}
	return nil
}

func (db *db) close() {
	C.ZTLF_DB_Close((*C.struct_ZTLF_DB)(db))
}

func (db *db) putRecord(r *Record) error {
	var changeOwner, sel0, sel1, links unsafe.Pointer
	if len(r.ChangeOwner) == 32 {
		changeOwner = unsafe.Pointer(&r.ChangeOwner[0])
	}
	for i := range r.SelectorIDs {
		if len(r.SelectorIDs[i]) == 32 {
			if uintptr(sel0) == 0 {
				sel0 = unsafe.Pointer(&r.SelectorIDs[i][0])
			} else {
				sel1 = unsafe.Pointer(&r.SelectorIDs[i][0])
			}
		}
	}
	lc := len(r.Links) / 32
	if lc > 0 {
		links = unsafe.Pointer(&r.Links[0])
	}

	var score uint32
	if r.WorkAlgorithm == RecordWorkAlgorithmWharrgarbl {
		score = WharrgarblGetDifficulty(r.Work[:])
	} else {
		score = 1
	}

	cerr := C.ZTLF_DB_PutRecord(
		(*C.struct_ZTLF_DB)(db),
		unsafe.Pointer(&r.Data[0]),
		C.uint(len(r.Data)),
		unsafe.Pointer(&r.ID[0]),
		unsafe.Pointer(&r.Owner[0]),
		unsafe.Pointer(&r.Hash[0]),
		C.ulonglong(r.Timestamp),
		C.ulonglong(r.TTL),
		C.uint(score),
		changeOwner,
		sel0,
		sel1,
		links,
		C.uint(lc))
	if cerr != 0 {
		return ErrorDatabase{int(cerr), "record add failed"}
	}

	return nil
}

func (db *db) getMatching(id, owner, sel0, sel1 []byte) (rd []APIRecordDetail) {
	var idP, ownerP, sel0P, sel1P unsafe.Pointer
	var doffdlen []uintptr

	if len(id) == 32 {
		idP = unsafe.Pointer(&id[0])
	}
	if len(owner) == 32 {
		ownerP = unsafe.Pointer(&owner[0])
	}
	if len(sel0) == 32 {
		sel0P = unsafe.Pointer(&sel0[0])
	}
	if len(sel1) == 32 {
		sel1P = unsafe.Pointer(&sel1[0])
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
		ok := int(C.ZTLF_DB_GetRecordData((*C.struct_ZTLF_DB)(db), C.ulonglong(doff), unsafe.Pointer(&(rd[i].Record.Data[0])), C.uint(dlen)))
		if ok == 0 { // unlikely, sanity check
			// TODO: log probable database corruption
			rd = nil
			break
		} else {
			if rd[i].Record.Unpack(nil) != nil { // same... would indicate a bad record in DB
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

// getDataByHash gets record data by hash and appends it to 'buf', returning bytes appended and buffer.
func (db *db) getDataByHash(h []byte, buf []byte) (int, []byte, error) {
	if len(h) != 32 {
		return 0, buf, ErrorInvalidParameter
	}

	var doff uint64
	dlen := int(C.ZTLF_DB_GetByHash((*C.struct_ZTLF_DB)(db), unsafe.Pointer(&(h[0])), (*C.ulonglong)(unsafe.Pointer(&doff))))
	if dlen == 0 {
		return 0, buf, nil
	}
	if dlen < RecordMinSize || dlen > RecordMaxSize {
		return 0, buf, ErrorDatabase{dlen, "invalid record size returned by DB_GetByHash(), database may be corrupt"}
	}

	startPos := len(buf)
	buf = append(buf, make([]byte, dlen)...)
	ok := int(C.ZTLF_DB_GetRecordData((*C.struct_ZTLF_DB)(db), C.ulonglong(doff), unsafe.Pointer(&(buf[startPos])), C.uint(dlen)))
	if ok == 0 {
		buf = buf[0:startPos]
		return 0, buf, ErrorIO
	}

	return dlen, buf, nil
}

func (db *db) hasRecord(h []byte) bool {
	if len(h) == 32 {
		var doff uint64
		dlen := int(C.ZTLF_DB_GetByHash((*C.struct_ZTLF_DB)(db), unsafe.Pointer(&(h[0])), (*C.ulonglong)(unsafe.Pointer(&doff))))
		return (dlen > RecordMinSize)
	}
	return false
}

// getLinks gets up to count 32-bit hashes of linkable records, returning the number actually retrieved.
func (db *db) getLinks(count uint) (uint, []byte, error) {
	if count == 0 {
		return 0, nil, nil
	}
	lbuf := make([]byte, 32*count)
	lc := uint(C.ZTLF_DB_GetLinks((*C.struct_ZTLF_DB)(db), unsafe.Pointer(&(lbuf[0])), C.uint(count), C.uint(RecordDesiredLinks)))
	return lc, lbuf[0 : 32*lc], nil
}

func (db *db) stats() (recordCount, dataSize uint64) {
	C.ZTLF_DB_Stats((*C.struct_ZTLF_DB)(db), (*C.ulonglong)(unsafe.Pointer(&recordCount)), (*C.ulonglong)(unsafe.Pointer(&dataSize)))
	return
}

func (db *db) crc64() uint64 {
	return uint64(C.ZTLF_DB_CRC64((*C.struct_ZTLF_DB)(db)))
}

func (db *db) hasPending() bool {
	return (C.ZTLF_DB_HasPending((*C.struct_ZTLF_DB)(db)) != 0)
}
