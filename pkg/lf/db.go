/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

// #cgo CFLAGS: -O3
// #cgo LDFLAGS: -lsqlite3
//#include <stdint.h>
//#define ZTLF_GOLANG 1
//struct ZTLF_DB;
//extern void ztlfLogOutputCCallback(int,const char *,int,const char *,void *);
//extern void ztlfSyncCCallback(struct ZTLF_DB *db,const void *,uint64_t,unsigned int,int,void *);
// #include "./native/db.h"
// #include "./native/db.c"
import "C"

import (
	"fmt"
	"log"
	"strconv"
	"sync"
	"unsafe"
)

const (
	dbMaxOwnerSize       uint = C.ZTLF_DB_QUERY_MAX_OWNER_SIZE
	dbMaxConfigValueSize int  = 1048576
)

// DB is an instance of the LF database that stores records and manages record weights and linkages.
type db struct {
	log                   [logLevelCount]*log.Logger
	globalLoggerIdx       uint
	globalSyncCallbackIdx uint
	cdb                   *C.struct_ZTLF_DB
}

// Global variables that store logger instances for use by the callback in db-log-callback.go.
var (
	globalLoggers           [][logLevelCount]*log.Logger
	globalLoggersLock       sync.Mutex
	globalSyncCallbacks     []func(uint64, uint, int, *[32]byte)
	globalSyncCallbacksLock sync.RWMutex
)

func (db *db) open(basePath string, loggers [logLevelCount]*log.Logger, syncCallback func(uint64, uint, int, *[32]byte)) error {
	var errbuf [2048]byte
	db.log = loggers
	db.cdb = new(C.struct_ZTLF_DB)

	globalLoggersLock.Lock()
	globalLoggers = append(globalLoggers, loggers)
	db.globalLoggerIdx = uint(len(globalLoggers) - 1)
	globalLoggersLock.Unlock()

	globalSyncCallbacksLock.Lock()
	globalSyncCallbacks = append(globalSyncCallbacks, syncCallback)
	db.globalSyncCallbackIdx = uint(len(globalSyncCallbacks) - 1)
	globalSyncCallbacksLock.Unlock()

	cerr := C.ZTLF_DB_Open_fromGo(db.cdb, C.CString(basePath), (*C.char)(unsafe.Pointer(&errbuf[0])), 2047, C.uintptr_t(db.globalLoggerIdx), C.uintptr_t(db.globalSyncCallbackIdx))
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
		fmt.Println(errstr)

		db.close()

		return ErrDatabase{int(cerr), "open failed (" + errstr + ")"}
	}

	return nil
}

func (db *db) close() {
	if db.cdb != nil {
		C.ZTLF_DB_Close(db.cdb)
	}
	db.cdb = nil

	globalLoggersLock.Lock()
	if db.globalLoggerIdx < uint(len(globalLoggers)) {
		globalLoggers[db.globalLoggerIdx] = [logLevelCount]*log.Logger{nil, nil, nil, nil, nil}
	}
	globalLoggersLock.Unlock()

	globalSyncCallbacksLock.Lock()
	if db.globalSyncCallbackIdx < uint(len(globalSyncCallbacks)) {
		globalSyncCallbacks[db.globalSyncCallbackIdx] = nil
	}
	globalSyncCallbacksLock.Unlock()
}

// putRecord adds a valid record to the database.
func (db *db) putRecord(r *Record) error {
	if len(r.recordBody.Owner) == 0 {
		return ErrRecordInvalid
	}
	rdata := r.Bytes()
	if len(rdata) == 0 {
		return ErrRecordInvalid
	}
	rhash := r.Hash()
	rid := r.ID()

	var selectorsPtr C.uintptr_t
	var selectorSizesPtr *C.uint
	selectorKeys := make([][]byte, len(r.Selectors))
	selectors := make([]uintptr, len(r.Selectors))
	selectorSizes := make([]C.uint, len(r.Selectors))
	if len(r.Selectors) > 0 {
		for i := 0; i < len(r.Selectors); i++ {
			selectorKeys[i] = r.SelectorKey(i)
			selectors[i] = uintptr(unsafe.Pointer(&selectorKeys[i][0]))
			selectorSizes[i] = C.uint(len(selectorKeys[i]))
		}
		selectorsPtr = C.uintptr_t(uintptr(unsafe.Pointer(&selectors[0])))
		selectorSizesPtr = &selectorSizes[0]
	}

	var lptr unsafe.Pointer
	l := make([]byte, 0, len(r.recordBody.Links)*32)
	for i := 0; i < len(r.recordBody.Links); i++ {
		l = append(l, r.recordBody.Links[i][:]...)
	}
	if len(l) > 0 {
		lptr = unsafe.Pointer(&l[0])
	}

	owner := r.recordBody.Owner
	rtype := C.int(0)
	if r.Type != nil {
		rtype = C.int(*r.Type)
	}

	cerr := C.ZTLF_DB_PutRecord_fromGo(
		db.cdb,
		unsafe.Pointer(&rdata[0]),
		C.uint(len(rdata)),
		rtype,
		unsafe.Pointer(&owner[0]),
		C.uint(len(owner)),
		unsafe.Pointer(&rhash),
		unsafe.Pointer(&rid),
		C.uint64_t(r.recordBody.Timestamp),
		C.uint32_t(r.Score()),
		selectorsPtr,
		selectorSizesPtr,
		C.uint(len(selectors)),
		lptr,
		C.uint(len(r.recordBody.Links)))

	if cerr != 0 {
		return ErrDatabase{int(cerr), "record add failed (" + strconv.Itoa(int(cerr)) + ")"}
	}
	return nil
}

// getDataByHash gets record data by hash and appends it to 'buf', returning bytes appended and buffer.
func (db *db) getDataByHash(h []byte, buf []byte) (int, []byte, error) {
	if len(h) != 32 {
		return 0, buf, ErrInvalidParameter
	}

	var doff uint64
	dlen := int(C.ZTLF_DB_GetByHash(db.cdb, unsafe.Pointer(&(h[0])), (*C.uint64_t)(unsafe.Pointer(&doff))))
	if dlen == 0 {
		return 0, buf, nil
	}

	startPos := len(buf)
	buf = append(buf, make([]byte, dlen)...)
	ok := int(C.ZTLF_DB_GetRecordData(db.cdb, C.uint64_t(doff), unsafe.Pointer(&(buf[startPos])), C.uint(dlen)))
	if ok == 0 {
		buf = buf[0:startPos]
		return 0, buf, ErrIO
	}

	return dlen, buf, nil
}

// getDataByOffset gets record data by its doff and dlen (offset and length in record data flat file).
func (db *db) getDataByOffset(doff uint64, dlen uint, buf []byte) ([]byte, error) {
	startPos := len(buf)
	buf = append(buf, make([]byte, dlen)...)
	ok := int(C.ZTLF_DB_GetRecordData(db.cdb, C.uint64_t(doff), unsafe.Pointer(&(buf[startPos])), C.uint(dlen)))
	if ok == 0 {
		buf = buf[0:startPos]
		return buf, ErrIO
	}
	return buf, nil
}

// hasRecord returns true if the record with the given hash exists (rejected table is not checked)
func (db *db) hasRecord(h []byte) bool {
	if len(h) == 32 {
		var doff uint64
		dlen := int(C.ZTLF_DB_GetByHash(db.cdb, unsafe.Pointer(&(h[0])), (*C.uint64_t)(unsafe.Pointer(&doff))))
		return dlen > 0
	}
	return false
}

// getLinks gets up to count 32-bit hashes of linkable records, returning the number actually retrieved.
func (db *db) getLinks(count uint) (uint, []byte, error) {
	if count == 0 {
		return 0, nil, nil
	}
	lbuf := make([]byte, 32*count)
	lc := uint(C.ZTLF_DB_GetLinks(db.cdb, unsafe.Pointer(&(lbuf[0])), C.uint(count)))
	return lc, lbuf[0 : 32*lc], nil
}

// getLinks2 is like getLinks but returns a slice of arrays instead of one slice with all the link IDs concatenated.
func (db *db) getLinks2(count uint) (ll [][32]byte, err error) {
	_, l, err := db.getLinks(count)
	if err != nil {
		return nil, err
	}
	if len(l) >= 32 {
		ll = make([][32]byte, len(l)/32)
		for i, j := 0, 0; (j + 32) <= len(l); j += 32 {
			copy(ll[i][:], l[j:j+32])
			i++
		}
	}
	return
}

// stats returns some basic statistics about this database.
func (db *db) stats() (recordCount, dataSize uint64) {
	C.ZTLF_DB_Stats(db.cdb, (*C.uint64_t)(unsafe.Pointer(&recordCount)), (*C.uint64_t)(unsafe.Pointer(&dataSize)))
	return
}

// crc64 returns a CRC64 of this database's important state information including hashes, graph weights, etc.
func (db *db) crc64() uint64 {
	return uint64(C.ZTLF_DB_CRC64(db.cdb))
}

// hasPending returns true if this database is not waiting for any records to fill any graph gaps or satisfy any links.
// This can also be used to check whether synchronization is complete since it returns true only if there are records
// and all links for them are satisfied.
func (db *db) hasPending() bool {
	return (C.ZTLF_DB_HasPending(db.cdb) > 0)
}

// haveDanglingLinks returns true if we have dangling links that haven't been retried more than N times.
func (db *db) haveDanglingLinks(ignoreAfterNRetries int) bool {
	return (C.ZTLF_DB_HaveDanglingLinks(db.cdb, C.int(ignoreAfterNRetries)) > 0)
}

// query executes a query against a number of selector ranges. The function is executed for each result, with
// results not sorted. The loop is broken if the function returns false. The owner is passed as a pointer to
// an array that is reused, so a copy must be made if you want to keep it. The arguments to the function are:
// timestamp, weight (low), weight (high), data offset, data length, local reputation, id, owner.
func (db *db) query(tsMin, tsMax int64, selectorRanges [][2][]byte, f func(uint64, uint64, uint64, uint64, uint64, int, *[32]byte, []byte) bool) error {
	if len(selectorRanges) == 0 {
		return nil
	}

	sel := make([]uintptr, len(selectorRanges)*2)
	selSizes := make([]C.uint, len(selectorRanges)*2)
	for i := 0; i < len(selectorRanges); i++ {
		if len(selectorRanges[i][0]) == 0 || len(selectorRanges[i][1]) == 0 {
			return ErrInvalidParameter
		}
		ii := i * 2
		sel[ii] = uintptr(unsafe.Pointer(&selectorRanges[i][0][0]))
		selSizes[ii] = C.uint(len(selectorRanges[i][0]))
		ii++
		sel[ii] = uintptr(unsafe.Pointer(&selectorRanges[i][1][0]))
		selSizes[ii] = C.uint(len(selectorRanges[i][1]))
	}

	cresults := C.ZTLF_DB_Query_fromGo(db.cdb, C.int64_t(tsMin), C.int64_t(tsMax), C.uintptr_t(uintptr(unsafe.Pointer(&sel[0]))), &selSizes[0], C.uint(len(selectorRanges)))
	if uintptr(unsafe.Pointer(cresults)) != 0 {
		var owner [dbMaxOwnerSize]byte
		var id [32]byte
		for i := C.long(0); i < cresults.count; i++ {
			cr := (*C.struct_ZTLF_QueryResult)(unsafe.Pointer(uintptr(unsafe.Pointer(&cresults.results[0])) + (uintptr(i) * unsafe.Sizeof(cresults.results[0]))))
			ownerSize := uint(cr.ownerSize)
			if ownerSize > 0 && ownerSize <= dbMaxOwnerSize && cr.dlen > 0 {
				for j := 0; j < 32; j++ {
					id[j] = byte(cr.id[j])
				}
				for j := uint(0); j < ownerSize; j++ {
					owner[j] = byte(cr.owner[j])
				}
				if !f(uint64(cr.ts), uint64(cr.weightL), uint64(cr.weightH), uint64(cr.doff), uint64(cr.dlen), int(cr.localReputation), &id, owner[0:ownerSize]) {
					break
				}
			}
		}
		C.free(unsafe.Pointer(cresults))
	}

	return nil
}

// getAllByOwner gets all (complete) records owned by a given owner key.
// Results are returned in ascending order of timestamp.
func (db *db) getAllByOwner(owner []byte, f func(uint64, uint64) bool) error {
	if len(owner) == 0 {
		return nil
	}
	results := C.ZTLF_DB_GetAllByOwner(db.cdb, unsafe.Pointer(&owner[0]), C.uint(len(owner)))
	if uintptr(unsafe.Pointer(results)) != 0 {
		for i := C.long(0); i < results.count; i++ {
			rec := (*C.struct_ZTLF_RecordIndex)(unsafe.Pointer(uintptr(unsafe.Pointer(&results.records[0])) + (uintptr(i) * unsafe.Sizeof(results.records[0]))))
			if !f(uint64(rec.doff), uint64(rec.dlen)) {
				break
			}
		}
		C.free(unsafe.Pointer(results))
	}
	return nil
}

// getWanted gets hashes we don't currently have but that are linked by others.
// If incrementRetryCount is true the retry count in the database is incremented for all returned hashes.
// The return is a hash count and a buffer with [count*32] bytes of 32-byte hashes.
func (db *db) getWanted(max, retryCountMin, retryCountMax int, incrementRetryCount bool) (int, []byte) {
	if max == 0 {
		return 0, nil
	}
	increment := C.int(0)
	if incrementRetryCount {
		increment = 1
	}
	buf := make([]byte, max*32)
	count := int(C.ZTLF_DB_GetWanted(db.cdb, unsafe.Pointer(&buf[0]), C.uint(max), C.uint(retryCountMin), C.uint(retryCountMax), increment))
	return count, buf[0 : count*32]
}

func (db *db) logComment(byRecordDoff uint64, assertion, reason int, subject []byte) error {
	var sub unsafe.Pointer
	if len(subject) > 0 {
		sub = unsafe.Pointer(&subject[0])
	}
	e := C.ZTLF_DB_LogComment(db.cdb, C.int64_t(byRecordDoff), C.int(assertion), C.int(reason), sub, C.int(len(subject)))
	if e != 0 {
		return fmt.Errorf("database error %d", int(e))
	}
	return nil
}

func (db *db) getConfig(key string) []byte {
	var tmp [dbMaxConfigValueSize]byte
	l := C.ZTLF_DB_GetConfig(db.cdb, C.CString(key), unsafe.Pointer(&tmp[0]), C.uint(dbMaxConfigValueSize))
	if l > 0 {
		r := make([]byte, uint(l))
		copy(r, tmp[0:uint(l)])
		return r
	}
	return nil
}

func (db *db) setConfig(key string, value []byte) error {
	if len(value) > 0 {
		if len(value) > dbMaxConfigValueSize {
			return ErrInvalidParameter
		}
		e := C.ZTLF_DB_SetConfig(db.cdb, C.CString(key), unsafe.Pointer(&value[0]), C.uint(len(value)))
		if e != 0 {
			return fmt.Errorf("database error %d", int(e))
		}
	}
	return nil
}
