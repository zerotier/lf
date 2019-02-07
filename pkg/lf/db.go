/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

// #cgo CFLAGS: -O3
// #cgo LDFLAGS: -lsqlite3
// #include "./native/db.h"
// #include "./native/db.c"
// extern void ztlfLogOutputCCallback(int,const char *,int,const char *,void *);
// static inline int ZTLF_DB_Open_fromGo(struct ZTLF_DB *db,const char *path,char *errbuf,unsigned int errbufSize,uintptr_t loggerArg) { return ZTLF_DB_Open(db,path,errbuf,errbufSize,&ztlfLogOutputCCallback,(void *)loggerArg); }
import "C"

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"unsafe"
)

const (
	dbMaxOwnerSize       uint = C.ZTLF_DB_QUERY_MAX_OWNER_SIZE
	dbMaxConfigValueSize int  = 131072
)

// DB is an instance of the LF database that stores records and manages record weights and linkages.
type db struct {
	logger          *log.Logger
	verboseLogger   *log.Logger
	globalLoggerIdx uint
	cdb             C.struct_ZTLF_DB
}

// Global variables that store logger instances for use by the callback in db-log-callback.go.
var (
	globalLoggers       []*log.Logger
	globalDefaultLogger = log.New(os.Stdout, "", log.LstdFlags)
	globalLoggersLock   sync.Mutex
)

func (db *db) open(path string, logger *log.Logger) error {
	db.logger = logger

	globalLoggersLock.Lock()
	globalLoggers = append(globalLoggers, logger)
	db.globalLoggerIdx = uint(len(globalLoggers) - 1)
	globalLoggersLock.Unlock()

	var errbuf [2048]byte
	cerr := C.ZTLF_DB_Open_fromGo((*C.struct_ZTLF_DB)(&db.cdb), C.CString(path), (*C.char)(unsafe.Pointer(&errbuf[0])), 2047, C.uintptr_t(db.globalLoggerIdx))
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

		globalLoggersLock.Lock()
		globalLoggers[db.globalLoggerIdx] = nil
		globalLoggersLock.Unlock()

		return ErrorDatabase{int(cerr), "open failed (" + errstr + ")"}
	}

	return nil
}

func (db *db) close() {
	C.ZTLF_DB_Close((*C.struct_ZTLF_DB)(&db.cdb))
	globalLoggersLock.Lock()
	globalLoggers[db.globalLoggerIdx] = nil
	globalLoggersLock.Unlock()
}

// putRecord adds a valid record to the database.
func (db *db) putRecord(r *Record) error {
	if len(r.Body.Owner) == 0 {
		return ErrorRecordInvalid
	}
	rdata := r.Bytes()
	if len(rdata) == 0 {
		return ErrorRecordInvalid
	}
	rhash := r.Hash()
	rid := r.ID()

	selectorKeys := make([][]byte, len(r.Selectors))
	selectors := make([]uintptr, len(r.Selectors))
	selectorSizes := make([]C.uint, len(r.Selectors))
	for i := 0; i < len(r.Selectors); i++ {
		selectorKeys[i] = r.Selectors[i].Key()
		selectors[i] = uintptr(unsafe.Pointer(&selectorKeys[i]))
		selectorSizes[i] = C.uint(len(selectorKeys[i]))
	}
	var sptr unsafe.Pointer
	var ssptr unsafe.Pointer
	if len(selectors) > 0 {
		sptr = unsafe.Pointer(&selectors[0])
		ssptr = unsafe.Pointer(&selectorSizes[0])
	}
	var lptr unsafe.Pointer
	if len(r.Body.Links) > 0 {
		lptr = unsafe.Pointer(&r.Body.Links[0])
	}
	owner := r.Body.Owner

	cerr := C.ZTLF_DB_PutRecord(
		(*C.struct_ZTLF_DB)(&db.cdb),
		unsafe.Pointer(&rdata[0]),
		C.uint(len(rdata)),
		unsafe.Pointer(&owner[0]),
		C.uint(len(owner)),
		unsafe.Pointer(rhash),
		unsafe.Pointer(rid),
		C.uint64_t(r.Body.Timestamp),
		C.uint32_t(r.Score()),
		(*unsafe.Pointer)(sptr),
		(*C.uint)(ssptr),
		C.uint(len(selectors)),
		lptr,
		C.uint(r.Body.LinkCount()))

	if cerr != 0 {
		return ErrorDatabase{int(cerr), "record add failed (" + strconv.Itoa(int(cerr)) + ")"}
	}
	return nil
}

// getDataByHash gets record data by hash and appends it to 'buf', returning bytes appended and buffer.
func (db *db) getDataByHash(h []byte, buf []byte) (int, []byte, error) {
	if len(h) != 32 {
		return 0, buf, ErrorInvalidParameter
	}

	var doff uint64
	dlen := int(C.ZTLF_DB_GetByHash((*C.struct_ZTLF_DB)(&db.cdb), unsafe.Pointer(&(h[0])), (*C.ulonglong)(unsafe.Pointer(&doff))))
	if dlen == 0 {
		return 0, buf, nil
	}

	startPos := len(buf)
	buf = append(buf, make([]byte, dlen)...)
	ok := int(C.ZTLF_DB_GetRecordData((*C.struct_ZTLF_DB)(&db.cdb), C.ulonglong(doff), unsafe.Pointer(&(buf[startPos])), C.uint(dlen)))
	if ok == 0 {
		buf = buf[0:startPos]
		return 0, buf, ErrorIO
	}

	return dlen, buf, nil
}

// getDataByOffset gets record data by its doff and dlen (offset and length in record data flat file).
func (db *db) getDataByOffset(doff uint64, dlen uint, buf []byte) ([]byte, error) {
	startPos := len(buf)
	buf = append(buf, make([]byte, dlen)...)
	ok := int(C.ZTLF_DB_GetRecordData((*C.struct_ZTLF_DB)(&db.cdb), C.ulonglong(doff), unsafe.Pointer(&(buf[startPos])), C.uint(dlen)))
	if ok == 0 {
		buf = buf[0:startPos]
		return buf, ErrorIO
	}
	return buf, nil
}

// hasRecord returns true if the record with the given hash exists (rejected table is not checked)
func (db *db) hasRecord(h []byte) bool {
	if len(h) == 32 {
		var doff uint64
		dlen := int(C.ZTLF_DB_GetByHash((*C.struct_ZTLF_DB)(&db.cdb), unsafe.Pointer(&(h[0])), (*C.ulonglong)(unsafe.Pointer(&doff))))
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
	lc := uint(C.ZTLF_DB_GetLinks((*C.struct_ZTLF_DB)(&db.cdb), unsafe.Pointer(&(lbuf[0])), C.uint(count)))
	return lc, lbuf[0 : 32*lc], nil
}

// stats returns some basic statistics about this database.
func (db *db) stats() (recordCount, dataSize uint64) {
	C.ZTLF_DB_Stats((*C.struct_ZTLF_DB)(&db.cdb), (*C.ulonglong)(unsafe.Pointer(&recordCount)), (*C.ulonglong)(unsafe.Pointer(&dataSize)))
	return
}

// crc64 returns a CRC64 of this database's important state information including hashes, graph weights, etc.
func (db *db) crc64() uint64 {
	return uint64(C.ZTLF_DB_CRC64((*C.struct_ZTLF_DB)(&db.cdb)))
}

// hasPending returns true if this database is not waiting for any records to fill any graph gaps or satisfy any links.
// This can also be used to check whether synchronization is complete since it returns true only if there are records
// and all links for them are satisfied.
func (db *db) hasPending() bool {
	return (C.ZTLF_DB_HasPending((*C.struct_ZTLF_DB)(&db.cdb)) > 0)
}

// query executes a query against a number of selector ranges. The function is executed for each result, with
// results not sorted. The loop is broken if the function returns false. The owner is passed as a pointer to
// an array that is reused, so a copy must be made if you want to keep it. The arguments to the function are:
// timestamp, weight (low), weight (high), data offset, data length, id, owner, owner size (bytes).
func (db *db) query(selectorRanges [][2][]byte, andOr []bool, f func(uint64, uint64, uint64, uint64, uint64, *[32]byte, []byte) bool) error {
	if len(selectorRanges) == 0 || len(andOr) != len(selectorRanges) {
		return nil
	}

	sel := make([]unsafe.Pointer, len(selectorRanges)*2)
	selSizes := make([]C.uint, len(selectorRanges)*2)
	selAndOr := make([]C.int, len(selectorRanges))
	for i := 0; i < len(selectorRanges); i++ {
		if len(selectorRanges[i][0]) == 0 || len(selectorRanges[i][1]) == 0 {
			return ErrorInvalidParameter
		}
		if andOr[i] {
			selAndOr[i] = 1
		}
		ii := i * 2
		sel[ii] = unsafe.Pointer(&selectorRanges[i][0][0])
		selSizes[ii] = C.uint(len(selectorRanges[i][0]))
		ii++
		sel[ii] = unsafe.Pointer(&selectorRanges[i][1][0])
		selSizes[ii] = C.uint(len(selectorRanges[i][1]))
	}

	cresults := C.ZTLF_DB_Query((*C.struct_ZTLF_DB)(&db.cdb), &sel[0], (*C.int)(unsafe.Pointer(&selAndOr[0])), (*C.uint)(unsafe.Pointer(&selSizes[0])), C.uint(len(selectorRanges)))
	if uintptr(unsafe.Pointer(cresults)) != 0 {
		var owner [dbMaxOwnerSize]byte
		var id [32]byte
		for i := C.long(0); i < cresults.count; i++ {
			cr := cresults.results[i]
			ownerSize := uint(cr.ownerSize)
			if ownerSize > 0 && ownerSize <= dbMaxOwnerSize && cr.dlen > 0 {
				for j := 0; j < 32; j++ {
					id[j] = byte(cr.id[j])
				}
				for j := uint(0); j < ownerSize; j++ {
					owner[j] = byte(cr.owner[j])
				}
				if !f(uint64(cr.ts), uint64(cr.weightL), uint64(cr.weightH), uint64(cr.doff), uint64(cr.dlen), &id, owner[0:ownerSize]) {
					break
				}
			}
		}
		C.free(unsafe.Pointer(cresults))
	}

	return nil
}

func (db *db) getConfig(key string) []byte {
	var tmp [dbMaxConfigValueSize]byte
	l := C.ZTLF_DB_GetConfig((*C.struct_ZTLF_DB)(&db.cdb), C.CString(key), unsafe.Pointer(&tmp[0]), C.uint(dbMaxConfigValueSize))
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
			return ErrorInvalidParameter
		}
		e := C.ZTLF_DB_SetConfig((*C.struct_ZTLF_DB)(&db.cdb), C.CString(key), unsafe.Pointer(&value[0]), C.uint(len(value)))
		if e != 0 {
			return fmt.Errorf("database error %d", int(e))
		}
	}
	return nil
}
