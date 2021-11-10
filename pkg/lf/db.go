/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c)2019-2021 ZeroTier, Inc.
 * https://www.zerotier.com/
 */

package lf

// Note: we include prebuilt sqlite3 for some platforms due to needing to
// build on ancient versions that have ancient SQLite3 like CentOS 7.

//#cgo CFLAGS: -O3
//#cgo darwin LDFLAGS: ${SRCDIR}/../../native/db_darwin.o ${SRCDIR}/../../native/sqlite3_darwin.o
//#cgo linux android LDFLAGS: ${SRCDIR}/../../native/db_linux.o ${SRCDIR}/../../native/sqlite3_linux.o
//#cgo freebsd LDFLAGS: ${SRCDIR}/../../native/db_freebsd.o ${SRCDIR}/../../native/sqlite3_freebsd.o
//#cgo openbsd LDFLAGS: ${SRCDIR}/../../native/db_openbsd.o ${SRCDIR}/../../native/sqlite3_openbsd.o
//#cgo netbsd LDFLAGS: ${SRCDIR}/../../native/db_netbsd.o ${SRCDIR}/../../native/sqlite3_netbsd.o
//#cgo windows LDFLAGS : ${SRCDIR}/../../native/db_windows.o ${SRCDIR}/../../native/sqlite3_windows.o
//#cgo solaris LDFLAGS : ${SRCDIR}/../../native/db_solaris.o ${SRCDIR}/../../native/sqlite3_solaris.o
//#cgo dragonfly LDFLAGS : ${SRCDIR}/../../native/db_dragonfly.o ${SRCDIR}/../../native/sqlite3_dragonfly.o
//#include <stdint.h>
//#define ZTLF_GOLANG 1
//struct ZTLF_DB;
//extern void ztlfLogOutputCCallback(int,const char *,int,const char *,void *);
//extern void ztlfSyncCCallback(struct ZTLF_DB *db,const void *,uint64_t,unsigned int,int,void *);
//#include "../../native/db.h"
import "C"

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"
	"strconv"
	"sync"
	"unsafe"
)

const (
	dbMaxOwnerSize       int = C.ZTLF_DB_QUERY_MAX_OWNER_SIZE
	dbMaxConfigValueSize int = 1048576

	// Reputations are in descending order in a circles of hell sense -- 0 is the worst possible thing.
	// Note that 0 and 63 must match native/db.h defines.
	dbReputationDefault                     = 63 // normal perfectly good looking record
	dbReputationTemporalViolation           = 48 // leave a bit of room above and below
	dbReputationRecordDeserializationFailed = 1  // record appears corrupt (shouldn't really happen at all)
	dbReputationCollision                   = 0  // record's selector names collide with another owner
)

// DB is an instance of the LF database that stores records and manages record weights and linkages.
type db struct {
	log                   [logLevelCount]*log.Logger
	globalLoggerIdx       uint
	globalSyncCallbackIdx uint
	cdb                   *C.struct_ZTLF_DB
	cdbLock               sync.Mutex
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

		db.cdb = nil // closing after incomplete open causes segfault
		db.close()

		return ErrDatabase{int(cerr), "open failed (" + errstr + ")"}
	}

	return nil
}

func (db *db) close() {
	db.cdbLock.Lock()
	defer db.cdbLock.Unlock()

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
	selectorKeys := make([][]byte, len(r.Selectors))
	selectors := make([]uintptr, len(r.Selectors))
	if len(r.Selectors) > 0 {
		for i := 0; i < len(r.Selectors); i++ {
			selectorKeys[i] = r.SelectorKey(i)
			selectors[i] = uintptr(unsafe.Pointer(&selectorKeys[i][0]))
		}
		selectorsPtr = C.uintptr_t(uintptr(unsafe.Pointer(&selectors[0])))
	}

	var lptr unsafe.Pointer
	l := make([]byte, 0, len(r.recordBody.Links)*32)
	for i := 0; i < len(r.recordBody.Links); i++ {
		l = append(l, r.recordBody.Links[i][:]...)
	}
	if len(l) > 0 {
		lptr = unsafe.Pointer(&l[0])
	}

	db.cdbLock.Lock()
	defer db.cdbLock.Unlock()

	cerr := C.ZTLF_DB_PutRecord_fromGo(
		db.cdb,
		unsafe.Pointer(&rdata[0]),
		C.uint(len(rdata)),
		C.int(r.Type),
		unsafe.Pointer(&r.recordBody.Owner[0]),
		C.uint(len(r.recordBody.Owner)),
		unsafe.Pointer(&rhash),
		unsafe.Pointer(&rid),
		C.uint64_t(r.recordBody.Timestamp),
		C.uint64_t(r.recordBody.PulseToken),
		C.uint32_t(r.Score()),
		selectorsPtr,
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

	db.cdbLock.Lock()
	defer db.cdbLock.Unlock()

	var doff, ts uint64
	dlen := int(C.ZTLF_DB_GetByHash(db.cdb, unsafe.Pointer(&(h[0])), (*C.uint64_t)(unsafe.Pointer(&doff)), (*C.uint64_t)(unsafe.Pointer(&ts))))
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
	db.cdbLock.Lock()
	defer db.cdbLock.Unlock()
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
		db.cdbLock.Lock()
		defer db.cdbLock.Unlock()
		var doff, ts uint64
		dlen := int(C.ZTLF_DB_GetByHash(db.cdb, unsafe.Pointer(&(h[0])), (*C.uint64_t)(unsafe.Pointer(&doff)), (*C.uint64_t)(unsafe.Pointer(&ts))))
		return dlen > 0
	}
	return false
}

// getRecordTimestampByHash returns whether or not the record exists and its timestamp in seconds since epoch.
func (db *db) getRecordTimestampByHash(h []byte) (bool, uint64) {
	if len(h) == 32 {
		db.cdbLock.Lock()
		defer db.cdbLock.Unlock()
		var doff, ts uint64
		if C.ZTLF_DB_GetByHash(db.cdb, unsafe.Pointer(&(h[0])), (*C.uint64_t)(unsafe.Pointer(&doff)), (*C.uint64_t)(unsafe.Pointer(&ts))) > 0 {
			return true, ts
		}
	}
	return false, 0
}

// getLinks gets up to count 32-bit hashes of linkable records, returning the number actually retrieved.
func (db *db) getLinks(count uint) (uint, []byte, error) {
	if count == 0 {
		return 0, nil, nil
	}
	db.cdbLock.Lock()
	defer db.cdbLock.Unlock()
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

func (db *db) updateRecordReputationByHash(h []byte, reputation int) {
	if len(h) == 32 {
		db.cdbLock.Lock()
		defer db.cdbLock.Unlock()
		C.ZTLF_DB_UpdateRecordReputationByHash(db.cdb, unsafe.Pointer(&h[0]), C.int(reputation))
	}
}

// stats returns some basic statistics about this database.
func (db *db) stats() (recordCount, dataSize uint64) {
	db.cdbLock.Lock()
	defer db.cdbLock.Unlock()
	C.ZTLF_DB_Stats(db.cdb, (*C.uint64_t)(unsafe.Pointer(&recordCount)), (*C.uint64_t)(unsafe.Pointer(&dataSize)))
	return
}

// crc64 returns a CRC64 of this database's important state information including hashes, graph weights, etc.
func (db *db) crc64() uint64 {
	db.cdbLock.Lock()
	defer db.cdbLock.Unlock()
	return uint64(C.ZTLF_DB_CRC64(db.cdb))
}

// hasPending returns true if this database is not waiting for any records to fill any graph gaps or satisfy any links.
// This can also be used to check whether synchronization is complete since it returns true only if there are records
// and all links for them are satisfied.
func (db *db) hasPending() bool {
	db.cdbLock.Lock()
	defer db.cdbLock.Unlock()
	return C.ZTLF_DB_HasPending(db.cdb) > 0
}

// haveDanglingLinks returns true if we have dangling links that haven't been retried more than N times.
func (db *db) haveDanglingLinks(ignoreAfterNRetries int) bool {
	db.cdbLock.Lock()
	defer db.cdbLock.Unlock()
	return C.ZTLF_DB_HaveDanglingLinks(db.cdb, C.int(ignoreAfterNRetries)) > 0
}

// query executes a query against a number of selector ranges. The function is executed for each result, with
// results not sorted. The loop is broken if the function returns false. The owner is passed as a pointer to
// an array that is reused, so a copy must be made if you want to keep it. The arguments to the function are:
// timestamp, weight (low), weight (high), data offset, data length, local reputation, cumulative selector key, owner, negative comments.
func (db *db) query(selectorRanges [][2][]byte, oracles []OwnerPublic, f func(uint64, uint64, uint64, uint64, uint64, int, uint64, []byte, uint) bool) error {
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

	var cresults *C.struct_ZTLF_QueryResults
	if len(oracles) > 0 {
		ora := make([]uintptr, len(oracles))
		oraSizes := make([]C.uint, len(oracles))
		for i := 0; i < len(oracles); i++ {
			if len(oracles[i]) == 0 {
				return ErrInvalidParameter
			}
			ora[i] = uintptr(unsafe.Pointer(&oracles[i][0]))
			oraSizes[i] = C.uint(len(oracles[i]))
		}

		db.cdbLock.Lock()
		cresults = C.ZTLF_DB_Query_fromGo(
			db.cdb,
			C.uintptr_t(uintptr(unsafe.Pointer(&sel[0]))),
			&selSizes[0],
			C.uint(len(selectorRanges)),
			C.uintptr_t(uintptr(unsafe.Pointer(&ora[0]))),
			&oraSizes[0],
			C.uint(len(oracles)))
		db.cdbLock.Unlock()
	} else {
		db.cdbLock.Lock()
		cresults = C.ZTLF_DB_Query_fromGo(
			db.cdb,
			C.uintptr_t(uintptr(unsafe.Pointer(&sel[0]))),
			&selSizes[0],
			C.uint(len(selectorRanges)),
			C.uintptr_t(0),
			nil,
			C.uint(0))
		db.cdbLock.Unlock()
	}

	if uintptr(unsafe.Pointer(cresults)) != 0 {
		defer C.free(unsafe.Pointer(cresults))
		for i := C.long(0); i < cresults.count; i++ {
			cr := (*C.struct_ZTLF_QueryResult)(unsafe.Pointer(uintptr(unsafe.Pointer(&cresults.results[0])) + (uintptr(i) * uintptr(C.sizeof_struct_ZTLF_QueryResult))))
			if cr.ownerSize > 0 && cr.dlen > 0 {
				if !f(uint64(cr.ts), uint64(cr.weightL), uint64(cr.weightH), uint64(cr.doff), uint64(cr.dlen), int(cr.localReputation), uint64(cr.ckey), C.GoBytes(unsafe.Pointer(&cr.owner[0]), C.int(cr.ownerSize)), uint(cr.negativeComments)) {
					break
				}
			}
		}
	}

	return nil
}

// getAllByOwner gets all (complete) records owned by a given owner key.
// Results are returned in ascending order of timestamp as: doff, dlen, reputation.
func (db *db) getAllByOwner(owner []byte, f func(uint64, uint64, int) bool) error {
	if len(owner) == 0 {
		return nil
	}
	db.cdbLock.Lock()
	results := C.ZTLF_DB_GetAllByOwner(db.cdb, unsafe.Pointer(&owner[0]), C.uint(len(owner)))
	db.cdbLock.Unlock()
	if uintptr(unsafe.Pointer(results)) != 0 {
		for i := C.long(0); i < results.count; i++ {
			rec := (*C.struct_ZTLF_RecordIndex)(unsafe.Pointer(uintptr(unsafe.Pointer(&results.records[0])) + (uintptr(i) * uintptr(C.sizeof_struct_ZTLF_RecordIndex))))
			if !f(uint64(rec.doff), uint64(rec.dlen), int(rec.localReputation)) {
				break
			}
		}
		C.free(unsafe.Pointer(results))
	}
	return nil
}

func (db *db) getOwnerStats(owner []byte) (recordCount uint64, recordBytes uint64) {
	if len(owner) == 0 {
		return
	}
	db.cdbLock.Lock()
	results := C.ZTLF_DB_GetAllByOwner(db.cdb, unsafe.Pointer(&owner[0]), C.uint(len(owner)))
	db.cdbLock.Unlock()
	if uintptr(unsafe.Pointer(results)) != 0 {
		for i := C.long(0); i < results.count; i++ {
			rec := (*C.struct_ZTLF_RecordIndex)(unsafe.Pointer(uintptr(unsafe.Pointer(&results.records[0])) + (uintptr(i) * uintptr(C.sizeof_struct_ZTLF_RecordIndex))))
			recordCount++
			recordBytes += uint64(rec.dlen)
		}
		C.free(unsafe.Pointer(results))
	}
	return
}

// getAllByOwner gets all (complete) records owned by a given ID that do not have the specified owner.
// Results are returned in ascending order of timestamp as: doff, dlen, reputation.
func (db *db) getAllByIDNotOwner(id []byte, owner []byte, f func(uint64, uint64, int) bool) error {
	if len(id) != 32 {
		return ErrInvalidParameter
	}
	if len(owner) == 0 {
		return nil
	}
	db.cdbLock.Lock()
	results := C.ZTLF_DB_GetAllByIDNotOwner(db.cdb, unsafe.Pointer(&id[0]), unsafe.Pointer(&owner[0]), C.uint(len(owner)))
	db.cdbLock.Unlock()
	if uintptr(unsafe.Pointer(results)) != 0 {
		for i := C.long(0); i < results.count; i++ {
			rec := (*C.struct_ZTLF_RecordIndex)(unsafe.Pointer(uintptr(unsafe.Pointer(&results.records[0])) + (uintptr(i) * uintptr(C.sizeof_struct_ZTLF_RecordIndex))))
			if !f(uint64(rec.doff), uint64(rec.dlen), int(rec.localReputation)) {
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
	db.cdbLock.Lock()
	count := int(C.ZTLF_DB_GetWanted(db.cdb, unsafe.Pointer(&buf[0]), C.uint(max), C.uint(retryCountMin), C.uint(retryCountMax), increment))
	db.cdbLock.Unlock()
	return count, buf[0 : count*32]
}

func (db *db) logComment(byRecordDoff uint64, assertion, reason int, subject []byte) error {
	var sub unsafe.Pointer
	if len(subject) > 0 {
		sub = unsafe.Pointer(&subject[0])
	}
	db.cdbLock.Lock()
	e := C.ZTLF_DB_LogComment(db.cdb, C.int64_t(byRecordDoff), C.int(assertion), C.int(reason), sub, C.int(len(subject)))
	db.cdbLock.Unlock()
	if e != 0 {
		return fmt.Errorf("database error %d", int(e))
	}
	return nil
}

func (db *db) getConfig(key string) []byte {
	db.cdbLock.Lock()
	defer db.cdbLock.Unlock()
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
	if len(value) > dbMaxConfigValueSize {
		return ErrInvalidParameter
	}
	db.cdbLock.Lock()
	defer db.cdbLock.Unlock()
	e := C.ZTLF_DB_SetConfig(db.cdb, C.CString(key), unsafe.Pointer(&value[0]), C.uint(len(value)))
	if e != 0 {
		return fmt.Errorf("database error %d", int(e))
	}
	return nil
}

/*
struct ZTLF_CertificateResults *ZTLF_DB_GetCertInfo(struct ZTLF_DB *db,const char *subjectSerial);
*/

func (db *db) putCert(cert *x509.Certificate, recordDoff uint64) error {
	if cert == nil || len(cert.Raw) == 0 {
		return errors.New("invalid certificate")
	}
	db.cdbLock.Lock()
	defer db.cdbLock.Unlock()
	e := C.ZTLF_DB_PutCert(db.cdb, C.CString(Base62Encode(cert.SerialNumber.Bytes())), C.CString(cert.Subject.SerialNumber), C.uint64_t(recordDoff), unsafe.Pointer(&cert.Raw[0]), C.uint(len(cert.Raw)))
	if e != 0 {
		return fmt.Errorf("database error %d", int(e))
	}
	return nil
}

func (db *db) putCertRevocation(revokedSerialNumber string, recordDoff uint64, recordDlen uint) error {
	db.cdbLock.Lock()
	defer db.cdbLock.Unlock()
	e := C.ZTLF_DB_PutCertRevocation(db.cdb, C.CString(revokedSerialNumber), C.uint64_t(recordDoff), C.uint(recordDlen))
	if e != 0 {
		return fmt.Errorf("database error %d", int(e))
	}
	return nil
}

// getCertInfo returns the certificates and CRLs for all relevant end chain and intermediate certs for a subject serial.
func (db *db) getCertInfo(subjectSerial string) (map[string]*x509.Certificate, map[string][]*pkix.CertificateList) {
	cBySerialNo := make(map[string]*x509.Certificate)
	crlByRevokedSerialNo := make(map[string][]*pkix.CertificateList)

	db.cdbLock.Lock()
	cr := C.ZTLF_DB_GetCertInfo(db.cdb, C.CString(subjectSerial))
	db.cdbLock.Unlock()
	if cr == nil {
		return cBySerialNo, crlByRevokedSerialNo
	}
	defer C.ZTLF_DB_FreeCertificateResults(cr)

	for crli, crlCount := uint(0), uint(cr.crlCount); crli < crlCount; crli++ {
		ri := (*C.struct_ZTLF_RecordIndex)(unsafe.Pointer(uintptr(unsafe.Pointer(cr.crls)) + (uintptr(crli) * uintptr(C.sizeof_struct_ZTLF_RecordIndex))))
		rdata, _ := db.getDataByOffset(uint64(ri.doff), uint(ri.dlen), nil)
		if len(rdata) > 0 {
			rec, _ := NewRecordFromBytes(rdata)
			if rec != nil {
				crlBytes, _ := rec.GetValue([]byte(RecordCertificateMaskingKey))
				if len(crlBytes) > 0 {
					crl, _ := x509.ParseCRL(crlBytes)
					for _, revoked := range crl.TBSCertList.RevokedCertificates {
						sn := Base62Encode(revoked.SerialNumber.Bytes())
						crlByRevokedSerialNo[sn] = append(crlByRevokedSerialNo[sn], crl)
					}
				}
			}
		}
	}

	certs, _ := x509.ParseCertificates(C.GoBytes(cr.certificates, C.int(cr.certificatesLength)))
	for _, cert := range certs {
		cBySerialNo[Base62Encode(cert.SerialNumber.Bytes())] = cert
	}

	return cBySerialNo, crlByRevokedSerialNo
}

func (db *db) markInLimbo(hash, owner []byte, localReceiveTime, ts uint64) error {
	if len(hash) != 32 || len(owner) == 0 {
		return ErrInvalidParameter
	}
	db.cdbLock.Lock()
	defer db.cdbLock.Unlock()
	e := C.ZTLF_DB_MarkInLimbo(db.cdb, unsafe.Pointer(&hash[0]), unsafe.Pointer(&owner[0]), C.uint(len(owner)), C.uint64_t(localReceiveTime), C.uint64_t(ts))
	if e != 0 {
		return fmt.Errorf("database error %d", int(e))
	}
	return nil
}

func (db *db) haveRecordIncludeLimbo(hash []byte) bool {
	if len(hash) != 32 {
		return false
	}
	db.cdbLock.Lock()
	defer db.cdbLock.Unlock()
	return C.ZTLF_DB_HaveRecordIncludeLimbo(db.cdb, unsafe.Pointer(&hash[0])) > 0
}

func (db *db) updatePulse(token, minutes, startRangeStart, startRangeEnd uint64) bool {
	db.cdbLock.Lock()
	defer db.cdbLock.Unlock()
	return C.ZTLF_DB_UpdatePulse(db.cdb, C.uint64_t(token), C.uint64_t(minutes), C.uint64_t(startRangeStart), C.uint64_t(startRangeEnd)) > 0
}

func (db *db) getPulse(token uint64) uint64 {
	db.cdbLock.Lock()
	defer db.cdbLock.Unlock()
	return uint64(C.ZTLF_DB_GetPulse(db.cdb, C.uint64_t(token)))
}
