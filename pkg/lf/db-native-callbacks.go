/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

// Callbacks called from C have to be in a separate file due to cgo linking weirdness.

// #cgo CFLAGS: -O3
// #cgo LDFLAGS: -lsqlite3
// #include "./native/db.h"
import "C"

import (
	"log"
	"sync"
	"unsafe"
)

// These must be the same as the log levels in native/common.h.
const logLevelNormal = 0
const logLevelWarning = -1
const logLevelFatal = -2
const logLevelVerbose = 1
const logLevelTrace = 2

type dbGetMatchingStateByIDOwner struct {
	doff, dlen       int64
	exp              uint64
	weightL, weightH uint64
}

type dbGetMatchingState struct {
	byIDOwner  map[[64]byte]*dbGetMatchingStateByIDOwner
	maxResults uint
}

// There's only one of these for now. We could make this more concurrent by having a pool,
// but right now the DB itself is not concurrent so there's no point. We have to statically
// allocate these somehow because we can't pass a pointer to this through C to the Go
// callback that actually handles each record.
var dbGetMatchingStateInstance dbGetMatchingState
var dbGetMatchingStateInstanceLock sync.Mutex

// This is the callback invoked from C database code as we iterate through results in db.getMatching().
//export ztlfDBInternalGetMatchingCCallback
func ztlfDBInternalGetMatchingCCallback(doff, dlen C.longlong, ts, exp C.ulonglong, id, owner, newOwner unsafe.Pointer, weightL, weightH C.ulonglong, arg C.ulong) C.int {
	state := dbGetMatchingStateInstance // right now there's only one and arg is unused

	var idOwner [64]byte
	copy(idOwner[0:32], (*((*[32]byte)(id)))[:])
	copy(idOwner[32:64], (*((*[32]byte)(owner)))[:])
	b := state.byIDOwner[idOwner]
	if b == nil {
		b = new(dbGetMatchingStateByIDOwner)
		if uintptr(newOwner) != 0 {
			copy(idOwner[32:64], (*((*[32]byte)(newOwner)))[:])
		}
		state.byIDOwner[idOwner] = b
	} else {
		if uintptr(newOwner) != 0 {
			delete(state.byIDOwner, idOwner)
			copy(idOwner[32:64], (*((*[32]byte)(newOwner)))[:])
			state.byIDOwner[idOwner] = b
		}
	}

	if uint64(ts) > b.exp {
		b.weightL = 0
		b.weightL = 0
	}
	b.doff = int64(doff)
	b.dlen = int64(dlen)
	b.exp = uint64(exp)

	owl := b.weightL
	b.weightL += uint64(weightL)
	if b.weightL < owl {
		b.weightH++
	}
	b.weightH += uint64(weightH)

	return 0
}

// This callback handles logger output from the C parts of LF. Right now that's mostly just db.c, so this is here,
// but it could in theory take log output from other code.
//export ztlfLogOutputCCallback
func ztlfLogOutputCCallback(level int, srcFile unsafe.Pointer, srcLine int, msg unsafe.Pointer, loggerArg unsafe.Pointer) {
	srcFileStr := "<unknown file>"
	if uintptr(srcFile) != 0 {
		srcFileStr = C.GoString((*C.char)(srcFile))
	}
	msgStr := "(no message)"
	msgStr = C.GoString((*C.char)(msg))

	larg := uint(uintptr(loggerArg))
	var logger, verboseLogger *log.Logger

	globalLoggersLock.Lock()

	if larg < uint(len(globalLoggers)) {
		logger = globalLoggers[larg]
		verboseLogger = globalVerboseLoggers[larg]
	}
	if logger == nil {
		logger = globalDefaultLogger
	}
	if verboseLogger == nil {
		verboseLogger = globalDefaultVerboseLogger
	}

	switch level {
	//case logLevelNormal:
	default:
		logger.Println(msgStr)
	case logLevelWarning:
		logger.Printf("WARNING [%s:%d] %s\n", srcFileStr, srcLine, msgStr)
	case logLevelFatal:
		logger.Printf("FATAL [%s:%d] %s\n", srcFileStr, srcLine, msgStr)
	case logLevelTrace:
		verboseLogger.Printf("TRACE [%s:%d] %s\n", srcFileStr, srcLine, msgStr)
	case logLevelVerbose:
		verboseLogger.Println(msgStr)
	}

	globalLoggersLock.Unlock()
}
