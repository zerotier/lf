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
	"unsafe"
)

// These must be the same as the log levels in native/common.h.
const logLevelNormal = 0
const logLevelWarning = -1
const logLevelFatal = -2
const logLevelVerbose = 1
const logLevelTrace = 2

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
