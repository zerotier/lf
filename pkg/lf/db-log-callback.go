/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
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
const (
	// LogLevelNormal indicates normal log messages that most users would want to see or record.
	LogLevelNormal int = 0

	// LogLevelWarning messages indicate a non-fatal but potentailly serious problem such as a database that may have corruption.
	LogLevelWarning int = -1

	// LogLevelFatal messages precede fatal error shutdowns and indicate serious problems like I/O errors or bugs.
	LogLevelFatal int = -2

	// LogLevelVerbose tracks details that some users might not care about.
	LogLevelVerbose int = 1

	// LogLevelTrace only works if tracing is enabled at compile time and outputs a ton of detail useful only to developers.
	LogLevelTrace int = 2
)

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
	var logger *log.Logger

	globalLoggersLock.Lock()

	if larg < uint(len(globalLoggers)) {
		logger = globalLoggers[larg]
	}
	if logger == nil {
		logger = globalDefaultLogger
	}

	switch level {
	//case logLevelNormal:
	default:
		logger.Println(msgStr)
	case LogLevelWarning:
		logger.Printf("WARNING [%s:%d] %s\n", srcFileStr, srcLine, msgStr)
	case LogLevelFatal:
		logger.Printf("FATAL [%s:%d] %s\n", srcFileStr, srcLine, msgStr)
	case LogLevelTrace:
		logger.Printf("TRACE [%s:%d] %s\n", srcFileStr, srcLine, msgStr)
	case LogLevelVerbose:
		logger.Println(msgStr)
	}

	globalLoggersLock.Unlock()
}
