/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c)2019-2021 ZeroTier, Inc.
 * https://www.zerotier.com/
 */

package lf

// Callbacks called from C have to be in a separate file due to cgo linking weirdness.

//#include <stdint.h>
import "C"

import (
	"log"
	"unsafe"
)

// These must be the same as the log levels in native/common.h.
const (
	// LogLevelFatal messages precede fatal error shutdowns and indicate serious problems like I/O errors or bugs.
	LogLevelFatal int = 0

	// LogLevelWarning messages indicate a non-fatal but potentailly serious problem such as a database that may have corruption.
	LogLevelWarning int = 1

	// LogLevelNormal indicates normal log messages that most users would want to see or record.
	LogLevelNormal int = 2

	// LogLevelVerbose tracks details that some users might not care about.
	LogLevelVerbose int = 3

	// LogLevelTrace only works if tracing is enabled at compile time and outputs a ton of detail useful only to developers.
	LogLevelTrace int = 4

	logLevelCount = 5
)

// This callback handles logger output from the C parts of LF. Right now that's mostly just db.c, so this is here,
// but it could in theory take log output from other C code if other C code existed.
//export ztlfLogOutputCCallback
func ztlfLogOutputCCallback(level C.int, srcFile unsafe.Pointer, srcLine C.int, msg unsafe.Pointer, loggerArg unsafe.Pointer) {
	srcFileStr := "<unknown file>"
	if uintptr(srcFile) != 0 {
		srcFileStr = C.GoString((*C.char)(srcFile))
	}
	msgStr := "(no message)"
	msgStr = C.GoString((*C.char)(msg))

	larg := uint(uintptr(loggerArg))

	globalLoggersLock.Lock()
	defer globalLoggersLock.Unlock()

	if level >= logLevelCount || level < 0 {
		return
	}
	var logger *log.Logger
	if larg < uint(len(globalLoggers)) {
		logger = globalLoggers[larg][level]
	}
	if logger == nil {
		return
	}

	switch int(level) {
	//case logLevelNormal:
	default:
		logger.Println(msgStr)
	case LogLevelWarning:
		logger.Printf("WARNING: %s\n", msgStr)
	case LogLevelFatal:
		logger.Printf("FATAL: %s\n", msgStr)
	case LogLevelTrace:
		logger.Printf("TRACE (C %s:%d): %s\n", srcFileStr, srcLine, msgStr)
	case LogLevelVerbose:
		logger.Println(msgStr)
	}
}
