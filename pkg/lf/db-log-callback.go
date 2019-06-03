/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * --
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial closed-source software that incorporates or links
 * directly against ZeroTier software without disclosing the source code
 * of your own application.
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
