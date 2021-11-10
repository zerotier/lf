/*
 * Copyright (c)2019 ZeroTier, Inc.
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file in the project's root directory.
 *
 * Change Date: 2023-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2.0 of the Apache License.
 */
/****/

package lf

// Callbacks called from C have to be in a separate file due to cgo linking weirdness.

//#include <stdint.h>
import "C"
import "unsafe"

//export ztlfSyncCCallback
func ztlfSyncCCallback(dbp unsafe.Pointer, hash unsafe.Pointer, doff C.uint64_t, dlen C.uint, reputation C.int, arg unsafe.Pointer) {
	globalSyncCallbacksLock.RLock()
	defer func() {
		_ = recover() // should not happen since this is caught elsewhere, but make non-fatal
		globalSyncCallbacksLock.RUnlock()
	}()
	idx := int(uintptr(arg) & 0x7fffffff)
	if idx < len(globalSyncCallbacks) && globalSyncCallbacks[idx] != nil {
		var hash2 [32]byte
		copy(hash2[:], ((*[32]byte)(hash))[:]) // make copy since this buffer changes between callbacks
		globalSyncCallbacks[idx](uint64(doff), uint(dlen), int(reputation), &hash2)
	}
}
