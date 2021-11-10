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
