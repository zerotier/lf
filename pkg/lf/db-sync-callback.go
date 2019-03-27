package lf

// Callbacks called from C have to be in a separate file due to cgo linking weirdness.

// #cgo CFLAGS: -O3
// #include "./native/db.h"
import "C"
import "unsafe"

//export ztlfSyncCCallback
func ztlfSyncCCallback(dbp unsafe.Pointer, hash unsafe.Pointer, doff C.uint64_t, dlen C.uint, arg unsafe.Pointer) {
	globalSyncCallbacksLock.RLock()
	defer func() {
		_ = recover() // should not happen since this is caught elsewhere, but make non-fatal
		globalSyncCallbacksLock.RUnlock()
	}()
	idx := int(uintptr(arg) & 0x7fffffff)
	if idx < len(globalSyncCallbacks) && globalSyncCallbacks[idx] != nil {
		globalSyncCallbacks[idx](uint64(doff), uint(dlen), (*[32]byte)(hash))
	}
}
