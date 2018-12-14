package lf

// #cgo CFLAGS: -O3
// #include "./native/wharrgarbl.h"
// #include "./native/wharrgarbl.c"
import "C"
import (
	"encoding/binary"
	"runtime"
	"sync"
	"unsafe"
)

// WharrgarblProofOfWorkSize is the size of Wharrgarbl's result in bytes.
const WharrgarblProofOfWorkSize = 20

// A single memory arena is kept around for performance reasons. All CPU cores are used by Wharrgarbl,
// so there is no point in parallelizing it.
var wharrgarblMemory unsafe.Pointer
var wharrgarblMemorySize uint
var wharrgarblMemoryLock sync.Mutex

// SpeckHash computes a simple Davies-Meyer type hash.
// This algorithm isn't for authentication or other security uses. It's only used in the Wharrgarbl
// PoW collision search. It's exposed for testing/verification.
func SpeckHash(in []byte) (out [2]uint64) {
	if len(in) > 0 {
		C.ZTLF_SpeckHash((*_Ctype_ulonglong)(unsafe.Pointer(&out)), unsafe.Pointer(&(in[0])), _Ctype_ulong(len(in)))
	} else {
		C.ZTLF_SpeckHash((*_Ctype_ulonglong)(unsafe.Pointer(&out)), nil, _Ctype_ulong(0))
	}
	return
}

// Wharrgarbl computes the result of the Wharrgarbl proof of work function using input as a unique challenge.
// This can of course be extremely time consuming, sometimes taking minutes for very high difficulties on some systems.
// The memory must be at least 12 bytes in size and need not be cleared between calls to Wharrgarbl(). Any failure results in
// zero being returned for iterations and an undefined result in []out.
func Wharrgarbl(in []byte, difficulty uint32, minMemorySize uint) (out [20]byte, iterations uint64) {
	if minMemorySize < 12 {
		return
	}

	wharrgarblMemoryLock.Lock()
	if wharrgarblMemorySize < minMemorySize {
		if uintptr(wharrgarblMemory) != 0 {
			C.free(wharrgarblMemory)
		}
		wharrgarblMemory = C.malloc(_Ctype_ulong(minMemorySize))
		if uintptr(wharrgarblMemory) == 0 {
			wharrgarblMemoryLock.Unlock()
			panic("out of memory (C malloc)")
		}
		wharrgarblMemorySize = minMemorySize
	}

	runtime.LockOSThread()
	iterations = uint64(C.ZTLF_Wharrgarbl(unsafe.Pointer(&out), unsafe.Pointer(&(in[0])), _Ctype_ulong(len(in)), _Ctype_uint(difficulty), wharrgarblMemory, _Ctype_ulong(wharrgarblMemorySize), _Ctype_uint(runtime.NumCPU())))
	runtime.UnlockOSThread()

	wharrgarblMemoryLock.Unlock()

	return
}

// WharrgarblVerify checks whether work is valid for the provided input, returning the difficulty used or 0 if work is not valid.
func WharrgarblVerify(work []byte, in []byte) uint32 {
	if len(work) != 20 {
		return 0
	}
	return uint32(C.ZTLF_WharrgarblVerify(unsafe.Pointer(&(work[0])), unsafe.Pointer(&(in[0])), _Ctype_ulong(len(in))))
}

// WharrgarblGetDifficulty extracts the difficulty from a work result without performing any verification.
func WharrgarblGetDifficulty(work []byte) uint32 {
	if len(work) == 20 {
		return binary.BigEndian.Uint32(work[16:20])
	}
	return 0
}

// WharrgarblFreeGlobalMemory frees any global memory areas allocated from previous calls to Wharrgarbl().
// Memory will be re-allocated if needed.
func WharrgarblFreeGlobalMemory() {
	wharrgarblMemoryLock.Lock()
	if uintptr(wharrgarblMemory) != 0 {
		C.free(wharrgarblMemory)
	}
	wharrgarblMemory = nil
	wharrgarblMemorySize = 0
	wharrgarblMemoryLock.Unlock()
}
