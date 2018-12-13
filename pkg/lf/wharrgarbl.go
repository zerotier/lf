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

// Wharrgarbl computes the result of the Wharrgarbl proof of work function using input as a unique challenge.
// This can of course be extremely time consuming, sometimes taking minutes for very high difficulties on some systems.
// The concurrency parameter specifies how many hardware threads to use. If it's zero the number of CPUs in the system is used.
// The memory must be at least 12 bytes in size and need not be cleared between calls to Wharrgarbl(). If computation fails
// for some reason (e.g. memory is nil) zero iterations will be returned. Otherwise iterations is the total number of search
// iterations executed on all threads to find the result.
func Wharrgarbl(in []byte, difficulty uint32, memory []byte, concurrency uint) (out [20]byte, iterations uint64) {
	if len(memory) < 12 {
		return
	}
	var waitForCompletionLock sync.Mutex
	waitForCompletionLock.Lock()
	go func() {
		runtime.LockOSThread()
		iterations = uint64(C.ZTLF_Wharrgarbl(unsafe.Pointer(&out), unsafe.Pointer(&(in[0])), _Ctype_ulong(len(in)), _Ctype_uint(difficulty), unsafe.Pointer(&(memory[0])), _Ctype_ulong(len(memory)), _Ctype_uint(concurrency)))
		waitForCompletionLock.Unlock()
		runtime.UnlockOSThread()
	}()
	waitForCompletionLock.Lock() // wait for C function to complete
	waitForCompletionLock.Unlock()
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
