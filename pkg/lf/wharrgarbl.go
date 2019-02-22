/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/crypto/sha3"
)

//#include <stdlib.h>
//#include <string.h>
import "C"

// Wharrgarbl holds a global pointer to memory allocated via external C malloc().
// There's not much point in allocating this on demand since this uses all cores
// anyway so one at a time is about the best you can do.
var (
	wharrgarblMemoryPtr     unsafe.Pointer
	wharrgarblMemorySize    uint
	wharrgarblMemoryEntries uint
	wharrgarblMemoryLock    sync.Mutex

	wharrgarblStaticTable            [4194304]uint64
	wharrgarblStaticTableInitialized = func() bool {
		wharrgarblStaticTableKey := sha3.Sum256([]byte("WharrrrRRRRgarbl!"))
		wharrgarblStaticTableMem := (*[4194304 * 8]byte)(unsafe.Pointer(&wharrgarblStaticTable[0]))
		for i := 0; i < 8; i++ {
			wharrgarblStaticTableAes, _ := aes.NewCipher(wharrgarblStaticTableKey[:])
			cfb := cipher.NewCFBEncrypter(wharrgarblStaticTableAes, wharrgarblStaticTableKey[0:16])
			cfb.XORKeyStream(wharrgarblStaticTableMem[:], wharrgarblStaticTableMem[:])
			wharrgarblStaticTableKey = sha3.Sum256(wharrgarblStaticTableMem[:])
		}
		return true
	}()
)

// WharrgarblOutputSize is the size of Wharrgarbl's result in bytes.
const WharrgarblOutputSize = 20

// wharrgarblMMOHash is a simple 16X Matyas-Meyer-Oseas single block hash function that also requires a 32MB static table.
func wharrgarblMMOHash(mmoCipher0, mmoCipher1 cipher.Block, in *[16]byte) uint64 {
	var tmp0, tmp1 [2]uint64
	tmp0s := ((*[16]byte)(unsafe.Pointer(&tmp0)))[:]
	tmp1s := ((*[16]byte)(unsafe.Pointer(&tmp1)))[:]

	mmoCipher0.Encrypt(tmp0s, in[:])
	for i := 0; i < 16; i++ {
		tmp0s[i] ^= in[i]
	}
	tmp0[1] ^= wharrgarblStaticTable[uint(tmp0[0])%4194304]

	mmoCipher1.Encrypt(tmp1s, tmp0s)
	tmp1[0] ^= tmp0[0]
	tmp1[1] ^= tmp0[1] ^ wharrgarblStaticTable[uint(tmp0[0])%4194304]

	mmoCipher0.Encrypt(tmp0s, tmp1s)
	tmp0[0] ^= tmp1[0]
	tmp0[1] ^= tmp1[1] ^ wharrgarblStaticTable[uint(tmp0[0])%4194304]

	mmoCipher1.Encrypt(tmp1s, tmp0s)
	tmp1[0] ^= tmp0[0]
	tmp1[1] ^= tmp0[1] ^ wharrgarblStaticTable[uint(tmp0[0])%4194304]

	mmoCipher0.Encrypt(tmp0s, tmp1s)
	tmp0[0] ^= tmp1[0]
	tmp0[1] ^= tmp1[1] ^ wharrgarblStaticTable[uint(tmp0[0])%4194304]

	mmoCipher1.Encrypt(tmp1s, tmp0s)
	tmp1[0] ^= tmp0[0]
	tmp1[1] ^= tmp0[1] ^ wharrgarblStaticTable[uint(tmp0[0])%4194304]

	mmoCipher0.Encrypt(tmp0s, tmp1s)
	tmp0[0] ^= tmp1[0]
	tmp0[1] ^= tmp1[1] ^ wharrgarblStaticTable[uint(tmp0[0])%4194304]

	mmoCipher1.Encrypt(tmp1s, tmp0s)
	tmp1[0] ^= tmp0[0]
	tmp1[1] ^= tmp0[1] ^ wharrgarblStaticTable[uint(tmp0[0])%4194304]

	mmoCipher0.Encrypt(tmp0s, tmp1s)
	tmp0[0] ^= tmp1[0]
	tmp0[1] ^= tmp1[1] ^ wharrgarblStaticTable[uint(tmp0[0])%4194304]

	mmoCipher1.Encrypt(tmp1s, tmp0s)
	tmp1[0] ^= tmp0[0]
	tmp1[1] ^= tmp0[1] ^ wharrgarblStaticTable[uint(tmp0[0])%4194304]

	mmoCipher0.Encrypt(tmp0s, tmp1s)
	tmp0[0] ^= tmp1[0]
	tmp0[1] ^= tmp1[1] ^ wharrgarblStaticTable[uint(tmp0[0])%4194304]

	mmoCipher1.Encrypt(tmp1s, tmp0s)
	tmp1[0] ^= tmp0[0]
	tmp1[1] ^= tmp0[1] ^ wharrgarblStaticTable[uint(tmp0[0])%4194304]

	mmoCipher0.Encrypt(tmp0s, tmp1s)
	tmp0[0] ^= tmp1[0]
	tmp0[1] ^= tmp1[1] ^ wharrgarblStaticTable[uint(tmp0[0])%4194304]

	mmoCipher1.Encrypt(tmp1s, tmp0s)
	tmp1[0] ^= tmp0[0]
	tmp1[1] ^= tmp0[1] ^ wharrgarblStaticTable[uint(tmp0[0])%4194304]

	mmoCipher0.Encrypt(tmp0s, tmp1s)
	tmp0[0] ^= tmp1[0]
	tmp0[1] ^= tmp1[1] ^ wharrgarblStaticTable[uint(tmp0[0])%4194304]

	mmoCipher1.Encrypt(tmp1s, tmp0s)
	tmp1[0] ^= tmp0[0]
	tmp1[1] ^= tmp0[1] ^ wharrgarblStaticTable[uint(tmp0[0])%4194304]

	return tmp1[0] ^ tmp1[1]
}

func wharrgarblWorkerFunc(mmoCipher0, mmoCipher1 cipher.Block, runNonce, diff64 uint64, iterations *uint64, done *uint32, outLock *sync.Mutex, out []byte, doneWG *sync.WaitGroup) {
	var collisionHashIn [16]byte
	var iter uint64
	var wharrgarblMemory *[2147483647]uint64
	wharrgarblMemory = (*[2147483647]uint64)(wharrgarblMemoryPtr) // array is not actually this big, but trick Go into using a simple pointer
	_ = wharrgarblMemory[wharrgarblMemoryEntries-1]

	thisCollider := rand.Uint32()
	for *done == 0 {
		iter++
		thisCollider++

		binary.BigEndian.PutUint32(collisionHashIn[4:8], thisCollider)
		thisCollision := wharrgarblMMOHash(mmoCipher0, mmoCipher1, &collisionHashIn) % diff64
		thisCollision32 := uint32(thisCollision) + uint32(thisCollision>>32)

		collisionTableIdx := uint(thisCollision^runNonce) % wharrgarblMemoryEntries
		collisionTableEntry := wharrgarblMemory[collisionTableIdx]

		if uint32(collisionTableEntry>>32) == thisCollision32 {
			otherCollider := uint32(collisionTableEntry)
			if otherCollider != thisCollider {
				binary.BigEndian.PutUint32(collisionHashIn[4:8], otherCollider)
				if (wharrgarblMMOHash(mmoCipher0, mmoCipher1, &collisionHashIn) % diff64) == thisCollision {
					atomic.StoreUint32(done, 1)
					outLock.Lock()
					binary.BigEndian.PutUint32(out[4:8], thisCollider)
					binary.BigEndian.PutUint32(out[12:16], otherCollider)
					outLock.Unlock()
					break
				}
			}
		}

		wharrgarblMemory[collisionTableIdx] = (uint64(thisCollision32) << 32) | uint64(thisCollider)
	}

	atomic.AddUint64(iterations, iter)

	doneWG.Done()
}

// Wharrgarbl computes a proof of work from an input challenge.
func Wharrgarbl(in []byte, difficulty uint32, minMemorySize uint) (out [20]byte, iterations uint64) {
	wharrgarblMemoryLock.Lock()
	defer wharrgarblMemoryLock.Unlock()

	if !wharrgarblStaticTableInitialized {
		panic("Wharrgarbl static table not initialized")
	}

	if minMemorySize < 1048576 {
		minMemorySize = 1048576
	}
	if wharrgarblMemorySize < minMemorySize {
		if wharrgarblMemorySize > 0 {
			C.free(wharrgarblMemoryPtr)
		}
		wharrgarblMemoryPtr = C.valloc(C.ulong(minMemorySize))
		if uintptr(wharrgarblMemoryPtr) == 0 {
			panic("out of memory (external malloc)")
		}
		C.memset(wharrgarblMemoryPtr, 0, C.ulong(minMemorySize))
		wharrgarblMemorySize = minMemorySize
		wharrgarblMemoryEntries = minMemorySize / 8
	}

	inHashed := sha3.Sum256(in)
	mmoCipher0, _ := aes.NewCipher(inHashed[0:16])
	mmoCipher1, _ := aes.NewCipher(inHashed[16:32])
	diff64 := (uint64(difficulty) << 28) | 0x000000000fffffff
	runNonce := rand.Uint64() // a nonce that randomizes indexes in the collision table to facilitate re-use without clearing

	var outLock sync.Mutex
	var done uint32
	var doneWG sync.WaitGroup
	cpus := runtime.NumCPU()
	doneWG.Add(cpus)
	for c := 1; c < cpus; c++ {
		go wharrgarblWorkerFunc(mmoCipher0, mmoCipher1, runNonce, diff64, &iterations, &done, &outLock, out[:], &doneWG)
	}
	wharrgarblWorkerFunc(mmoCipher0, mmoCipher1, runNonce, diff64, &iterations, &done, &outLock, out[:], &doneWG)
	doneWG.Wait()

	binary.BigEndian.PutUint32(out[16:20], difficulty)

	return
}

// WharrgarblVerify checks whether work is valid for the provided input, returning the difficulty used or 0 if work is not valid.
func WharrgarblVerify(work []byte, in []byte) uint32 {
	if len(work) != WharrgarblOutputSize {
		return 0
	}

	var collisionHashIn [16]byte
	inHashed := sha3.Sum256(in)
	mmoCipher0, _ := aes.NewCipher(inHashed[0:16])
	mmoCipher1, _ := aes.NewCipher(inHashed[16:32])

	var colliders [2]uint64
	for i := 0; i < 2; i++ {
		colliders[i] = binary.BigEndian.Uint64(work[8*i:])
	}
	difficulty := binary.BigEndian.Uint32(work[16:20])

	if colliders[0] == colliders[1] {
		return 0
	}

	diff64 := (uint64(difficulty) << 28) | 0x000000000fffffff
	var collisions [2]uint64
	for i := 0; i < 2; i++ {
		binary.BigEndian.PutUint64(collisionHashIn[0:8], colliders[i])
		collisions[i] = wharrgarblMMOHash(mmoCipher0, mmoCipher1, &collisionHashIn) % diff64
	}

	if collisions[0] == collisions[1] {
		return difficulty
	}
	return 0
}

// WharrgarblGetDifficulty extracts the difficulty from a work result without performing any verification.
func WharrgarblGetDifficulty(work []byte) uint32 {
	if len(work) == WharrgarblOutputSize {
		return binary.BigEndian.Uint32(work[16:20]) // difficulty is appended as last 4 bytes
	}
	return 0
}

// WharrgarblFreeMemory frees the global memory arena if it is allocated.
// It will automatically be re-allocated if needed.
func WharrgarblFreeMemory() {
	wharrgarblMemoryLock.Lock()
	defer wharrgarblMemoryLock.Unlock()
	if wharrgarblMemorySize > 0 {
		C.free(wharrgarblMemoryPtr)
		wharrgarblMemorySize = 0
		wharrgarblMemoryEntries = 0
	}
}
