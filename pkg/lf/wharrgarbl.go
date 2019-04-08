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
	wharrgarblMemoryEntries uintptr
	wharrgarblMemoryLock    sync.Mutex
)

// WharrgarblOutputSize is the size of Wharrgarbl's result in bytes.
const WharrgarblOutputSize = 14

// wharrgarblMMOHash is a multiple (48) iteration single block Matyas-Meyer-Oseas hash.
// It's not used for things like signatures or authentication, just as a cryptographic
// random function for Wharrgarbl collision search proof of work. It takes two keyed
// ciphers for MMO where these are keyed by the Wharrgarbl input, making each Wharrgarbl
// PoW search unique in terms of the random function searched.
func wharrgarblMMOHash(mmoCipher0, mmoCipher1 cipher.Block, tmp *[4]uint64, in *[16]byte) uint64 {
	tmp0 := (*[16]byte)(unsafe.Pointer(tmp))[:]
	tmp1 := (*[16]byte)(unsafe.Pointer(&tmp[2]))[:]

	mmoCipher0.Encrypt(tmp0, in[:])
	for i := 0; i < 16; i++ {
		tmp0[i] ^= in[i]
	}

	mmoCipher1.Encrypt(tmp1, tmp0)
	tmp[2] ^= tmp[0]
	tmp[3] ^= tmp[1]

	for k := 0; k < 46; k++ {
		mmoCipher0.Encrypt(tmp0, tmp1)
		tmp[0] ^= tmp[2]
		tmp[1] ^= tmp[3]

		mmoCipher1.Encrypt(tmp1, tmp0)
		tmp[2] ^= tmp[0]
		tmp[3] ^= tmp[1]
	}

	return binary.BigEndian.Uint64(tmp1[0:8]) ^ binary.BigEndian.Uint64(tmp1[8:16])
}

func wharrgarblWorkerFunc(mmoCipher0, mmoCipher1 cipher.Block, runNonce, diff64 uint64, iterations *uint64, done *uint32, outLock *sync.Mutex, out []byte, doneWG *sync.WaitGroup) {
	var collisionHashIn [16]byte
	var iter uint64
	var tmp [4]uint64

	// Generate an initial 40-bit collider.
	thisCollider := uint64(rand.Uint32()) ^ (uint64(rand.Uint32()&0x3f) << 32)
	for atomic.LoadUint32(done) == 0 {
		iter++

		thisCollider++
		collisionHashIn[3] = byte(thisCollider >> 32)
		collisionHashIn[4] = byte(thisCollider >> 24)
		collisionHashIn[5] = byte(thisCollider >> 16)
		collisionHashIn[6] = byte(thisCollider >> 8)
		collisionHashIn[7] = byte(thisCollider)
		thisCollision := wharrgarblMMOHash(mmoCipher0, mmoCipher1, &tmp, &collisionHashIn) % diff64

		// The collision table contains 64-bit entries indexed by collision. These contain
		// the collider (least significant 40 bits) and 24 bits of the other collision. We
		// then recompute the full collision for the other collider to verify since there's
		// a 1/2^24 chance of a false positive.
		collisionTableEntry := (*uint64)(unsafe.Pointer(uintptr(wharrgarblMemoryPtr) + (uintptr(thisCollision^runNonce)%wharrgarblMemoryEntries)<<3))

		collisionTableEntryCurrent := *collisionTableEntry
		thisCollision24 := uint32(thisCollision) & 0x00ffffff
		if uint32(collisionTableEntryCurrent>>40) == thisCollision24 {
			otherCollider := collisionTableEntryCurrent & 0xffffffffff
			if otherCollider != thisCollider {
				collisionHashIn[3] = byte(otherCollider >> 32)
				collisionHashIn[4] = byte(otherCollider >> 24)
				collisionHashIn[5] = byte(otherCollider >> 16)
				collisionHashIn[6] = byte(otherCollider >> 8)
				collisionHashIn[7] = byte(otherCollider)
				if (wharrgarblMMOHash(mmoCipher0, mmoCipher1, &tmp, &collisionHashIn) % diff64) == thisCollision {
					atomic.StoreUint32(done, 1)
					outLock.Lock()
					out[0] = byte(thisCollider >> 32)
					out[1] = byte(thisCollider >> 24)
					out[2] = byte(thisCollider >> 16)
					out[3] = byte(thisCollider >> 8)
					out[4] = byte(thisCollider)
					out[5] = byte(otherCollider >> 32)
					out[6] = byte(otherCollider >> 24)
					out[7] = byte(otherCollider >> 16)
					out[8] = byte(otherCollider >> 8)
					out[9] = byte(otherCollider)
					outLock.Unlock()
					break
				}
			}
		}

		*collisionTableEntry = (uint64(thisCollision24) << 40) | uint64(thisCollider)
	}

	atomic.AddUint64(iterations, iter)
	doneWG.Done()
}

// Wharrgarbl computes a proof of work from an input challenge.
func Wharrgarbl(in []byte, difficulty uint32, minMemorySize uint) (out [WharrgarblOutputSize]byte, iterations uint64) {
	wharrgarblMemoryLock.Lock()
	defer wharrgarblMemoryLock.Unlock()

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
		wharrgarblMemoryEntries = uintptr(minMemorySize / 8)
	}

	inHashed := sha3.Sum512(in)
	mmoCipher0, _ := aes.NewCipher(inHashed[0:32])
	mmoCipher1, _ := aes.NewCipher(inHashed[32:64])
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

	binary.BigEndian.PutUint32(out[10:14], difficulty)

	return
}

// WharrgarblVerify checks whether work is valid for the provided input, returning the difficulty used or 0 if work is not valid.
func WharrgarblVerify(work []byte, in []byte) uint32 {
	if len(work) != WharrgarblOutputSize {
		return 0
	}

	var collisionHashIn [16]byte
	inHashed := sha3.Sum512(in)
	mmoCipher0, _ := aes.NewCipher(inHashed[0:32])
	mmoCipher1, _ := aes.NewCipher(inHashed[32:64])

	var colliders [2]uint64
	colliders[0] = (uint64(work[0]) << 32) | (uint64(work[1]) << 24) | (uint64(work[2]) << 16) | (uint64(work[3]) << 8) | uint64(work[4])
	colliders[1] = (uint64(work[5]) << 32) | (uint64(work[6]) << 24) | (uint64(work[7]) << 16) | (uint64(work[8]) << 8) | uint64(work[9])
	difficulty := binary.BigEndian.Uint32(work[10:14])

	if colliders[0] == colliders[1] {
		return 0
	}

	diff64 := (uint64(difficulty) << 28) | 0x000000000fffffff
	var collisions [2]uint64
	var tmp [4]uint64
	for i := 0; i < 2; i++ {
		binary.BigEndian.PutUint64(collisionHashIn[0:8], colliders[i])
		collisions[i] = wharrgarblMMOHash(mmoCipher0, mmoCipher1, &tmp, &collisionHashIn) % diff64
	}

	if collisions[0] == collisions[1] {
		return difficulty
	}
	return 0
}

// WharrgarblGetDifficulty extracts the difficulty from a work result without performing any verification.
func WharrgarblGetDifficulty(work []byte) uint32 {
	if len(work) == WharrgarblOutputSize {
		return binary.BigEndian.Uint32(work[10:14]) // difficulty is appended as last 4 bytes
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
