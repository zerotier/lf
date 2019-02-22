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

var (
	wharrgarblMemory        [134217728]uint32
	wharrgarblMemoryEntries = uint64(len(wharrgarblMemory) / 2)
	wharrgarblMemoryLock    sync.Mutex
)

// WharrgarblOutputSize is the size of Wharrgarbl's result in bytes.
const WharrgarblOutputSize = 20

// wharrgarblMMOHash is a simple 64X Matyas-Meyer-Oseas single block hash function.
func wharrgarblMMOHash(mmoCipher0, mmoCipher1 cipher.Block, out, in *[16]byte) {
	var tmp0, tmp1 [2]uint64
	tmp0s := ((*[16]byte)(unsafe.Pointer(&tmp0)))[:]
	tmp1s := ((*[16]byte)(unsafe.Pointer(&tmp1)))[:]

	mmoCipher0.Encrypt(tmp0s, in[:])
	for i := 0; i < 16; i++ {
		tmp0s[i] ^= in[i]
	}
	mmoCipher1.Encrypt(tmp1s, tmp0s)
	tmp1[0] ^= tmp0[0]
	tmp1[1] ^= tmp0[1]

	for k := 0; k < 60; k++ {
		mmoCipher0.Encrypt(tmp0s, tmp1s)
		tmp0[0] ^= tmp1[0]
		tmp0[1] ^= tmp1[1]
		mmoCipher1.Encrypt(tmp1s, tmp0s)
		tmp1[0] ^= tmp0[0]
		tmp1[1] ^= tmp0[1]
	}

	mmoCipher0.Encrypt(tmp0s, tmp1s)
	tmp0[0] ^= tmp1[0]
	tmp0[1] ^= tmp1[1]
	mmoCipher1.Encrypt(out[:], tmp0s)
	for i := 0; i < 16; i++ {
		out[i] ^= tmp0s[i]
	}
}

func wharrgarblWorkerFunc(mmoCipher0, mmoCipher1 cipher.Block, runNonce, diff64 uint64, iterations *uint64, done *uint32, outLock *sync.Mutex, out []byte, doneWG *sync.WaitGroup) {
	var collisionHashIn, collisionHashOut [16]byte
	var iter uint64
	thisCollider := rand.Uint32()

	for atomic.LoadUint32(done) == 0 {
		iter++
		thisCollider++

		binary.BigEndian.PutUint32(collisionHashIn[4:8], thisCollider)
		wharrgarblMMOHash(mmoCipher0, mmoCipher1, &collisionHashOut, &collisionHashIn)
		thisCollision := (binary.BigEndian.Uint64(collisionHashOut[0:8]) ^ binary.BigEndian.Uint64(collisionHashOut[8:16])) % diff64
		thisCollision32 := uint32(thisCollision) + uint32(thisCollision>>32)
		memIdx := uint((thisCollision^runNonce)%wharrgarblMemoryEntries) * 2

		if wharrgarblMemory[memIdx] == thisCollision32 {
			otherCollider := wharrgarblMemory[memIdx+1]
			if otherCollider != thisCollider {
				binary.BigEndian.PutUint32(collisionHashIn[4:8], otherCollider)
				wharrgarblMMOHash(mmoCipher0, mmoCipher1, &collisionHashOut, &collisionHashIn)
				otherCollision := (binary.BigEndian.Uint64(collisionHashOut[0:8]) ^ binary.BigEndian.Uint64(collisionHashOut[8:16])) % diff64
				if otherCollision == thisCollision {
					atomic.StoreUint32(done, 1)
					outLock.Lock()
					binary.BigEndian.PutUint32(out[4:8], thisCollider)
					binary.BigEndian.PutUint32(out[12:16], otherCollider)
					outLock.Unlock()
					break
				}
			}
		}

		wharrgarblMemory[memIdx] = thisCollision32
		wharrgarblMemory[memIdx+1] = uint32(thisCollider)
	}

	atomic.AddUint64(iterations, iter)

	doneWG.Done()
}

// Wharrgarbl computes a proof of work from an input challenge.
func Wharrgarbl(in []byte, difficulty uint32, minMemorySize uint) (out [20]byte, iterations uint64) {
	wharrgarblMemoryLock.Lock()
	defer wharrgarblMemoryLock.Unlock()

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

	var collisionHashIn, collisionHashOut [16]byte
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
		wharrgarblMMOHash(mmoCipher0, mmoCipher1, &collisionHashOut, &collisionHashIn)
		collisions[i] = (binary.BigEndian.Uint64(collisionHashOut[0:8]) ^ binary.BigEndian.Uint64(collisionHashOut[8:16])) % diff64
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

// WharrgarblFreeGlobalMemory frees any global memory areas allocated from previous calls to Wharrgarbl().
// Memory will be re-allocated if needed.
func WharrgarblFreeGlobalMemory() {
	wharrgarblMemoryLock.Lock()
	//wharrgarblMemory = nil
	wharrgarblMemoryLock.Unlock()
}
