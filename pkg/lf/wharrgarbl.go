/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"encoding/binary"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/sha3"
)

var (
	wharrgarblMemory     []uint32
	wharrgarblMemoryLock sync.Mutex
)

// WharrgarblOutputSize is the size of Wharrgarbl's result in bytes.
const WharrgarblOutputSize = 20

// Wharrgarbl computes a proof of work from an input challenge.
func Wharrgarbl(in []byte, difficulty uint32, minMemorySize uint) (out [20]byte, iterations uint64) {
	wharrgarblMemoryLock.Lock()
	defer wharrgarblMemoryLock.Unlock()
	if minMemorySize < (1024 * 3) {
		minMemorySize = (1024 * 3)
	}
	if uint(len(wharrgarblMemory)) < (minMemorySize / 4) {
		wharrgarblMemory = make([]uint32, minMemorySize/4)
	}
	collisionTableSize := uint64(len(wharrgarblMemory) / 3)

	inHashed := sha3.Sum256(in)

	diff64 := (uint64(difficulty) << 32) | 0x00000000ffffffff
	runNonce := rand.Uint64() // a nonce that randomizes indexes in the collision table to facilitate re-use without clearing
	cpus := runtime.NumCPU()
	var outLock sync.Mutex
	var done uint32
	var doneWG sync.WaitGroup
	doneWG.Add(cpus)
	for c := 0; c < cpus; c++ {
		go func() {
			var hashBuf [40]byte
			copy(hashBuf[8:], inHashed[:])
			var collisionHash [32]byte
			thisCollider := rand.Uint64()
			var iter uint64
			for atomic.LoadUint32(&done) == 0 {
				iter++
				thisCollider++

				hashBuf[0] = byte(thisCollider >> 56)
				hashBuf[1] = byte(thisCollider >> 48)
				hashBuf[2] = byte(thisCollider >> 40)
				hashBuf[3] = byte(thisCollider >> 32)
				hashBuf[4] = byte(thisCollider >> 24)
				hashBuf[5] = byte(thisCollider >> 16)
				hashBuf[6] = byte(thisCollider >> 8)
				hashBuf[7] = byte(thisCollider)
				collisionHash = blake2s.Sum256(hashBuf[:])
				thisCollision := (uint64(collisionHash[0])<<56 | uint64(collisionHash[1])<<48 | uint64(collisionHash[2])<<40 | uint64(collisionHash[3])<<32 | uint64(collisionHash[4])<<24 | uint64(collisionHash[5])<<16 | uint64(collisionHash[6])<<8 | uint64(collisionHash[7])) % diff64
				thisCollision32 := uint32(thisCollision) + uint32(thisCollision>>32)
				memIdx := uint((thisCollision^runNonce)%collisionTableSize) * 3

				if wharrgarblMemory[memIdx] == thisCollision32 {
					otherCollider := (uint64(wharrgarblMemory[memIdx+1]) << 32) | uint64(wharrgarblMemory[memIdx+2])
					if otherCollider != thisCollider {
						binary.BigEndian.PutUint64(hashBuf[:], otherCollider)
						collisionHash = blake2s.Sum256(hashBuf[:])
						if (binary.BigEndian.Uint64(collisionHash[:]) % diff64) == thisCollision {
							atomic.StoreUint32(&done, 1)
							outLock.Lock()
							binary.BigEndian.PutUint64(out[0:8], thisCollider)
							binary.BigEndian.PutUint64(out[8:16], otherCollider)
							outLock.Unlock()
							break
						}
					}
				}

				wharrgarblMemory[memIdx] = thisCollision32
				wharrgarblMemory[memIdx+1] = uint32(thisCollider >> 32)
				wharrgarblMemory[memIdx+2] = uint32(thisCollider)
			}
			atomic.AddUint64(&iterations, iter)
			doneWG.Done()
		}()
	}
	doneWG.Wait()

	binary.BigEndian.PutUint32(out[16:20], difficulty)

	return
}

// WharrgarblVerify checks whether work is valid for the provided input, returning the difficulty used or 0 if work is not valid.
func WharrgarblVerify(work []byte, in []byte) uint32 {
	if len(work) != WharrgarblOutputSize {
		return 0
	}

	inHashed := sha3.Sum256(in)
	var hashBuf [40]byte
	copy(hashBuf[8:], inHashed[:])

	var colliders [2]uint64
	for i := 0; i < 2; i++ {
		colliders[i] = binary.BigEndian.Uint64(work[8*i:])
	}
	difficulty := binary.BigEndian.Uint32(work[16:20])

	if colliders[0] == colliders[1] {
		return 0
	}

	diff64 := (uint64(difficulty) << 32) | 0x00000000ffffffff
	var collisionHash [32]byte
	var collisions [2]uint64
	for i := 0; i < 2; i++ {
		binary.BigEndian.PutUint64(hashBuf[:], colliders[i])
		collisionHash = blake2s.Sum256(hashBuf[:])
		collisions[i] = binary.BigEndian.Uint64(collisionHash[0:8]) % diff64
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
	wharrgarblMemory = nil
	wharrgarblMemoryLock.Unlock()
}
