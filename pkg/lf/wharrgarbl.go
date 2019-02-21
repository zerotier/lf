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
	wharrgarblMemory     []uint32
	wharrgarblMemoryLock sync.Mutex
)

// WharrgarblOutputSize is the size of Wharrgarbl's result in bytes.
const WharrgarblOutputSize = 20

// wharrgarblMMOHash is a simple 32X Matyas-Meyer-Oseas single block hash function.
// https://en.wikipedia.org/wiki/One-way_compression_function#Matyas–Meyer–Oseas
// https://crypto.stackexchange.com/questions/56247/matyas-meyer-oseas-for-super-fast-single-block-hash-function
func wharrgarblMMOHash(mmoCipher0, mmoCipher1 cipher.Block, out, in *[2]uint64) {
	var tmp [2]uint64
	mmoCipher0.Encrypt(((*[16]byte)(unsafe.Pointer(&tmp)))[:], ((*[16]byte)(unsafe.Pointer(in)))[:])
	tmp[0] ^= in[0]
	tmp[1] ^= in[1]
	mmoCipher1.Encrypt(((*[16]byte)(unsafe.Pointer(out)))[:], ((*[16]byte)(unsafe.Pointer(&tmp)))[:])
	out[0] ^= tmp[0]
	out[1] ^= tmp[1]
	for k := 0; k < 15; k++ {
		mmoCipher0.Encrypt(((*[16]byte)(unsafe.Pointer(&tmp)))[:], ((*[16]byte)(unsafe.Pointer(out)))[:])
		tmp[0] ^= out[0]
		tmp[1] ^= out[1]
		mmoCipher1.Encrypt(((*[16]byte)(unsafe.Pointer(out)))[:], ((*[16]byte)(unsafe.Pointer(&tmp)))[:])
		out[0] ^= tmp[0]
		out[1] ^= tmp[1]
	}
}

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
	mmoCipher0, _ := aes.NewCipher(inHashed[0:16])
	mmoCipher1, _ := aes.NewCipher(inHashed[16:32])

	diff64 := (uint64(difficulty) << 32) | 0x00000000ffffffff
	runNonce := rand.Uint64() // a nonce that randomizes indexes in the collision table to facilitate re-use without clearing
	cpus := runtime.NumCPU()
	var outLock sync.Mutex
	var done uint32
	var doneWG sync.WaitGroup
	doneWG.Add(cpus)
	for c := 0; c < cpus; c++ {
		go func() {
			var hashBuf, collisionHash [2]uint64
			thisCollider := rand.Uint64()
			var iter uint64
			for atomic.LoadUint32(&done) == 0 {
				iter++
				thisCollider++

				hashBuf[0] = thisCollider
				wharrgarblMMOHash(mmoCipher0, mmoCipher1, &collisionHash, &hashBuf)
				thisCollision := (collisionHash[0] ^ collisionHash[1]) % diff64
				thisCollision32 := uint32(thisCollision) + uint32(thisCollision>>32)
				memIdx := uint((thisCollision^runNonce)%collisionTableSize) * 3

				if wharrgarblMemory[memIdx] == thisCollision32 {
					otherCollider := (uint64(wharrgarblMemory[memIdx+1]) << 32) | uint64(wharrgarblMemory[memIdx+2])
					if otherCollider != thisCollider {
						hashBuf[0] = otherCollider
						wharrgarblMMOHash(mmoCipher0, mmoCipher1, &collisionHash, &hashBuf)
						if ((collisionHash[0] ^ collisionHash[1]) % diff64) == thisCollision {
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
	var hashBuf, collisionHash [2]uint64
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

	diff64 := (uint64(difficulty) << 32) | 0x00000000ffffffff
	var collisions [2]uint64
	for i := 0; i < 2; i++ {
		hashBuf[0] = colliders[i]
		wharrgarblMMOHash(mmoCipher0, mmoCipher1, &collisionHash, &hashBuf)
		collisions[i] = (collisionHash[0] ^ collisionHash[1]) % diff64
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
