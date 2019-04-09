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
	"crypto/sha512"
	"encoding/binary"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/sha3"
)

const internalWharrgarblTableSize = 67108864

var internalWharrgarblTable *[internalWharrgarblTableSize]byte
var internalWharrgarblTableLock sync.RWMutex

// WharrgarblOutputSize is the size of Wharrgarbl's result in bytes.
const WharrgarblOutputSize = 14

// Wharrgarblr is an instance of the Wharrgarbl proof of work function.
type Wharrgarblr struct {
	memory []uint64
	lock   sync.Mutex
	done   uint32
}

// internalWharrgarblHash is a Matyer-Meyer-Oseas-like keyed single block hash used as a search target for collision search.
func internalWharrgarblHash(cipher0, cipher1 cipher.Block, tmp []byte, in *[16]byte) uint64 {
	_ = tmp[15]

	cipher0.Encrypt(tmp, in[:])

	tmp[0] ^= in[0] ^ internalWharrgarblTable[(uint32(tmp[0])|uint32(tmp[1])<<16|uint32(tmp[2])<<8|uint32(tmp[3])<<24)%internalWharrgarblTableSize]
	tmp[1] ^= in[1] ^ internalWharrgarblTable[(uint32(tmp[1])|uint32(tmp[2])<<16|uint32(tmp[3])<<8|uint32(tmp[4])<<24)%internalWharrgarblTableSize]
	tmp[2] ^= in[2] ^ internalWharrgarblTable[(uint32(tmp[2])|uint32(tmp[3])<<16|uint32(tmp[4])<<8|uint32(tmp[5])<<24)%internalWharrgarblTableSize]
	tmp[3] ^= in[3] ^ internalWharrgarblTable[(uint32(tmp[3])|uint32(tmp[4])<<16|uint32(tmp[5])<<8|uint32(tmp[6])<<24)%internalWharrgarblTableSize]
	tmp[4] ^= in[4] ^ internalWharrgarblTable[(uint32(tmp[4])|uint32(tmp[5])<<16|uint32(tmp[6])<<8|uint32(tmp[7])<<24)%internalWharrgarblTableSize]
	tmp[5] ^= in[5] ^ internalWharrgarblTable[(uint32(tmp[5])|uint32(tmp[6])<<16|uint32(tmp[7])<<8|uint32(tmp[8])<<24)%internalWharrgarblTableSize]
	tmp[6] ^= in[6] ^ internalWharrgarblTable[(uint32(tmp[6])|uint32(tmp[7])<<16|uint32(tmp[8])<<8|uint32(tmp[9])<<24)%internalWharrgarblTableSize]
	tmp[7] ^= in[7] ^ internalWharrgarblTable[(uint32(tmp[7])|uint32(tmp[8])<<16|uint32(tmp[9])<<8|uint32(tmp[10])<<24)%internalWharrgarblTableSize]
	tmp[8] ^= in[8] ^ internalWharrgarblTable[(uint32(tmp[8])|uint32(tmp[9])<<16|uint32(tmp[10])<<8|uint32(tmp[11])<<24)%internalWharrgarblTableSize]
	tmp[9] ^= in[9] ^ internalWharrgarblTable[(uint32(tmp[9])|uint32(tmp[10])<<16|uint32(tmp[11])<<8|uint32(tmp[12])<<24)%internalWharrgarblTableSize]
	tmp[10] ^= in[10] ^ internalWharrgarblTable[(uint32(tmp[10])|uint32(tmp[11])<<16|uint32(tmp[12])<<8|uint32(tmp[13])<<24)%internalWharrgarblTableSize]
	tmp[11] ^= in[11] ^ internalWharrgarblTable[(uint32(tmp[11])|uint32(tmp[12])<<16|uint32(tmp[13])<<8|uint32(tmp[14])<<24)%internalWharrgarblTableSize]
	tmp[12] ^= in[12] ^ internalWharrgarblTable[(uint32(tmp[12])|uint32(tmp[13])<<16|uint32(tmp[14])<<8|uint32(tmp[15])<<24)%internalWharrgarblTableSize]
	tmp[13] ^= in[13] ^ internalWharrgarblTable[(uint32(tmp[13])|uint32(tmp[14])<<16|uint32(tmp[15])<<8|uint32(tmp[0])<<24)%internalWharrgarblTableSize]
	tmp[14] ^= in[14] ^ internalWharrgarblTable[(uint32(tmp[14])|uint32(tmp[15])<<16|uint32(tmp[0])<<8|uint32(tmp[1])<<24)%internalWharrgarblTableSize]
	tmp[15] ^= in[15] ^ internalWharrgarblTable[(uint32(tmp[15])|uint32(tmp[0])<<16|uint32(tmp[1])<<8|uint32(tmp[2])<<24)%internalWharrgarblTableSize]

	inner := binary.BigEndian.Uint64(tmp[0:8])

	cipher1.Encrypt(tmp, tmp)

	tmp[0] ^= in[0] ^ internalWharrgarblTable[(uint32(tmp[0])|uint32(tmp[1])<<16|uint32(tmp[2])<<8|uint32(tmp[3])<<24)%internalWharrgarblTableSize]
	tmp[1] ^= in[1] ^ internalWharrgarblTable[(uint32(tmp[1])|uint32(tmp[2])<<16|uint32(tmp[3])<<8|uint32(tmp[4])<<24)%internalWharrgarblTableSize]
	tmp[2] ^= in[2] ^ internalWharrgarblTable[(uint32(tmp[2])|uint32(tmp[3])<<16|uint32(tmp[4])<<8|uint32(tmp[5])<<24)%internalWharrgarblTableSize]
	tmp[3] ^= in[3] ^ internalWharrgarblTable[(uint32(tmp[3])|uint32(tmp[4])<<16|uint32(tmp[5])<<8|uint32(tmp[6])<<24)%internalWharrgarblTableSize]
	tmp[4] ^= in[4] ^ internalWharrgarblTable[(uint32(tmp[4])|uint32(tmp[5])<<16|uint32(tmp[6])<<8|uint32(tmp[7])<<24)%internalWharrgarblTableSize]
	tmp[5] ^= in[5] ^ internalWharrgarblTable[(uint32(tmp[5])|uint32(tmp[6])<<16|uint32(tmp[7])<<8|uint32(tmp[8])<<24)%internalWharrgarblTableSize]
	tmp[6] ^= in[6] ^ internalWharrgarblTable[(uint32(tmp[6])|uint32(tmp[7])<<16|uint32(tmp[8])<<8|uint32(tmp[9])<<24)%internalWharrgarblTableSize]
	tmp[7] ^= in[7] ^ internalWharrgarblTable[(uint32(tmp[7])|uint32(tmp[8])<<16|uint32(tmp[9])<<8|uint32(tmp[10])<<24)%internalWharrgarblTableSize]
	tmp[8] ^= in[8] ^ internalWharrgarblTable[(uint32(tmp[8])|uint32(tmp[9])<<16|uint32(tmp[10])<<8|uint32(tmp[11])<<24)%internalWharrgarblTableSize]
	tmp[9] ^= in[9] ^ internalWharrgarblTable[(uint32(tmp[9])|uint32(tmp[10])<<16|uint32(tmp[11])<<8|uint32(tmp[12])<<24)%internalWharrgarblTableSize]
	tmp[10] ^= in[10] ^ internalWharrgarblTable[(uint32(tmp[10])|uint32(tmp[11])<<16|uint32(tmp[12])<<8|uint32(tmp[13])<<24)%internalWharrgarblTableSize]
	tmp[11] ^= in[11] ^ internalWharrgarblTable[(uint32(tmp[11])|uint32(tmp[12])<<16|uint32(tmp[13])<<8|uint32(tmp[14])<<24)%internalWharrgarblTableSize]
	tmp[12] ^= in[12] ^ internalWharrgarblTable[(uint32(tmp[12])|uint32(tmp[13])<<16|uint32(tmp[14])<<8|uint32(tmp[15])<<24)%internalWharrgarblTableSize]
	tmp[13] ^= in[13] ^ internalWharrgarblTable[(uint32(tmp[13])|uint32(tmp[14])<<16|uint32(tmp[15])<<8|uint32(tmp[0])<<24)%internalWharrgarblTableSize]
	tmp[14] ^= in[14] ^ internalWharrgarblTable[(uint32(tmp[14])|uint32(tmp[15])<<16|uint32(tmp[0])<<8|uint32(tmp[1])<<24)%internalWharrgarblTableSize]
	tmp[15] ^= in[15] ^ internalWharrgarblTable[(uint32(tmp[15])|uint32(tmp[0])<<16|uint32(tmp[1])<<8|uint32(tmp[2])<<24)%internalWharrgarblTableSize]

	return binary.BigEndian.Uint64(tmp[0:8]) ^ inner
}

// NewWharrgarblr creates a new Wharrgarbl instance with the given memory size (for memory/speed tradeoff).
func NewWharrgarblr(memorySize uint) (wg *Wharrgarblr) {
	wg = new(Wharrgarblr)
	if memorySize < 1048576 {
		memorySize = 1048576
	}
	wg.memory = make([]uint64, memorySize/8)

	internalWharrgarblTableLock.RLock()
	if internalWharrgarblTable != nil {
		internalWharrgarblTableLock.RUnlock()
		return
	}
	internalWharrgarblTableLock.RUnlock()
	internalWharrgarblTableLock.Lock()
	if internalWharrgarblTable != nil {
		internalWharrgarblTableLock.Unlock()
		return
	}
	internalWharrgarblTable = new([internalWharrgarblTableSize]byte)
	copy(internalWharrgarblTable[:], []byte("My hovercraft is full of eels!"))
	for i := 0; i < 4; i++ {
		h := sha512.Sum512(internalWharrgarblTable[:])
		aes, _ := aes.NewCipher(h[0:32])
		c := cipher.NewCFBEncrypter(aes, h[32:48])
		c.XORKeyStream(internalWharrgarblTable[:], internalWharrgarblTable[:])
	}
	internalWharrgarblTableLock.Unlock()

	return
}

func (wg *Wharrgarblr) internalWorkerFunc(mmoCipher0, mmoCipher1 cipher.Block, runNonce, diff64 uint64, iterations *uint64, outLock *sync.Mutex, out []byte, doneWG *sync.WaitGroup) {
	var collisionHashIn [16]byte
	var tmpm [16]byte
	var iter uint64
	tmp := tmpm[:]
	ct := wg.memory
	ctlen := uint(len(ct))

	// Generate an initial 40-bit collider.
	thisCollider := rand.Uint64() + rand.Uint64()
	for atomic.LoadUint32(&wg.done) == 0 {
		iter++

		thisCollider++
		thisCollider &= 0xffffffffff
		collisionHashIn[3] = byte(thisCollider >> 32)
		collisionHashIn[4] = byte(thisCollider >> 24)
		collisionHashIn[5] = byte(thisCollider >> 16)
		collisionHashIn[6] = byte(thisCollider >> 8)
		collisionHashIn[7] = byte(thisCollider)
		thisCollision := internalWharrgarblHash(mmoCipher0, mmoCipher1, tmp, &collisionHashIn) % diff64

		// The collision table contains 64-bit entries indexed by collision. These contain
		// the collider (least significant 40 bits) and 24 bits of the other collision. We
		// then recompute the full collision for the other collider to verify since there's
		// a 1/2^24 chance of a false positive.
		collisionTableEntry := &ct[uint(thisCollision^runNonce)%ctlen]

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
				if (internalWharrgarblHash(mmoCipher0, mmoCipher1, tmp, &collisionHashIn) % diff64) == thisCollision {
					atomic.StoreUint32(&wg.done, 1)
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
func (wg *Wharrgarblr) compute(in []byte, difficulty uint32) (out [WharrgarblOutputSize]byte, iterations uint64) {
	wg.lock.Lock()
	internalWharrgarblTableLock.RLock()
	defer wg.lock.Unlock()
	defer internalWharrgarblTableLock.RUnlock()

	inHashed := sha3.Sum512(in)
	mmoCipher0, _ := aes.NewCipher(inHashed[0:32])
	mmoCipher1, _ := aes.NewCipher(inHashed[32:64])
	diff64 := (uint64(difficulty) << 28) | 0x000000000fffffff
	runNonce := rand.Uint64() // a nonce that randomizes indexes in the collision table to facilitate re-use without clearing

	var outLock sync.Mutex
	var doneWG sync.WaitGroup
	cpus := runtime.NumCPU()
	doneWG.Add(cpus)
	atomic.StoreUint32(&wg.done, 0)
	for c := 1; c < cpus; c++ {
		go wg.internalWorkerFunc(mmoCipher0, mmoCipher1, runNonce, diff64, &iterations, &outLock, out[:], &doneWG)
	}
	wg.internalWorkerFunc(mmoCipher0, mmoCipher1, runNonce, diff64, &iterations, &outLock, out[:], &doneWG)
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
	var tmp [16]byte
	for i := 0; i < 2; i++ {
		binary.BigEndian.PutUint64(collisionHashIn[0:8], colliders[i])
		collisions[i] = internalWharrgarblHash(mmoCipher0, mmoCipher1, tmp[:], &collisionHashIn) % diff64
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
