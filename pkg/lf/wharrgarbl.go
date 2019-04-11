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
)

const internalWharrgarblTableSize = 67108864

var internalWharrgarblTable *[internalWharrgarblTableSize]byte
var internalWharrgarblTableLock sync.RWMutex

// WharrgarblOutputSize is the size of Wharrgarbl's result in bytes.
const WharrgarblOutputSize = 14

// Wharrgarblr is an instance of the Wharrgarbl proof of work function.
type Wharrgarblr struct {
	memory      []uint64
	lock        sync.Mutex
	threadCount uint
	done        uint32
}

// internalWharrgarblHash is a Matyer-Meyer-Oseas-like keyed single block hash used as a search target for collision search.
// It also relies on a huge table to impose a random memory seek requirement. This makes GPU or ASIC acceleration a
// lot more challenging and likely less fruitful.
func internalWharrgarblHash(cipher0, cipher1 cipher.Block, tmp []byte, in *[16]byte) uint64 {
	_ = tmp[15]

	cipher0.Encrypt(tmp, in[:])

	// This inner transform makes use of a simple xorshift PRNG to randomize
	// memory access. See: https://en.wikipedia.org/wiki/Xorshift#xorshift*
	x := binary.BigEndian.Uint64(tmp[8:16])
	xorShift64StarState := x

	tmp[0] ^= in[0] + internalWharrgarblTable[x%internalWharrgarblTableSize]

	//x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[0])

	tmp[1] ^= in[1] - internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[1])

	tmp[2] ^= in[2] + internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[2])

	tmp[3] ^= in[3] - internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[3])

	tmp[4] ^= in[4] + internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[4])

	tmp[5] ^= in[5] - internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[5])

	tmp[6] ^= in[6] + internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[6])

	tmp[7] ^= in[7] - internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[7])

	tmp[8] ^= in[8] + internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[8])

	tmp[9] ^= in[9] - internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[9])

	tmp[10] ^= in[10] + internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[10])

	tmp[11] ^= in[11] - internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[11])

	tmp[12] ^= in[12] + internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[12])

	tmp[13] ^= in[13] - internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[13])

	tmp[14] ^= in[14] + internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[14])

	tmp[15] ^= in[15] - internalWharrgarblTable[x%internalWharrgarblTableSize]

	inner0 := binary.BigEndian.Uint64(tmp[0:8])
	inner1 := binary.BigEndian.Uint64(tmp[8:16])

	cipher1.Encrypt(tmp, tmp)

	tmp[0] ^= in[0] + internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[0])

	tmp[1] ^= in[1] - internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[1])

	tmp[2] ^= in[2] + internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[2])

	tmp[3] ^= in[3] - internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[3])

	tmp[4] ^= in[4] + internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[4])

	tmp[5] ^= in[5] - internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[5])

	tmp[6] ^= in[6] + internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[6])

	tmp[7] ^= in[7] - internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[7])

	tmp[8] ^= in[8] + internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[8])

	tmp[9] ^= in[9] - internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[9])

	tmp[10] ^= in[10] + internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[10])

	tmp[11] ^= in[11] - internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[11])

	tmp[12] ^= in[12] + internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[12])

	tmp[13] ^= in[13] - internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[13])

	tmp[14] ^= in[14] + internalWharrgarblTable[x%internalWharrgarblTableSize]

	x = xorShift64StarState
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	xorShift64StarState = x
	x *= 0x2545f4914f6cdd1d
	x += uint64(tmp[14])

	tmp[15] ^= in[15] - internalWharrgarblTable[x%internalWharrgarblTableSize]

	return binary.BigEndian.Uint64(tmp[0:8]) ^ binary.BigEndian.Uint64(tmp[8:16]) ^ inner0 ^ inner1
}

// NewWharrgarblr creates a new Wharrgarbl instance with the given memory size (for memory/speed tradeoff).
// If thread count is 0 the reported CPU/core count of the system is used.
func NewWharrgarblr(memorySize uint, threadCount uint) (wg *Wharrgarblr) {
	wg = new(Wharrgarblr)

	if memorySize < 1048576 {
		memorySize = 1048576
	}
	wg.memory = make([]uint64, memorySize/8)
	wg.SetThreadCount(threadCount)

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
	for i := 0; i < 2; i++ {
		h := sha512.Sum512(internalWharrgarblTable[:])
		aes, _ := aes.NewCipher(h[0:32])
		c := cipher.NewCFBEncrypter(aes, h[32:48])
		c.XORKeyStream(internalWharrgarblTable[:], internalWharrgarblTable[:])
		c.XORKeyStream(internalWharrgarblTable[:], internalWharrgarblTable[:])
		c.XORKeyStream(internalWharrgarblTable[:], internalWharrgarblTable[:])
	}
	internalWharrgarblTableLock.Unlock()

	return
}

func (wg *Wharrgarblr) internalWorkerFunc(mmoCipher0, mmoCipher1 cipher.Block, runNonce, diff64 uint64, iterations *uint64, outLock *sync.Mutex, out []byte, doneWG *sync.WaitGroup) {
	var tmpm [16]byte
	var collisionHashIn [16]byte
	var iter uint64
	tmp := tmpm[:]
	ct := wg.memory
	ctlen := uint(len(ct))
	_ = ct[ctlen-1]

	thisCollider := rand.Uint64()
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

// Compute computes Wharrgarbl PoW using this instance.
func (wg *Wharrgarblr) Compute(in []byte, difficulty uint32) (out [WharrgarblOutputSize]byte, iterations uint64) {
	wg.lock.Lock()
	internalWharrgarblTableLock.RLock()
	defer wg.lock.Unlock()
	defer internalWharrgarblTableLock.RUnlock()

	inHashed := sha512.Sum512(in)
	mmoCipher0, _ := aes.NewCipher(inHashed[0:32])
	mmoCipher1, _ := aes.NewCipher(inHashed[32:64])
	diff64 := (uint64(difficulty) << 28) | 0x000000000fffffff
	runNonce := rand.Uint64() // a nonce that randomizes indexes in the collision table to facilitate re-use without clearing

	var outLock sync.Mutex
	var doneWG sync.WaitGroup
	doneWG.Add(int(wg.threadCount))
	atomic.StoreUint32(&wg.done, 0)
	for c := uint(1); c < wg.threadCount; c++ {
		go wg.internalWorkerFunc(mmoCipher0, mmoCipher1, runNonce, diff64, &iterations, &outLock, out[:], &doneWG)
	}
	wg.internalWorkerFunc(mmoCipher0, mmoCipher1, runNonce, diff64, &iterations, &outLock, out[:], &doneWG)
	doneWG.Wait()

	binary.BigEndian.PutUint32(out[10:14], difficulty)

	return
}

// Abort aborts a Compute() currently in process (results of Compute() are undefined).
func (wg *Wharrgarblr) Abort() {
	atomic.StoreUint32(&wg.done, 1)
}

// SetThreadCount sets the thread count for subsequent calls to Compute() (use 0 for system thread count).
func (wg *Wharrgarblr) SetThreadCount(threadCount uint) {
	if threadCount == 0 {
		wg.threadCount = uint(runtime.NumCPU())
	} else {
		wg.threadCount = threadCount
	}
}

// WharrgarblVerify checks whether work is valid for the provided input, returning the difficulty used or 0 if work is not valid.
func WharrgarblVerify(work []byte, in []byte) uint32 {
	if len(work) != WharrgarblOutputSize {
		return 0
	}

	var collisionHashIn [16]byte
	inHashed := sha512.Sum512(in)
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
