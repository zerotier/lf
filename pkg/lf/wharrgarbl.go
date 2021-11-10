/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c)2019-2021 ZeroTier, Inc.
 * https://www.zerotier.com/
 */

package lf

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/binary"
	"hash/crc32"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"runtime"
	"sync"
	"sync/atomic"

	"lf/third_party/lfmd5"
)

// wharrgarblTableSize is the size of the static table used by wharrgarblHash
const wharrgarblTableSize = 0x8000000

// wharrgarblTableMask is the mask to constrain a value to 0..wharrgarblTableSize (faster than modulus)
const wharrgarblTableMask = 0x7ffffff

var wharrgarblTable *[wharrgarblTableSize]byte
var wharrgarblTableLock sync.RWMutex

// WharrgarblOutputSize is the size of Wharrgarbl's result in bytes
const WharrgarblOutputSize = 14

// Wharrgarblr is an instance of the Wharrgarbl proof of work function
type Wharrgarblr struct {
	memory      []uint64
	lock        sync.Mutex
	threadCount uint
	done        uint32
}

// wharrgarblFrankenhash combines AES and MD5 with random accesses to a big static memory table for an
// intentionally slow keyed (via AES) collision target hash. MD5's security issues don't matter here.
// It was chosen because it's fast on many architectures and ASM implementations are readily available.
// A forked MD5 implementation is used that's been hacked for better performance as a short input hash.
func wharrgarblFrankenhash(md5 *lfmd5.Digest, cipher0, cipher1 cipher.Block, tmp []byte, in *[16]byte) uint64 {
	_ = tmp[15]

	cipher0.Encrypt(tmp, in[:])
	cipher1.Encrypt(tmp, tmp)

	md5.Reset()
	_, _ = md5.Write(in[:])
	_, _ = md5.Write(tmp)

	for k, nn := 0, 1+(int(tmp[0])%6); k < nn; k++ {
		for i := 0; i < 8; i++ {
			tmp[i] ^= wharrgarblTable[binary.LittleEndian.Uint32(tmp)&wharrgarblTableMask]
			cipher0.Encrypt(tmp, tmp)
		}
		_, _ = md5.Write(tmp)

		for i := 0; i < 8; i++ {
			tmp[i] ^= wharrgarblTable[binary.LittleEndian.Uint32(tmp)&wharrgarblTableMask]
			cipher1.Encrypt(tmp, tmp)
		}
		_, _ = md5.Write(tmp)

		// GPUs generally suck at branching
		switch tmp[0] & 7 {
		case 0:
			_, _ = md5.Write(tmp)
		case 1:
			_, _ = md5.Write(in[:])
			_, _ = md5.Write(tmp)
			_, _ = md5.Write(in[:])
			_, _ = md5.Write(tmp)
		case 2:
			cipher0.Encrypt(tmp, tmp)
		case 3:
			cipher1.Encrypt(tmp, tmp)
			cipher0.Encrypt(tmp, tmp)
		case 4:
			if tmp[1] == 253 {
				cipher0.Encrypt(tmp, tmp)
				cipher1.Encrypt(tmp, tmp)
				cipher1.Encrypt(tmp, tmp)
				cipher0.Encrypt(tmp, tmp)
				cipher0.Encrypt(tmp, tmp)
				cipher1.Encrypt(tmp, tmp)
				cipher0.Encrypt(tmp, tmp)
				cipher0.Encrypt(tmp, tmp)
				cipher1.Encrypt(tmp, tmp)
				cipher0.Encrypt(tmp, tmp)
				cipher0.Encrypt(tmp, tmp)
				cipher1.Encrypt(tmp, tmp)
				cipher1.Encrypt(tmp, tmp)
				cipher1.Encrypt(tmp, tmp)
				cipher1.Encrypt(tmp, tmp)
				cipher0.Encrypt(tmp, tmp)
				cipher1.Encrypt(tmp, tmp)
				cipher1.Encrypt(tmp, tmp)
			} else {
				cipher1.Encrypt(tmp, tmp)
				cipher0.Encrypt(tmp, tmp)
				cipher1.Encrypt(tmp, tmp)
				cipher1.Encrypt(tmp, tmp)
				cipher0.Encrypt(tmp, tmp)
			}
		case 5:
			cipher1.Encrypt(tmp, tmp)
			_, _ = md5.Write(tmp)
			cipher0.Encrypt(tmp, tmp)
			cipher1.Encrypt(tmp, tmp)
			cipher0.Encrypt(tmp, tmp)
			if tmp[0] == 3 {
				cipher1.Encrypt(tmp, tmp)
			} else {
				cipher0.Encrypt(tmp, tmp)
				_, _ = md5.Write(tmp)
				cipher0.Encrypt(tmp, tmp)
			}
		case 6:
			for i := 1; i < 16; i++ {
				tmp[i] += tmp[i-1]
			}
		case 7:
			binary.LittleEndian.PutUint64(tmp, binary.LittleEndian.Uint64(tmp)+(binary.LittleEndian.Uint64(tmp)/(binary.LittleEndian.Uint64(tmp[8:16])|1)))
		}
		_, _ = md5.Write(tmp)

		// More branching triggering an occasional big memory read
		if tmp[1] == 17 && tmp[7] < 7 && tmp[13] > 251 {
			_, _ = md5.Write(wharrgarblTable[:])
		}
	}

	md5.FastSum(tmp)
	return binary.LittleEndian.Uint64(tmp[0:8]) ^ binary.LittleEndian.Uint64(tmp[8:16])
}

// WharrgarblInitTable initializes the internal memory table if it's not already.
// If cacheFilePath is non-empty the table will be cached there for faster startup.
func WharrgarblInitTable(cacheFilePath string) {
	wharrgarblTableLock.RLock()
	if wharrgarblTable != nil {
		wharrgarblTableLock.RUnlock()
		return
	}
	wharrgarblTableLock.RUnlock()

	wharrgarblTableLock.Lock()
	if wharrgarblTable != nil {
		wharrgarblTableLock.Unlock()
		return
	}

	wharrgarblTable = new([wharrgarblTableSize]byte)

	if len(cacheFilePath) > 0 {
		cf, _ := os.Open(cacheFilePath)
		if cf != nil {
			_, err := io.ReadFull(cf, wharrgarblTable[:])
			if err == nil {
				if crc32.ChecksumIEEE(wharrgarblTable[:]) == 0xf25f8b7d {
					wharrgarblTableLock.Unlock()
					return
				}
			}
			for i := 0; i < wharrgarblTableSize; i++ {
				wharrgarblTable[i] = 0
			}
		}
	}

	copy(wharrgarblTable[:], "My hovercraft is full of eels!")
	for i := 0; i < 4; i++ {
		h := sha512.Sum512(wharrgarblTable[:])
		aesCipher, _ := aes.NewCipher(h[0:32])
		c := cipher.NewCFBEncrypter(aesCipher, h[32:48])
		c.XORKeyStream(wharrgarblTable[:], wharrgarblTable[:])
		c.XORKeyStream(wharrgarblTable[:], wharrgarblTable[:])
	}

	if len(cacheFilePath) > 0 {
		go ioutil.WriteFile(cacheFilePath, wharrgarblTable[:], 0644)
	}

	wharrgarblTableLock.Unlock()
}

// NewWharrgarblr creates a new Wharrgarbl instance with the given memory size (for memory/speed tradeoff).
// If thread count is 0 the reported CPU/core count of the system is used.
func NewWharrgarblr(memorySize uint, threadCount int) (wg *Wharrgarblr) {
	wg = new(Wharrgarblr)

	if memorySize < 1048576 {
		memorySize = 1048576
	}
	wg.memory = make([]uint64, memorySize/8)
	wg.SetThreadCount(threadCount)
	WharrgarblInitTable("")
	return
}

func (wg *Wharrgarblr) internalWorkerFunc(mmoCipher0, mmoCipher1 cipher.Block, runNonce, diff64 uint64, iterations *uint64, outLock *sync.Mutex, out []byte, doneWG *sync.WaitGroup) {
	var tmpm [16]byte
	var collisionHashIn [16]byte
	var iter uint64
	md5 := new(lfmd5.Digest)
	tmp := tmpm[:]
	ct := wg.memory
	ctlen := uint(len(ct))
	_ = ct[ctlen-1]

	thisCollider := rand.Uint64()
	for atomic.LoadUint32(&wg.done) == 0 {
		iter++
		if (iter & 0xff) == 0 {
			runtime.Gosched() // this might not be necessary but doesn't seem to hurt and probably makes this coexist better on nodes
		}

		thisCollider++
		thisCollider &= 0xffffffffff
		collisionHashIn[3] = byte(thisCollider >> 32)
		collisionHashIn[4] = byte(thisCollider >> 24)
		collisionHashIn[5] = byte(thisCollider >> 16)
		collisionHashIn[6] = byte(thisCollider >> 8)
		collisionHashIn[7] = byte(thisCollider)
		thisCollision := wharrgarblFrankenhash(md5, mmoCipher0, mmoCipher1, tmp, &collisionHashIn) % diff64

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
				if (wharrgarblFrankenhash(md5, mmoCipher0, mmoCipher1, tmp, &collisionHashIn) % diff64) == thisCollision {
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

		*collisionTableEntry = (uint64(thisCollision24) << 40) | thisCollider
	}

	atomic.AddUint64(iterations, iter)
	doneWG.Done()
}

// Compute computes Wharrgarbl PoW using this instance.
// It returns a proof of work and how many total search iterations were required to find it.
// A single Wharrgarblr can only Compute one PoW at a time and uses all its threads to do so.
func (wg *Wharrgarblr) Compute(in []byte, difficulty uint32) (out [WharrgarblOutputSize]byte, iterations uint64) {
	wg.lock.Lock()
	wharrgarblTableLock.RLock()
	defer wg.lock.Unlock()
	defer wharrgarblTableLock.RUnlock()

	inHashed := sha512.Sum512(in)
	mmoCipher0, _ := aes.NewCipher(inHashed[0:32])
	mmoCipher1, _ := aes.NewCipher(inHashed[32:64])
	diff64 := (uint64(difficulty) << 29) | 0x000000001fffffff // 64-bit modulus for collision search
	runNonce := rand.Uint64()                                 // nonce that randomizes table entries to permit table re-use without memory zeroing

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

// Abort aborts the current Compute() currently in process.
// The return values of Compute() after this call are undefined and should be thrown away.
func (wg *Wharrgarblr) Abort() {
	atomic.StoreUint32(&wg.done, 1)
}

// SetThreadCount sets the thread count for subsequent calls to Compute() (use 0 for system thread count).
func (wg *Wharrgarblr) SetThreadCount(threadCount int) {
	if threadCount <= 0 {
		wg.threadCount = uint(runtime.NumCPU())
	} else {
		wg.threadCount = uint(threadCount)
	}
}

// WharrgarblVerify checks whether work is valid for the provided input, returning the difficulty used or 0 if work is not valid.
func WharrgarblVerify(work []byte, in []byte) uint32 {
	if len(work) != WharrgarblOutputSize {
		return 0
	}

	WharrgarblInitTable("")
	wharrgarblTableLock.RLock()
	defer wharrgarblTableLock.RUnlock()

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

	diff64 := (uint64(difficulty) << 29) | 0x000000001fffffff
	var collisions [2]uint64
	var tmp [16]byte
	var md5 lfmd5.Digest
	for i := 0; i < 2; i++ {
		binary.BigEndian.PutUint64(collisionHashIn[0:8], colliders[i])
		collisions[i] = wharrgarblFrankenhash(&md5, mmoCipher0, mmoCipher1, tmp[:], &collisionHashIn) % diff64
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
