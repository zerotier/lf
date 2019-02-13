/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	secrand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path"
	"strconv"
	"time"

	"golang.org/x/crypto/sha3"
)

//////////////////////////////////////////////////////////////////////////////

// TestCore tests various core functions and helpers.
func TestCore(out io.Writer) bool {
	// This checks to make sure the Sum method of hashes fills arrays as expected.
	// This is sort of an ambiguous behavior in the API docs, so we want to detect
	// if the actual behavior changes. If it does we'll have to change a few spots.
	testStr := []byte("My hovercraft is full of eels.")
	fmt.Fprintf(out, "Testing hash slice filling behavior (API behavior check)... ")
	ref := sha256.Sum256(testStr)
	th := sha256.New()
	_, err := th.Write(testStr)
	if err != nil {
		panic(err)
	}
	var thout [32]byte
	th.Sum(thout[:0])
	ref2 := sha3.Sum512(testStr)
	th2 := sha3.New512()
	_, err = th2.Write(testStr)
	if err != nil {
		panic(err)
	}
	var thout2 [64]byte
	th2.Sum(thout2[:0])
	if bytes.Equal(thout[:], ref[:]) && bytes.Equal(thout2[:], ref2[:]) {
		fmt.Fprintf(out, "OK\n")
	} else {
		fmt.Fprintf(out, "FAILED\n")
		return false
	}

	curves := []elliptic.Curve{elliptic.P384(), ECCCurveBrainpoolP160T1}
	for ci := range curves {
		curve := curves[ci]
		fmt.Fprintf(out, "Testing %s ECDSA...\n", curve.Params().Name)
		priv, err := ecdsa.GenerateKey(curve, secrand.Reader)
		if err != nil {
			fmt.Fprintf(out, "  FAILED (generate): %s\n", err.Error())
			return false
		}
		pub, err := ECDSACompressPublicKey(&priv.PublicKey)
		if err != nil {
			fmt.Fprintf(out, "  FAILED (compress): %s\n", err.Error())
			return false
		}
		fmt.Fprintf(out, "  Public Key: [%d] %x\n", len(pub), pub)
		pub2, err := ECDSADecompressPublicKey(curve, pub)
		if err != nil {
			fmt.Fprintf(out, "  FAILED (decompress): %s\n", err.Error())
			return false
		}
		if pub2.X.Cmp(priv.PublicKey.X) != 0 || pub2.Y.Cmp(priv.PublicKey.Y) != 0 {
			fmt.Fprintf(out, "  FAILED (decompress): results are not the same!\n")
			return false
		}
		var junk [32]byte
		secrand.Read(junk[:])
		sig, err := ECDSASign(priv, junk[:])
		if err != nil {
			fmt.Fprintf(out, "  FAILED (sign): %s\n", err.Error())
			return false
		}
		fmt.Fprintf(out, "  Signature: [%d] %x\n", len(sig), sig)
		if !ECDSAVerify(&priv.PublicKey, junk[:], sig) {
			fmt.Fprintf(out, "  FAILED (verify): verify failed for correct message\n")
			return false
		}
		junk[1]++
		if ECDSAVerify(&priv.PublicKey, junk[:], sig) {
			fmt.Fprintf(out, "  FAILED (verify): verify succeeded for incorrect message\n")
			return false
		}
		junk[1]--
		sig[2]++
		if ECDSAVerify(&priv.PublicKey, junk[:], sig) {
			fmt.Fprintf(out, "  FAILED (verify): verify succeeded for incorrect signature (but correct message)\n")
			return false
		}
	}

	fmt.Fprintf(out, "Testing Selector... ")
	var testSelectors [128]Selector
	var testSelectorClaimHash [32]byte
	secrand.Read(testSelectorClaimHash[:])
	for k := range testSelectors {
		testSelectors[k].Claim(testSelectorClaimHash[:], uint64(k), testSelectorClaimHash[:])
		if !testSelectors[k].VerifyClaim(testSelectorClaimHash[:]) {
			fmt.Fprintf(out, "FAILED (verify #%d)\n", k)
			return false
		}
	}
	for k := 1; k < len(testSelectors); k++ {
		if bytes.Compare(testSelectors[k-1].Key(), testSelectors[k].Key()) >= 0 {
			fmt.Fprintf(out, "FAILED (compare %d not < %d)\n", k-1, k)
			return false
		}
	}
	fmt.Fprintf(out, "OK\n")

	fmt.Fprintf(out, "Testing Record marshal/unmarshal... ")
	for k := 0; k < 32; k++ {
		var testLinks [][]byte
		for i := 0; i < 3; i++ {
			var tmp [32]byte
			secrand.Read(tmp[:])
			testLinks = append(testLinks, tmp[:])
		}
		var testValue [32]byte
		secrand.Read(testValue[:])
		owner, err := NewOwner(OwnerTypeEd25519)
		if err != nil {
			fmt.Fprintf(out, "FAILED (create owner): %s\n", err.Error())
			return false
		}
		rec, err := NewRecord(testValue[:], testLinks, []byte("test"), [][]byte{[]byte("test0")}, []uint64{0}, nil, uint64(k), RecordWorkAlgorithmNone, owner)
		if err != nil {
			fmt.Fprintf(out, "FAILED (create record): %s\n", err.Error())
			return false
		}
		var testBuf0 bytes.Buffer
		err = rec.MarshalTo(&testBuf0)
		if err != nil {
			fmt.Fprintf(out, "FAILED (marshal record): %s\n", err.Error())
			return false
		}
		var rec2 Record
		err = rec2.UnmarshalFrom(&testBuf0)
		if err != nil {
			fmt.Fprintf(out, "FAILED (unmarshal record): %s\n", err.Error())
			return false
		}
		h0, h1 := rec.Hash(), rec2.Hash()
		if !bytes.Equal(h0[:], h1[:]) {
			fmt.Fprintf(out, "FAILED (hashes are not equal)\n")
			return false
		}
	}
	fmt.Fprintf(out, "OK\n")

	fmt.Fprintf(out, "Testing Record will full proof of work (generate, verify)... ")
	var testLinks [][]byte
	for i := 0; i < 3; i++ {
		var tmp [32]byte
		secrand.Read(tmp[:])
		testLinks = append(testLinks, tmp[:])
	}
	var testValue [32]byte
	secrand.Read(testValue[:])
	owner, err := NewOwner(OwnerTypeEd25519)
	if err != nil {
		fmt.Fprintf(out, "FAILED (create owner): %s\n", err.Error())
		return false
	}
	rec, err := NewRecord(testValue[:], testLinks, []byte("test"), [][]byte{[]byte("full record test")}, []uint64{0}, nil, TimeSec(), RecordWorkAlgorithmWharrgarbl, owner)
	if err != nil {
		fmt.Fprintf(out, "FAILED (new record creation): %s\n", err.Error())
		return false
	}
	err = rec.Validate()
	if err != nil {
		fmt.Fprintf(out, "FAILED (validate): %s\n", err.Error())
		return false
	}
	fmt.Fprintf(out, "OK\n")

	return true
}

//////////////////////////////////////////////////////////////////////////////

// TestWharrgarbl tests and runs benchmarks on the Wharrgarbl proof of work.
func TestWharrgarbl(out io.Writer) bool {
	testWharrgarblSamples := 25
	var junk [32]byte
	var wout [20]byte
	fmt.Fprintf(out, "RecordWharrgarblCost and RecordWharrgarblScore:\n")
	for s := uint(1); s <= RecordMaxSize; s *= 2 {
		fmt.Fprintf(out, "  %5d: cost: %.8x score: %.8x\n", s, RecordWharrgarblCost(s), RecordWharrgarblScore(RecordWharrgarblCost(s)))
	}
	fmt.Fprintf(out, "Testing and benchmarking Wharrgarbl proof of work algorithm...\n")
	for rs := uint(256); rs <= 2048; rs += 256 {
		secrand.Read(junk[:])
		diff := RecordWharrgarblCost(rs)
		var iterations, ii uint64
		startTime := TimeMs()
		for k := 0; k < testWharrgarblSamples; k++ {
			wout, ii = Wharrgarbl(junk[:], diff, recordWharrgarblMemory)
			iterations += ii
		}
		runTime := (TimeMs() - startTime) / uint64(testWharrgarblSamples)
		iterations /= uint64(testWharrgarblSamples)
		if WharrgarblVerify(wout[:], junk[:]) == 0 {
			fmt.Fprintf(out, "  %.8x: FAILED (verify)\n", diff)
			return false
		}
		fmt.Fprintf(out, "  %.8x: %d milliseconds %d iterations (difficulty for %d bytes)\n", diff, runTime, iterations, rs)
	}
	return true
}

//////////////////////////////////////////////////////////////////////////////

const testDatabaseInstances = 3
const testDatabaseRecords = 1000
const testDatabaseOwners = 16

// TestDatabase tests the database using a large set of randomly generated records.
func TestDatabase(testBasePath string, out io.Writer) bool {
	var err error
	var db [testDatabaseInstances]db

	testBasePath = path.Join(testBasePath, strconv.FormatInt(int64(os.Getpid()), 10))

	fmt.Fprintf(out, "Creating and opening %d databases in \"%s\"... ", testDatabaseInstances, testBasePath)
	for i := range db {
		p := path.Join(testBasePath, strconv.FormatInt(int64(i), 10))
		os.MkdirAll(p, 0755)
		err = db[i].open(p, nil)
		if err != nil {
			fmt.Fprintf(out, "FAILED: %s\n", err.Error())
			return false
		}
	}
	fmt.Fprintf(out, "OK\n")

	defer func() {
		for i := range db {
			db[i].close()
		}
	}()

	fmt.Fprintf(out, "Generating %d owner public/private key pairs... ", testDatabaseOwners)
	var owners [testDatabaseOwners]*Owner
	for i := range owners {
		owners[i], err = NewOwner(OwnerTypeEd25519)
		if err != nil {
			fmt.Fprintf(out, "FAILED: %s\n", err.Error())
			return false
		}
	}
	fmt.Fprintf(out, "OK\n")

	fmt.Fprintf(out, "Generating %d random linked records... ", testDatabaseRecords)
	var records [testDatabaseRecords]*Record
	ts := TimeSec()
	for ri := 0; ri < testDatabaseRecords; ri++ {
		var linkTo []uint
		for i := 0; i < 3 && i < ri; i++ {
			lt := uint(rand.Int31()) % uint(ri)
			for j := 0; j < (ri * 2); j++ {
				if sliceContainsUInt(linkTo, lt) {
					lt = (lt + 1) % uint(ri)
				} else {
					linkTo = append(linkTo, lt)
					break
				}
			}
		}
		var links [][]byte
		for i := range linkTo {
			links = append(links, records[linkTo[i]].Hash()[:])
		}

		ts++
		sel := []byte("test-owner-number-" + strconv.FormatInt(int64(ri%testDatabaseOwners), 10))
		value := []byte(strconv.FormatUint(ts, 10))
		records[ri], err = NewRecord(value, links, []byte("test"), [][]byte{sel}, []uint64{0}, nil, ts, RecordWorkAlgorithmNone, owners[ri%testDatabaseOwners])
		if err != nil {
			fmt.Fprintf(out, "FAILED: %s\n", err.Error())
			return false
		}
		valueDec := records[ri].GetValue([]byte("test"))
		if !bytes.Equal(value, valueDec) {
			fmt.Fprintf(out, "FAILED: record value unmask failed!\n")
			return false
		}
	}
	fmt.Fprintf(out, "OK\n")

	fmt.Fprintf(out, "Inserting records into all three databases...\n")
	for dbi := 0; dbi < testDatabaseInstances; dbi++ {
		for ri := 0; ri < testDatabaseRecords; ri++ {
			a := uint(rand.Int31()) % uint(testDatabaseRecords)
			b := uint(rand.Int31()) % uint(testDatabaseRecords)
			if a != b {
				records[a], records[b] = records[b], records[a]
			}
		}
		for ri := 0; ri < testDatabaseRecords; ri++ {
			err = db[dbi].putRecord(records[ri])
			if err != nil {
				fmt.Fprintf(out, "  #%d FAILED: %s\n", dbi, err.Error())
				return false
			}
		}
		fmt.Fprintf(out, "  #%d OK\n", dbi)
	}

	fmt.Fprintf(out, "Waiting for graph traversal and weight reconciliation...")
	for dbi := 0; dbi < testDatabaseInstances; dbi++ {
		for db[dbi].hasPending() {
			time.Sleep(time.Second / 2)
		}
		fmt.Fprintf(out, " %d", dbi)
	}
	fmt.Fprintf(out, " OK\n")

	fmt.Fprintf(out, "Checking database CRC64s...\n")
	var c64s [testDatabaseInstances]uint64
	for dbi := 0; dbi < testDatabaseInstances; dbi++ {
		c64s[dbi] = db[dbi].crc64()
		if dbi == 0 || c64s[dbi-1] == c64s[dbi] {
			fmt.Fprintf(out, "  OK %.16x\n", c64s[dbi])
		} else {
			fmt.Fprintf(out, "  FAILED %.16x != %.16x\n", c64s[dbi], c64s[dbi-1])
			return false
		}
	}
	fmt.Fprintf(out, "All databases reached the same final state for hashes, weights, and links.\n")

	return true
}

//////////////////////////////////////////////////////////////////////////////
