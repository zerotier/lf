/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	secrand "crypto/rand"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path"
	"strconv"
	"time"
)

// TestCore tests various core functions and helpers.
func TestCore(out io.Writer) bool {
	fmt.Fprintf(out, "Testing SpeckHash (part of Wharrgarbl)... ")
	spout := SpeckHash([]byte("My hovercraft is full of eels."))
	if spout[0] != 0xf50d1a72e7c3d28d || spout[1] != 0x709f7b2828f258ef {
		fmt.Fprintf(out, "FAILED %x\n", spout)
		return false
	}
	spout = SpeckHash(nil)
	if spout[0] != 0xc37bb21256623786 || spout[1] != 0xe65f29102074e0b0 {
		fmt.Fprintf(out, "FAILED %x\n", spout)
		return false
	}
	fmt.Fprintf(out, "OK\n")

	curves := []elliptic.Curve{elliptic.P384(), &ECCCurveSecP112R1}
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

	return true
}

// TestWharrgarbl tests and runs benchmarks on the Wharrgarbl proof of work.
func TestWharrgarbl(out io.Writer) bool {
	testWharrgarblSamples := 25
	var junk [64]byte
	var wout [20]byte
	fmt.Fprintf(out, "Testing and benchmarking Wharrgarbl proof of work algorithm...\n")
	for rs := uint(256); rs <= 2048; rs += 256 {
		diff := RecordWharrgarblCost(rs)
		var iterations, ii uint64
		startTime := TimeMs()
		for k := 0; k < testWharrgarblSamples; k++ {
			wout, ii = Wharrgarbl(junk[:], diff, RecordWharrgarblMemory)
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
	var ownerPub [testDatabaseOwners][]byte
	var ownerPriv [testDatabaseOwners]*ecdsa.PrivateKey
	for i := range ownerPub {
		ownerPub[i], ownerPriv[i] = GenerateOwner()
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
		for i := 0; i < RecordDesiredLinks && i < ri; i++ {
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
		records[ri], err = NewRecord(value, links, [][]byte{sel}, true, ownerPub[ri%testDatabaseOwners], ts, RecordWorkAlgorithmNone, ownerPriv[ri%testDatabaseOwners])
		if err != nil {
			fmt.Fprintf(out, "FAILED: %s\n", err.Error())
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
