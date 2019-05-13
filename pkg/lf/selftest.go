/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * --
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial closed-source software that incorporates or links
 * directly against ZeroTier software without disclosing the source code
 * of your own application.
 */

package lf

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"path"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"../../third_party/lfmd5"
)

func sliceContainsUInt(s []uint, e uint) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

//////////////////////////////////////////////////////////////////////////////

// TestCore tests various core functions and helpers.
func TestCore(out io.Writer) bool {
	testStr := []byte("My hovercraft is full of eels.") // input for hash tests

	// This checks to make sure the Sum method of hashes fills arrays as expected.
	// This is sort of an ambiguous behavior in the API docs, so we want to detect
	// if the actual behavior changes. If it does we'll have to change a few spots.
	fmt.Fprintf(out, "Testing hash slice filling behavior (API behavior check)... ")
	ref := sha256.Sum256(testStr)
	th := sha256.New()
	_, err := th.Write(testStr)
	if err != nil {
		panic(err)
	}
	var thout [32]byte
	th.Sum(thout[:0])
	if bytes.Equal(thout[:], ref[:]) {
		fmt.Fprintf(out, "OK\n")
	} else {
		fmt.Fprintf(out, "FAILED\n")
		return false
	}

	fmt.Fprintf(out, "Testing Blob serialize/deserialize and Base62... ")
	var tmpjunk [256]byte
	for k := 1; k <= 256; k++ {
		testBlob := Blob(tmpjunk[0:k])
		rand.Read(testBlob)
		j, err := json.Marshal(&testBlob)
		if err != nil {
			fmt.Fprintf(out, "FAILED: %s\n", err.Error())
			return false
		}
		var testBlob2 Blob
		err = json.Unmarshal(j, &testBlob2)
		if err != nil {
			fmt.Fprintf(out, "FAILED: %s\n", err.Error())
			return false
		}
		if !bytes.Equal(testBlob, testBlob2) {
			fmt.Fprintf(out, "ERROR: results do not match\n")
			return false
		}
	}
	fmt.Fprintf(out, "OK\n")

	fmt.Fprintf(out, "Testing built-in fork of MD5 (used in proof of work function)... ")
	var mymd5test lfmd5.Digest
	mymd5test.Reset()
	mymd5test.Write(testStr)
	var mymd5out [16]byte
	mymd5test.FastSum(mymd5out[:])
	if hex.EncodeToString(mymd5out[:]) != "d464064618e61b35dca3e5dee84c7b56" {
		fmt.Fprintf(out, "FAILED %x\n", mymd5out)
		return false
	}
	fmt.Fprintf(out, "OK\n")

	fmt.Fprintf(out, "Testing Shandwich256... ")
	t0 := Shandwich256(testStr)
	t1h := NewShandwich256()
	t1h.Write(testStr)
	t1 := t1h.Sum(nil)
	if bytes.Equal(t0[:], t1) && hex.EncodeToString(t0[:]) == "7f1431b5dbeb7b15129ed4d9ebd97cee1e5b6eb01623405b2c4b33844f1e1bb1" {
		fmt.Fprintf(out, "OK\n")
	} else {
		fmt.Fprintf(out, "FAILED %x\n", t0)
		return false
	}

	fmt.Fprintf(out, "Testing deterministic owner generation from seed... P-384 ")
	op384, _ := NewOwnerFromSeed(OwnerTypeNistP384, []byte("lol"))
	if hex.EncodeToString(op384.Public) != "7edb3b9ecc106d4a452275ecf71ab1b271e0a82ca2dc9df2" {
		fmt.Fprintf(out, "FAILED %x\n", op384.Public)
		return false
	}
	testSigHash := sha256.Sum256(testStr)
	sig, err := op384.Sign(testSigHash[:])
	if err != nil {
		fmt.Fprintf(out, "FAILED (sign)\n")
		return false
	}
	if !op384.Verify(testSigHash[:], sig) {
		fmt.Fprintf(out, "FAILED (verify)\n")
		return false
	}
	fmt.Fprint(out, "P-224 ")
	op224, _ := NewOwnerFromSeed(OwnerTypeNistP224, []byte("lol"))
	if hex.EncodeToString(op224.Public) != "6e5e629632947fbfb1d60bb79221" {
		fmt.Fprintf(out, "FAILED %x\n", op224.Public)
		return false
	}
	sig, err = op224.Sign(testSigHash[:])
	if err != nil {
		fmt.Fprintf(out, "FAILED (sign)\n")
		return false
	}
	if !op224.Verify(testSigHash[:], sig) {
		fmt.Fprintf(out, "FAILED (verify)\n")
		return false
	}
	fmt.Fprint(out, "ed25519 ")
	o25519, _ := NewOwnerFromSeed(OwnerTypeEd25519, []byte("lol"))
	if hex.EncodeToString(o25519.Public) != "f49e48675d885cabdfd6c84b47ee0017948699ecf356e9902d786cad245450c2" {
		fmt.Fprintf(out, "FAILED %x\n", o25519.Public)
		return false
	}
	sig, err = o25519.Sign(testSigHash[:])
	if err != nil {
		fmt.Fprintf(out, "FAILED (sign)\n")
		return false
	}
	if !o25519.Verify(testSigHash[:], sig) {
		fmt.Fprintf(out, "FAILED (verify)\n")
		return false
	}
	fmt.Fprintf(out, "OK\n")

	fmt.Fprintf(out, "Testing Ordinal... ")
	for k := 0; k < 1024; k++ {
		rn := rand.Uint32()
		var orda, ordb Ordinal
		orda.Set(uint64(rn), []byte{byte(k)})
		ordb.Set(uint64(rn)+1, []byte{byte(k)})
		if bytes.Compare(orda[:], ordb[:]) > 0 {
			fmt.Fprintf(out, "FAILED (ordinal A must be less than ordinal B)\n")
			return false
		}
	}
	fmt.Fprintf(out, "OK\n")

	fmt.Fprintf(out, "Testing Selector... ")
	var testSelectors [256]Selector
	var testSelectorClaimHash [32]byte
	secureRandom.Read(testSelectorClaimHash[:])
	for k := range testSelectors {
		testSelectors[k].set([]byte("name"), uint64(k), testSelectorClaimHash[:])
		ts2, err := newSelectorFromBytes(testSelectors[k].bytes())
		if err != nil || !bytes.Equal(ts2.Ordinal[:], testSelectors[k].Ordinal[:]) || !bytes.Equal(ts2.Claim, testSelectors[k].Claim) {
			fmt.Fprintln(out, "FAILED (marshal/unmarshal)")
			return false
		}
	}
	for k := 1; k < len(testSelectors); k++ {
		sk := testSelectors[k].key(testSelectorClaimHash[:])
		if bytes.Compare(testSelectors[k-1].key(testSelectorClaimHash[:]), sk) >= 0 {
			fmt.Fprintf(out, "FAILED (compare %d not < %d)\n", k-1, k)
			return false
		}
	}
	var selTest Selector
	selTest.set([]byte("name"), 1234, testSelectorClaimHash[:])
	if !bytes.Equal(MakeSelectorKey([]byte("name"), 1234), selTest.key(testSelectorClaimHash[:])) {
		fmt.Fprintf(out, "FAILED (keys from key() vs MakeSelectorKey() are not equal)\n")
		return false
	}
	fmt.Fprintf(out, "OK\n")

	curves := []elliptic.Curve{elliptic.P521(), elliptic.P384(), elliptic.P224(), ECCCurveBrainpoolP160T1}
	for ci := range curves {
		curve := curves[ci]

		fmt.Fprintf(out, "Testing %s ECDSA...\n", curve.Params().Name)
		priv, err := ecdsa.GenerateKey(curve, secureRandom)
		if err != nil {
			fmt.Fprintf(out, "  FAILED (generate): %s\n", err.Error())
			return false
		}
		pub, err := ECDSACompressPublicKey(&priv.PublicKey)
		if err != nil {
			fmt.Fprintf(out, "  FAILED (compress): %s\n", err.Error())
			return false
		}
		fmt.Fprintf(out, "  Public Key: [%d] %x...\n", len(pub), pub[0:16])
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
		secureRandom.Read(junk[:])
		sig, err := ECDSASign(priv, junk[:])
		if err != nil {
			fmt.Fprintf(out, "  FAILED (sign): %s\n", err.Error())
			return false
		}
		fmt.Fprintf(out, "  Signature: [%d] %x...\n", len(sig), sig[0:16])
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

		for i := 0; i < 32; i++ {
			secureRandom.Read(junk[:])
			sig, _ := ECDSASignEmbedRecoveryIndex(priv, junk[:])
			if i == 0 {
				fmt.Fprintf(out, "  Key Recoverable Signature: [%d] %x...\n  Testing key recovery... ", len(sig), sig[0:16])
			}
			pub := ECDSARecover(curve, junk[:], sig)
			if pub == nil {
				fmt.Fprintf(out, "FAILED (ECDSARecover returned nil)\n")
			}
			if pub.X.Cmp(priv.PublicKey.X) != 0 || pub.Y.Cmp(priv.PublicKey.Y) != 0 {
				pcomp, _ := ECDSACompressPublicKey(pub)
				fmt.Fprintf(out, "FAILED (ECDSARecover returned wrong key: %x)\n", pcomp)
			}
		}
		fmt.Fprintf(out, "OK\n")
	}

	fmt.Fprintf(out, "Testing Record marshal/unmarshal... ")
	for k := 0; k < 32; k++ {
		var testLinks [][32]byte
		for i := 0; i < 3; i++ {
			var tmp [32]byte
			secureRandom.Read(tmp[:])
			testLinks = append(testLinks, tmp)
		}
		owner, err := NewOwner(OwnerTypeNistP224)
		if err != nil {
			fmt.Fprintf(out, "FAILED (create owner): %s\n", err.Error())
			return false
		}
		testVal := []byte("Supercalifragilisticexpealidocious!")
		rec, err := NewRecord(RecordTypeDatum, testVal, testLinks, []byte("test"), [][]byte{[]byte("test0")}, []uint64{0}, nil, uint64(k), nil, owner)
		if err != nil {
			fmt.Fprintf(out, "FAILED (create record): %s\n", err.Error())
			return false
		}
		var testBuf0 bytes.Buffer
		err = rec.MarshalTo(&testBuf0, false)
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
		testVal2, err := rec.GetValue([]byte("test"))
		if err != nil || !bytes.Equal(testVal2, testVal) {
			fmt.Fprintf(out, "FAILED (values are not equal)\n")
			return false
		}
	}
	fmt.Fprintf(out, "OK\n")

	fmt.Fprintf(out, "Testing Record with full proof of work (generate, verify)... ")
	var testLinks [][32]byte
	for i := 0; i < 3; i++ {
		var tmp [32]byte
		secureRandom.Read(tmp[:])
		testLinks = append(testLinks, tmp)
	}
	var testValue [32]byte
	secureRandom.Read(testValue[:])
	owner, err := NewOwner(OwnerTypeNistP224)
	if err != nil {
		fmt.Fprintf(out, "FAILED (create owner): %s\n", err.Error())
		return false
	}
	wg := NewWharrgarblr(RecordDefaultWharrgarblMemory, 0)
	rec, err := NewRecord(RecordTypeDatum, testValue[:], testLinks, []byte("test"), [][]byte{[]byte("full record test")}, []uint64{0}, nil, TimeSec(), wg, owner)
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
	var startTime, iterations, runTime uint64
	testWharrgarblSamples := 16
	var junk [32]byte
	var wout [WharrgarblOutputSize]byte

	// Have to do this here to generate the table
	wg := NewWharrgarblr(RecordDefaultWharrgarblMemory, 0)

	fmt.Fprintf(out, "Wharrgarbl cost and score:\n")
	for s := uint(1); s <= RecordMaxSize; s *= 2 {
		fmt.Fprintf(out, "  %5d: cost: %.8x score: %.8x\n", s, recordWharrgarblCost(s), recordWharrgarblScore(recordWharrgarblCost(s)))
	}

	fmt.Fprintf(out, "Testing and benchmarking Wharrgarbl proof of work algorithm...\n")
	for rs := uint(256); rs <= 4096; rs += 256 {
		diff := recordWharrgarblCost(rs)
		iterations = 0
		startTime = TimeMs()
		for k := 0; k < testWharrgarblSamples; k++ {
			var ii uint64
			wout, ii = wg.Compute(junk[:], diff)
			iterations += ii
		}
		runTime = (TimeMs() - startTime) / uint64(testWharrgarblSamples)
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
const testDatabaseRecords = 4096
const testDatabaseOwners = 16

// TestDatabase tests the database using a large set of randomly generated records.
func TestDatabase(testBasePath string, out io.Writer) bool {
	var err error
	var dbs [testDatabaseInstances]db

	testBasePath = path.Join(testBasePath, strconv.FormatInt(int64(os.Getpid()), 10))
	logger := log.New(os.Stdout, "[db] ", 0)

	fmt.Fprintf(out, "Creating and opening %d databases in \"%s\"... ", testDatabaseInstances, testBasePath)
	for i := range dbs {
		p := path.Join(testBasePath, strconv.FormatInt(int64(i), 10))
		os.MkdirAll(p, 0755)
		err = dbs[i].open(p, [logLevelCount]*log.Logger{logger, logger, logger, logger, logger}, func(doff uint64, dlen uint, reputation int, hash *[32]byte) {})
		if err != nil {
			fmt.Fprintf(out, "FAILED: %s\n", err.Error())
			return false
		}
	}
	fmt.Fprintf(out, "OK\n")

	defer func() {
		for i := range dbs {
			dbs[i].close()
		}
	}()

	fmt.Fprintf(out, "Generating %d owner public/private key pairs... ", testDatabaseOwners)
	var owners [testDatabaseOwners]*Owner
	for i := range owners {
		owners[i], err = NewOwner(OwnerTypeNistP224)
		if err != nil {
			fmt.Fprintf(out, "FAILED: %s\n", err.Error())
			return false
		}
	}
	fmt.Fprintf(out, "OK\n")

	fmt.Fprintf(out, "Generating %d random linked records... ", testDatabaseRecords)
	var values, selectors, selectorKeys [testDatabaseRecords][]byte
	var ordinals [testDatabaseRecords]uint64
	var records [testDatabaseRecords]*Record
	ts := TimeSec()
	testMaskingKey := []byte("maskingkey")
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
		var links [][32]byte
		for i := range linkTo {
			links = append(links, records[linkTo[i]].Hash())
		}

		ownerIdx := ri % testDatabaseOwners
		ts++
		values[ri] = []byte(strconv.FormatUint(ts, 10))
		selectors[ri] = []byte(fmt.Sprintf("%.16x", ownerIdx))
		ordinals[ri] = uint64(ri)
		records[ri], err = NewRecord(
			RecordTypeDatum,
			values[ri],
			links,
			testMaskingKey,
			[][]byte{selectors[ri]},
			[]uint64{ordinals[ri]},
			nil,
			ts,
			nil,
			owners[ownerIdx])
		if err != nil {
			fmt.Fprintf(out, "FAILED: %s\n", err.Error())
			return false
		}

		valueDec, _ := records[ri].GetValue(testMaskingKey)
		if !bytes.Equal(values[ri], valueDec) {
			fmt.Fprintf(out, "FAILED: record value unmask failed!\n")
			return false
		}
		valueDec = nil
		valueDec, _ = records[ri].GetValue([]byte("not maskingkey"))
		if bytes.Equal(values[ri], valueDec) {
			fmt.Fprintf(out, "FAILED: record value unmask succeeded with wrong key!\n")
			return false
		}

		selectorKeys[ri] = records[ri].SelectorKey(0)
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
			err = dbs[dbi].putRecord(records[ri])
			if err != nil {
				fmt.Fprintf(out, "  #%d FAILED: %s\n", dbi, err.Error())
				return false
			}
		}
		fmt.Fprintf(out, "  #%d OK\n", dbi)
	}

	fmt.Fprintf(out, "Waiting for graph traversal and weight reconciliation... ")
	for dbi := 0; dbi < testDatabaseInstances; dbi++ {
		for dbs[dbi].hasPending() {
			time.Sleep(time.Second / 2)
		}
	}
	fmt.Fprintf(out, "OK\n")

	fmt.Fprintf(out, "Checking database CRC64s...\n")
	var c64s [testDatabaseInstances]uint64
	for dbi := 0; dbi < testDatabaseInstances; dbi++ {
		c64s[dbi] = dbs[dbi].crc64()
		if dbi == 0 || c64s[dbi-1] == c64s[dbi] {
			fmt.Fprintf(out, "  OK %.16x\n", c64s[dbi])
		} else {
			fmt.Fprintf(out, "  FAILED %.16x != %.16x\n", c64s[dbi], c64s[dbi-1])
			return false
		}
	}
	fmt.Fprintf(out, "All databases reached the same final state for hashes, weights, and links.\n")

	fmt.Fprintf(out, "Testing database queries by selector and selector range...\n")
	var gotRecordCount uint32
	wg := new(sync.WaitGroup)
	wg.Add(testDatabaseInstances)
	for dbi2 := 0; dbi2 < testDatabaseInstances; dbi2++ {
		dbi := dbi2
		go func() {
			defer wg.Done()
			rb := make([]byte, 0, 4096)
			for ri := 0; ri < testDatabaseRecords; ri++ {
				err = dbs[dbi].query(0, 9223372036854775807, [][2][]byte{{selectorKeys[ri], selectorKeys[ri]}}, func(ts, weightL, weightH, doff, dlen uint64, localReputation int, key uint64, owner []byte) bool {
					rdata, err := dbs[dbi].getDataByOffset(doff, uint(dlen), rb[:0])
					if err != nil {
						fmt.Fprintf(out, "  FAILED to retrieve (selector key: %x) (%s)\n", selectorKeys[ri], err.Error())
						return false
					}
					rec, err := NewRecordFromBytes(rdata)
					if err != nil {
						fmt.Fprintf(out, "  FAILED to unmarshal (selector key: %x) (%s)\n", selectorKeys[ri], err.Error())
						return false
					}
					valueDec, err := rec.GetValue(testMaskingKey)
					if err != nil {
						fmt.Fprintf(out, "  FAILED to unmask value (selector key: %x) (%s)\n", selectorKeys[ri], err.Error())
						return false
					}
					if !bytes.Equal(valueDec, values[ri]) {
						fmt.Fprintf(out, "  FAILED to unmask value (selector key: %x) (values do not match)", selectorKeys[ri])
						return false
					}
					rc := atomic.AddUint32(&gotRecordCount, 1)
					if (rc % 1000) == 0 {
						fmt.Fprintf(out, "  ... %d records\n", rc)
					}
					return true
				})
			}
		}()
	}
	wg.Wait()
	if gotRecordCount != (testDatabaseRecords * testDatabaseInstances) {
		fmt.Fprintf(out, "  FAILED non-range query test: got %d records, expected %d\n", gotRecordCount, testDatabaseRecords*testDatabaseInstances)
	}
	fmt.Fprintf(out, "  Non-range query test OK (%d records from %d parallel databases)\n", gotRecordCount, testDatabaseInstances)
	gotRecordCount = 0
	wg = new(sync.WaitGroup)
	wg.Add(testDatabaseInstances)
	for dbi2 := 0; dbi2 < testDatabaseInstances; dbi2++ {
		dbi := dbi2
		go func() {
			defer wg.Done()
			rb := make([]byte, 0, 4096)
			for oi := 0; oi < testDatabaseOwners; oi++ {
				sk0 := MakeSelectorKey([]byte(fmt.Sprintf("%.16x", oi)), 0)
				sk1 := MakeSelectorKey([]byte(fmt.Sprintf("%.16x", oi)), 0xffffffffffffffff)
				err = dbs[dbi].query(0, 9223372036854775807, [][2][]byte{{sk0, sk1}}, func(ts, weightL, weightH, doff, dlen uint64, localReputation int, key uint64, owner []byte) bool {
					_, err := dbs[dbi].getDataByOffset(doff, uint(dlen), rb[:0])
					if err != nil {
						fmt.Fprintf(out, "  FAILED to retrieve (selector key range %x-%x) (%s)\n", sk0, sk1, err.Error())
						return false
					}
					rc := atomic.AddUint32(&gotRecordCount, 1)
					if (rc % 1000) == 0 {
						fmt.Fprintf(out, "  ... %d records\n", rc)
					}
					return true
				})
			}
		}()
	}
	wg.Wait()
	if gotRecordCount != (testDatabaseRecords * testDatabaseInstances) {
		fmt.Fprintf(out, "  FAILED ordinal range query test: got %d records, expected %d\n", gotRecordCount, testDatabaseRecords*testDatabaseInstances)
	}
	fmt.Fprintf(out, "  Ordinal range query test OK (%d records from %d parallel databases)\n", gotRecordCount, testDatabaseInstances)

	return true
}
