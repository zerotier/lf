/*
 * Copyright (c)2019 ZeroTier, Inc.
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file in the project's root directory.
 *
 * Change Date: 2023-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2.0 of the Apache License.
 */
/****/

package lf

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
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

	"lf/third_party/lfmd5"
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
	rand.Seed(time.Now().UnixNano())
	testStr := []byte("My hovercraft is full of eels.") // input for hash tests

	// This checks to make sure the Sum method of hashes fills arrays as expected.
	// This is sort of an ambiguous behavior in the API docs, so we want to detect
	// if the actual behavior changes. If it does we'll have to change a few spots.
	_, _ = fmt.Fprintf(out, "Testing hash slice filling behavior (API behavior check)... ")
	ref := sha256.Sum256(testStr)
	th := sha256.New()
	_, err := th.Write(testStr)
	if err != nil {
		panic(err)
	}
	var thout [32]byte
	th.Sum(thout[:0])
	if bytes.Equal(thout[:], ref[:]) {
		_, _ = fmt.Fprintf(out, "OK\n")
	} else {
		_, _ = fmt.Fprintf(out, "FAILED\n")
		return false
	}

	_, _ = fmt.Fprintf(out, "Testing Blob serialize/deserialize and Base62... ")
	var tmpjunk [256]byte
	for k := 1; k <= 256; k++ {
		testBlob := Blob(tmpjunk[0:k])
		rand.Read(testBlob)
		j, err := json.Marshal(&testBlob)
		if err != nil {
			_, _ = fmt.Fprintf(out, "FAILED: %s\n", err.Error())
			return false
		}
		var testBlob2 Blob
		err = json.Unmarshal(j, &testBlob2)
		if err != nil {
			_, _ = fmt.Fprintf(out, "FAILED: %s\n", err.Error())
			return false
		}
		if !bytes.Equal(testBlob, testBlob2) {
			_, _ = fmt.Fprintf(out, "ERROR: results do not match\n")
			return false
		}
	}
	_, _ = fmt.Fprintf(out, "OK\n")

	_, _ = fmt.Fprintf(out, "Testing built-in fork of MD5 (used in proof of work function)... ")
	var mymd5test lfmd5.Digest
	mymd5test.Reset()
	_, _ = mymd5test.Write(testStr)
	var mymd5out [16]byte
	mymd5test.FastSum(mymd5out[:])
	if hex.EncodeToString(mymd5out[:]) != "d464064618e61b35dca3e5dee84c7b56" {
		_, _ = fmt.Fprintf(out, "FAILED %x\n", mymd5out)
		return false
	}
	_, _ = fmt.Fprintf(out, "OK\n")

	_, _ = fmt.Fprintf(out, "Testing and benchmarking TH64 micro-hash... ")
	th64out := th64(0xdeadbeefdeadbeef)
	if th64out != 0x1411eaec63f6644b || th64n(0xdeadbeefdeadbeef, 1) != th64out {
		_, _ = fmt.Fprintf(out, "FAILED %x\n", th64out)
		return false
	}
	start := time.Now()
	th64out = th64n(0xdeadbeefdeadbeef, 10000000)
	end := time.Now()
	_, _ = fmt.Fprintf(out, "OK (%f hashes/sec)\n", 10000000.0/end.Sub(start).Seconds())

	_, _ = fmt.Fprintf(out, "Testing Ordinal... ")
	var rk [8]byte
	var orda, ordb Ordinal
	var ocount float64
	ostart := time.Now()
	rand.Read(rk[:])
	for k := 0; k < 128; k++ {
		binary.LittleEndian.PutUint16(rk[:], uint16(k))
		orda.Set(0, rk[:])
		ordb.Set(0xffffffffffffffff, rk[:])
		ocount += 2.0
		if bytes.Compare(orda[:], ordb[:]) >= 0 {
			_, _ = fmt.Fprintf(out, "FAILED (ordinal A must be less than ordinal B (0-max))\n")
			return false
		}

		rn := rand.Uint64()
		for i := 0; i < 8; i++ {
			orda.Set(rn, rk[:])
			ordb.Set(rn+1, rk[:])
			ocount += 2.0
			if bytes.Compare(orda[:], ordb[:]) >= 0 {
				_, _ = fmt.Fprintf(out, "FAILED (ordinal A must be less than ordinal B (%.16x))\n", rn)
				return false
			}
			rn++
			if rn >= 0xfffffffffffffff0 {
				rn = 0
			}
		}
	}
	oend := time.Now()
	for k := 0; k < 128; k++ {
		rn := rand.Uint64()
		binary.LittleEndian.PutUint16(rk[:], uint16(k))
		binary.LittleEndian.PutUint32(rk[4:], uint32(rn))
		orda.Set(rn, rk[:])
		if orda.Get(rk[:]) != rn {
			fmt.Printf("\n%x %.16x %.16x\n", orda, rn, orda.Get(rk[:]))
			_, _ = fmt.Fprintf(out, "FAILED (Get() failed to decrypt ordinal)\n")
			return false
		}
	}
	_, _ = fmt.Fprintf(out, "OK (%f ms/ordinal)\n", (oend.Sub(ostart).Seconds()*1000.0)/ocount)

	_, _ = fmt.Fprintf(out, "Testing Selector... ")
	var testSelectors [256]Selector
	var testSelectorClaimHash [32]byte
	_, _ = secureRandom.Read(testSelectorClaimHash[:])
	for k := range testSelectors {
		testSelectors[k].set([]byte("name"), uint64(k), testSelectorClaimHash[:])
		ts2, err := NewSelectorFromBytes(testSelectors[k].Bytes())
		if err != nil || !bytes.Equal(ts2.Ordinal[:], testSelectors[k].Ordinal[:]) || !bytes.Equal(ts2.Claim, testSelectors[k].Claim) {
			_, _ = fmt.Fprintln(out, "FAILED (marshal/unmarshal)")
			return false
		}
	}
	for k := 1; k < len(testSelectors); k++ {
		sk := testSelectors[k].key(testSelectorClaimHash[:])
		if bytes.Compare(testSelectors[k-1].key(testSelectorClaimHash[:]), sk) >= 0 {
			_, _ = fmt.Fprintf(out, "FAILED (compare %d not < %d)\n", k-1, k)
			return false
		}
	}
	for k := 0; k < 32; k++ {
		rn := rand.Uint64()
		var selTest Selector
		selTest.set([]byte("name"), rn, testSelectorClaimHash[:])
		if !bytes.Equal(MakeSelectorKey([]byte("name"), rn), selTest.key(testSelectorClaimHash[:])) {
			_, _ = fmt.Fprintf(out, "FAILED (keys from key() vs MakeSelectorKey() are not equal)\n")
			return false
		}
	}
	_, _ = fmt.Fprintf(out, "OK\n")

	curves := []elliptic.Curve{elliptic.P384(), elliptic.P224(), ECCCurveBrainpoolP160T1}
	for ci := range curves {
		curve := curves[ci]

		_, _ = fmt.Fprintf(out, "Testing %s ECDSA...\n", curve.Params().Name)
		priv, err := ecdsa.GenerateKey(curve, secureRandom)
		if err != nil {
			_, _ = fmt.Fprintf(out, "  FAILED (generate): %s\n", err.Error())
			return false
		}
		pub, err := ECDSACompressPublicKey(&priv.PublicKey)
		if err != nil {
			_, _ = fmt.Fprintf(out, "  FAILED (compress): %s\n", err.Error())
			return false
		}
		_, _ = fmt.Fprintf(out, "  Public Key: [%d] %x...\n", len(pub), pub[0:16])
		pub2, err := ECDSADecompressPublicKey(curve, pub)
		if err != nil {
			_, _ = fmt.Fprintf(out, "  FAILED (decompress): %s\n", err.Error())
			return false
		}
		if pub2.X.Cmp(priv.PublicKey.X) != 0 || pub2.Y.Cmp(priv.PublicKey.Y) != 0 {
			_, _ = fmt.Fprintf(out, "  FAILED (decompress): results are not the same!\n")
			return false
		}

		var junk [32]byte
		_, _ = secureRandom.Read(junk[:])
		sig, err := ECDSASign(priv, junk[:])
		if err != nil {
			_, _ = fmt.Fprintf(out, "  FAILED (sign): %s\n", err.Error())
			return false
		}
		_, _ = fmt.Fprintf(out, "  Signature: [%d] %x...\n", len(sig), sig[0:16])
		if !ECDSAVerify(&priv.PublicKey, junk[:], sig) {
			_, _ = fmt.Fprintf(out, "  FAILED (verify): verify failed for correct message\n")
			return false
		}
		junk[1]++
		if ECDSAVerify(&priv.PublicKey, junk[:], sig) {
			_, _ = fmt.Fprintf(out, "  FAILED (verify): verify succeeded for incorrect message\n")
			return false
		}
		junk[1]--
		sig[2]++
		if ECDSAVerify(&priv.PublicKey, junk[:], sig) {
			_, _ = fmt.Fprintf(out, "  FAILED (verify): verify succeeded for incorrect signature (but correct message)\n")
			return false
		}

		for i := 0; i < 32; i++ {
			_, _ = secureRandom.Read(junk[:])
			sig, _ := ECDSASignEmbedRecoveryIndex(priv, junk[:])
			if i == 0 {
				_, _ = fmt.Fprintf(out, "  Key Recoverable Signature: [%d] %x...\n  Testing key recovery... ", len(sig), sig[0:16])
			}
			pub := ECDSARecover(curve, junk[:], sig)
			if pub == nil {
				_, _ = fmt.Fprintf(out, "FAILED (ECDSARecover returned nil)\n")
				return false
			}
			if pub.X.Cmp(priv.PublicKey.X) != 0 || pub.Y.Cmp(priv.PublicKey.Y) != 0 {
				pcomp, _ := ECDSACompressPublicKey(pub)
				_, _ = fmt.Fprintf(out, "FAILED (ECDSARecover returned wrong key: %x)\n", pcomp)
				return false
			}
		}
		_, _ = fmt.Fprintf(out, "OK\n")
	}

	_, _ = fmt.Fprintf(out, "Testing Owner...")
	for _, ownerType := range []byte{OwnerTypeNistP224, OwnerTypeNistP384, OwnerTypeEd25519} {
		owner, err := NewOwner(ownerType)
		if err != nil {
			_, _ = fmt.Fprintf(out, " FAILED (create: %s)", err.Error())
			return false
		}
		_, _ = fmt.Fprintf(out, " %s", owner.TypeString())
		ownerPrivBytes, err := owner.PrivateBytes()
		if err != nil {
			_, _ = fmt.Fprintf(out, " FAILED (encode private: %s)", err.Error())
			return false
		}
		owner2, err := NewOwnerFromPrivateBytes(ownerPrivBytes)
		if err != nil {
			_, _ = fmt.Fprintf(out, " FAILED (decode private: %s)", err.Error())
			return false
		}
		sig, err := owner.Sign(testStr)
		if err != nil {
			_, _ = fmt.Fprintf(out, " FAILED (sign: %s)", err.Error())
			return false
		}
		if !owner2.Verify(testStr, sig) {
			if err != nil {
				_, _ = fmt.Fprintf(out, " FAILED (verify #1 failed)")
				return false
			}
		}
		owner3 := Owner{Public: owner.Public}
		if !owner3.Verify(testStr, sig) {
			if err != nil {
				_, _ = fmt.Fprintf(out, " FAILED (verify #2 failed)")
				return false
			}
		}
	}
	_, _ = fmt.Fprintf(out, " OK\n")

	_, _ = fmt.Fprintf(out, "Testing deterministic owner generation from seed... p384 ")
	op384, _ := NewOwnerFromSeed(OwnerTypeNistP384, []byte("lol"))
	op384s := hex.EncodeToString(op384.Public)
	if op384s != "071da200540e3774af83a33e2494db3d8c8e4ea15201dfbe" {
		_, _ = fmt.Fprintf(out, "FAILED %s\n", op384s)
		return false
	}
	testSigHash := sha256.Sum256(testStr)
	sig, err := op384.Sign(testSigHash[:])
	if err != nil {
		_, _ = fmt.Fprintf(out, "FAILED (sign)\n")
		return false
	}
	if !op384.Verify(testSigHash[:], sig) {
		_, _ = fmt.Fprintf(out, "FAILED (verify)\n")
		return false
	}
	_, _ = fmt.Fprint(out, "p224 ")
	op224, _ := NewOwnerFromSeed(OwnerTypeNistP224, []byte("lol"))
	op224s := hex.EncodeToString(op224.Public)
	if op224s != "c561d9cb504bd966d451d421fd77" {
		_, _ = fmt.Fprintf(out, "FAILED %s\n", op224s)
		return false
	}
	sig, err = op224.Sign(testSigHash[:])
	if err != nil {
		_, _ = fmt.Fprintf(out, "FAILED (sign)\n")
		return false
	}
	if !op224.Verify(testSigHash[:], sig) {
		_, _ = fmt.Fprintf(out, "FAILED (verify)\n")
		return false
	}
	_, _ = fmt.Fprint(out, "ed25519 ")
	o25519, _ := NewOwnerFromSeed(OwnerTypeEd25519, []byte("lol"))
	o25519s := hex.EncodeToString(o25519.Public)
	if o25519s != "c289a225c996df1998b7aa0e4af9f1142a81d5ab8c55484dadbac7b48baefc8e" {
		_, _ = fmt.Fprintf(out, "FAILED %s\n", o25519s)
		return false
	}
	sig, err = o25519.Sign(testSigHash[:])
	if err != nil {
		_, _ = fmt.Fprintf(out, "FAILED (sign)\n")
		return false
	}
	if !o25519.Verify(testSigHash[:], sig) {
		_, _ = fmt.Fprintf(out, "FAILED (verify)\n")
		return false
	}
	_, _ = fmt.Fprintf(out, "OK\n")

	_, _ = fmt.Fprintf(out, "Testing Pulse...")
	ptowner, _ := NewOwner(OwnerTypeNistP224)
	for n := 0; n < 3; n++ {
		token, _ := NewPulse(ptowner, [][]byte{[]byte("test")}, []uint64{1234}, 1, 0)
		tk := token.Key()
		for k := uint(0); k <= RecordMaxPulseSpan; k += 8212 {
			p, _ := NewPulse(ptowner, [][]byte{[]byte("test")}, []uint64{1234}, 1, k)
			if p.Token() != tk {
				fmt.Printf(" FAILED\n")
				return false
			}
		}
	}
	_, _ = fmt.Fprintf(out, " OK\n")

	_, _ = fmt.Fprintf(out, "Testing Record marshal/unmarshal... ")
	for k := 0; k < 32; k++ {
		var testLinks [][32]byte
		for i := 0; i < 3; i++ {
			var tmp [32]byte
			_, _ = secureRandom.Read(tmp[:])
			testLinks = append(testLinks, tmp)
		}
		owner, err := NewOwner(OwnerTypeNistP224)
		if err != nil {
			_, _ = fmt.Fprintf(out, "FAILED (create owner): %s\n", err.Error())
			return false
		}
		testVal := []byte("Supercalifragilisticexpealidocious!")
		rec, err := NewRecord(RecordTypeDatum, testVal, testLinks, []byte("test"), [][]byte{[]byte("test0")}, []uint64{0}, uint64(k), nil, owner)
		if err != nil {
			_, _ = fmt.Fprintf(out, "FAILED (create record): %s\n", err.Error())
			return false
		}
		var testBuf0 bytes.Buffer
		err = rec.MarshalTo(&testBuf0, false)
		if err != nil {
			_, _ = fmt.Fprintf(out, "FAILED (marshal record): %s\n", err.Error())
			return false
		}
		var rec2 Record
		err = rec2.UnmarshalFrom(&testBuf0)
		if err != nil {
			_, _ = fmt.Fprintf(out, "FAILED (unmarshal record): %s\n", err.Error())
			return false
		}
		h0, h1 := rec.Hash(), rec2.Hash()
		if !bytes.Equal(h0[:], h1[:]) {
			_, _ = fmt.Fprintf(out, "FAILED (hashes are not equal)\n")
			return false
		}
		testVal2, err := rec.GetValue([]byte("test"))
		if err != nil || !bytes.Equal(testVal2, testVal) {
			_, _ = fmt.Fprintf(out, "FAILED (values are not equal)\n")
			return false
		}
	}
	_, _ = fmt.Fprintf(out, "OK\n")

	_, _ = fmt.Fprintf(out, "Testing Record with full proof of work (generate, verify)... ")
	var testLinks [][32]byte
	for i := 0; i < 3; i++ {
		var tmp [32]byte
		_, _ = secureRandom.Read(tmp[:])
		testLinks = append(testLinks, tmp)
	}
	var testValue [32]byte
	_, _ = secureRandom.Read(testValue[:])
	owner, err := NewOwner(OwnerTypeNistP224)
	if err != nil {
		_, _ = fmt.Fprintf(out, "FAILED (create owner): %s\n", err.Error())
		return false
	}
	wg := NewWharrgarblr(RecordDefaultWharrgarblMemory, 0)
	rec, err := NewRecord(RecordTypeDatum, testValue[:], testLinks, []byte("test"), [][]byte{[]byte("full record test")}, []uint64{0}, TimeSec(), wg, owner)
	if err != nil {
		_, _ = fmt.Fprintf(out, "FAILED (new record creation): %s\n", err.Error())
		return false
	}
	err = rec.Validate()
	if err != nil {
		_, _ = fmt.Fprintf(out, "FAILED (validate): %s\n", err.Error())
		return false
	}
	if !rec.ValidateWork() {
		_, _ = fmt.Fprintf(out, "FAILED (validate work)\n")
		return false
	}
	_, _ = fmt.Fprintf(out, "OK\n")

	return true
}

//////////////////////////////////////////////////////////////////////////////

// TestWharrgarbl tests and runs benchmarks on the Wharrgarbl proof of work.
func TestWharrgarbl(out io.Writer) bool {
	testWharrgarblSamples := 16
	var junk [32]byte
	var wout [WharrgarblOutputSize]byte

	// Have to do this here to generate the table
	wg := NewWharrgarblr(RecordDefaultWharrgarblMemory, 0)

	_, _ = fmt.Fprintf(out, "Wharrgarbl cost and score:\n")
	for s := uint(1); s <= RecordMaxSize; s *= 2 {
		_, _ = fmt.Fprintf(out, "  %5d: cost: %.8x score: %.8x\n", s, recordWharrgarblCost(s), recordWharrgarblScore(recordWharrgarblCost(s)))
	}

	_, _ = fmt.Fprintf(out, "Testing and benchmarking Wharrgarbl proof of work algorithm...\n")
	for rs := uint(256); rs <= 2048; rs += 256 {
		diff := recordWharrgarblCost(rs)
		iterations := uint64(0)
		startTime := time.Now()
		for k := 0; k < testWharrgarblSamples; k++ {
			var ii uint64
			wout, ii = wg.Compute(junk[:], diff)
			iterations += ii
		}
		runTime := time.Now().Sub(startTime).Seconds() / float64(testWharrgarblSamples)
		iterations /= uint64(testWharrgarblSamples)
		if WharrgarblVerify(wout[:], junk[:]) == 0 {
			_, _ = fmt.Fprintf(out, "  %.8x: FAILED (verify)\n", diff)
			return false
		}
		_, _ = fmt.Fprintf(out, "  %.8x: %f seconds, %d iterations, difficulty %.8x for %d bytes\n", diff, runTime, iterations, diff, rs)
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

	_, _ = fmt.Fprintf(out, "Creating and opening %d databases in \"%s\"... ", testDatabaseInstances, testBasePath)
	for i := range dbs {
		p := path.Join(testBasePath, strconv.FormatInt(int64(i), 10))
		_ = os.MkdirAll(p, 0755)
		err = dbs[i].open(p, [logLevelCount]*log.Logger{logger, logger, logger, logger, logger}, func(doff uint64, dlen uint, reputation int, hash *[32]byte) {})
		if err != nil {
			_, _ = fmt.Fprintf(out, "FAILED: %s\n", err.Error())
			return false
		}
	}
	_, _ = fmt.Fprintf(out, "OK\n")

	defer func() {
		for i := range dbs {
			dbs[i].close()
		}
	}()

	_, _ = fmt.Fprintf(out, "Generating %d owner public/private key pairs... ", testDatabaseOwners)
	var owners [testDatabaseOwners]*Owner
	for i := range owners {
		owners[i], err = NewOwner(OwnerTypeNistP224)
		if err != nil {
			_, _ = fmt.Fprintf(out, "FAILED: %s\n", err.Error())
			return false
		}
	}
	_, _ = fmt.Fprintf(out, "OK\n")

	_, _ = fmt.Fprintf(out, "Generating %d random linked records... ", testDatabaseRecords)
	var values, selectors, selectorKeys [testDatabaseRecords][]byte
	var ordinals [testDatabaseRecords]uint64
	var records [testDatabaseRecords]*Record
	ts := TimeSec()
	testMaskingKey := []byte("maskingkey")
	rand.Seed(time.Now().UnixNano())
	selRandom := fmt.Sprintf("%d", rand.Uint64())
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
		values[ri] = []byte(fmt.Sprintf("%.16x%.16x", ownerIdx, ri))
		selectors[ri] = []byte(fmt.Sprintf("%.16x%s", ownerIdx, selRandom))
		ordinals[ri] = uint64(ri)
		records[ri], err = NewRecord(
			RecordTypeDatum,
			values[ri],
			links,
			testMaskingKey,
			[][]byte{selectors[ri]},
			[]uint64{ordinals[ri]},
			ts,
			nil,
			owners[ownerIdx])
		if err != nil {
			_, _ = fmt.Fprintf(out, "FAILED: %s\n", err.Error())
			return false
		}

		valueDec, _ := records[ri].GetValue(testMaskingKey)
		if !bytes.Equal(values[ri], valueDec) {
			_, _ = fmt.Fprintf(out, "FAILED: record value unmask failed!\n")
			return false
		}
		valueDec = nil
		valueDec, _ = records[ri].GetValue([]byte("not maskingkey"))
		if bytes.Equal(values[ri], valueDec) {
			_, _ = fmt.Fprintf(out, "FAILED: record value unmask succeeded with wrong key!\n")
			return false
		}

		selectorKeys[ri] = records[ri].SelectorKey(0)
	}
	_, _ = fmt.Fprintf(out, "OK\n")

	_, _ = fmt.Fprintf(out, "Inserting records into all three databases...\n")
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
				_, _ = fmt.Fprintf(out, "  #%d FAILED: %s\n", dbi, err.Error())
				return false
			}
		}
		_, _ = fmt.Fprintf(out, "  #%d OK\n", dbi)
	}

	_, _ = fmt.Fprintf(out, "Waiting for graph traversal and weight reconciliation... ")
	for dbi := 0; dbi < testDatabaseInstances; dbi++ {
		for dbs[dbi].hasPending() {
			time.Sleep(time.Second / 2)
		}
	}
	_, _ = fmt.Fprintf(out, "OK\n")

	_, _ = fmt.Fprintf(out, "Checking database CRC64s...\n")
	var c64s [testDatabaseInstances]uint64
	for dbi := 0; dbi < testDatabaseInstances; dbi++ {
		c64s[dbi] = dbs[dbi].crc64()
		if dbi == 0 || c64s[dbi-1] == c64s[dbi] {
			_, _ = fmt.Fprintf(out, "  OK %.16x\n", c64s[dbi])
		} else {
			_, _ = fmt.Fprintf(out, "  FAILED %.16x != %.16x\n", c64s[dbi], c64s[dbi-1])
			return false
		}
	}
	_, _ = fmt.Fprintf(out, "All databases reached the same final state for hashes, weights, and links.\n")

	_, _ = fmt.Fprintf(out, "Testing database queries by selector and selector range...\n")
	var gotRecordCount uint32
	wg := new(sync.WaitGroup)
	wg.Add(testDatabaseInstances)
	for dbi2 := 0; dbi2 < testDatabaseInstances; dbi2++ {
		dbi := dbi2
		go func() {
			defer wg.Done()
			rb := make([]byte, 0, 4096)
			for ri := 0; ri < testDatabaseRecords; ri++ {
				err = dbs[dbi].query([][2][]byte{{selectorKeys[ri], selectorKeys[ri]}}, nil, func(ts, weightL, weightH, doff, dlen uint64, localReputation int, key uint64, owner []byte, negativeComments uint) bool {
					rdata, err := dbs[dbi].getDataByOffset(doff, uint(dlen), rb[:0])
					if err != nil {
						_, _ = fmt.Fprintf(out, "  FAILED to retrieve (selector key: %x) (%s)\n", selectorKeys[ri], err.Error())
						return false
					}
					rec, err := NewRecordFromBytes(rdata)
					if err != nil {
						_, _ = fmt.Fprintf(out, "  FAILED to unmarshal (selector key: %x) (%s)\n", selectorKeys[ri], err.Error())
						return false
					}
					valueDec, err := rec.GetValue(testMaskingKey)
					if err != nil {
						_, _ = fmt.Fprintf(out, "  FAILED to unmask value (selector key: %x) (%s)\n", selectorKeys[ri], err.Error())
						return false
					}
					if !bytes.Equal(valueDec, values[ri]) {
						_, _ = fmt.Fprintf(out, "  FAILED to unmask value (selector key: %x) (values do not match)", selectorKeys[ri])
						return false
					}
					rc := atomic.AddUint32(&gotRecordCount, 1)
					if (rc % 1000) == 0 {
						_, _ = fmt.Fprintf(out, "  ... %d records\n", rc)
					}
					return true
				})
			}
		}()
	}
	wg.Wait()
	if gotRecordCount != (testDatabaseRecords * testDatabaseInstances) {
		_, _ = fmt.Fprintf(out, "  FAILED non-range query test: got %d records, expected %d\n", gotRecordCount, testDatabaseRecords*testDatabaseInstances)
	}
	_, _ = fmt.Fprintf(out, "  Non-range query test OK (%d records from %d parallel databases)\n", gotRecordCount, testDatabaseInstances)
	gotRecordCount = 0
	wg = new(sync.WaitGroup)
	wg.Add(testDatabaseInstances)
	for dbi2 := 0; dbi2 < testDatabaseInstances; dbi2++ {
		dbi := dbi2
		go func() {
			defer wg.Done()
			rb := make([]byte, 0, 4096)
			for oi := 0; oi < testDatabaseOwners; oi++ {
				ptk := []byte(fmt.Sprintf("%.16x%s", oi, selRandom))
				sk0 := MakeSelectorKey(ptk, 0)
				sk1 := MakeSelectorKey(ptk, 0xffffffffffffffff)
				err = dbs[dbi].query([][2][]byte{{sk0, sk1}}, nil, func(ts, weightL, weightH, doff, dlen uint64, localReputation int, key uint64, owner []byte, negativeComments uint) bool {
					_, err := dbs[dbi].getDataByOffset(doff, uint(dlen), rb[:0])
					if err != nil {
						_, _ = fmt.Fprintf(out, "  FAILED to retrieve (selector key range %x-%x) (%s)\n", sk0, sk1, err.Error())
						return false
					}
					rc := atomic.AddUint32(&gotRecordCount, 1)
					if (rc % 1000) == 0 {
						_, _ = fmt.Fprintf(out, "  ... %d records\n", rc)
					}
					return true
				})
			}
		}()
	}
	wg.Wait()
	if atomic.LoadUint32(&gotRecordCount) != (testDatabaseRecords * testDatabaseInstances) {
		_, _ = fmt.Fprintf(out, "  FAILED ordinal range query test: got %d records, expected %d\n", gotRecordCount, testDatabaseRecords*testDatabaseInstances)
		return false
	}
	_, _ = fmt.Fprintf(out, "  Ordinal range query test OK (%d records from %d parallel databases)\n", gotRecordCount, testDatabaseInstances)

	return true
}
