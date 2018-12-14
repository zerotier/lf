package lf

import (
	"fmt"
	"io"
)

const testWharrgarblSamples = 25

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

	return true
}

// TestWharrgarbl tests and runs benchmarks on the Wharrgarbl proof of work.
func TestWharrgarbl(out io.Writer) bool {
	var junk [64]byte
	var wout [20]byte
	fmt.Fprintf(out, "Testing and benchmarking Wharrgarbl proof of work algorithm...\n")
	for rs := 256; rs <= 2048; rs += 256 {
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
