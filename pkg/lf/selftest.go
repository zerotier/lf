package lf

import (
	"fmt"
	"io"
)

const testWharrgarblSamples = 25

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
			wout, ii = Wharrgarbl(junk[:], diff, 1024*1024*512)
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
