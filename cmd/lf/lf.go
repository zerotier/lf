package main

import (
	"os"

	"../../pkg/lf"
)

func main() {
	lf.TestCore(os.Stdout)
	os.Stdout.WriteString("\n")
	lf.TestWharrgarbl(os.Stdout)
}
