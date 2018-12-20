package main

import (
	"os"

	"../../pkg/lf"
)

func main() {
	lf.TestDatabase("/tmp/lftest", os.Stdout)
}
