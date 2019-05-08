# Makefile for easily building LF on MacOS, Linux, BSD, etc.

GOPKGS=golang.org/x/crypto/ed25519 golang.org/x/crypto/sha3 github.com/tidwall/pretty gopkg.in/kothar/brotli-go.v0/enc gopkg.in/kothar/brotli-go.v0/dec

all: lf

lf: FORCE
	go get $(GOPKGS)
	go build -o lf -a cmd/lf/*.go

clean:	FORCE
	rm -rf lf lf-db-test

godeps:	FORCE
	go get -u $(GOPKGS)

FORCE:
