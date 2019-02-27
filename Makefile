# Makefile for

all: lf

lf: FORCE
	go build -a cmd/lf/lf.go

clean:	FORCE
	rm -rf lf lf-db-test

godeps:	FORCE
	go get -u github.com/NYTimes/gziphandler
	go get -u github.com/codahale/rfc6979
	go get -u github.com/tidwall/pretty
	go get -u golang.org/x/crypto/ed25519
	go get -u golang.org/x/crypto/sha3

FORCE:
