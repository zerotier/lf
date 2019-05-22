# Makefile for easily building LF on MacOS, Linux, BSD, etc.

all: lf

lf: FORCE
	go build cmd/lf/lf.go

clean:	FORCE
	rm -rf lf lf-db-test

FORCE:
