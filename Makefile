# Makefile for easily building LF on MacOS, Linux, BSD, etc.

all: lf

lf: native
	go build cmd/lf/lf.go

native:	FORCE
	cc -O3 -c -o native/db.o native/db.c

clean:	FORCE
	rm -rf lf lf-db-test native/*.o

FORCE:
