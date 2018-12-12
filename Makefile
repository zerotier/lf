CC=cc
CFLAGS=-O3 -fvectorize -std=c99 -Wall
#CFLAGS=-g
LIBS=-lsqlite3

OBJS=\
	common.o \
	db.o \
	ed25519.o \
	lf.o \
	map.o \
	node.o \
	record.o \
	selftest.o \
	sha3.o \
	wharrgarbl.o

all:	lf

lf:	$(OBJS)
	$(CC) -o lf $(OBJS) -lsqlite3

clean:	FORCE
	rm -rf lf $(OBJS) *.o *.dSYM lf-selftest-*

FORCE:
