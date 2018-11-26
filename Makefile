CC=cc
CFLAGS=-O3 -fvectorize -std=c99 -Wall
LIBS=-lsqlite3

OBJS=\
	base58.o \
	common.o \
	curve25519.o \
	db.o \
	ed25519.o \
	lf.o \
	map.o \
	node.o \
	record.o \
	selftest.o \
	wharrgarbl.o

all:	lf

lf:	$(OBJS)
	$(CC) -o lf $(OBJS) -lsqlite3

clean:	FORCE
	rm -rf lf $(OBJS) *.o *.dSYM

FORCE:
