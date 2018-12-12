CC=cc
CFLAGS=-O3 -fvectorize -std=c99 -Wall
#CFLAGS=-g
LIBS=-lsqlite3

OBJS=\
	common.o \
	db.o \
	ed25519.o \
	map.o \
	record.o \
	selftest.o \
	sha3.o \
	wharrgarbl.o

libZTLF:	$(OBJS)
	ar rcs libZTLF.a $(OBJS)
	ranlib libZTLF.a

clean:	FORCE
	rm -rf lf $(OBJS) *.a *.o *.dSYM lf-selftest-*

FORCE:
