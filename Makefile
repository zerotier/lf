CC=cc
CFLAGS=-O3 -fvectorize -std=c99 -Wall
#CFLAGS=-g
LIBS=-lsqlite3

OBJS=\
	api.o \
	base58.o \
	base64url.o \
	common.o \
	curve25519.o \
	db.o \
	ed25519.o \
	ieee754.o \
	lf.o \
	map.o \
	node.o \
	record.o \
	selftest.o \
	tiny-json.o \
	wharrgarbl.o

all:	lf

lf:	$(OBJS)
	$(CC) -o lf $(OBJS) -lsqlite3

clean:	FORCE
	rm -rf lf $(OBJS) *.o *.dSYM

FORCE:
