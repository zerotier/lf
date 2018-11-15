CC=cc
CFLAGS=-O3 -fvectorize -std=c99 -Wall
LIBS=-lsqlite3

OBJS=\
	common.o \
	db.o \
	ed25519.o \
	lf.o \
	map.o \
	record.o \
	selftest.o \
	thirdparty/sandbird/sandbird.o \
	thirdparty/tiny-json/tiny-json.o \
	wharrgarbl.o

all:	lf

lf:	$(OBJS)
	$(CC) -o lf $(OBJS) -lsqlite3

clean:	FORCE
	rm -rf lf $(OBJS) *.o *.dSYM

FORCE:
