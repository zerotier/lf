CC=cc
CFLAGS=-O3 -fvectorize -std=c99 -Wall
LIBS=-lsqlite3

OBJS=common.o db.o ed25519.o map.o toml.o wharrgarbl.o

all:	lf

lf:	$(OBJS)

clean:	FORCE
	rm -rf *.o lf *.dSYM

FORCE:
