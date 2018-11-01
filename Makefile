CC=cc
CFLAGS=-O2
LIBS=-lsqlite3

OBJS=common.o db.o ed25519.o wharrgarbl.o

all:	lf

lf:	$(OBJS)

clean:	FORCE
	rm -rf *.o lf *.dSYM

FORCE:
