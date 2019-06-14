# Makefile for easily building LF on MacOS, Linux, BSD, etc.

UNAME_S := $(shell uname -s | tr '[:upper:]' '[:lower:]')

CC := cc
CFLAGS := -O3

SQLITE3_FLAGS := \
	-Inative/sqlite3 \
	-DVERSION=\"3.28.0\" \
	-DSTDC_HEADERS=1 \
	-DHAVE_SYS_TYPES_H=1 \
	-DHAVE_SYS_STAT_H=1 \
	-DHAVE_STDLIB_H=1 \
	-DHAVE_STRING_H=1 \
	-DHAVE_MEMORY_H=1 \
	-DHAVE_STRINGS_H=1 \
	-DHAVE_INTTYPES_H=1 \
	-DHAVE_STDINT_H=1 \
	-DHAVE_UNISTD_H=1 \
	-DHAVE_USLEEP=1 \
	-DHAVE_LOCALTIME_R=1 \
	-DHAVE_GMTIME_R=1 \
	-DHAVE_DECL_STRERROR_R=1 \
	-DHAVE_STRERROR_R=1 \
	-DSQLITE_OMIT_LOAD_EXTENSION=1 \
	-DSQLITE_THREADSAFE=0

all: lf

lf:	native
	go build cmd/lf/lf.go

native:	FORCE
	$(CC) $(CFLAGS) -c -o native/db_$(UNAME_S).o native/db.c
	$(CC) $(CFLAGS) $(SQLITE3_FLAGS) -c -o native/sqlite3_$(UNAME_S).o native/sqlite3/sqlite3.c

clean:	FORCE
	rm -rf lf lf-db-test native/*.o native/*.a

FORCE:
