package lf

// #cgo CFLAGS: -O3
// #cgo LDFLAGS: -lsqlite3
// #include "./native/db.h"
// #include "./native/db.c"
import "C"
import "fmt"

// DB is an instance of the LF database that stores records and manages record weights and linkages.
type DB C.struct_ZTLF_DB

// Open opens this database, creating path and files if they do not exist.
func (db *DB) Open(path string) error {
	cerr := C.ZTLF_DB_Open((*C.struct_ZTLF_DB)(db), C.CString(path))
	if cerr != 0 {
		return fmt.Errorf("Database open failed: %d", cerr)
	}
	return nil
}

// Close closes this database (it cannot be used after this call)
func (db *DB) Close() {
	C.ZTLF_DB_Close((*C.struct_ZTLF_DB)(db))
}
