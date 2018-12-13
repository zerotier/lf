package lf

// #cgo LDFLAGS: -L../../internal/libZTLF -lZTLF -lsqlite3
// #include "../../internal/libZTLF/db.h"
import "C"
import "fmt"

/*
int ZTLF_DB_Open(struct ZTLF_DB *db,const char *path);
void ZTLF_DB_Close(struct ZTLF_DB *db);
void ZTLF_DB_EachByID(struct ZTLF_DB *const db,const void *id,void (*handler)(const uint64_t *,const struct ZTLF_Record *,unsigned int),const uint64_t cutoffTime);
int ZTLF_DB_PutRecord(struct ZTLF_DB *db,struct ZTLF_ExpandedRecord *const er);
bool ZTLF_DB_HasGraphPendingRecords(struct ZTLF_DB *db);
unsigned long ZTLF_DB_HashState(struct ZTLF_DB *db,uint8_t stateHash[48]);
static inline const char *ZTLF_DB_LastSqliteErrorMessage(struct ZTLF_DB *db) { return sqlite3_errmsg(db->dbc); }
*/

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
