/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#ifndef ZT_LF_DB_H
#define ZT_LF_DB_H

#include "common.h"
#include "vector.h"
#include "mappedfile.h"

#ifdef ZTLF_SQLITE_INCLUDE
#include ZTLF_SQLITE_INCLUDE
#else
#include <sqlite3.h>
#endif

#define ZTLF_DB_GRAPH_NODE_LOCK_ARRAY_SIZE 197 /* prime to randomize lock distribution */

/**
 * Structure making up graph.bin
 * 
 * This packed structure tracks records' weights and links to other records by
 * graph node offset. It's stored in little endian format since most systems are
 * little endian and this therefore will usually give the best performance. The
 * graph.bin file is memory mapped for extremely fast traversal and weight
 * adjustment.
 */
ZTLF_PACKED_STRUCT(struct ZTLF_DB_GraphNode
{
	volatile uint64_t weightL;           /* least significant 64 bits of 80-bit weight */
	volatile uint16_t weightH;           /* most significant 16 bits of 80-bit weight */
	volatile uint64_t linkedCount;       /* number of nodes linking TO this one */
	uint8_t linkCount;                   /* size of linkedRecordGoff[] */
	volatile int64_t linkedRecordGoff[]; /* graph node offsets of linked records or -1 for holes (will be filled later) */
});

/* Big enough for the largest NIST ECC curve, can be increased if needed. */
#define ZTLF_DB_QUERY_MAX_OWNER_SIZE 72

/**
 * Structure that holds a result of ZTLF_Query()
 */
struct ZTLF_QueryResult
{
	uint64_t ts;
	uint64_t weightL,weightH;
	uint64_t doff;
	unsigned int dlen;
	unsigned int ownerSize;
	uint8_t owner[ZTLF_DB_QUERY_MAX_OWNER_SIZE];
};

/**
 * Structure that holds an array of query results.
 */
struct ZTLF_QueryResults
{
	long count;
	struct ZTLF_QueryResult results[1]; /* this is actually variable size, but Go doesn't support [] so compensate in C code by allocating capacity minus one */
};

#define ZTLF_DB_MAX_GRAPH_NODE_SIZE (sizeof(struct ZTLF_DB_GraphNode) + (256 * sizeof(int64_t)))

/**
 * Write checkpoints no more often than once per hour.
 */
#define ZTLF_DB_MIN_CHECKPOINT_INTERVAL 3600000

/**
 * An instance of the LF database (C side)
 */
struct ZTLF_DB
{
	char path[PATH_MAX];
	LogOutputCallback logger;
	uintptr_t loggerArg;

	sqlite3 *dbc;
	sqlite3_stmt *sSetConfig;
	sqlite3_stmt *sGetConfig;
	sqlite3_stmt *sAddRejected;
	sqlite3_stmt *sAddRecord;
	sqlite3_stmt *sAddSelector;
	sqlite3_stmt *sGetRecordCount;
	sqlite3_stmt *sGetDataSize;
	sqlite3_stmt *sGetAllRecords;
	sqlite3_stmt *sGetCompletedRecordCount;
	sqlite3_stmt *sGetCompletedRecordHashes;
	sqlite3_stmt *sGetLinkCandidates;
	sqlite3_stmt *sGetRecordByHash;
	sqlite3_stmt *sGetMaxRecordDoff;
	sqlite3_stmt *sGetMaxRecordGoff;
	sqlite3_stmt *sGetRecordGoffByHash;
	sqlite3_stmt *sGetRecordScoreByGoff;
	sqlite3_stmt *sGetDanglingLinks;
	sqlite3_stmt *sDeleteDanglingLinks;
	sqlite3_stmt *sDeleteWantedHash;
	sqlite3_stmt *sAddDanglingLink;
	sqlite3_stmt *sAddWantedHash;
	sqlite3_stmt *sAddHole;
	sqlite3_stmt *sFlagRecordWeightApplicationPending;
	sqlite3_stmt *sGetRecordsForWeightApplication;
	sqlite3_stmt *sGetHoles;
	sqlite3_stmt *sDeleteHole;
	sqlite3_stmt *sUpdatePendingHoleCount;
	sqlite3_stmt *sDeleteCompletedPending;
	sqlite3_stmt *sGetAnyPending;
	sqlite3_stmt *sQueryClearRecordSet;
	sqlite3_stmt *sQueryOrSelectorRange;
	sqlite3_stmt *sQueryAndSelectorRange;
	sqlite3_stmt *sQueryGetResults;

	volatile uint64_t lastCheckpoint;

	pthread_mutex_t dbLock;
	pthread_mutex_t graphNodeLocks[ZTLF_DB_GRAPH_NODE_LOCK_ARRAY_SIZE]; /* used to lock graph nodes by locking node lock goff % NODE_LOCK_ARRAY_SIZE */

	/* The write lock state of the RW locks for these memory mapped files is
	 * used to lock them in the case where the memory mapped file must be
	 * grown, since on most OSes this requires it to be unmapped and remapped.
	 * Otherwise only the read lock channel is used even when graph nodes are
	 * updated. To synchronize writes to graph nodes the graphNodeLocks mutex
	 * array is used. */
	struct ZTLF_MappedFile gf;
	pthread_rwlock_t gfLock;
	struct ZTLF_MappedFile df;
	pthread_rwlock_t dfLock;

	int rejectedFd;
	pthread_mutex_t rejectedLock;

	pthread_t graphThread;
	volatile bool graphThreadStarted;
	volatile bool running;
};

int ZTLF_DB_Open(struct ZTLF_DB *db,const char *path,char *errbuf,unsigned int errbufSize,LogOutputCallback logger,void *loggerArg);

void ZTLF_DB_Close(struct ZTLF_DB *db);

int ZTLF_DB_PutRejected(
	struct ZTLF_DB *db,
	const void *rec,
	const unsigned int rsize,
	const void *hash,
	const int reason);

int ZTLF_DB_PutRecord(
	struct ZTLF_DB *db,
	const void *rec,
	const unsigned int rsize,
	const void *owner,
	const unsigned int ownerSize,
	const void *hash,
	const void *id,
	const uint64_t ts,
	const uint32_t score,
	const void **sel,
	const unsigned int *selSize,
	const unsigned int selCount,
	const void *links,
	const unsigned int linkCount,
	const int reputation);

/* The parameters sel[], selAndOr[], and selSize[] describe selectors being queried against. For each
 * selector there are TWO entries in sel[] and selSize[] and one in selAndOr[]. The two entries in sel[]
 * and selSize[] describe an inclusive range. To search for equality just make that range a single value
 * repeated twice. This means that e.g. for 3 selectors the size of sel[] and selSize[] would be 6 and
 * the size of selAndOr[] would be 3. The selAndOr[] flag array determines whether this selector is
 * taken AND the or OR the previous. It is ignored for the first selector since there's nothing to AND
 * or OR it with. */
struct ZTLF_QueryResults *ZTLF_DB_Query(struct ZTLF_DB *db,const void **sel,const int *selAndOr,const unsigned int *selSize,const unsigned int selCount);

/* Gets the data offset and data length of a record by its hash (returns length, sets doff). */
unsigned int ZTLF_DB_GetByHash(struct ZTLF_DB *db,const void *hash,uint64_t *doff);

/* Gets up to cnt hashes of records to which a new record should link, returning actual number of links written to lbuf. */
unsigned int ZTLF_DB_GetLinks(struct ZTLF_DB *db,void *const lbuf,const unsigned int cnt,const unsigned int desiredLinks);

/* Fill result pointer arguments with statistics about this database. */
void ZTLF_DB_Stats(struct ZTLF_DB *db,uint64_t *recordCount,uint64_t *dataSize);

/* Compute a CRC64 of all record hashes and their weights in deterministic order (for testing and consistency checking) */
uint64_t ZTLF_DB_CRC64(struct ZTLF_DB *db);

/* Returns nonzero if there are pending records (excluding those with dangling links). */
int ZTLF_DB_HasPending(struct ZTLF_DB *db);

static inline const char *ZTLF_DB_LastSqliteErrorMessage(struct ZTLF_DB *db) { return sqlite3_errmsg(db->dbc); }

static inline int ZTLF_DB_GetRecordData(struct ZTLF_DB *db,uint64_t doff,void *data,unsigned int dlen)
{
	pthread_rwlock_rdlock(&db->dfLock);
	void *const d = ZTLF_MappedFile_TryGet(&db->df,doff,(uintptr_t)dlen);
	if (d) {
		memcpy(data,d,dlen);
		pthread_rwlock_unlock(&db->dfLock);
		return 1;
	}
	pthread_rwlock_unlock(&db->dfLock);
	return 0;
}

#endif
