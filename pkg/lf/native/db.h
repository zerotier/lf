/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#ifndef ZT_LF_DB_H
#define ZT_LF_DB_H

#include "common.h"
#include "vector.h"
#include "mappedfile.h"
#include "suint96.h"

#ifdef ZTLF_SQLITE_INCLUDE
#include ZTLF_SQLITE_INCLUDE
#else
#include <sqlite3.h>
#endif

#define ZTLF_DB_GRAPH_NODE_LOCK_ARRAY_SIZE 197

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
	uint64_t weightsFileOffset;          /* offset of weight in weights "file" */
	uint8_t linkCount;                   /* size of linkedRecordGoff[] */
	volatile int64_t linkedRecordGoff[]; /* graph node offsets of linked records or -1 for holes (will be filled later) */
});

/* Big enough for the largest NIST ECC curve, can be increased if needed. */
#define ZTLF_DB_QUERY_MAX_OWNER_SIZE 72

struct ZTLF_DB;

struct ZTLF_QueryResult
{
	uint64_t ts;
	uint64_t weightL,weightH;
	uint64_t doff;
	unsigned int dlen;
	unsigned int ownerSize;
	int localReputation;
	uint8_t id[32];
	uint8_t owner[ZTLF_DB_QUERY_MAX_OWNER_SIZE];
};

struct ZTLF_QueryResults
{
	long count;
	struct ZTLF_QueryResult results[1]; /* this is actually variable size, but Go doesn't support [] */
};

struct ZTLF_RecordIndex
{
	uint64_t doff;
	uint64_t dlen;
};

struct ZTLF_RecordList
{
	long count;
	struct ZTLF_RecordIndex records[1]; /* this is actually variable size, but Go doesn't support [] */
};

#define ZTLF_DB_MAX_GRAPH_NODE_SIZE (sizeof(struct ZTLF_DB_GraphNode) + (256 * sizeof(int64_t)))

/**
 * Callback for when records are fully synchronized
 * 
 * Parameters are: database, record hash, data offset, data length, and an arbitrary argument.
 */
typedef void (*RecordSynchronizedCallback)(struct ZTLF_DB *,const void *,uint64_t,unsigned int,void *);

/**
 * An instance of the LF database (C side)
 */
struct ZTLF_DB
{
	char path[PATH_MAX];
	LogOutputCallback logger;
	RecordSynchronizedCallback recordSyncCallback;
	uintptr_t loggerArg;
	uintptr_t recordSyncArg;

	sqlite3 *dbc;
	sqlite3_stmt *sSetConfig;
	sqlite3_stmt *sGetConfig;
	sqlite3_stmt *sAddRejected;
	sqlite3_stmt *sAddRecord;
	sqlite3_stmt *sIncRecordLinkedCountByGoff;
	sqlite3_stmt *sAddSelector;
	sqlite3_stmt *sGetRecordCount;
	sqlite3_stmt *sGetDataSize;
	sqlite3_stmt *sGetAllRecords;
	sqlite3_stmt *sGetAllByOwner;
	sqlite3_stmt *sGetIDOwnerReputation;
	sqlite3_stmt *sHaveRecordsWithIDNotOwner;
	sqlite3_stmt *sDemoteCollisions;
	sqlite3_stmt *sGetLinkCandidates;
	sqlite3_stmt *sGetRecordByHash;
	sqlite3_stmt *sGetMaxRecordDoff;
	sqlite3_stmt *sGetMaxRecordGoff;
	sqlite3_stmt *sGetRecordGoffByHash;
	sqlite3_stmt *sGetRecordInfoByGoff;
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
	sqlite3_stmt *sGetPendingCount;
	sqlite3_stmt *sHaveDanglingLinks;
	sqlite3_stmt *sGetWanted;
	sqlite3_stmt *sIncWantedRetries;
	sqlite3_stmt *sGetReputableOwners;
	sqlite3_stmt *sLogComment;
	sqlite3_stmt *sQueryClearRecordSet;
	sqlite3_stmt *sQueryOrSelectorRange;
	sqlite3_stmt *sQueryAndSelectorRange;
	sqlite3_stmt *sQueryGetResults;

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

	/* The striped weights file has its own built-in lock. */
	struct ZTLF_SUInt96 wf;

	pthread_t graphThread;
	volatile bool graphThreadStarted;
	volatile bool running;
};

int ZTLF_DB_Open(
	struct ZTLF_DB *db,
	const char *path,
	char *errbuf,
	unsigned int errbufSize,
	LogOutputCallback logger,
	void *loggerArg,
	RecordSynchronizedCallback recordSync,
	void *recordSyncArg);

void ZTLF_DB_Close(struct ZTLF_DB *db);

int ZTLF_DB_PutRecord(
	struct ZTLF_DB *db,
	const void *rec,
	const unsigned int rsize,
	const int rtype,
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
	const unsigned int linkCount);

struct ZTLF_QueryResults *ZTLF_DB_Query(struct ZTLF_DB *db,const int64_t tsMin,const int64_t tsMax,const void **sel,const unsigned int *selSize,const unsigned int selCount);

struct ZTLF_RecordList *ZTLF_DB_GetAllByOwner(struct ZTLF_DB *db,const void *owner,const unsigned int ownerLen);

/* Gets the data offset and data length of a record by its hash (returns length, sets doff). */
unsigned int ZTLF_DB_GetByHash(struct ZTLF_DB *db,const void *hash,uint64_t *doff);

/* Gets up to cnt hashes of records to which a new record should link, returning actual number of links written to lbuf. */
unsigned int ZTLF_DB_GetLinks(struct ZTLF_DB *db,void *const lbuf,unsigned int cnt);

/* Fill result pointer arguments with statistics about this database. */
void ZTLF_DB_Stats(struct ZTLF_DB *db,uint64_t *recordCount,uint64_t *dataSize);

/* Compute a CRC64 of all record hashes and their weights in deterministic order (for testing and consistency checking) */
uint64_t ZTLF_DB_CRC64(struct ZTLF_DB *db);

/* -1: no records at all, 0: no pending, 1: pending records */
int ZTLF_DB_HasPending(struct ZTLF_DB *db);

/* returns non-zero if we have dangling links that haven't been retried more than N times */
int ZTLF_DB_HaveDanglingLinks(struct ZTLF_DB *db,int ignoreWantedAfterNRetries);

/* gets wanted hashes, returns count of hashes. buf must have enough space for up to maxHashes hashes. */
unsigned int ZTLF_DB_GetWanted(struct ZTLF_DB *db,void *buf,const unsigned int maxHashes,const unsigned int retryCountMin,const unsigned int retryCountMax,const int incrementRetryCount);

/* log commentary */
int ZTLF_DB_LogComment(struct ZTLF_DB *db,const int64_t byRecordDoff,const int assertion,const int reason,const void *const subject,const int subjectLen,const void *const object,const int objectLen);

int ZTLF_DB_SetConfig(struct ZTLF_DB *db,const char *key,const void *value,const unsigned int vlen);
unsigned int ZTLF_DB_GetConfig(struct ZTLF_DB *db,const char *key,void *value,const unsigned int valueMaxLen);

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

/* Golang-specific shims to get around some inconvenient aspects of cgo */

#ifdef ZTLF_GOLANG
static inline int ZTLF_DB_Open_fromGo(struct ZTLF_DB *db,const char *path,char *errbuf,unsigned int errbufSize,uintptr_t loggerArg,uintptr_t syncCallbackArg)
{
	return ZTLF_DB_Open(db,path,errbuf,errbufSize,&ztlfLogOutputCCallback,(void *)loggerArg,&ztlfSyncCCallback,(void *)syncCallbackArg);
}
static inline int ZTLF_DB_PutRecord_fromGo(
	struct ZTLF_DB *db,
	const void *rec,
	const unsigned int rsize,
	const int rtype,
	const void *owner,
	const unsigned int ownerSize,
	const void *hash,
	const void *id,
	const uint64_t ts,
	const uint32_t score,
	const uintptr_t sel,
	const unsigned int *selSize,
	const unsigned int selCount,
	const void *links,
	const unsigned int linkCount)
{
	return ZTLF_DB_PutRecord(db,rec,rsize,rtype,owner,ownerSize,hash,id,ts,score,(const void **)sel,selSize,selCount,links,linkCount);
}
static inline struct ZTLF_QueryResults *ZTLF_DB_Query_fromGo(struct ZTLF_DB *db,const int64_t tsMin,const int64_t tsMax,const uintptr_t sel,const unsigned int *selSize,const unsigned int selCount)
{
	return ZTLF_DB_Query(db,tsMin,tsMax,(const void **)sel,selSize,selCount);
}
#endif

#endif
