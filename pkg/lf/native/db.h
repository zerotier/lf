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

struct ZTLF_DB
{
	char path[PATH_MAX];

	sqlite3 *dbc;
	sqlite3_stmt *sAddRecord;
	sqlite3_stmt *sGetRecordCount;
	sqlite3_stmt *sGetDataSize;
	sqlite3_stmt *sGetAllRecords;
	sqlite3_stmt *sGetMaxRecordDoff;
	sqlite3_stmt *sGetMaxRecordGoff;
	sqlite3_stmt *sGetRecordGoffByHash;
	sqlite3_stmt *sGetRecordScoreByGoff;
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

	sqlite3_stmt *sGetMatching[16];

	pthread_mutex_t dbLock;
	pthread_mutex_t graphNodeLocks[ZTLF_DB_GRAPH_NODE_LOCK_ARRAY_SIZE]; /* used to lock graph nodes by locking node lock goff % NODE_LOCK_ARRAY_SIZE */

	struct ZTLF_MappedFile gf;
	pthread_rwlock_t gfLock;
	struct ZTLF_MappedFile df;
	pthread_rwlock_t dfLock;

	pthread_t graphThread;
	volatile bool graphThreadStarted;
	volatile bool running;
};

int ZTLF_DB_Open(struct ZTLF_DB *db,const char *path);

void ZTLF_DB_Close(struct ZTLF_DB *db);

int ZTLF_DB_PutRecord(
	struct ZTLF_DB *db,
	const void *rec,
	const unsigned int rsize,
	const void *id,
	const void *owner,
	const void *hash,
	const uint64_t ts,
	const uint64_t ttl,
	const uint32_t score,
	const void *changeOwner,
	const void *sel0,
	const void *sel1,
	const void *links,
	const unsigned int linkCount);

/* Function arguments: doff, dlen, ts, exp, id, owner, new_owner, least significant 64 bits of weight, most significant 64 bits of weight, arg */
void ZTLF_DB_GetMatching(struct ZTLF_DB *db,const void *id,const void *owner,const void *sel0,const void *sel1,int (*f)(int64_t,int64_t,uint64_t,uint64_t,void *,void *,void *,uint64_t,uint64_t,unsigned long),unsigned long arg);

bool ZTLF_DB_HasGraphPendingRecords(struct ZTLF_DB *db);

void ZTLF_DB_Stats(struct ZTLF_DB *db,uint64_t *recordCount,uint64_t *dataSize);

// Compute a CRC64 of all record hashes and their weights (for self test and consistency checking)
uint64_t ZTLF_DB_CRC64(struct ZTLF_DB *db);

static inline const char *ZTLF_DB_LastSqliteErrorMessage(struct ZTLF_DB *db) { return sqlite3_errmsg(db->dbc); }

static inline int ZTLF_DB_GetRecordData(struct ZTLF_DB *db,unsigned long long doff,void *data,unsigned int dlen)
{
	pthread_rwlock_rdlock(&db->dfLock);
	void *const d = ZTLF_MappedFile_TryGet(&db->df,doff,(uintptr_t)dlen);
	pthread_rwlock_unlock(&db->dfLock);
	if (d) {
		memcpy(data,d,dlen);
		return 1;
	}
	return 0;
}

#endif
