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
#include "record.h"
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
	sqlite3_stmt *sGetAllRecords;
	sqlite3_stmt *sGetMaxRecordDoff;
	sqlite3_stmt *sGetMaxRecordGoff;
	sqlite3_stmt *sGetRecordHistoryById;
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
	sqlite3_stmt *sAddLinkable;

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
void ZTLF_DB_EachByID(struct ZTLF_DB *const db,const void *id,void (*handler)(const uint64_t *,const struct ZTLF_Record *,unsigned int),const uint64_t cutoffTime);
int ZTLF_DB_PutRecord(struct ZTLF_DB *db,struct ZTLF_ExpandedRecord *const er);
bool ZTLF_DB_HasGraphPendingRecords(struct ZTLF_DB *db);
unsigned long ZTLF_DB_HashState(struct ZTLF_DB *db,uint8_t stateHash[48]);

static inline const char *ZTLF_DB_LastSqliteErrorMessage(struct ZTLF_DB *db) { return sqlite3_errmsg(db->dbc); }

#endif
