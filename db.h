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

#ifdef ZTLF_SQLITE_INCLUDE
#include ZTLF_SQLITE_INCLUDE
#else
#include <sqlite3.h>
#endif

struct ZTLF_DB
{
	char path[PATH_MAX];

	sqlite3 *dbc;
	sqlite3_stmt *sAddRecord;
	sqlite3_stmt *sGetMaxRecordGoff;
	sqlite3_stmt *sGetRecordHistoryById;
	sqlite3_stmt *sGetRecordGoffByHash;
	sqlite3_stmt *sGetRecordWeightByGoff;
	sqlite3_stmt *sGetDanglingLinks;
	sqlite3_stmt *sDeleteDanglingLinks;
	sqlite3_stmt *sDeleteWantedHash;
	sqlite3_stmt *sAddDanglingLink;
	sqlite3_stmt *sAddWantedHash;
	sqlite3_stmt *sAddHole;
	sqlite3_stmt *sFlagRecordWeightApplicationPending;
	sqlite3_stmt *sGetPeerFirstConnectTime;
	sqlite3_stmt *sAddUpdatePeer;
	sqlite3_stmt *sAddPotentialPeer;
	sqlite3_stmt *sGetRecordsForWeightApplication;
	sqlite3_stmt *sGetHoles;
	sqlite3_stmt *sDeleteHole;
	sqlite3_stmt *sUpdatePendingHoleCount;
	sqlite3_stmt *sDeleteCompletedPending;

	pthread_mutex_t dbLock;

	uint64_t gfcap;
	uint8_t *gfm;
	int gfd;
	pthread_rwlock_t gfLock;

	int df;

	pthread_t graphThread;
	volatile bool graphThreadStarted;
	volatile bool running;
};

int ZTLF_DB_open(struct ZTLF_DB *db,const char *path);
void ZTLF_DB_close(struct ZTLF_DB *db);
bool ZTLF_DB_logOutgoingPeerConnectSuccess(struct ZTLF_DB *const db,const void *keyHash,const unsigned int addressType,const void *address,const unsigned int addressLength,const unsigned int port);
void ZTLF_DB_logPotentialPeer(struct ZTLF_DB *const db,const void *keyHash,const unsigned int addressType,const void *address,const unsigned int addressLength,const unsigned int port);
int ZTLF_DB_putRecord(struct ZTLF_DB *db,struct ZTLF_ExpandedRecord *const er);

static inline const char *ZTLF_DB_lastSqliteErrorMessage(struct ZTLF_DB *db) { return sqlite3_errmsg(db->dbc); }

#endif
