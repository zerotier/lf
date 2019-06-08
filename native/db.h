/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * --
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial closed-source software that incorporates or links
 * directly against ZeroTier software without disclosing the source code
 * of your own application.
 */

#ifndef ZT_LF_DB_H
#define ZT_LF_DB_H

#include "common.h"
#include "vector.h"
#include "mappedfile.h"
#include "suint96.h"

#if (defined(__linux__) || defined(__linux) || defined(__LINUX__)) && (defined(__amd64) || defined(__amd64__) || defined(__x86_64) || defined(__x86_64__) || defined(__AMD64) || defined(__AMD64__) || defined(_M_X64) || defined(_M_AMD64))
#include "precompiled/sqlite3.h"
#else
#include <sqlite3.h>
#endif

#define ZTLF_DB_GRAPH_NODE_LOCK_ARRAY_SIZE 197

/* NOTE: these reputations must match constants in db.go */

/* Reputation for default good records */
#define ZTLF_DB_REPUTATION_DEFAULT 63
#define ZTLF_DB_REPUTATION_DEFAULT_S "63"

/* Reputation for records that appear to be collisions with other record composite keys */
#define ZTLF_DB_REPUTATION_COLLISION 0

/* commentAssertionRecordCollidesWithClaimedID from Go */
#define ZTLF_DB_COMMENT_ASSERTION_RECORD_COLLIDES_WITH_CLAIMED_ID 1

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
	int64_t linkedRecordGoff[];          /* graph node offsets of linked records or -1 for holes (will be filled later) */
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
	unsigned int negativeComments;
	int localReputation;
	uint64_t ckey;
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
	int localReputation;
};

struct ZTLF_RecordList
{
	long count;
	struct ZTLF_RecordIndex records[1]; /* this is actually variable size, but Go doesn't support [] */
};

struct ZTLF_CertificateResults
{
	void *certificates;
	struct ZTLF_RecordIndex *crls;
	unsigned long certificatesLength;
	unsigned long crlCount;
};

#define ZTLF_DB_MAX_GRAPH_NODE_SIZE (sizeof(struct ZTLF_DB_GraphNode) + (256 * sizeof(int64_t)))

/**
 * Callback for when records are fully synchronized
 * 
 * Parameters are: database, record hash, data offset, data length, reputation, and an arbitrary argument.
 */
typedef void (*RecordSynchronizedCallback)(struct ZTLF_DB *,const void *,uint64_t,unsigned int,int,void *);

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
	sqlite3_stmt *sGetAllByIDNotOwner;
	sqlite3_stmt *sGetIDOwnerReputation;
	sqlite3_stmt *sHaveRecordsWithIDNotOwner;
	sqlite3_stmt *sDemoteCollisions;
	sqlite3_stmt *sUpdateRecordReputationByHash;
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
	sqlite3_stmt *sLogComment;
	sqlite3_stmt *sGetCommentsBySubjectAndCommentOracle;
	sqlite3_stmt *sQueryClearRecordSet;
	sqlite3_stmt *sQueryOrSelectorRange;
	sqlite3_stmt *sQueryAndSelectorRange;
	sqlite3_stmt *sQueryGetResults;
	sqlite3_stmt *sPutCert;
	sqlite3_stmt *sPutCertRevocation;
	sqlite3_stmt *sGetCertsBySubject;
	sqlite3_stmt *sGetCertRevocationsByRevokedSerial;
	sqlite3_stmt *sMarkInLimbo;
	sqlite3_stmt *sTakeFromLimbo;
	sqlite3_stmt *sHaveRecordInLimbo;

	pthread_mutex_t dbLock;
	pthread_mutex_t graphNodeLocks[ZTLF_DB_GRAPH_NODE_LOCK_ARRAY_SIZE]; /* used to lock graph nodes by locking node lock goff % NODE_LOCK_ARRAY_SIZE */

	struct ZTLF_MappedFile gf;
	pthread_rwlock_t gfLock; /* this is only locked for write when the mapped file's size might be adjusted */
	int df;
	struct ZTLF_SUInt96 wf;

	pthread_t graphThread;
	int graphThreadStarted;
	int running;
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
	const void **selKey,
	const unsigned int selCount,
	const void *links,
	const unsigned int linkCount);

struct ZTLF_QueryResults *ZTLF_DB_Query(
	struct ZTLF_DB *db,
	const int64_t tsMin,
	const int64_t tsMax,
	const void **sel,
	const unsigned int *selSize,
	const unsigned int selCount,
	const void **oracles,
	const unsigned int *oracleSize,
	const unsigned int oracleCount);

struct ZTLF_RecordList *ZTLF_DB_GetAllByOwner(struct ZTLF_DB *db,const void *owner,const unsigned int ownerLen);
struct ZTLF_RecordList *ZTLF_DB_GetAllByIDNotOwner(struct ZTLF_DB *db,const void *id,const void *owner,const unsigned int ownerLen);

/* Gets the data offset and data length of a record by its hash (returns length, sets doff and ts). */
unsigned int ZTLF_DB_GetByHash(struct ZTLF_DB *db,const void *hash,uint64_t *doff,uint64_t *ts);

/* Gets up to cnt hashes of records to which a new record should link, returning actual number of links written to lbuf. */
unsigned int ZTLF_DB_GetLinks(struct ZTLF_DB *db,void *const lbuf,unsigned int cnt);

/* This sets a record's reputation */
void ZTLF_DB_UpdateRecordReputationByHash(struct ZTLF_DB *db,const void *const hash,const int reputation);

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
int ZTLF_DB_LogComment(struct ZTLF_DB *db,const int64_t byRecordDoff,const int assertion,const int reason,const void *const subject,const int subjectLen);

int ZTLF_DB_SetConfig(struct ZTLF_DB *db,const char *key,const void *value,const unsigned int vlen);
unsigned int ZTLF_DB_GetConfig(struct ZTLF_DB *db,const char *key,void *value,const unsigned int valueMaxLen);

static inline const char *ZTLF_DB_LastSqliteErrorMessage(struct ZTLF_DB *db) { return sqlite3_errmsg(db->dbc); }

static inline int ZTLF_DB_GetRecordData(struct ZTLF_DB *db,uint64_t doff,void *data,unsigned int dlen)
{
	if (db->df >= 0) {
		if ((long)pread(db->df,data,(size_t)dlen,(off_t)doff) == (long)dlen)
			return 1;
	}
	return 0;
}

int ZTLF_DB_PutCert(
	struct ZTLF_DB *db,
	const char *serial,
	const char *subjectSerial,
	const uint64_t recordDoff,
	const void *cert,
	const unsigned int certLen);

int ZTLF_DB_PutCertRevocation(
	struct ZTLF_DB *db,
	const char *revokedSerialNumber,
	const uint64_t recordDoff,
	const unsigned int recordDlen);

struct ZTLF_CertificateResults *ZTLF_DB_GetCertInfo(struct ZTLF_DB *db,const char *subjectSerial);

static inline void ZTLF_DB_FreeCertificateResults(struct ZTLF_CertificateResults *cr)
{
	if (cr) {
		if (cr->certificates)
			free((void *)cr->certificates);
		if (cr->crls)
			free((void *)cr->crls);
		free((void *)cr);
	}
}

int ZTLF_DB_MarkInLimbo(struct ZTLF_DB *db,const void *hash,const void *owner,const unsigned int ownerSize,const uint64_t localReceiveTime,const uint64_t ts);

int ZTLF_DB_HaveRecordIncludeLimbo(struct ZTLF_DB *db,const void *hash);

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
	const uintptr_t selKey,
	const unsigned int selCount,
	const void *links,
	const unsigned int linkCount)
{
	return ZTLF_DB_PutRecord(db,rec,rsize,rtype,owner,ownerSize,hash,id,ts,score,(const void **)selKey,selCount,links,linkCount);
}
static inline struct ZTLF_QueryResults *ZTLF_DB_Query_fromGo(
	struct ZTLF_DB *db,
	const int64_t tsMin,
	const int64_t tsMax,
	const uintptr_t sel,
	const unsigned int *selSize,
	const unsigned int selCount,
	const uintptr_t oracles,
	const unsigned int *oracleSize,
	const unsigned int oracleCount)
{
	return ZTLF_DB_Query(db,tsMin,tsMax,(const void **)sel,selSize,selCount,(const void **)oracles,oracleSize,oracleCount);
}
#endif

#endif
