/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#include "db.h"
#include "vector.h"
#include "iset.h"
#include "map.h"

#define ZTLF_GRAPH_FILE_CAPACITY_INCREMENT 1048576

ZTLF_PACKED_STRUCT(struct ZTLF_DB_GraphNode
{
	double totalWeight;
	uint8_t linkCount;
	int64_t linkedRecordGoff[];
});

/*
 * record
 *   doff:                 offset of record data in 'records' flat file (primary key)
 *   dlen:                 length of record data
 *   goff:                 offset of graph node in memory mapped graph file (in graph nodes, not bytes)
 *   ts:                   record timestamp in seconds since epoch
 *   exp:                  record expiration time in seconds since epoch
 *   id:                   record ID
 *   owner:                record owner
 *   hash:                 shandwich256(record data)
 * 
 * dangling_link
 *   hash:                 hash of record we don't have
 *   linking_record_doff:  primary key of record that 'wants' this record
 *   last_retry_time:      time of last retry in seconds since epoch
 *   retry_count:          number of attempst that have been made to get this record
 * 
 * peer
 *   key_hash:             SHA384(public key)
 *   address_type:         currently either 4 or 6
 *   address:              IPv4 or IPv6 IP
 *   last_connect_time:    timestamp of most recent outgoing connect to this peer key at this IP/port (ms)
 *   first_connect_time:   timestamp of first outgoing connect to this peer key at this IP/port (ms)
 */

#define ZTLF_DB_INIT_SQL \
"PRAGMA locking_mode = EXCLUSIVE;\n" \
"PRAGMA journal_mode = MEMORY;\n" \
"PRAGMA cache_size = -524288;\n" \
"PRAGMA synchronous = 0;\n" \
"PRAGMA auto_vacuum = 0;\n" \
"PRAGMA foreign_keys = OFF;\n" \
"PRAGMA automatic_index = OFF;\n" \
\
"CREATE TABLE IF NOT EXISTS config (\"k\" TEXT PRIMARY KEY NOT NULL,\"v\" BLOB NOT NULL) WITHOUT ROWID;\n" \
\
"CREATE TABLE IF NOT EXISTS record (" \
"doff INTEGER PRIMARY KEY NOT NULL," \
"dlen INTEGER NOT NULL," \
"goff INTEGER NOT NULL," \
"ts INTEGER NOT NULL," \
"exp INTEGER NOT NULL," \
"id BLOB(32) NOT NULL," \
"owner BLOB(32) NOT NULL," \
"hash BLOB(32) NOT NULL," \
"new_owner BLOB(32)," \
"sel0 BLOB," \
"sel1 BLOB" \
") WITHOUT ROWID;\n" \
\
"CREATE UNIQUE INDEX IF NOT EXISTS record_goff ON record(goff);\n" \
"CREATE INDEX IF NOT EXISTS record_ts ON record(ts);\n" \
"CREATE INDEX IF NOT EXISTS record_id_ts ON record(id,ts);\n" \
"CREATE UNIQUE INDEX IF NOT EXISTS record_hash ON record(hash);\n" \
"CREATE INDEX IF NOT EXISTS record_sel0 ON record(sel0);\n" \
"CREATE INDEX IF NOT EXISTS record_sel1 ON record(sel1);\n" \
\
"CREATE TABLE IF NOT EXISTS dangling_link (" \
"hash BLOB(32) NOT NULL," \
"linking_record_doff INTEGER NOT NULL," \
"last_retry_time INTEGER NOT NULL," \
"retry_count INTEGER NOT NULL," \
"PRIMARY KEY(hash,linking_record_doff)" \
") WITHOUT ROWID;\n" \
\
"CREATE INDEX IF NOT EXISTS dangling_link_linking_record_doff ON dangling_link(linking_record_doff);\n" \
"CREATE INDEX IF NOT EXISTS dangling_link_retry_count_last_retry_time ON dangling_link(retry_count,last_retry_time);\n" \
\
"CREATE TABLE IF NOT EXISTS peer (" \
"key_hash BLOB(48) PRIMARY KEY NOT NULL," \
"address BLOB NOT NULL," \
"address_type INTEGER NOT NULL," \
"port INTEGER NOT NULL," \
"last_connect_time INTEGER NOT NULL," \
"first_connect_time INTEGER NOT NULL" \
") WITHOUT ROWID;\n" \
\
"CREATE INDEX IF NOT EXISTS peer_last_connect_time_first_connect_time ON peer(last_connect_time,first_connect_time);\n"

int ZTLF_DB_open(struct ZTLF_DB *db,const char *path)
{
	char tmp[PATH_MAX];
	int e = 0;

	if (strlen(path) >= (PATH_MAX - 16))
		return ZTLF_NEG(ENAMETOOLONG);
	memset(db,0,sizeof(struct ZTLF_DB));
	strncpy(db->path,path,PATH_MAX);
	db->gfd = -1;
	db->df = -1;
	pthread_mutex_init(&db->dbcLock,NULL);
	pthread_mutex_init(&db->gfLock,NULL);

	mkdir(path,0755);

	ZTLF_L_trace("opening database at %s",path);

	snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR "lf.pid",path);
	int pidf = open(tmp,O_WRONLY|O_CREAT|O_TRUNC,0644);
	if (pidf < 0)
		goto exit_with_error;
	snprintf(tmp,sizeof(tmp),"%ld",(long)getpid());
	write(pidf,tmp,strlen(tmp));
	close(pidf);

	snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR "index.db",path);
	if ((e = sqlite3_open_v2(tmp,&db->dbc,SQLITE_OPEN_CREATE|SQLITE_OPEN_READWRITE|SQLITE_OPEN_NOMUTEX,NULL)) != SQLITE_OK)
		goto exit_with_error;

	if ((e = sqlite3_exec(db->dbc,(ZTLF_DB_INIT_SQL),NULL,NULL,NULL)) != SQLITE_OK)
		goto exit_with_error;

	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT INTO record (doff,dlen,goff,ts,exp,id,owner,hash,new_owner,sel0,sel1) VALUES (?,?,?,?,?,?,?,?,?,?,?)",-1,&db->sAddRecord,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT MAX(goff) FROM record",-1,&db->sGetMaxRecordGoff,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT MAX(ts) FROM record",-1,&db->sGetLatestRecordTimestamp,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT doff,dlen,goff,ts,exp,owner FROM record WHERE id = ? AND doff NOT IN (SELECT dangling_link.linking_record_doff FROM dangling_link WHERE dangling_link.linking_record_doff = record.doff) ORDER BY ts DESC",-1,&db->sGetRecordHistoryById,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT COUNT(1) FROM record",-1,&db->sGetRecordCount,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT doff,goff FROM record WHERE hash = ?",-1,&db->sGetRecordInfoByHash,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT r.goff FROM dangling_link AS dl,record AS r WHERE dl.hash = ? AND r.doff = dl.linking_record_doff",-1,&db->sGetDanglingLinks,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"DELETE FROM dangling_link WHERE hash = ?",-1,&db->sDeleteDanglingLinks,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT OR REPLACE INTO dangling_link (hash,linking_record_doff,last_retry_time,retry_count) VALUES (?,?,0,0)",-1,&db->sAddDanglingLink,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT DISTINCT hash FROM dangling_link WHERE retry_count < ? ORDER BY last_retry_time ASC LIMIT ?",-1,&db->sGetDanglingLinksForRetry,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"UPDATE dangling_link SET last_retry_time = ?,retry_count = (retry_count + 1) WHERE hash = ?",-1,&db->sUpdateDanglingLinkRetryInfo,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT first_connect_time FROM peer WHERE key_hash = ?",-1,&db->sGetPeerFirstConnectTime,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT OR REPLACE INTO peer (key_hash,address,address_type,port,last_connect_time,first_connect_time) VALUES (?,?,?,?,?,?)",-1,&db->sAddUpdatePeer,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT OR IGNORE INTO peer (key_hash,address,address_type,port,last_connect_time,first_connect_time) VALUES (?,?,?,?,0,0)",-1,&db->sAddPotentialPeer,NULL)) != SQLITE_OK)
		goto exit_with_error;

	snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR "graph.bin",path);
	db->gfd = open(tmp,O_RDWR|O_CREAT,0644);
	if (db->gfd < 0)
		goto exit_with_error;
	const long siz = lseek(db->gfd,0,SEEK_END);
	if (siz < 0)
		goto exit_with_error;
	if (siz < ZTLF_GRAPH_FILE_CAPACITY_INCREMENT) {
		if (ftruncate(db->gfd,ZTLF_GRAPH_FILE_CAPACITY_INCREMENT))
			goto exit_with_error;
		db->gfcap = ZTLF_GRAPH_FILE_CAPACITY_INCREMENT;
	} else {
		db->gfcap = (uint64_t)siz;
	}
	db->gfm = mmap(NULL,(size_t)db->gfcap,PROT_READ|PROT_WRITE,MAP_FILE|MAP_SHARED,db->gfd,0);
	if (!db->gfm)
		goto exit_with_error;

	snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR "records.bin",path);
	db->df = open(tmp,O_RDWR|O_CREAT,0644);
	if (db->df < 0)
		goto exit_with_error;

	db->running = 1;

	return 0;

exit_with_error:
	ZTLF_DB_close(db);
	return ((e) ? ZTLF_POS(e) : ZTLF_NEG(errno));
}

void ZTLF_DB_close(struct ZTLF_DB *db)
{
	char tmp[PATH_MAX];

	pthread_mutex_lock(&db->dbcLock);
	pthread_mutex_lock(&db->gfLock);

	ZTLF_L_trace("closing database at %s",db->path);

	if (db->df >= 0)
		close(db->df);

	if (db->dbc) {
		if (db->sAddRecord)                 sqlite3_finalize(db->sAddRecord);
		if (db->sGetMaxRecordGoff)          sqlite3_finalize(db->sGetMaxRecordGoff);
		if (db->sGetLatestRecordTimestamp)  sqlite3_finalize(db->sGetLatestRecordTimestamp);
		if (db->sGetRecordHistoryById)      sqlite3_finalize(db->sGetRecordHistoryById);
		if (db->sGetRecordCount)            sqlite3_finalize(db->sGetRecordCount);
		if (db->sGetRecordInfoByHash)       sqlite3_finalize(db->sGetRecordInfoByHash);
		if (db->sGetDanglingLinks)          sqlite3_finalize(db->sGetDanglingLinks);
		if (db->sDeleteDanglingLinks)       sqlite3_finalize(db->sDeleteDanglingLinks);
		if (db->sAddDanglingLink)           sqlite3_finalize(db->sAddDanglingLink);
		if (db->sGetDanglingLinksForRetry)  sqlite3_finalize(db->sGetDanglingLinksForRetry);
		if (db->sGetPeerFirstConnectTime)   sqlite3_finalize(db->sGetPeerFirstConnectTime);
		if (db->sAddUpdatePeer)             sqlite3_finalize(db->sAddUpdatePeer);
		if (db->sAddPotentialPeer)          sqlite3_finalize(db->sAddPotentialPeer);
		sqlite3_close_v2(db->dbc);
	}

	if (db->gfm)
		munmap((void *)db->gfm,(size_t)db->gfcap);
	if (db->gfd >= 0)
		close(db->gfd);

	db->running = 0;

	snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR "lf.pid",db->path);
	unlink(tmp);

	pthread_mutex_unlock(&db->dbcLock);
	pthread_mutex_unlock(&db->gfLock);
	pthread_mutex_destroy(&db->dbcLock);
	pthread_mutex_destroy(&db->gfLock);
}

bool ZTLF_DB_logOutgoingPeerConnectSuccess(struct ZTLF_DB *const db,const void *key_hash,const unsigned int address_type,const void *address,const unsigned int addressLength,const unsigned int port)
{
	bool r = true;
	pthread_mutex_lock(&db->dbcLock);

	int64_t now = (int64_t)ZTLF_timeMs();
	int64_t first_connect_time = now;

	sqlite3_reset(db->sGetPeerFirstConnectTime);
	sqlite3_bind_blob(db->sGetPeerFirstConnectTime,1,key_hash,48,SQLITE_STATIC);
	if (sqlite3_step(db->sGetPeerFirstConnectTime) == SQLITE_ROW) {
		const int64_t fct = sqlite3_column_int64(db->sGetPeerFirstConnectTime,0);
		if (fct > 0) {
			first_connect_time = fct;
			r = false;
		}
	}

	sqlite3_reset(db->sAddUpdatePeer);
	sqlite3_bind_blob(db->sAddUpdatePeer,1,key_hash,48,SQLITE_STATIC);
	sqlite3_bind_blob(db->sAddUpdatePeer,2,address,addressLength,SQLITE_STATIC);
	sqlite3_bind_int(db->sAddUpdatePeer,3,(int)address_type);
	sqlite3_bind_int(db->sAddUpdatePeer,4,(int)port);
	sqlite3_bind_int64(db->sAddUpdatePeer,5,now);
	sqlite3_bind_int64(db->sAddUpdatePeer,6,first_connect_time);
	sqlite3_step(db->sAddUpdatePeer);

	pthread_mutex_unlock(&db->dbcLock);
	return r;
}

void ZTLF_DB_logPotentialPeer(struct ZTLF_DB *const db,const void *key_hash,const unsigned int address_type,const void *address,const unsigned int addressLength,const unsigned int port)
{
	pthread_mutex_lock(&db->dbcLock);
	sqlite3_reset(db->sAddPotentialPeer);
	sqlite3_bind_blob(db->sAddPotentialPeer,1,key_hash,48,SQLITE_STATIC);
	sqlite3_bind_blob(db->sAddPotentialPeer,2,address,addressLength,SQLITE_STATIC);
	sqlite3_bind_int(db->sAddPotentialPeer,3,(int)address_type);
	sqlite3_bind_int(db->sAddPotentialPeer,4,(int)port);
	sqlite3_step(db->sAddPotentialPeer);
	pthread_mutex_unlock(&db->dbcLock);
}

#if 0
struct _ZTLF_getRecord_owner
{
	int64_t latestDoff;
	int64_t latestDlen;
	uint64_t nextTs;
	double aggregatedTotalWeight;
	bool eof;
};

long ZTLF_DB_getRecord(struct ZTLF_DB *const db,struct ZTLF_Record *r,double *aggregatedTotalWeight,const void *const id)
{
	uint64_t owner[4];
	struct ZTLF_Map256 m;

	ZTLF_Map256_init(&m,4,free);

	pthread_mutex_lock(&db->dbcLock);

	sqlite3_reset(db->sGetRecordHistoryById);
	sqlite3_bind_blob(db->sGetRecordHistoryById,1,id,32,SQLITE_STATIC);
	while (sqlite3_step(db->sGetRecordHistoryById) == SQLITE_ROW) {
		memcpy(owner,sqlite3_column_blob(db->sGetRecordHistoryById,5),sizeof(owner));
		struct _ZTLF_getRecord_owner *o = (struct _ZTLF_getRecord_owner *)ZTLF_Map256_get(&m,owner);

		if (!o) {
			ZTLF_MALLOC_CHECK(o = (struct _ZTLF_getRecord_owner *)malloc(sizeof(struct _ZTLF_getRecord_owner)));
			o->latestDoff = sqlite3_column_int64(db->sGetRecordHistoryById,0);
			o->latestDlen = sqlite3_column_int64(db->sGetRecordHistoryById,1);
			o->nextTs = 0;
			o->aggregatedTotalWeight = 0.0;
			o->eof = false;
			ZTLF_Map256_set(&m,owner,o);
		}

		if (!o->eof) {
			if ((uint64_t)sqlite3_column_int64(db->sGetRecordHistoryById,4) < o->nextTs) {
				/* We encountered an expired record, so this ends this owner's most recent set of records for this ID. */
				o->eof = true;
			} else {
				/* Total weight of this owner's set of IDs is the sum of the total weights of each update in the set. */
				double tw;
				ZTLF_UNALIGNED_ASSIGN_8(tw,((struct ZTLF_DB_GraphNode *)(db->gfm + (uintptr_t)sqlite3_column_int64(db->sGetRecordHistoryById,2)))->totalWeight);
				o->aggregatedTotalWeight += tw;
			}

			/* "Next" timestamp is previous row since we iterate backwards through timestamp history. */
			o->nextTs = (uint64_t)sqlite3_column_int64(db->sGetRecordHistoryById,3);
		}
	}

	pthread_mutex_unlock(&db->dbcLock);

	int64_t bestDoff = -1;
	int64_t bestDlen = -1;
	double bestTw = -1.0;

	ZTLF_Map256_eachValue(&m,{
		struct _ZTLF_getRecord_owner *const o = (struct _ZTLF_getRecord_owner *)ztlfMapValue;
		if (o->aggregatedTotalWeight > bestTw) {
			bestDoff = o->latestDoff;
			bestDlen = o->latestDlen;
		}
	});

	ZTLF_Map256_destroy(&m);

	if ((bestDoff >= 0)&&(bestDlen > ZTLF_RECORD_MIN_SIZE)) {
		if (lseek(db->df,(off_t)bestDoff,SEEK_SET) == (off_t)bestDoff) {
			long rsize = (long)read(db->df,r,(size_t)bestDlen);
			if (rsize == (long)bestDlen) {
				if (aggregatedTotalWeight)
					*aggregatedTotalWeight = bestTw;
				return rsize;
			}
		}
	}

	return 0;
}
#endif

int ZTLF_DB_putRecord(struct ZTLF_DB *db,struct ZTLF_ExpandedRecord *const er)
{
	uint8_t rwtmp[ZTLF_RECORD_MAX_SIZE + 8];
	int e = 0,result = 0;

	if ((!er)||(er->size < ZTLF_RECORD_MIN_SIZE)||(er->size > ZTLF_RECORD_MAX_SIZE)) { /* sanity checks */
		return ZTLF_NEG(EINVAL);
	}

	struct ZTLF_Vector_i64 graphTraversalQueue;
	ZTLF_Vector_i64_init(&graphTraversalQueue,1048576);

	bool dbLocked = true;
	pthread_mutex_lock(&db->dbcLock);
	pthread_mutex_lock(&db->gfLock);

	ZTLF_L_trace("adding record %s (%s)",ZTLF_hexstr(er->r->id,32,0),ZTLF_hexstr(er->hash,32,1));

	/* Figure out where the next record's graph node offset should be: right after previous highest. */
	int64_t goff = 0;
	sqlite3_reset(db->sGetMaxRecordGoff);
	if (sqlite3_step(db->sGetMaxRecordGoff) == SQLITE_ROW) {
		const int64_t highestExistingGoff = sqlite3_column_int64(db->sGetMaxRecordGoff,0);
		goff = highestExistingGoff +
		       sizeof(struct ZTLF_DB_GraphNode) +
					 (((unsigned long)((struct ZTLF_DB_GraphNode *)(db->gfm + (uintptr_t)highestExistingGoff))->linkCount) * sizeof(int64_t));
		if ((goff % sizeof(double)) != 0) /* align graph nodes to multiples of sizeof(double) */
			goff += sizeof(double) - (uintptr_t)(goff % sizeof(double));
	}

	ZTLF_L_trace("graph node offset: %lld",(long long)goff);

	/* Grow graph file if needed. */
	if ((uint64_t)(goff + ZTLF_RECORD_MAX_SIZE) >= db->gfcap) {
		ZTLF_L_trace("growing graph file: %llu -> %llu",(unsigned long long)db->gfcap,(unsigned long long)(db->gfcap + ZTLF_GRAPH_FILE_CAPACITY_INCREMENT));
		munmap((void *)db->gfm,(size_t)db->gfcap);
		if (ftruncate(db->gfd,(off_t)(db->gfcap + ZTLF_GRAPH_FILE_CAPACITY_INCREMENT))) {
			db->gfm = mmap(NULL,(size_t)db->gfcap,PROT_READ|PROT_WRITE,MAP_FILE|MAP_SHARED,db->gfd,0);
			if (!db->gfm) {
				fprintf(stderr,"FATAL: unable to remap weights file after failed extend (likely disk problem or out of memory): %d\n",errno);
				abort();
			}
			result = ZTLF_NEG(errno);
			goto exit_putRecord;
		}
		db->gfcap += ZTLF_GRAPH_FILE_CAPACITY_INCREMENT;
		db->gfm = mmap(NULL,(size_t)db->gfcap,PROT_READ|PROT_WRITE,MAP_FILE|MAP_SHARED,db->gfd,0);
		if (!db->gfm) {
			result = ZTLF_NEG(errno);
			goto exit_putRecord;
		}
	}

	/* Get pointer to current record's graph node. */
	volatile struct ZTLF_DB_GraphNode *const graphNode = (volatile struct ZTLF_DB_GraphNode *)(db->gfm + (uintptr_t)goff);

	/* Figure out where record will be appended to record data file. */
	int64_t doff = lseek(db->df,0,SEEK_END);
	if (doff < 0) {
		result = ZTLF_NEG(errno);
		goto exit_putRecord;
	}
	doff += 2; /* actual offset is +2 to account for size prefix before record */

	ZTLF_L_trace("data file offset: %lld",(long long)doff);

	/* Write record size and record to data file. Size prefix is not used by this
	 * code but allows the record data file to be parsed and used as input for e.g.
	 * bulk loading of records. */
	rwtmp[0] = (uint8_t)((er->size >> 8) & 0xff);
	rwtmp[1] = (uint8_t)(er->size & 0xff);
	memcpy(rwtmp + 2,er->r,er->size); 
	if (write(db->df,rwtmp,(size_t)(er->size + 2)) != (ssize_t)(er->size + 2)) {
		result = ZTLF_NEG(errno);
		goto exit_putRecord;
	}
	fsync(db->df);

	ZTLF_L_trace("record appended to data file (%u bytes)",er->size);

	/* Add entry to main record table. */
	sqlite3_reset(db->sAddRecord);
	sqlite3_bind_int64(db->sAddRecord,1,doff);
	sqlite3_bind_int64(db->sAddRecord,2,(sqlite3_int64)er->size);
	sqlite3_bind_int64(db->sAddRecord,3,goff);
	sqlite3_bind_int64(db->sAddRecord,4,(sqlite3_int64)er->timestamp);
	sqlite3_bind_int64(db->sAddRecord,5,(sqlite3_int64)er->expiration);
	sqlite3_bind_blob(db->sAddRecord,6,er->r->id,sizeof(er->r->id),SQLITE_STATIC);
	sqlite3_bind_blob(db->sAddRecord,7,er->r->owner,sizeof(er->r->owner),SQLITE_STATIC);
	sqlite3_bind_blob(db->sAddRecord,8,er->hash,32,SQLITE_STATIC);
	bool haveNewOwner = false;
	for(int i=0;i<2;++i) {
		if (er->metaDataType[i] == ZTLF_RECORD_METADATA_CHANGE_OWNER) {
			sqlite3_bind_blob(db->sAddRecord,9,er->metaData[i],er->metaDataSize[i],SQLITE_STATIC);
			haveNewOwner = true;
			break;
		}
	}
	if (!haveNewOwner)
		sqlite3_bind_null(db->sAddRecord,9);
	int selectorColIdx = 10;
	for(int i=0;i<2;++i) {
		if (er->metaDataType[i] == ZTLF_RECORD_METADATA_SELECTOR)
			sqlite3_bind_blob(db->sAddRecord,selectorColIdx++,er->metaData[i],er->metaDataSize[i],SQLITE_STATIC);
	}
	while (selectorColIdx < 12)
		sqlite3_bind_null(db->sAddRecord,selectorColIdx++);
	if ((e = sqlite3_step(db->sAddRecord)) != SQLITE_DONE) {
		result = ZTLF_POS(e);
		goto exit_putRecord;
	}

	/* Set links from this record in graph node or create dangling link entries. */
	ZTLF_L_trace("checking %u links from this record",er->linkCount);
	graphNode->linkCount = (uint8_t)er->linkCount;
	const int64_t neg1 = -1;
	for(unsigned int i=0,j=er->linkCount;i<j;++i) {
		const uint8_t *l = er->links + (i * 32);
		sqlite3_reset(db->sGetRecordInfoByHash);
		sqlite3_bind_blob(db->sGetRecordInfoByHash,1,l,32,SQLITE_STATIC);
		if (sqlite3_step(db->sGetRecordInfoByHash) == SQLITE_ROW) {
			const int64_t linkedGoff = sqlite3_column_int64(db->sGetRecordInfoByHash,1);
			ZTLF_L_trace("linked record %s exists, offset in graph file: %lld",ZTLF_hextr(l,32,0),linkedGoff);
			ZTLF_UNALIGNED_ASSIGN_8(graphNode->linkedRecordGoff[i],linkedGoff);
			ZTLF_Vector_i64_append(&graphTraversalQueue,linkedGoff);
		} else {
			ZTLF_L_trace("linked record %s does not exist, adding to dangling links",ZTLF_hexstr(l,32,0));
			sqlite3_reset(db->sAddDanglingLink);
			sqlite3_bind_blob(db->sAddDanglingLink,1,l,32,SQLITE_STATIC);
			sqlite3_bind_int64(db->sAddDanglingLink,2,doff);
			if ((e = sqlite3_step(db->sAddDanglingLink)) != SQLITE_DONE) {
				ZTLF_L_warning("database error adding dangling link: %d (%s)",e,sqlite3_errmsg(db->dbc));
			}
			ZTLF_UNALIGNED_ASSIGN_8(graphNode->linkedRecordGoff[i],neg1);
		}
	}

	/* Compute this record's total weight from its internal weight plus the total weights of
	 * records linking to it. Also set this record's graph node offset in linking records'
	 * graph nodes. */
	double totalWeight = er->weight;
	sqlite3_reset(db->sGetDanglingLinks);
	sqlite3_bind_blob(db->sGetDanglingLinks,1,er->hash,32,SQLITE_STATIC);
	ZTLF_L_trace("getting any dangling links to this record and adding linking records' weights to this record's total weight (initial weight: %f)",totalWeight);
	while (sqlite3_step(db->sGetDanglingLinks) == SQLITE_ROW) {
		const int64_t linkingGoff = sqlite3_column_int64(db->sGetDanglingLinks,0);
		volatile struct ZTLF_DB_GraphNode *const linkingRecordGraphNode = (volatile struct ZTLF_DB_GraphNode *)(db->gfm + (uintptr_t)linkingGoff);
		double tw;
		ZTLF_UNALIGNED_ASSIGN_8(tw,linkingRecordGraphNode->totalWeight);
		totalWeight += tw;
		ZTLF_L_trace("added weight %f from graph node @%lld (new weight: %f)",tw,(long long)linkingGoff,totalWeight);
		for(unsigned int j=0,k=linkingRecordGraphNode->linkCount;j<k;++j) {
			int64_t lrgoff;
			ZTLF_UNALIGNED_ASSIGN_8(lrgoff,linkingRecordGraphNode->linkedRecordGoff[j]);
			if (lrgoff < 0) {
				ZTLF_L_trace("updated graph node @%lld with pointer to this record's graph node",(long long)linkingGoff);
				ZTLF_UNALIGNED_ASSIGN_8(linkingRecordGraphNode->linkedRecordGoff[j],goff);
				break;
			}
		}
	}

	/* Delete dangling links to this record. */
	ZTLF_L_trace("deleting all dangling links to this record");
	sqlite3_reset(db->sDeleteDanglingLinks);
	sqlite3_bind_blob(db->sDeleteDanglingLinks,1,er->hash,32,SQLITE_STATIC);
	if ((e = sqlite3_step(db->sDeleteDanglingLinks)) != SQLITE_DONE) {
		ZTLF_L_warning("database error deleting dangling links: %d (%s)",e,sqlite3_errmsg(db->dbc));
	}

	/* Set this record's initial total weight in its graph node. */
	ZTLF_UNALIGNED_ASSIGN_8(graphNode->totalWeight,totalWeight);

	/* SQLite database work is now done. */
	pthread_mutex_unlock(&db->dbcLock);
	dbLocked = false;

	/* Traverse graph of all records below this one and add this record's weight
	 * to their total weights. */
	ZTLF_L_trace("updating weights of all records below this record in graph");
	struct ZTLF_ISet *const visited = ZTLF_ISet_new();
	const double wtmp = er->weight;
	for(unsigned long i=0;i<graphTraversalQueue.size;) {
		const int64_t goff = graphTraversalQueue.v[i++];
		if (ZTLF_ISet_put(visited,goff)) {
			ZTLF_L_trace("adding %f to weight @%lld",wtmp,(long long)goff);

			volatile struct ZTLF_DB_GraphNode *const gn = (volatile struct ZTLF_DB_GraphNode *)(db->gfm + (uintptr_t)goff);
			double tw;
			ZTLF_UNALIGNED_ASSIGN_8(tw,gn->totalWeight);
			tw += wtmp;
			ZTLF_UNALIGNED_ASSIGN_8(gn->totalWeight,tw);
			for(unsigned int j=0,k=gn->linkCount;j<k;++j) {
				int64_t tmp;
				ZTLF_UNALIGNED_ASSIGN_8(tmp,gn->linkedRecordGoff[j]);
				if (tmp >= 0) {
					ZTLF_Vector_i64_append(&graphTraversalQueue,tmp);
				}
			}

			if (i >= 1048576) { /* compact queue periodically to save memory */
				memmove(graphTraversalQueue.v,graphTraversalQueue.v + i,sizeof(int64_t) * (graphTraversalQueue.size -= i));
				i = 0;
			}
		}
	}
	ZTLF_ISet_free(visited);

exit_putRecord:
	pthread_mutex_unlock(&db->gfLock);
	if (dbLocked)
		pthread_mutex_unlock(&db->dbcLock);

	ZTLF_Vector_i64_free(&graphTraversalQueue);

	return result;
}
