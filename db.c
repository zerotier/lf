/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * --
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial closed-source software that incorporates or links
 * directly against ZeroTier software without disclosing the source code
 * of your own application.
 */

#include "db.h"
#include "vector.h"
#include "iset.h"

#define ZTLF_GRAPH_FILE_CAPACITY_INCREMENT 1048576

/*
 * record
 *   doff:                offset of record data in 'records' flat file (primary key)
 *   dlen:                length of record data
 *   goff:                offset of graph node in memory mapped graph file (in graph nodes, not bytes)
 *   ts:                  record timestamp in seconds since epoch
 *   exp:                 record expiration time in seconds since epoch
 *   id:                  record ID
 *   owner:               record owner
 *   hash:                shandwich256(record data)
 * 
 * dangling_link
 *   hash:                hash of record we don't have
 *   linking_record_doff: primary key of record that 'wants' this record
 *   last_retry_time:     time of last retry in seconds since epoch
 *   retry_count:         number of attempst that have been made to get this record
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
"hash BLOB(32) NOT NULL" \
") WITHOUT ROWID;\n" \
\
"CREATE UNIQUE INDEX IF NOT EXISTS record_goff ON record(goff);\n" \
"CREATE INDEX IF NOT EXISTS record_ts ON record(ts);\n" \
"CREATE INDEX IF NOT EXISTS record_id ON record(id);\n" \
"CREATE INDEX IF NOT EXISTS record_owner ON record(owner);\n" \
"CREATE UNIQUE INDEX IF NOT EXISTS record_hash ON record(hash);\n" \
\
"CREATE TABLE IF NOT EXISTS dangling_link (" \
"hash BLOB(32) NOT NULL," \
"linking_record_doff INTEGER NOT NULL," \
"last_retry_time INTEGER NOT NULL," \
"retry_count INTEGER NOT NULL," \
"PRIMARY KEY(hash,linking_record_doff)" \
") WITHOUT ROWID;\n" \
\
"CREATE INDEX IF NOT EXISTS dangling_link_retry_count_last_retry_time ON dangling_link(retry_count,last_retry_time);\n"

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

	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT INTO record (doff,dlen,goff,ts,exp,id,owner,hash) VALUES (?,?,?,?,?,?,?,?)",-1,&db->sAddRecord,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT MAX(ts) FROM record",-1,&db->sGetLatestRecordTimestamp,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT doff,dlen,goff,ts,exp,owner FROM record WHERE id = ? GROUP BY owner ORDER BY ts ASC",-1,&db->sGetRecordsById,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT COUNT(1) FROM record",-1,&db->sGetRecordCount,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT doff,goff FROM record WHERE hash = ?",-1,&db->sGetRecordInfoByHash,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT r.goff FROM dangling_link AS dl,record AS r WHERE dl.hash = ? AND r.doff = dl.linking_record_doff",-1,&db->sGetDanglingLinks,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"DELETE FROM dangling_link WHERE hash = ?",-1,&db->sDeleteDanglingLinks,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT OR REPLACE INTO dangling_link (hash,linking_record_doff,last_retry,retry_count) VALUES (?,?,0,0)",-1,&db->sAddDanglingLink,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT DISTINCT hash FROM dangling_link WHERE retry_count < ? ORDER BY last_retry_time ASC LIMIT ?",-1,&db->sGetDanglingLinksForRetry,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"UPDATE dangling_link SET last_retry_time = ?,retry_count = (retry_count + 1) WHERE hash = ?",-1,&db->sUpdateDanglingLinkRetryInfo,NULL)) != SQLITE_OK)
		goto exit_with_error;

	snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR "graph.bin",path);
	db->gfd = open(tmp,O_RDWR|O_CREAT,0644);
	if (db->gfd < 0)
		goto exit_with_error;
	const long siz = lseek(db->gfd,0,SEEK_END);
	if (siz < 0)
		goto exit_with_error;
	if (siz < (ZTLF_GRAPH_FILE_CAPACITY_INCREMENT * sizeof(struct ZTLF_DB_GraphNode))) {
		if (ftruncate(db->gfd,ZTLF_GRAPH_FILE_CAPACITY_INCREMENT * sizeof(struct ZTLF_DB_GraphNode)))
			goto exit_with_error;
		db->gfcap = ZTLF_GRAPH_FILE_CAPACITY_INCREMENT;
	} else {
		db->gfcap = (uint64_t)(siz / sizeof(struct ZTLF_DB_GraphNode));
	}
	db->gfm = mmap(NULL,(size_t)(db->gfcap * sizeof(struct ZTLF_DB_GraphNode)),PROT_READ|PROT_WRITE,MAP_FILE|MAP_SHARED,db->gfd,0);
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

	if (db->df >= 0)
		close(db->df);

	if (db->dbc) {
		if (db->sAddRecord) sqlite3_finalize(db->sAddRecord);
		if (db->sGetLatestRecordTimestamp) sqlite3_finalize(db->sGetLatestRecordTimestamp);
		if (db->sGetRecordsById) sqlite3_finalize(db->sGetRecordsById);
		if (db->sGetRecordCount) sqlite3_finalize(db->sGetRecordCount);
		if (db->sGetRecordInfoByHash) sqlite3_finalize(db->sGetRecordInfoByHash);
		if (db->sGetDanglingLinks) sqlite3_finalize(db->sGetDanglingLinks);
		if (db->sDeleteDanglingLinks) sqlite3_finalize(db->sDeleteDanglingLinks);
		if (db->sAddDanglingLink) sqlite3_finalize(db->sAddDanglingLink);
		if (db->sGetDanglingLinksForRetry) sqlite3_finalize(db->sGetDanglingLinksForRetry);
		sqlite3_close_v2(db->dbc);
	}

	if (db->gfm)
		munmap((void *)db->gfm,(size_t)(db->gfcap * sizeof(struct ZTLF_DB_GraphNode)));
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

long ZTLF_getRecord(struct ZTLF_DB *const db,struct ZTLF_Record *r,double *totalWeight,const void *const id)
{
	int64_t bestOwnerDoff = 0;
	int64_t bestOwnerDlen = 0;
	double bestOwnerTotalWeight = 0.0;
	uint64_t lastRecordOwner[4];
	int64_t lastRecordDoff = 0;
	int64_t lastRecordDlen = 0;
	double currTotalWeight = 0.0;
	int64_t lastRecordExpTime = 0;

	pthread_mutex_lock(&db->dbcLock);

	/* Iterate through records grouped by owner and sorted in ascending
	 * timestamp order. When we hit a change in owner or an expired record,
	 * this is considered the end of a set of records with a common
	 * owner and lineage. The 'right' record is the most recent record
	 * in the set with the highest sum of total weights for a given owner. */
	sqlite3_reset(db->sGetRecordsById);
	sqlite3_bind_blob(db->sGetRecordsById,1,id,32,SQLITE_STATIC);
	while (sqlite3_step(db->sGetRecordsById) == SQLITE_ROW) {
		const int64_t ts = sqlite3_column_int64(db->sGetRecordsById,3);
		const void *owner = sqlite3_column_blob(db->sGetRecordsById,5);
		if ((ts >= lastRecordExpTime)||(memcmp(lastRecordOwner,owner,32))) {
			if ((lastRecordDlen > ZTLF_RECORD_MIN_SIZE)&&(currTotalWeight > bestOwnerTotalWeight)) {
				bestOwnerDoff = lastRecordDoff;
				bestOwnerDlen = lastRecordDlen;
				bestOwnerTotalWeight = currTotalWeight;
			}
			currTotalWeight = 0.0;
		}
		memcpy(lastRecordOwner,owner,32);
		lastRecordDoff = sqlite3_column_int64(db->sGetRecordsById,0);
		lastRecordDlen = sqlite3_column_int64(db->sGetRecordsById,1);

		/* This is read only and the memory is volatile, so this should be fine. There is a
		 * small chance of slight inaccuracies if updates are in progress but overall it
		 * should not be a significant issue. */
		const uintptr_t goff = (uintptr_t)sqlite3_column_int64(db->sGetRecordsById,2);
		if (likely(goff < db->gfcap))
			currTotalWeight += db->gfm[goff].totalWeight;
		lastRecordExpTime = sqlite3_column_int64(db->sGetRecordsById,4);
	}
	if ((lastRecordDlen > ZTLF_RECORD_MIN_SIZE)&&(currTotalWeight > bestOwnerTotalWeight)) {
		bestOwnerDoff = lastRecordDoff;
		bestOwnerDlen = lastRecordDlen;
		bestOwnerTotalWeight = currTotalWeight;
	}

	if (bestOwnerDlen > 0) {
		if (lseek(db->df,(off_t)bestOwnerDoff,SEEK_SET) != (off_t)bestOwnerDoff) {
			pthread_mutex_unlock(&db->dbcLock);
			return ZTLF_NEG(errno);
		}
		if (read(db->df,r,(size_t)bestOwnerDlen) != (ssize_t)bestOwnerDlen) {
			pthread_mutex_unlock(&db->dbcLock);
			return ZTLF_NEG(errno);
		}
		pthread_mutex_unlock(&db->dbcLock);
		*totalWeight = bestOwnerTotalWeight;
		return (long)bestOwnerDlen;
	}

	pthread_mutex_unlock(&db->dbcLock);
	return 0;
}

int ZTLF_putRecord(struct ZTLF_DB *db,struct ZTLF_RecordInfo *const ri)
{
	uint8_t rwtmp[ZTLF_RECORD_MAX_SIZE + 8];
	int e = 0,result = 0;

	if ((!ri)||(ri->size < ZTLF_RECORD_MIN_SIZE)||(ri->size > ZTLF_RECORD_MAX_SIZE)) { /* sanity checks */
		return ZTLF_NEG(EINVAL);
	}

	struct ZTLF_Vector_i64 graphTraversalQueue;
	ZTLF_Vector_i64_init(&graphTraversalQueue,1048576);

	bool dbLocked = true;
	pthread_mutex_lock(&db->dbcLock);
	pthread_mutex_lock(&db->gfLock);

	/* Figure out where the next offset in the graph file is, which is always
	 * equal to the current size of the record table as each record gets one entry.
	 * Grow graph file if necessary. */
	int64_t goff = 0;
	sqlite3_reset(db->sGetRecordCount);
	if (sqlite3_step(db->sGetRecordCount) == SQLITE_ROW)
		goff = sqlite3_column_int64(db->sGetRecordCount,0);
	if ((uint64_t)goff >= db->gfcap) {
		munmap((void *)db->gfm,(size_t)(db->gfcap * sizeof(struct ZTLF_DB_GraphNode)));
		if (ftruncate(db->gfd,(off_t)((db->gfcap + ZTLF_GRAPH_FILE_CAPACITY_INCREMENT) * sizeof(struct ZTLF_DB_GraphNode)))) {
			db->gfm = mmap(NULL,(size_t)(db->gfcap * sizeof(struct ZTLF_DB_GraphNode)),PROT_READ|PROT_WRITE,MAP_FILE|MAP_SHARED,db->gfd,0);
			if (!db->gfm) {
				fprintf(stderr,"FATAL: unable to remap weights file after failed extend (likely disk problem or out of memory): %d\n",errno);
				abort();
			}
			result = ZTLF_NEG(errno);
			goto exit_putRecord;
		}
		db->gfcap += ZTLF_GRAPH_FILE_CAPACITY_INCREMENT;
		db->gfm = mmap(NULL,(size_t)(db->gfcap * sizeof(struct ZTLF_DB_GraphNode)),PROT_READ|PROT_WRITE,MAP_FILE|MAP_SHARED,db->gfd,0);
		if (!db->gfm) {
			result = ZTLF_NEG(errno);
			goto exit_putRecord;
		}
	}
	volatile struct ZTLF_DB_GraphNode *const graphNode = db->gfm + (uintptr_t)goff;

	/* Figure out where record will be appended to record data file. */
	int64_t doff = lseek(db->df,0,SEEK_END);
	if (doff < 0) {
		result = ZTLF_NEG(errno);
		goto exit_putRecord;
	}
	doff += 2; /* actual offset is +2 to account for size prefix before record */

	/* Write record size and record to data file. Size prefix is not used by this
	 * code but allows the record data file to be parsed and used as input for e.g.
	 * bulk loading of records. */
	rwtmp[0] = (uint8_t)((ri->size >> 8) & 0xff);
	rwtmp[1] = (uint8_t)(ri->size & 0xff);
	memcpy(rwtmp + 2,ri->r,ri->size); 
	if (write(db->df,rwtmp,(size_t)(ri->size + 2)) != (ssize_t)(ri->size + 2)) {
		result = ZTLF_NEG(errno);
		goto exit_putRecord;
	}
	fsync(db->df);

	/* Add entry to main record table. */
	sqlite3_reset(db->sAddRecord);
	sqlite3_bind_int64(db->sAddRecord,1,doff);
	sqlite3_bind_int64(db->sAddRecord,2,(sqlite3_int64)ri->size);
	sqlite3_bind_int64(db->sAddRecord,3,goff);
	sqlite3_bind_int64(db->sAddRecord,4,(sqlite3_int64)ri->timestamp);
	sqlite3_bind_int64(db->sAddRecord,5,(sqlite3_int64)ri->expiration);
	sqlite3_bind_blob(db->sAddRecord,6,ri->r->id,sizeof(ri->r->id),SQLITE_STATIC);
	sqlite3_bind_blob(db->sAddRecord,7,ri->r->owner,sizeof(ri->r->owner),SQLITE_STATIC);
	sqlite3_bind_blob(db->sAddRecord,8,ri->hash,32,SQLITE_STATIC);
	if ((e = sqlite3_step(db->sAddRecord)) != SQLITE_DONE) {
		result = ZTLF_POS(e);
		goto exit_putRecord;
	}

	/* Set links from this record in graph node or create dangling link entries. */
	for(unsigned long i=0;i<ZTLF_RECORD_LINK_COUNT;++i) {
		if ((ri->r->links[i][0])||(ri->r->links[i][1])||(ri->r->links[i][2])||(ri->r->links[i][3])) {
			sqlite3_reset(db->sGetRecordInfoByHash);
			sqlite3_bind_blob(db->sGetRecordInfoByHash,1,ri->r->links[i],32,SQLITE_STATIC);
			if (sqlite3_step(db->sGetRecordInfoByHash) == SQLITE_ROW) {
				const int64_t linkedGoff = sqlite3_column_int64(db->sGetRecordInfoByHash,1);
				graphNode->linkedRecordGoff[i] = linkedGoff;
				ZTLF_Vector_i64_append(&graphTraversalQueue,linkedGoff);
			} else {
				sqlite3_reset(db->sAddDanglingLink);
				sqlite3_bind_blob(db->sAddDanglingLink,1,ri->r->links[i],32,SQLITE_STATIC);
				sqlite3_bind_int64(db->sAddDanglingLink,2,doff);
				if ((e = sqlite3_step(db->sAddDanglingLink)) != SQLITE_DONE)
					fprintf(stderr,"WARNING: database error adding dangling link: %d\n",e);
				graphNode->linkedRecordGoff[i] = -1;
			}
		}
	}

	/* Compute this record's total weight from its internal weight plus the total weights of
	 * records linking to it. Also set this record's graph node offset in linking records'
	 * graph nodes. */
	double totalWeight = ri->weight;
	sqlite3_reset(db->sGetDanglingLinks);
	sqlite3_bind_blob(db->sGetDanglingLinks,1,ri->hash,32,SQLITE_STATIC);
	while (sqlite3_step(db->sGetDanglingLinks) == SQLITE_ROW) {
		volatile struct ZTLF_DB_GraphNode *const gn = db->gfm + (uintptr_t)sqlite3_column_int64(db->sGetDanglingLinks,0);
		totalWeight += gn->totalWeight;
		for(unsigned long j=0;j<ZTLF_RECORD_LINK_COUNT;++j) {
			if (gn->linkedRecordGoff[j] < 0) {
				gn->linkedRecordGoff[j] = goff;
				break;
			}
		}
	}

	/* Delete dangling links to this record. */
	sqlite3_reset(db->sDeleteDanglingLinks);
	sqlite3_bind_blob(db->sDeleteDanglingLinks,1,ri->hash,32,SQLITE_STATIC);
	if ((e = sqlite3_step(db->sDeleteDanglingLinks)) != SQLITE_DONE)
		fprintf(stderr,"WARNING: database error deleting dangling links for received record: %d\n",e);
	graphNode->totalWeight = totalWeight;

	/* SQLite database work is now done. */
	pthread_mutex_unlock(&db->dbcLock);
	dbLocked = false;

	/* Traverse graph of all records below this one and add this record's weight
	 * to their total weights. */
	struct ZTLF_ISet *const visited = ZTLF_ISet_new();
	const double wtmp = ri->weight;
	for(unsigned long i=0;i<graphTraversalQueue.size;) {
		const int64_t goff = graphTraversalQueue.v[i++];
		if (ZTLF_ISet_put(visited,goff)) {
			volatile struct ZTLF_DB_GraphNode *const gn = db->gfm + (uintptr_t)goff;
			gn->totalWeight += wtmp;
			for(unsigned long j=0;j<ZTLF_RECORD_LINK_COUNT;++j) {
				const int64_t tmp = gn->linkedRecordGoff[j];
				if (tmp >= 0) {
					ZTLF_Vector_i64_append(&graphTraversalQueue,tmp);
				}
			}
			if (i >= 1048576) { /* compact periodically to save memory */
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
