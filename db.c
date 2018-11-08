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
#include "record.h"

#ifndef __WINDOWS__
#include <sys/mman.h>
/* Linux doesn't have MAP_NOCACHE */
#ifndef MAP_NOCACHE
#define MAP_NOCACHE 0
#endif
#endif

#define ZTLF_NEG(e) (((e) <= 0) ? (e) : -(e))
#define ZTLF_POS(e) (((e) >= 0) ? (e) : -(e))

#define ZTLF_DB_INIT_SQL \
"PRAGMA locking_mode = EXCLUSIVE;\n" \
"PRAGMA journal_mode = MEMORY;\n" \
"PRAGMA cache_size = -262144;\n" \
"PRAGMA synchronous = 0;\n" \
"PRAGMA auto_vacuum = 0;\n" \
"PRAGMA foreign_keys = OFF;\n" \
"PRAGMA automatic_index = OFF;\n" \
\
"CREATE TABLE IF NOT EXISTS config (\"k\" TEXT PRIMARY KEY NOT NULL,\"v\" BLOB NOT NULL) WITHOUT ROWID;\n" \
\
"CREATE TABLE IF NOT EXISTS record (" \
"doff INTEGER PRIMARY KEY NOT NULL" \
"dlen INTEGER NOT NULL," \
"woff INTEGER NOT NULL," \
"ts INTEGER NOT NULL," \
"exp INTEGER NOT NULL," \
"id BLOB(32) NOT NULL," \
"owner BLOB(32) NOT NULL," \
"hash BLOB(32) NOT NULL" \
") WITHOUT ROWID;\n" \
\
"CREATE UNIQUE INDEX IF NOT EXISTS record_id_owner_ts ON record(id,owner,ts);\n" \
"CREATE UNIQUE INDEX IF NOT EXISTS record_hash ON record(hash);\n" \
\
"CREATE TABLE IF NOT EXISTS link (" \
"linking_record_doff INTEGER NOT NULL," \
"linked_record_doff INTEGER NOT NULL," \
"PRIMARY KEY(linking_record_doff,linked_record_doff)" \
") WITHOUT ROWID;\n" \
\
"CREATE TABLE IF NOT EXISTS dangling_link (" \
"hash BLOB(32) NOT NULL," \
"linking_record_doff INTEGER NOT NULL," \
"last_retry_time INTEGER NOT NULL," \
"retry_count INTEGER NOT NULL," \
"PRIMARY KEY(hash,linking_record_doff)" \
") WITHOUT ROWID;\n"

int ZTLF_DB_open(struct ZTLF_DB *db,const char *path)
{
	int e = 0;
	char tmp[8192];

	memset(db,0,sizeof(struct ZTLF_DB));
	db->wfd = -1;

	mkdir(path,0755);

	snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR "records",path);
	db->df = fopen(tmp,"w+b");
	if (!db->df)
		return ZTLF_NEG(errno);

	snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR "index",path);
	if ((e = sqlite3_open_v2(tmp,&db->dbc,SQLITE_OPEN_CREATE|SQLITE_OPEN_READWRITE|SQLITE_OPEN_NOMUTEX,NULL)) != SQLITE_OK) {
		fclose(db->df);
		return ZTLF_NEG(e);
	}

	if ((e = sqlite3_exec(db->dbc,(ZTLF_DB_INIT_SQL),NULL,NULL,NULL)) != SQLITE_OK)
		goto exit_with_error;

	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT INTO record (doff,dlen,woff,ts,exp,id,owner,hash) VALUES (?,?,?,?,?,?,?,?)",-1,&db->sAddRecord,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT COUNT(1) FROM record",-1,&db->sGetRecordCount,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT doff FROM record WHERE hash = ?",-1,&db->sGetRecordInfoByHash,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT OR IGNORE INTO link (linking_record_doff,linked_record_doff) VALUES (?,?)",-1,&db->sAddLink,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT dl.linking_record_doff,r.woff FROM dangling_link AS dl,record AS r WHERE dl.hash = ? AND r.doff = dl.linking_record_doff",-1,&db->sGetDanglingLinks,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"DELETE FROM dangling_link WHERE hash = ?",-1,&db->sDeleteDanglingLinks,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT INTO dangling_link (hash,linking_record_doff,last_retry,retry_count) VALUES (?,?,0,0)",-1,&db->sAddDanglingLink,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"WITH RECURSIVE below(x) AS (VALUES(?) UNION ALL SELECT link.linked_record_doff FROM link,below WHERE link.linking_record_doff = linked.x) SELECT record.woff FROM record,below WHERE record.doff = below.x",-1,&db->sGetRecordsBelow,NULL)) != SQLITE_OK)
		goto exit_with_error;

	snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR "weights",path);
	db->wfd = open(tmp,O_RDWR|O_CREAT,0644);
	if (db->wfd < 0) {
		e = errno;
		goto exit_with_error;
	}
	const long siz = lseek(db->wfd,0,SEEK_END);
	if (siz < 0) {
		e = errno;
		goto exit_with_error;
	}
	if (siz < (1048576 * sizeof(double))) {
		if (ftruncate(db->wfd,1048576 * sizeof(double))) {
			e = errno;
			goto exit_with_error;
		}
		db->wfcap = 1048576;
	} else {
		db->wfcap = (uint64_t)(siz / sizeof(double));
	}
	db->wfm = mmap(NULL,(size_t)db->wfcap,PROT_READ|PROT_WRITE,MAP_FILE|MAP_SHARED|MAP_NOCACHE,db->wfd,0);
	if (!db->wfm) {
		e = errno;
		goto exit_with_error;
	}

	pthread_mutex_init(&db->lock,NULL);

	return 0;

exit_with_error:
	ZTLF_DB_close(db);
	return ZTLF_NEG(e);
}

void ZTLF_DB_close(struct ZTLF_DB *db)
{
	pthread_mutex_lock(&db->lock);
	if (db->df)
		fclose(db->df);
	if (db->dbc) {
		if (db->sAddRecord) sqlite3_finalize(db->sAddRecord);
		sqlite3_close_v2(db->dbc);
	}
	if (db->wfm)
		munmap(db->wfm,(size_t)db->wfcap);
	if (db->wfd >= 0)
		close(db->wfd);
	pthread_mutex_unlock(&db->lock);
	pthread_mutex_destroy(&db->lock);
}

int ZTLF_putRecord(struct ZTLF_DB *db,struct ZTLF_Record *r,const unsigned long rsize)
{
	int e = 0,result = 0;

	uint64_t hash[4];
	struct ZTLF_RecordInfo ri;

	unsigned long recCnt = 0;
	unsigned long recCap = 131072;
	int64_t *recs = (int64_t *)malloc(sizeof(int64_t) * 131072);
	if (!recs) {
		return ZTLF_NEG(errno);
	}

	ZTLF_Shandwich256(hash,r,rsize);
	ZTLF_Record_expand(&ri,r,rsize);

	pthread_mutex_lock(&db->lock);

	/* Write raw record to append-only data file. Each record is prefixed
	 * with a size even though this size is not directly used. This way if
	 * the index DB becomes corrupt the DB can be re-initialized from the
	 * records file by importing its entire content. Records files can also
	 * be distributed to help rapidly bring up a node. */
	if (fseek(db->df,0,SEEK_END)) {
		pthread_mutex_unlock(&db->lock);
		return ZTLF_NEG(errno);
	}
	int64_t doff = (int64_t)ftello(db->df);
	if (doff < 0) {
		pthread_mutex_unlock(&db->lock);
		return ZTLF_NEG(errno);
	}
	uint16_t sizePrefix = htons((uint16_t)rsize);
	if (fwrite(&sizePrefix,2,1,db->df) != 1) {
		pthread_mutex_unlock(&db->lock);
		return ZTLF_NEG(errno);
	}
	doff += 2;
	if (fwrite(r,rsize,1,db->df) != 1) {
		pthread_mutex_unlock(&db->lock);
		return ZTLF_NEG(errno);
	}
	fflush(db->df);

	if ((e = sqlite3_exec(db->dbc,"BEGIN TRANSACTION",NULL,NULL,NULL)) != SQLITE_OK) {
		pthread_mutex_unlock(&db->lock);
		return ZTLF_POS(e);
	}

	/* The record count will be the offset in the memory mapped weights file of
	 * the double corresponding to this record's total weight. Enlarge file if needed. */
	uint64_t woff = 0;
	sqlite3_reset(db->sGetRecordCount);
	if (sqlite3_step(db->sGetRecordCount) == SQLITE_ROW)
		woff = (uint64_t)sqlite3_column_int64(db->sGetRecordCount,0);
	if (woff >= db->wfcap) {
		munmap(db->wfm,(size_t)db->wfcap);
		if (ftruncate(db->wfd,(off_t)(db->wfcap * 2 * sizeof(double)))) {
			db->wfm = mmap(NULL,(size_t)db->wfcap,PROT_READ|PROT_WRITE,MAP_FILE|MAP_SHARED|MAP_NOCACHE,db->wfd,0);
			result = ZTLF_NEG(errno);
			goto exit_putRecord;
		}
		db->wfcap *= 2;
		db->wfm = mmap(NULL,(size_t)db->wfcap,PROT_READ|PROT_WRITE,MAP_FILE|MAP_SHARED|MAP_NOCACHE,db->wfd,0);
		if (!db->wfm) {
			result = ZTLF_NEG(errno);
			goto exit_putRecord;
		}
	}

	/* Add entry to main record table. */
	sqlite3_reset(db->sAddRecord);
	sqlite3_bind_int64(db->sAddRecord,1,doff);
	sqlite3_bind_int64(db->sAddRecord,2,(sqlite3_int64)rsize);
	sqlite3_bind_int64(db->sAddRecord,3,(sqlite3_int64)woff);
	sqlite3_bind_int64(db->sAddRecord,4,(sqlite3_int64)ri.timestamp);
	sqlite3_bind_int64(db->sAddRecord,5,(sqlite3_int64)ri.expiration);
	sqlite3_bind_blob(db->sAddRecord,6,r->id,sizeof(r->id),SQLITE_STATIC);
	sqlite3_bind_blob(db->sAddRecord,7,r->owner,sizeof(r->owner),SQLITE_STATIC);
	sqlite3_bind_blob(db->sAddRecord,8,hash,sizeof(hash),SQLITE_STATIC);
	if ((e = sqlite3_step(db->sAddRecord)) != SQLITE_DONE) {
		result = ZTLF_POS(e);
		goto exit_putRecord;
	}

	/* Compute this record's total weight from its internal weight plus the weights of those
	 * that link to it, and also promote dangling links to real links. Set this record's
	 * total weight in the memory mapped weights file. */
	double totalWeight = ri.weight;
	if (!recs) {
		result = ZTLF_NEG(errno);
		goto exit_putRecord;
	}
	sqlite3_reset(db->sGetDanglingLinks);
	sqlite3_bind_blob(db->sGetDanglingLinks,1,hash,sizeof(hash),SQLITE_STATIC);
	while (sqlite3_step(db->sGetDanglingLinks) == SQLITE_ROW) {
		const int64_t recDoff = sqlite3_column_int64(db->sGetDanglingLinks,0);
		const int64_t recWoff = sqlite3_column_int64(db->sGetDanglingLinks,1);
		if ((recWoff >= 0)&&((uint64_t)recWoff < db->wfcap)) {
			if (recCnt >= recCap) {
				int64_t *const tmp = (int64_t *)realloc(recs,sizeof(int64_t) * (recCap *= 2));
				if (!tmp) {
					result = ZTLF_NEG(errno);
					goto exit_putRecord;
				}
				recs = tmp;
			}
			recs[recCnt++] = recDoff;
			totalWeight += db->wfm[recWoff];
		}
	}
	for(unsigned long i=0;i<recCnt;++i) {
		sqlite3_reset(db->sAddLink);
		sqlite3_bind_int64(db->sAddLink,1,recs[i]);
		sqlite3_bind_int64(db->sAddLink,2,doff);
		if ((e = sqlite3_step(db->sAddLink)) != SQLITE_DONE) {
			result = ZTLF_POS(e);
			goto exit_putRecord;
		}
	}
	sqlite3_reset(db->sDeleteDanglingLinks);
	sqlite3_bind_blob(db->sDeleteDanglingLinks,1,hash,sizeof(hash),SQLITE_STATIC);
	if ((e = sqlite3_step(db->sDeleteDanglingLinks)) != SQLITE_DONE) {
		result = ZTLF_POS(e);
		goto exit_putRecord;
	}
	db->wfm[woff] = totalWeight;

	/* Add link (or dangling link) records for this record's links */
	for(unsigned long i=0;i<ZTLF_RECORD_LINK_COUNT;++i) {
		if ((r->links[i][0])||(r->links[i][1])||(r->links[i][2])||(r->links[i][3])) {
			sqlite3_reset(db->sGetRecordInfoByHash);
			sqlite3_bind_blob(db->sGetRecordInfoByHash,1,r->links[i],sizeof(hash),SQLITE_STATIC);
			if (sqlite3_step(db->sGetRecordInfoByHash) == SQLITE_ROW) {
				const int64_t linkedRecordDoff = sqlite3_column_int64(db->sGetRecordInfoByHash,0);
				sqlite3_reset(db->sAddLink);
				sqlite3_bind_int64(db->sAddLink,1,doff);
				sqlite3_bind_int64(db->sAddLink,2,linkedRecordDoff);
				if ((e = sqlite3_step(db->sAddLink)) != SQLITE_DONE) {
					result = ZTLF_POS(e);
					goto exit_putRecord;
				}
			} else {
				sqlite3_reset(db->sAddDanglingLink);
				sqlite3_bind_blob(db->sAddDanglingLink,1,r->links[i],sizeof(hash),SQLITE_STATIC);
				sqlite3_bind_int64(db->sAddDanglingLink,2,doff);
				if ((e = sqlite3_step(db->sAddDanglingLink)) != SQLITE_DONE) {
					result = ZTLF_POS(e);
					goto exit_putRecord;
				}
			}
		}
	}

	/* Ensure that DB commits correctly before modifying the weights file */
	if ((e = sqlite3_exec(db->dbc,"COMMIT",NULL,NULL,NULL)) != SQLITE_OK) {
		result = ZTLF_POS(e);
		goto exit_putRecord;
	}

	/* Adjust total weights of all records below this one. */
	int64_t weightFileStartSyncRegion = woff;
	int64_t weightFileEndSyncRegion = woff + 1;
	sqlite3_reset(db->sGetRecordsBelow);
	sqlite3_bind_int64(db->sGetRecordsBelow,1,doff);
	const double wtmp = ri.weight;
	while (sqlite3_step(db->sGetRecordsBelow) == SQLITE_ROW) {
		const int64_t woffBelow = sqlite3_column_int64(db->sGetRecordsBelow,0);
		if ((woffBelow >= 0)&&((uint64_t)woffBelow < db->wfcap)) {
			if (woffBelow < weightFileStartSyncRegion)
				weightFileStartSyncRegion = woffBelow;
			if (woffBelow > weightFileEndSyncRegion)
				weightFileEndSyncRegion = woffBelow;
			db->wfm[woffBelow] += wtmp;
		}
	}

	/* Write out changes to weights file */
	if (msync(db->wfm + weightFileStartSyncRegion,sizeof(double) * (weightFileEndSyncRegion - weightFileStartSyncRegion),MS_ASYNC)) {
		fprintf(stderr,"FATAL: msync() failed: %d (weights file now likely corrupt)\n",errno);
		abort();
	}

exit_putRecord:
	if (result != 0)
		sqlite3_exec(db->dbc,"ROLLBACK",NULL,NULL,NULL);

	pthread_mutex_unlock(&db->lock);

	if (recs)
		free(recs);

	return result;
}
