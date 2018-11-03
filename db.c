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
#include "map.h"
#include "record.h"

#define ZTLF_NEG(e) (((e) <= 0) ? (e) : -(e))

#define ZTLF_DB_INIT_SQL \
"PRAGMA locking_mode = EXCLUSIVE;\n" \
"PRAGMA journal_mode = MEMORY;\n" \
"PRAGMA cache_size = -2097152;\n" \
"PRAGMA synchronous = 1;\n" \
"PRAGMA auto_vacuum = 0;\n" \
"PRAGMA foreign_keys = OFF;\n" \
"PRAGMA automatic_index = OFF;\n" \
"CREATE TABLE IF NOT EXISTS config (\"k\" TEXT PRIMARY KEY NOT NULL,\"v\" BLOB NOT NULL);\n" \
"CREATE TABLE IF NOT EXISTS record (\n" \
" rowid INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,\n" \
" weight REAL NOT NULL,\n" \
" internalWeight REAL NOT NULL,\n" \
" timestamp INTEGER NOT NULL,\n" \
" idOwnerHash BLOB(24) NOT NULL,\n" \
" id BLOB(32) NOT NULL,\n" \
" data BLOB NOT NULL\n" \
");\n" \
"CREATE INDEX IF NOT EXISTS record_idOwnerHash ON record(idOwnerHash);\n" \
"CREATE INDEX IF NOT EXISTS record_id ON record(id);\n" \
"CREATE TABLE IF NOT EXISTS link (\n" \
" toIdOwnerHash BLOB(24) NOT NULL,\n" \
" fromRecordRowid INTEGER NOT NULL,\n" \
" PRIMARY KEY(toIdOwnerHash,fromRecordRowid)\n" \
") WITHOUT ROWID;\n" \
"CREATE INDEX IF NOT EXISTS link_fromRecordRowid ON link(fromRecordRowid);\n" \
"CREATE TABLE IF NOT EXISTS wanted (\n" \
" idOwnerHash BLOB(24) NOT NULL,\n" \
" fromRecordRowid INTEGER NOT NULL,\n" \
" timestamp INTEGER NOT NULL,\n" \
" retries INTEGER NOT NULL DEFAULT(0),\n" \
" PRIMARY KEY(idOwnerHash,fromRecordRowid)\n" \
") WITHOUT ROWID;\n"

int ZTLF_DB_open(struct ZTLF_DB *db,const char *path)
{
	int e = 0;

	memset(db,0,sizeof(struct ZTLF_DB));

	if ((e = sqlite3_open_v2(path,&db->dbc,SQLITE_OPEN_CREATE|SQLITE_OPEN_READWRITE|SQLITE_OPEN_NOMUTEX,NULL)) != SQLITE_OK)
		return ZTLF_NEG(e);

	if ((e = sqlite3_exec(db->dbc,(ZTLF_DB_INIT_SQL),NULL,NULL,NULL)) != SQLITE_OK)
		goto exit_with_error;

	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT INTO record (weight,internalWeight,timestamp,idOwnerHash,id,data) VALUES (?,?,?,?,?,?)",-1,&db->sAddRecord,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"UPDATE record SET weight = ?,internalWeight = ?,timestamp = ?,data = ? WHERE rowid = ?",-1,&db->sUpdateRecord,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT data FROM record WHERE id = ? ORDER BY weight DESC",-1,&db->sGetRecord,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT rowid,internalWeight,data FROM record WHERE idOwnerHash = ?",-1,&db->sGetRecord2,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT rowid,timestamp FROM record WHERE idOwnerHash = ?",-1,&db->sGetRecordInfo,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"UPDATE record SET weight = (weight + ?) WHERE rowid = ?",-1,&db->sChangeRecordWeight1,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"UPDATE record SET weight = (weight + ?) WHERE rowid IN (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",-1,&db->sChangeRecordWeight16,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT OR IGNORE INTO link (toIdOwnerHash,fromRecordRowid) VALUES (?,?)",-1,&db->sAddLink,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"DELETE FROM link WHERE toIdOwnerHash = ? AND fromRecordRowid = ?",-1,&db->sDeleteLinkedFrom,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT record.rowid FROM link,record WHERE link.fromRecordRowid = ? AND record.idOwnerHash = link.toIdOwnerHash",-1,&db->sGetLinksFrom,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT record.internalWeight,record.idOwnerHash FROM link,record WHERE link.toIdOwnerHash = ? AND record.rowid = link.fromRecordRowid",-1,&db->sGetLinksTo,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT OR IGNORE INTO wanted (idOwnerHash,fromRecordRowid,timestamp,retries) VALUES (?,?,?,0)",-1,&db->sAddWanted,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"DELETE FROM wanted WHERE idOwnerHash = ? AND timestamp <= ?",-1,&db->sDeleteWanted,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"DELETE FROM wanted WHERE idOwnerHash = ? AND fromRecordRowid = ?",-1,&db->sDeleteWantedFrom,NULL)) != SQLITE_OK)
		goto exit_with_error;

	pthread_mutex_init(&db->lock,NULL);

	return 0;

exit_with_error:
	ZTLF_DB_close(db);
	return ZTLF_NEG(e);
}

void ZTLF_DB_close(struct ZTLF_DB *db)
{
	if (db->dbc) {
		pthread_mutex_lock(&db->lock);
		if (db->sAddRecord) sqlite3_finalize(db->sAddRecord);
		if (db->sUpdateRecord) sqlite3_finalize(db->sUpdateRecord);
		if (db->sGetRecord) sqlite3_finalize(db->sGetRecord);
		if (db->sGetRecord2) sqlite3_finalize(db->sGetRecord2);
		if (db->sGetRecordInfo) sqlite3_finalize(db->sGetRecordInfo);
		if (db->sChangeRecordWeight1) sqlite3_finalize(db->sChangeRecordWeight1);
		if (db->sChangeRecordWeight16) sqlite3_finalize(db->sChangeRecordWeight16);
		if (db->sAddLink) sqlite3_finalize(db->sAddLink);
		if (db->sDeleteLinkedFrom) sqlite3_finalize(db->sDeleteLinkedFrom);
		if (db->sGetLinksFrom) sqlite3_finalize(db->sGetLinksFrom);
		if (db->sGetLinksTo) sqlite3_finalize(db->sGetLinksTo);
		if (db->sAddWanted) sqlite3_finalize(db->sAddWanted);
		if (db->sDeleteWanted) sqlite3_finalize(db->sDeleteWanted);
		if (db->sDeleteWantedFrom) sqlite3_finalize(db->sDeleteWantedFrom);
		sqlite3_close_v2(db->dbc);
		pthread_mutex_unlock(&db->lock);
		pthread_mutex_destroy(&db->lock);
		memset(db,0,sizeof(struct ZTLF_DB));
	}
}

int ZTLF_putRecord(struct ZTLF_DB *db,struct ZTLF_Record *r,const unsigned long rsize)
{
	unsigned long belowQueueSize = 0;
	unsigned long belowQueueCapacity = 0;
	unsigned long oldBelowQueueSize = 0;
	unsigned long oldBelowQueueCapacity = 0;
	int64_t *belowQueue = (int64_t *)0;
	int64_t *oldBelowQueue = (int64_t *)0;

	int e = 0,result = 0;

	uint64_t idOwnerHash[3];
	const double internalWeight = ZTLF_Record_getInternalWeight(r,rsize);
	ZTLF_Record_idOwnerHash(r,idOwnerHash);

	pthread_mutex_lock(&db->lock);

	int64_t rowid = -1;
	struct ZTLF_Record *old = NULL;
	double oldInternalWeight = 0.0;
	unsigned long osize = 0;
	sqlite3_reset(db->sGetRecord2);
	sqlite3_bind_blob(db->sGetRecord2,1,idOwnerHash,sizeof(idOwnerHash),SQLITE_STATIC);
	while (sqlite3_step(db->sGetRecord2) == SQLITE_ROW) {
		int s = sqlite3_column_bytes(db->sGetRecord2,2);
		if (s >= ZTLF_RECORD_MIN_SIZE) {
			old = (struct ZTLF_Record *)sqlite3_column_blob(db->sGetRecord2,2);
			if (memcmp(old->id,r->id,sizeof(r->id))) { /* sanity check */
				old = NULL;
			} else {
				rowid = sqlite3_column_int64(db->sGetRecord2,0);
				oldInternalWeight = sqlite3_column_double(db->sGetRecord2,1);
				osize = (unsigned long)s;
			}
		}
	}

	if ((e = sqlite3_exec(db->dbc,"BEGIN TRANSACTION",NULL,NULL,NULL)) != SQLITE_OK) {
		pthread_mutex_unlock(&db->lock);
		return ZTLF_NEG(e);
	}

	if (old) {
		if (old->timestamp >= r->timestamp) {
			result = 0;
			goto exit_putRecord;
		}

		/* Delete links and wanted records that are no longer linked from this record, and
		 * start building a set of records below the old record. */
		oldBelowQueueCapacity = 1024;
		oldBelowQueue = (int64_t *)malloc(sizeof(int64_t) * 1024);
		for(unsigned long i=0;i<ZTLF_RECORD_LINK_COUNT;++i) {
			if ((old->links[i].timestamp != 0)&&((old->links[i].idOwnerHash[0]|old->links[i].idOwnerHash[1]|old->links[i].idOwnerHash[2]) != 0)) {
				sqlite3_reset(db->sGetRecordInfo);
				sqlite3_bind_blob(db->sGetRecordInfo,1,old->links[i].idOwnerHash,sizeof(old->links[i].idOwnerHash),SQLITE_STATIC);
				while (sqlite3_step(db->sGetRecordInfo) == SQLITE_ROW) {
					const int64_t rid = sqlite3_column_int64(db->sGetRecordInfo,0);
					if ((rid >= 0)&&(!ZTLF_i64contains(oldBelowQueue,oldBelowQueueSize,rid))) {
						if (oldBelowQueueSize >= oldBelowQueueCapacity) {
							ZTLF_MALLOC_CHECK(oldBelowQueue = (int64_t *)realloc(oldBelowQueue,sizeof(int64_t) * (oldBelowQueueCapacity *= 4)));
						}
						oldBelowQueue[oldBelowQueueSize++] = rid;
					}
				}

				int stillHave = 0;
				for(unsigned long j=0;j<ZTLF_RECORD_LINK_COUNT;++j) {
					if ((r->links[j].idOwnerHash[0] == old->links[i].idOwnerHash[0])&&(r->links[j].idOwnerHash[1] == old->links[i].idOwnerHash[1])&&(r->links[j].idOwnerHash[2] == old->links[i].idOwnerHash[2])) {
						stillHave = 1;
						break;
					}
				}
				if (!stillHave) {
					sqlite3_reset(db->sDeleteLinkedFrom);
					sqlite3_bind_blob(db->sDeleteLinkedFrom,1,old->links[i].idOwnerHash,sizeof(old->links[i].idOwnerHash),SQLITE_STATIC);
					sqlite3_bind_int64(db->sDeleteLinkedFrom,2,rowid);
					if ((e = sqlite3_step(db->sDeleteLinkedFrom)) != SQLITE_DONE) {
						result = ZTLF_NEG(e);
						goto exit_putRecord;
					}

					sqlite3_reset(db->sDeleteWantedFrom);
					sqlite3_bind_blob(db->sDeleteWantedFrom,1,old->links[i].idOwnerHash,sizeof(old->links[i].idOwnerHash),SQLITE_STATIC);
					sqlite3_bind_int64(db->sDeleteWantedFrom,2,rowid);
					if ((e = sqlite3_step(db->sDeleteWantedFrom)) != SQLITE_DONE) {
						result = ZTLF_NEG(e);
						goto exit_putRecord;
					}
				}
			}
		}

		/* Subtract old internal weight from all records below old record. */
		if (oldBelowQueueSize) {
			for(unsigned long q=0;q<oldBelowQueueSize;++q) {
				sqlite3_reset(db->sGetLinksFrom);
				sqlite3_bind_int64(db->sGetLinksFrom,1,oldBelowQueue[q]);
				while (sqlite3_step(db->sGetLinksFrom) == SQLITE_ROW) {
					const int64_t rid = sqlite3_column_int64(db->sGetLinksFrom,0);
					if ((rid >= 0)&&(rid != rowid)&&(!ZTLF_i64contains(oldBelowQueue,oldBelowQueueSize,rid))) {
						if (oldBelowQueueSize >= oldBelowQueueCapacity) {
							ZTLF_MALLOC_CHECK(oldBelowQueue = (int64_t *)realloc(oldBelowQueue,sizeof(int64_t) * (oldBelowQueueCapacity *= 4)));
						}
						oldBelowQueue[oldBelowQueueSize++] = rid;
					}
				}
			}

			const double nWeight = -oldInternalWeight;
			unsigned long qptr = 0;
			unsigned long qs = oldBelowQueueSize;
			while (qs >= 16) {
				qs -= 16;
				sqlite3_reset(db->sChangeRecordWeight16);
				sqlite3_bind_double(db->sChangeRecordWeight16,1,nWeight);
				for(unsigned long i=2;i<=17;i++)
					sqlite3_bind_int64(db->sChangeRecordWeight16,i,oldBelowQueue[qptr++]);
				if ((e = sqlite3_step(db->sChangeRecordWeight16)) != SQLITE_DONE) {
					result = ZTLF_NEG(e);
					goto exit_putRecord;
				}
			}
			while (qs) {
				--qs;
				sqlite3_reset(db->sChangeRecordWeight1);
				sqlite3_bind_double(db->sChangeRecordWeight1,1,nWeight);
				sqlite3_bind_int64(db->sChangeRecordWeight1,2,oldBelowQueue[qptr++]);
				if ((e = sqlite3_step(db->sChangeRecordWeight1)) != SQLITE_DONE) {
					result = ZTLF_NEG(e);
					goto exit_putRecord;
				}
			}
		}
	}

	/* Compute total weight by adding up the internal weights of all records that
	 * link to this one, traversing the entire graph. */
	double weight = internalWeight;
	{
		unsigned long aboveQueueCapacity = 1024 * 3;
		uint64_t *aboveQueue = (uint64_t *)malloc(sizeof(uint64_t) * 1024 * 3);

		aboveQueue[0] = idOwnerHash[0];
		aboveQueue[1] = idOwnerHash[1];
		aboveQueue[2] = idOwnerHash[2];
		unsigned long aboveQueueSize = 3;

		struct ZTLF_Map aboveVisitedSet;
		ZTLF_Map_init(&aboveVisitedSet,4096,NULL);

		for(unsigned long q=0;q<aboveQueueSize;q+=3) {
			sqlite3_reset(db->sGetLinksTo);
			sqlite3_bind_blob(db->sGetLinksTo,1,aboveQueue + q,sizeof(uint64_t) * 3,SQLITE_STATIC);
			while (sqlite3_step(db->sGetLinksTo) == SQLITE_ROW) {
				const double w = sqlite3_column_double(db->sGetLinksTo,0);
				const void *h = sqlite3_column_blob(db->sGetLinksTo,1);
				if ((sqlite3_column_bytes(db->sGetLinksTo,1) == (sizeof(uint64_t) * 3))&&(memcmp(idOwnerHash,h,sizeof(idOwnerHash)) != 0)) {
					if (ZTLF_Map_set(&aboveVisitedSet,h,sizeof(uint64_t) * 3,ZTLF_MAP_VALUE_SET) > 0) {
						weight += w;
						if (aboveQueueSize >= aboveQueueCapacity) {
							ZTLF_MALLOC_CHECK(aboveQueue = (uint64_t *)realloc(aboveQueue,sizeof(uint64_t) * (aboveQueueCapacity *= 4)));
						}
						memcpy(aboveQueue + aboveQueueSize,h,sizeof(uint64_t) * 3);
						aboveQueueSize += 3;
					}
				}
			}
		}

		ZTLF_Map_destroy(&aboveVisitedSet);
		free(aboveQueue);
	}

	if (old) {
		sqlite3_reset(db->sUpdateRecord);
		sqlite3_bind_double(db->sUpdateRecord,1,weight);
		sqlite3_bind_double(db->sUpdateRecord,2,internalWeight);
		sqlite3_bind_int64(db->sUpdateRecord,3,(sqlite3_int64)r->timestamp);
		sqlite3_bind_blob(db->sUpdateRecord,4,r,rsize,SQLITE_STATIC);
		sqlite3_bind_int64(db->sUpdateRecord,5,rowid);
		if ((e = sqlite3_step(db->sUpdateRecord)) != SQLITE_DONE) {
			result = ZTLF_NEG(e);
			goto exit_putRecord;
		}
	} else {
		sqlite3_reset(db->sAddRecord);
		sqlite3_bind_double(db->sAddRecord,1,weight);
		sqlite3_bind_double(db->sAddRecord,2,internalWeight);
		sqlite3_bind_int64(db->sAddRecord,3,(sqlite3_int64)r->timestamp);
		sqlite3_bind_blob(db->sAddRecord,4,idOwnerHash,sizeof(idOwnerHash),SQLITE_STATIC);
		sqlite3_bind_blob(db->sAddRecord,5,r->id,sizeof(r->id),SQLITE_STATIC);
		sqlite3_bind_blob(db->sAddRecord,6,r,rsize,SQLITE_STATIC);
		if ((e = sqlite3_step(db->sAddRecord)) != SQLITE_DONE) {
			result = ZTLF_NEG(e);
			goto exit_putRecord;
		}
		rowid = sqlite3_last_insert_rowid(db->dbc);
		if (rowid < 0) {
			result = -SQLITE_ERROR;
			goto exit_putRecord;
		}
	}

	/* Add links and wanted records and start building a set of records below the new record. */
	belowQueueCapacity = 1024;
	belowQueue = (int64_t *)malloc(sizeof(int64_t) * 1024);
	for(unsigned long i=0;i<ZTLF_RECORD_LINK_COUNT;++i) {
		if ((r->links[i].timestamp != 0)&&((r->links[i].idOwnerHash[0]|r->links[i].idOwnerHash[1]|r->links[i].idOwnerHash[2]) != 0)) {
			sqlite3_reset(db->sAddLink);
			sqlite3_bind_blob(db->sAddLink,1,r->links[i].idOwnerHash,sizeof(r->links[i].idOwnerHash),SQLITE_STATIC);
			sqlite3_bind_int64(db->sAddLink,2,rowid);
			if ((e = sqlite3_step(db->sAddLink)) != SQLITE_DONE) {
				result = ZTLF_NEG(e);
				goto exit_putRecord;
			}

			sqlite3_reset(db->sGetRecordInfo);
			sqlite3_bind_blob(db->sGetRecordInfo,1,r->links[i].idOwnerHash,sizeof(r->links[i].idOwnerHash),SQLITE_STATIC);
			while (sqlite3_step(db->sGetRecordInfo) == SQLITE_ROW) {
				const int64_t rid = sqlite3_column_int64(db->sGetRecordInfo,0);
				const uint64_t ts = (uint64_t)sqlite3_column_int64(db->sGetRecordInfo,1);
				if ((rid < 0)||(ts < r->links[i].timestamp)) {
					sqlite3_reset(db->sAddWanted);
					sqlite3_bind_blob(db->sAddWanted,1,r->links[i].idOwnerHash,sizeof(r->links[i].idOwnerHash),SQLITE_STATIC);
					sqlite3_bind_int64(db->sAddWanted,2,rowid);
					sqlite3_bind_int64(db->sAddWanted,3,(sqlite3_int64)r->links[i].timestamp);
					if ((e = sqlite3_step(db->sAddWanted)) != SQLITE_DONE) {
						result = ZTLF_NEG(e);
						goto exit_putRecord;
					}
				} else if (rid >= 0) {
					if (!ZTLF_i64contains(belowQueue,belowQueueSize,rid)) {
						if (belowQueueSize >= belowQueueCapacity) {
							ZTLF_MALLOC_CHECK(belowQueue = (int64_t *)realloc(belowQueue,sizeof(int64_t) * (belowQueueCapacity *= 4)));
						}
						belowQueue[belowQueueSize++] = rid;
					}
				}
			}
		}
	}

	/* Add new record internal weight to all records below it. */
	if ((belowQueueSize > 0)&&(internalWeight > 0.0)) {
		for(unsigned long q=0;q<belowQueueSize;++q) {
			sqlite3_reset(db->sGetLinksFrom);
			sqlite3_bind_int64(db->sGetLinksFrom,1,belowQueue[q]);
			while (sqlite3_step(db->sGetLinksFrom) == SQLITE_ROW) {
				const int64_t rid = sqlite3_column_int64(db->sGetLinksFrom,0);
				if ((rid >= 0)&&(rid != rowid)&&(!ZTLF_i64contains(belowQueue,belowQueueSize,rid))) {
					if (belowQueueSize >= belowQueueCapacity) {
						ZTLF_MALLOC_CHECK(belowQueue = (int64_t *)realloc(belowQueue,sizeof(int64_t) * (belowQueueCapacity *= 4)));
					}
					belowQueue[belowQueueSize++] = rid;
				}
			}
		}

		unsigned long qptr = 0;
		unsigned long qs = belowQueueSize;
		while (qs >= 16) {
			qs -= 16;
			sqlite3_reset(db->sChangeRecordWeight16);
			sqlite3_bind_double(db->sChangeRecordWeight16,1,internalWeight);
			for(unsigned long i=2;i<=17;i++)
				sqlite3_bind_int64(db->sChangeRecordWeight16,i,belowQueue[qptr++]);
			if ((e = sqlite3_step(db->sChangeRecordWeight16)) != SQLITE_DONE) {
				result = ZTLF_NEG(e);
				goto exit_putRecord;
			}
		}
		while (qs) {
			--qs;
			sqlite3_reset(db->sChangeRecordWeight1);
			sqlite3_bind_double(db->sChangeRecordWeight1,1,internalWeight);
			sqlite3_bind_int64(db->sChangeRecordWeight1,2,belowQueue[qptr++]);
			if ((e = sqlite3_step(db->sChangeRecordWeight1)) != SQLITE_DONE) {
				result = ZTLF_NEG(e);
				goto exit_putRecord;
			}
		}
	}

	/* Delete any wanted records for this record. */
	sqlite3_reset(db->sDeleteWanted);
	sqlite3_bind_blob(db->sDeleteWanted,1,idOwnerHash,sizeof(idOwnerHash),SQLITE_STATIC);
	sqlite3_bind_int64(db->sDeleteWanted,2,(sqlite3_int64)r->timestamp);
	if ((e = sqlite3_step(db->sDeleteWanted)) != SQLITE_DONE) {
		result = ZTLF_NEG(e);
		goto exit_putRecord;
	}

	if ((e = sqlite3_exec(db->dbc,"COMMIT",NULL,NULL,NULL)) != SQLITE_OK)
		result = ZTLF_NEG(e);

exit_putRecord:
	if (result < 0)
		sqlite3_exec(db->dbc,"ROLLBACK",NULL,NULL,NULL);

	pthread_mutex_unlock(&db->lock);

	if (belowQueue)
		free(belowQueue);

	if (oldBelowQueue)
		free(oldBelowQueue);

	return result;
}
