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

#define ZT_LF_DB_INIT_SQL \
"PRAGMA locking_mode = EXCLUSIVE;\n" \
"PRAGMA journal_mode = MEMORY;\n" \
"PRAGMA cache_size = -262144;\n" \
"PRAGMA synchronous = 0;\n" \
"PRAGMA auto_vacuum = 0;\n" \
"PRAGMA foreign_keys = OFF;\n" \
"PRAGMA automatic_index = OFF;\n" \
"CREATE TABLE IF NOT EXISTS config (k VARCHAR(256) PRIMARY KEY NOT NULL,v BLOB NOT NULL);\n" \
"CREATE TABLE IF NOT EXISTS record (\n" \
" rowid INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,\n" \
" id BLOB(32) NOT NULL,\n" \
" idOwnerHash BLOB(24) NOT NULL,\n" \
" timestamp INTEGER NOT NULL,\n" \
" weight REAL NOT NULL,\n" \
" data BLOB NOT NULL,\n" \
" PRIMARY KEY(id,idOwnerHash)\n" \
");\n" \
"CREATE INDEX IF NOT EXISTS record_idOwnerHash ON record(idOwnerHash);\n" \
"CREATE INDEX IF NOT EXISTS record_weight ON record(weight);\n" \
"CREATE TABLE IF NOT EXISTS backlink (\n" \
" toIdOwnerHash BLOB(24) NOT NULL,\n" \
" fromRecordRowid INTEGER NOT NULL,\n" \
" PRIMARY KEY(idOwnerHash,fromRecordRowid)\n" \
");\n" \
"CREATE TABLE IF NOT EXISTS wanted (\n" \
" idOwnerHash BLOB(24) NOT NULL,\n" \
" fromRecordRowid INTEGER NOT NULL,\n" \
" timestamp INTEGER NOT NULL,\n" \
" retries INTEGER NOT NULL DEFAULT(0),\n" \
" PRIMARY KEY(idOwnerHash,fromRecordRowid)\n" \
") WITHOUT ROWID;\n" \
"CREATE INDEX IF NOT EXISTS wanted_fromRecordRowid ON wanted(fromRecordRowid);\n"

int ZTLF_DB_open(struct ZTLF_DB *db,const char *path)
{
	int e = 0;

	memset(db,0,sizeof(struct ZTLF_DB));

	if ((e = sqlite3_open_v2(path,&db->dbc,SQLITE_OPEN_CREATE|SQLITE_OPEN_READWRITE|SQLITE_OPEN_NOMUTEX,NULL)) != SQLITE_OK)
		return e;

	if ((e = sqlite3_exec(db->dbc,(ZT_LF_DB_INIT_SQL),NULL,NULL,NULL)) != SQLITE_OK)
		goto exit_with_error;

	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT INTO record (id,idOwnerHash,timestamp,weight,data) VALUES (?,?,?,?,?)",-1,&db->sAddRecord,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT data FROM record WHERE id = ? ORDER BY weight DESC LIMIT 1",-1,&db->sGetRecord,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT data FROM record WHERE id = ? AND idOwnerHash = ?",-1,&db->sGetRecord2,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT idOwnerHash,MAX(weight) FROM record GROUP BY idOwnerHash ORDER BY MAX(weight) DESC",-1,&db->sGetLowestWeightRecords,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"UPDATE record SET weight = (weight + ?) WHERE idOwnerHash = ?",-1,&db->sAddToRecordWeight,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"UPDATE record SET weight = (weight - ?) WHERE idOwnerHash = ?",-1,&db->sSubFromRecordWeight,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT OR IGNORE INTO wanted (idOwnerHash,fromRecordRowid,timestamp,retries) VALUES (?,?,?,0)",-1,&db->sAddWanted,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"DELETE FROM wanted WHERE idOwnerHash = ? AND timestamp <= ?",-1,&db->sDeleteWanted,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"DELETE FROM wanted WHERE fromRecordRowid = ?",-1,&db->sDeleteWantedFrom,NULL)) != SQLITE_OK)
		goto exit_with_error;

	pthread_mutex_init(&db->lock,NULL);

	return 0;

exit_with_error:
	ZTLF_DB_close(db);
	return e;
}

void ZTLF_DB_close(struct ZTLF_DB *db)
{
	if (db->dbc) {
		if (db->sAddRecord) sqlite3_finalize(db->sAddRecord);
		if (db->sGetRecord) sqlite3_finalize(db->sGetRecord);
		if (db->sGetRecord2) sqlite3_finalize(db->sGetRecord2);
		if (db->sAddToRecordWeight) sqlite3_finalize(db->sAddToRecordWeight);
		if (db->sSubFromRecordWeight) sqlite3_finalize(db->sSubFromRecordWeight);
		if (db->sAddWanted) sqlite3_finalize(db->sAddWanted);
		if (db->sDeleteWanted) sqlite3_finalize(db->sDeleteWanted);
		if (db->sDeleteWantedFrom) sqlite3_finalize(db->sDeleteWantedFrom);
		sqlite3_close_v2(db->dbc);
		pthread_mutex_destroy(&db->lock);
		memset(db,0,sizeof(struct ZTLF_DB));
	}
}

int ZTLF_putRecord(struct ZTLF_DB *db,struct ZTLF_Record *r)
{
	int result = 0;

	uint64_t idOwnerHash[3];
	ZTLF_Record_idOwnerHash(r,idOwnerHash);

	pthread_mutex_lock(&db->lock);

	if (sqlite3_exec(db->dbc,"BEGIN TRANSACTION",NULL,NULL,NULL) != SQLITE_OK) {
		pthread_mutex_unlock(&db->lock);
		return -1;
	}

	/* Get any existing version of this record */

	/* If record is new... */
	/* Compute new record's weight based on existing links to it. */
	/* else compute new record's weight based on its own change in difficulty, endorsements, etc. */

	/* Determine difference in weights that should be applied to records under this one. */

	/* Recursively adjust weights of all records under this one. */

	if (sqlite3_exec(db->dbc,"COMMIT",NULL,NULL,NULL) != SQLITE_OK) {
		result = -1;
		goto exit_putRecord;
	}

exit_putRecord:
	if (result < 0)
		sqlite3_exec(db->dbc,"ROLLBACK",NULL,NULL,NULL);
	pthread_mutex_unlock(&db->lock);
	return result;
}
