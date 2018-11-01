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

#define ZT_LF_DB_INIT_SQL (\
"CREATE TABLE IF NOT EXISTS config (k VARCHAR(256) PRIMARY KEY NOT NULL,v BLOB NOT NULL);\n" \
"CREATE TABLE IF NOT EXISTS record (\n" \
" rowid INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,\n" \
" id BLOB(32) NOT NULL,\n" \
" owner BLOB(32) NOT NULL,\n" \
" idOwnerHash BLOB(24) NOT NULL,\n" \
" timestamp INTEGER NOT NULL,\n" \
" expiration INTEGER NOT NULL,\n" \
" data BLOB NOT NULL,\n" \
" PRIMARY KEY(id,owner)\n" \
");\n" \
"CREATE INDEX IF NOT EXISTS record_idOwnerHash ON record(idOwnerHash);\n" \
"CREATE INDEX IF NOT EXISTS record_timestamp_expiration ON record(timestamp,expiration);\n" \
"CREATE TABLE IF NOT EXISTS link (\n" \
" idOwnerHash BLOB(24),\n" \
" recordRowid INTEGER NOT NULL,\n" \
" work INTEGER NOT NULL,\n" \
" retries INTEGER NOT NULL DEFAULT(0),\n" \
" PRIMARY KEY(idOwnerHash,recordRowid)\n" \
") WITHOUT ROWID;\n")

int ZTLF_db_open(const char *path,struct ZTLF_db *db)
{
	int e = 0;

	memset(db,0,sizeof(struct ZTLF_db));

	if ((e = sqlite3_open_v2(path,&db->dbc,SQLITE_OPEN_CREATE|SQLITE_OPEN_READWRITE|SQLITE_OPEN_NOMUTEX,NULL)) != SQLITE_OK)
		goto exit_with_error;

	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT INTO record (id,owner,idOwnerHash,timestamp,expiration,data) VALUES (?,?,?,?,?,?)",-1,&db->sAddRecord,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT INTO link (idOwnerHash,recordRowid,work) VALUES (?,?,?)",-1,&db->sAddLink,NULL)) != SQLITE_OK)
		goto exit_with_error;

	return 0;

exit_with_error:
	ZTLF_db_close(db);
	return e;
}

void ZTLF_db_close(struct ZTLF_db *db)
{
	if (db->dbc) {
		if (db->sAddRecord) sqlite3_finalize(db->sAddRecord);
		sqlite3_close_v2(db->dbc);
		memset(db,0,sizeof(struct ZTLF_db));
	}
}
