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

#ifndef ZT_LF_DB_H
#define ZT_LF_DB_H

#include "common.h"
#include "record.h"

#include <sqlite3.h>

struct ZTLF_DB
{
	sqlite3 *dbc;

	sqlite3_stmt *sAddRecord;
	sqlite3_stmt *sGetRecord;
	sqlite3_stmt *sGetRecord2;
	sqlite3_stmt *sGetLowestWeightRecords;
	sqlite3_stmt *sAddToRecordWeight;
	sqlite3_stmt *sSubFromRecordWeight;
	sqlite3_stmt *sAddWanted;
	sqlite3_stmt *sDeleteWanted;
	sqlite3_stmt *sDeleteWantedFrom;

	pthread_mutex_t lock;
};


int ZTLF_DB_open(struct ZTLF_DB *db,const char *path);
void ZTLF_DB_close(struct ZTLF_DB *db);

#endif
