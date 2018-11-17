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
#include "vector.h"
#include "record.h"

#ifdef ZTLF_SQLITE_INCLUDE
#include ZTLF_SQLITE_INCLUDE
#else
#include <sqlite3.h>
#endif

ZTLF_PACKED_STRUCT(struct ZTLF_DB_GraphNode
{
	double totalWeight;
	int64_t linkedRecordGoff[ZTLF_RECORD_LINK_COUNT];
});

struct ZTLF_DB
{
	char path[PATH_MAX];

	sqlite3 *dbc;
	sqlite3_stmt *sAddRecord;
	sqlite3_stmt *sGetLatestRecordTimestamp;
	sqlite3_stmt *sGetRecordHistoryById;
	sqlite3_stmt *sGetRecordCount;
	sqlite3_stmt *sGetRecordInfoByHash;
	sqlite3_stmt *sGetDanglingLinks;
	sqlite3_stmt *sDeleteDanglingLinks;
	sqlite3_stmt *sAddDanglingLink;
	sqlite3_stmt *sGetDanglingLinksForRetry;
	sqlite3_stmt *sUpdateDanglingLinkRetryInfo;

	uint64_t gfcap;
	volatile struct ZTLF_DB_GraphNode *gfm;
	int gfd;

	int df;

	volatile int running;

	pthread_mutex_t dbcLock;
	pthread_mutex_t gfLock;
};

int ZTLF_DB_open(struct ZTLF_DB *db,const char *path);

void ZTLF_DB_close(struct ZTLF_DB *db);

long ZTLF_getRecord(struct ZTLF_DB *const db,struct ZTLF_Record *r,double *aggregatedTotalWeight,const void *const id);

int ZTLF_putRecord(struct ZTLF_DB *db,struct ZTLF_RecordInfo *const ri);

#endif
