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

/**
 * Structure making up graph.bin
 * 
 * This packed structure tracks records' weights and links to other records by
 * graph node offset. It's stored in little endian format since most systems are
 * little endian and this therefore will usually give the best performance. It's
 * not guaranteed to be portable between architectures, though it should work
 * across LE architectures that use IEEE double.
 */
ZTLF_PACKED_STRUCT(struct ZTLF_DB_GraphNode
{
	double totalWeight;
	uint8_t linkCount;
	int64_t linkedRecordGoff[];
});

/*
 * record
 *   doff                     offset of record data in 'records' flat file (primary key)
 *   dlen                     length of record data
 *   goff                     offset of graph node in memory mapped graph file (unique key)
 *   ts                       record timestamp in seconds since epoch
 *   exp                      record expiration time in seconds since epoch
 *   weight                   weight of this record (not including those that link to it)
 *   id                       record ID (key)
 *   owner                    record owner
 *   hash                     shandwich256(record data) (unique key)
 *   new_owner                if non-NULL, the new owner that should inherit the past owner's weight
 *   sel0                     if non-NULL, arbitrary selection key 0 (key)
 *   sel1                     if non-NULL, arbitrary selection key 1 (key)
 * 
 * dangling_link
 *   hash                     hash of record we don't have
 *   linking_record_goff      graph node offset of record with dangling link
 *   linking_record_link_idx  index in linkedRecordGoff[] of missing link
 * 
 * hole
 *   waiting_record_goff      graph offset of record that is waiting on this hole to be filled
 *   incomplete_goff          graph offset of graph node with missing links
 *   incomplete_link_idx      index of missing link in linkedRecordGoff[]
 * 
 * graph_pending
 *   record_goff              graph offset of record pending completion of weight application
 *   hole_count               most recent count of entries in hole that are blocking this node
 * 
 * wanted
 *   hash                     hash of wanted record
 *   retries                  number of retries attempted so far
 *   last_retry_time          time of last retry
 * 
 * peer
 *   key_hash                 SHA384(public key)
 *   address_type             currently either 4 or 6
 *   address                  IPv4 or IPv6 IP
 *   last_connect_time        timestamp of most recent outgoing connect to this peer key at this IP/port (ms)
 *   first_connect_time       timestamp of first outgoing connect to this peer key at this IP/port (ms)
 *
 * Most tables are somewhat self-explanatory.
 * 
 * The hole and dangling_link tables are similar but serve different functions. The dangling_link table
 * documents immediate missing links from a given linking record and is functionally tied to the wanted
 * table. The latter tracks attempts to retrieve missing records. The hole table documents missing links
 * in the graph anywhere beneath a given record. It's used to track progress in what may be multiple
 * graph traversal iterations to apply a record's weights to the records below it.
 * 
 * The graph_pending table tracks records whose weights have not yet been fully applied to the entire
 * graph below them. This occurs if there are holes in the graph. The current value of hole_count can
 * be compared with a computed value to determine if some of those holes have been filled and if graph
 * traversal and weight application should be attempted again. When the graph is successfully traversed
 * completely with no holes detected these entries are deleted.
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
"weight REAL NOT NULL," \
"id BLOB(32) NOT NULL," \
"owner BLOB(32) NOT NULL," \
"hash BLOB(32) NOT NULL," \
"new_owner BLOB(32)," \
"sel0 BLOB(32)," \
"sel1 BLOB(32)" \
") WITHOUT ROWID;\n" \
\
"CREATE UNIQUE INDEX IF NOT EXISTS record_goff ON record(goff);\n" \
"CREATE INDEX IF NOT EXISTS record_id_ts ON record(id,ts);\n" \
"CREATE UNIQUE INDEX IF NOT EXISTS record_hash ON record(hash);\n" \
"CREATE INDEX IF NOT EXISTS record_sel0_sel1 ON record(sel0,sel1);\n" \
"CREATE INDEX IF NOT EXISTS record_sel1_sel0 ON record(sel1,sel0);\n" \
\
"CREATE TABLE IF NOT EXISTS dangling_link (" \
"hash BLOB(32) NOT NULL," \
"linking_record_goff INTEGER NOT NULL," \
"linking_record_link_idx INTEGER NOT NULL," \
"PRIMARY KEY(hash,linking_record_goff,linking_record_link_idx)" \
") WITHOUT ROWID;\n" \
\
"CREATE INDEX IF NOT EXISTS dangling_link_linking_record_goff_linking_record_link_idx ON dangling_link(linking_record_goff,linking_record_link_idx);\n" \
\
"CREATE TABLE IF NOT EXISTS hole (" \
"waiting_record_goff INTEGER NOT NULL," \
"incomplete_goff INTEGER NOT NULL," \
"incomplete_link_idx INTEGER NOT NULL," \
"PRIMARY KEY(waiting_record_goff,incomplete_goff,incomplete_link_idx)" \
") WITHOUT ROWID;\n" \
\
"CREATE TABLE IF NOT EXISTS graph_pending (" \
"record_goff INTEGER PRIMARY KEY NOT NULL," \
"hole_count INTEGER NOT NULL" \
") WITHOUT ROWID;\n" \
\
"CREATE TABLE IF NOT EXISTS wanted (" \
"hash BLOB(32) PRIMARY KEY NOT NULL," \
"retries INTEGER NOT NULL," \
"last_retry_time INTEGER NOT NULL" \
") WITHOUT ROWID;\n" \
\
"CREATE INDEX IF NOT EXISTS wanted_retries_last_retry_time ON wanted(retries,last_retry_time);\n" \
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

static void *_ZTLF_DB_graphThreadMain(void *arg)
{
	struct ZTLF_DB *const db = (struct ZTLF_DB *)arg;
	uint64_t hk[2];
	struct ZTLF_Vector_i64 recordQueue,graphTraversalQueue;
	struct ZTLF_Map128 holes;
	struct ZTLF_ISet *const visited = ZTLF_ISet_new();
	ZTLF_Vector_i64_init(&graphTraversalQueue,2097152);
	ZTLF_Vector_i64_init(&recordQueue,1024);
	ZTLF_Map128_init(&holes,1024,NULL);

	ZTLF_L_verbose("graph: weight distribution thread starting");

	while (db->running) {
		/* Sleep 0.5s between each pending record query as these are somewhat expensive. */
		for(int i=0;i<5;++i) {
			usleep(100000);
			if (!db->running) goto end_graph_thread;
		}

		/* Get records that are pending because they're new or some of their holes appear filled. */
		pthread_mutex_lock(&db->dbcLock);
		sqlite3_reset(db->sGetRecordsForWeightApplication);
		while (sqlite3_step(db->sGetRecordsForWeightApplication) == SQLITE_ROW) {
			ZTLF_Vector_i64_append(&recordQueue,sqlite3_column_int64(db->sGetRecordsForWeightApplication,0));
		}
		pthread_mutex_unlock(&db->dbcLock);

		if (recordQueue.size > 0) {
			ZTLF_L_trace("graph: found %lu records to process",recordQueue.size);
		} else {
			continue;
		}

		while ((recordQueue.size > 0)&&(db->running)) {
			const int64_t waitingGoff = recordQueue.v[recordQueue.size-1];
			--recordQueue.size;
			ZTLF_L_trace("graph: adjusting weights for records below graph node %lld",(long long)waitingGoff);

			/* Get weight and any previously known holes in the graph below this node. */
			int holeCount = 0;
			double weight = 0.0;
			ZTLF_Map128_clear(&holes);
			pthread_mutex_lock(&db->dbcLock);
			sqlite3_reset(db->sGetRecordWeightByGoff);
			sqlite3_bind_int64(db->sGetRecordWeightByGoff,1,waitingGoff);
			if (sqlite3_step(db->sGetRecordWeightByGoff) == SQLITE_ROW) {
				weight = sqlite3_column_double(db->sGetRecordWeightByGoff,0);
			}
			sqlite3_reset(db->sGetHoles);
			sqlite3_bind_int64(db->sGetHoles,1,waitingGoff);
			while (sqlite3_step(db->sGetHoles) == SQLITE_ROW) {
				hk[0] = (uint64_t)sqlite3_column_int64(db->sGetHoles,0);
				hk[1] = (uint64_t)sqlite3_column_int(db->sGetHoles,1);
				ZTLF_Map128_set(&holes,hk,(void *)1);
				ZTLF_L_trace("graph: graph below %lld previously led to hole at %llu[%llu]",(long long)waitingGoff,(unsigned long long)hk[0],(unsigned long long)hk[1]);
				++holeCount;
			}
			pthread_mutex_unlock(&db->dbcLock);

			if (weight <= 0.0) {
				ZTLF_L_warning("graph: record with graph node offset %lld appears to have invalid weight %f, using 0.0 but the database may be corrupt or there's a bug!",waitingGoff,weight);
				weight = 0.0;
			}

			ZTLF_ISet_clear(visited);
			ZTLF_Vector_i64_clear(&graphTraversalQueue);

			pthread_mutex_lock(&db->gfLock);

			/* Initialize queue and weight from this record's node to start graph traversal. */
			struct ZTLF_DB_GraphNode *gn = (struct ZTLF_DB_GraphNode *)(db->gfm + (uintptr_t)waitingGoff);
			hk[0] = (uint64_t)waitingGoff;
			for(unsigned int i=0,j=gn->linkCount;i<j;++i) {
				hk[1] = (uint64_t)i;
				if (!ZTLF_Map128_get(&holes,hk)) {
					const int64_t nextGoff = ZTLF_get64_le(gn->linkedRecordGoff[i]);
					if (nextGoff >= 0) {
						ZTLF_Vector_i64_append(&graphTraversalQueue,nextGoff);
					} else {
						ZTLF_L_warning("graph: found unexpected dangling link in %lld",waitingGoff);
						pthread_mutex_lock(&db->dbcLock);
						sqlite3_reset(db->sAddHole);
						sqlite3_bind_int64(db->sAddHole,1,waitingGoff);
						sqlite3_bind_int64(db->sAddHole,2,waitingGoff);
						sqlite3_bind_int(db->sAddHole,3,i);
						sqlite3_step(db->sAddHole);
						pthread_mutex_unlock(&db->dbcLock);
					}
				}
			}

			/* Pass 1: if there are pre-existing holes it means this is a second or Nth pass. Traverse
			 * the graph once and skip previously detected holes and without changing weights. This
			 * populates the visited node set with nodes that would have been visited before so their
			 * weights are not adjusted a second time. */
			if (holeCount > 0) {
				ZTLF_L_trace("graph: node %lld has %d holes, performing no-op pass starting with %lu nodes to regenerate visited node set",waitingGoff,holeCount,graphTraversalQueue.size);
				for(unsigned long i=0;i<graphTraversalQueue.size;) {
					const int64_t goff = graphTraversalQueue.v[i++];
					if (ZTLF_ISet_put(visited,goff)) {
						gn = (struct ZTLF_DB_GraphNode *)(db->gfm + (uintptr_t)goff);

						hk[0] = (uint64_t)goff;
						for(unsigned int i=0,j=gn->linkCount;i<j;++i) {
							hk[1] = (uint64_t)i;
							if (!ZTLF_Map128_get(&holes,hk)) {
								const int64_t nextGoff = ZTLF_get64_le(gn->linkedRecordGoff[i]);
								if (nextGoff >= 0) {
									ZTLF_Vector_i64_append(&graphTraversalQueue,nextGoff);
								} else {
									ZTLF_L_warning("graph: found unexpected hole in graph below %lld at %lld[%u] (should have been previously marked, marking now)",(long long)waitingGoff,(long long)goff,i);
									pthread_mutex_lock(&db->dbcLock);
									sqlite3_reset(db->sAddHole);
									sqlite3_bind_int64(db->sAddHole,1,waitingGoff);
									sqlite3_bind_int64(db->sAddHole,2,goff);
									sqlite3_bind_int(db->sAddHole,3,i);
									sqlite3_step(db->sAddHole);
									pthread_mutex_unlock(&db->dbcLock);
								}
							}
						}

						if (i >= 1048576) { /* compact queue periodically to save memory */
							memmove(graphTraversalQueue.v,graphTraversalQueue.v + i,sizeof(int64_t) * (graphTraversalQueue.size -= i));
							i = 0;
						}
					}
				}
			}

			/* Add any now-filled holes to graph traversal queue and delete hole records for them. */
			ZTLF_Map128_each(&holes,{
				const int64_t goff = ((struct ZTLF_DB_GraphNode *)(db->gfm + (uintptr_t)ztlfMapKey[0]))->linkedRecordGoff[(uintptr_t)ztlfMapKey[1]];
				if (goff >= 0) {
					ZTLF_L_trace("graph: hole below %lld at %llu[%u] is now filled with pointer to %lld",(long long)waitingGoff,(unsigned long long)ztlfMapKey[0],(unsigned int)ztlfMapKey[1],(long long)goff);
					ZTLF_Vector_i64_append(&graphTraversalQueue,goff);
					pthread_mutex_lock(&db->dbcLock);
					sqlite3_reset(db->sDeleteHole);
					sqlite3_bind_int64(db->sDeleteHole,1,waitingGoff);
					sqlite3_bind_int64(db->sDeleteHole,2,(sqlite_int64)ztlfMapKey[0]);
					sqlite3_bind_int(db->sDeleteHole,3,(int)ztlfMapKey[1]);
					sqlite3_step(db->sDeleteHole);
					pthread_mutex_unlock(&db->dbcLock);
				}
			});

			/* Pass 2: traverse the graph starting with the holes -- or if there were none, from the record
			 * itself -- and adjust weights. This adjusts weights that were not adjusted last time. Make sure
			 * to record any newly discovered holes (insert ignores holes that are still there from before). */
#ifdef ZTLF_TRACE
			int64_t depth = 0;
#endif
			for(unsigned long i=0;i<graphTraversalQueue.size;) {
				const int64_t goff = graphTraversalQueue.v[i++];

#ifdef ZTLF_TRACE
				if (goff < 0) { /* negative values are used to track depth */
					depth = goff;
					continue;
				}
#endif

				if (ZTLF_ISet_put(visited,goff)) {
					gn = (struct ZTLF_DB_GraphNode *)(db->gfm + (uintptr_t)goff);

					double tw;
					ZTLF_setdbl_le(tw,gn->totalWeight);
#ifdef ZTLF_TRACE
					ZTLF_L_trace("graph: [depth: %lld] adding weight %f from %lld to %lld, new weight is %f",-depth,weight,(long long)waitingGoff,(long long)goff,tw + weight);
#endif
					tw += weight;
					ZTLF_setdbl_le(gn->totalWeight,tw);

#ifdef ZTLF_TRACE
					ZTLF_Vector_i64_append(&graphTraversalQueue,depth - 1);
#endif

					for(unsigned int i=0,j=gn->linkCount;i<j;++i) {
						const int64_t nextGoff = ZTLF_get64_le(gn->linkedRecordGoff[i]);
						if (nextGoff >= 0) {
							ZTLF_Vector_i64_append(&graphTraversalQueue,nextGoff);
						} else {
							ZTLF_L_trace("graph: found hole below %lld at %lld[%u]",(long long)waitingGoff,(long long)goff,i);
							pthread_mutex_lock(&db->dbcLock);
							sqlite3_reset(db->sAddHole);
							sqlite3_bind_int64(db->sAddHole,1,waitingGoff);
							sqlite3_bind_int64(db->sAddHole,2,goff);
							sqlite3_bind_int(db->sAddHole,3,i);
							sqlite3_step(db->sAddHole);
							pthread_mutex_unlock(&db->dbcLock);
						}
					}

					if (i >= 1048576) { /* compact queue periodically to save memory */
						memmove(graphTraversalQueue.v,graphTraversalQueue.v + i,sizeof(int64_t) * (graphTraversalQueue.size -= i));
						i = 0;
					}
				}
			}

			pthread_mutex_unlock(&db->gfLock);

			/* Update hole count and delete pending entry for this record if there are no more holes. */
			pthread_mutex_lock(&db->dbcLock);
			sqlite3_reset(db->sUpdatePendingHoleCount);
			sqlite3_bind_int64(db->sUpdatePendingHoleCount,1,waitingGoff);
			sqlite3_bind_int64(db->sUpdatePendingHoleCount,2,waitingGoff);
			sqlite3_step(db->sUpdatePendingHoleCount);
			sqlite3_reset(db->sDeleteCompletedPending);
			sqlite3_bind_int64(db->sDeleteCompletedPending,1,waitingGoff);
			sqlite3_step(db->sDeleteCompletedPending);
			pthread_mutex_unlock(&db->dbcLock);
		}
	}

end_graph_thread:
	ZTLF_L_verbose("graph: weight distribution thread shutting down");

	ZTLF_Map128_destroy(&holes);
	ZTLF_Vector_i64_free(&recordQueue);
	ZTLF_Vector_i64_free(&graphTraversalQueue);
	ZTLF_ISet_free(visited);

	return NULL;
}

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
	db->graphThreadStarted = false;
	pthread_mutex_init(&db->dbcLock,NULL);
	pthread_mutex_init(&db->gfLock,NULL);

	mkdir(path,0755);

	ZTLF_L_trace("opening database at %s",path);

	/* Save PID of running instance of LF. */
#ifndef __WINDOWS__
	snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR "lf.pid",path);
	int pidf = open(tmp,O_WRONLY|O_TRUNC);
	if (pidf >= 0) {
		ZTLF_L_warning("LF may not have been shut down properly! database corruption is possible! (pid file still exists from previous run)");
	} else {
		pidf = open(tmp,O_WRONLY|O_CREAT|O_TRUNC,0644);
	}
	if (pidf < 0)
		goto exit_with_error;
	snprintf(tmp,sizeof(tmp),"%ld",(long)getpid());
	write(pidf,tmp,strlen(tmp));
	close(pidf);
#endif

	/* Open database and initialize schema if necessary. */
	snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR "index.db",path);
	if ((e = sqlite3_open_v2(tmp,&db->dbc,SQLITE_OPEN_CREATE|SQLITE_OPEN_READWRITE|SQLITE_OPEN_NOMUTEX,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_exec(db->dbc,(ZTLF_DB_INIT_SQL),NULL,NULL,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Add a new record. */
	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT INTO record (doff,dlen,goff,ts,exp,weight,id,owner,hash,new_owner,sel0,sel1) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",-1,&db->sAddRecord,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Get the current highest graph node byte offset for any record (used to determine placement of next record). */
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT MAX(goff) FROM record",-1,&db->sGetMaxRecordGoff,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* List all complete records (with no dangling links) with a given ID in reverse timestamp (revision) order. */
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT r.doff,r.dlen,r.goff,r.ts,r.exp,r.owner,r.new_owner FROM record AS r WHERE r.id = ? AND (SELECT COUNT(1) FROM dangling_link AS dl WHERE dl.linking_record_goff = r.goff) = 0 ORDER BY r.ts DESC",-1,&db->sGetRecordHistoryById,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Get the graph node offset (byte offset in graph file) for a record. */
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT goff FROM record WHERE hash = ?",-1,&db->sGetRecordGoffByHash,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Get the weight of a record by its graph node offset. */
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT weight FROM record WHERE goff = ?",-1,&db->sGetRecordWeightByGoff,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Get the graph node offsets of all records that have dangling links to a given record so their nodes can be updated. */
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT linking_record_goff FROM dangling_link WHERE hash = ?",-1,&db->sGetDanglingLinks,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Remove all dangling link entries that reference a record we now have. */
	if ((e = sqlite3_prepare_v2(db->dbc,"DELETE FROM dangling_link WHERE hash = ?",-1,&db->sDeleteDanglingLinks,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Remove wanted entry for a record we now have. */
	if ((e = sqlite3_prepare_v2(db->dbc,"DELETE FROM wanted WHERE hash = ?",-1,&db->sDeleteWantedHash,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Log an unfulfilled link to a hash beneath a given record. */
	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT OR IGNORE INTO dangling_link (hash,linking_record_goff,linking_record_link_idx) VALUES (?,?,?)",-1,&db->sAddDanglingLink,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Insert or reset the wanted entry for a given hash, initaiting attempts to get the record from peers. */
	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT OR REPLACE INTO wanted (hash,retries,last_retry_time) VALUES (?,0,0)",-1,&db->sAddWantedHash,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Remember a hole discovered in the graph while traversing below a given record. */
	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT OR IGNORE INTO hole (waiting_record_goff,incomplete_goff,incomplete_link_idx) VALUES (?,?,?)",-1,&db->sAddHole,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Indicate that a record is pending graph traversal and weight application to linked records and their parents. */
	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT OR REPLACE INTO graph_pending (record_goff,hole_count) VALUES (?,?)",-1,&db->sFlagRecordWeightApplicationPending,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Get the very first time we connected (outbound) to a peer. */
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT first_connect_time FROM peer WHERE key_hash = ?",-1,&db->sGetPeerFirstConnectTime,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Add or replace a peer record. */
	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT OR REPLACE INTO peer (key_hash,address,address_type,port,last_connect_time,first_connect_time) VALUES (?,?,?,?,?,?)",-1,&db->sAddUpdatePeer,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Add a potential but so far unverified peer, leaving record unchanged if a
	 * peer record is already present in the databse. */
	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT OR IGNORE INTO peer (key_hash,address,address_type,port,last_connect_time,first_connect_time) VALUES (?,?,?,?,0,0)",-1,&db->sAddPotentialPeer,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Get graph node offsets of records that still need graph traversal and weight application
	 * where these records have no immediate dangling links and where the previous hole
	 * count is zero or does not equal what seems to be the current hole count (holes minus
	 * those that have been filled). */
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT gp.record_goff FROM graph_pending AS gp WHERE (SELECT COUNT(1) FROM dangling_link AS dl1 WHERE dl1.linking_record_goff = gp.record_goff) = 0 AND (gp.hole_count <= 0 OR gp.hole_count != (SELECT COUNT(1) FROM hole AS h WHERE h.waiting_record_goff = gp.record_goff AND (SELECT COUNT(1) FROM dangling_link AS dl2 WHERE dl2.linking_record_goff = h.incomplete_goff AND dl2.linking_record_link_idx = h.incomplete_link_idx) = 0))",-1,&db->sGetRecordsForWeightApplication,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Get known memorized holes in the graph below a given record from last graph iteration. */
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT incomplete_goff,incomplete_link_idx FROM hole WHERE waiting_record_goff = ?",-1,&db->sGetHoles,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Delete a now filled graph hole. */
	if ((e = sqlite3_prepare_v2(db->dbc,"DELETE FROM hole WHERE waiting_record_goff = ? AND incomplete_goff = ? AND incomplete_link_idx = ?",-1,&db->sDeleteHole,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Update the pending record with a new count of the number of holes in the graph beneath it. */
	if ((e = sqlite3_prepare_v2(db->dbc,"UPDATE graph_pending SET hole_count = (SELECT COUNT(1) FROM hole WHERE hole.waiting_record_goff = ?) WHERE record_goff = ?",-1,&db->sUpdatePendingHoleCount,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Delete pending record entry if the graph beneath it has now been completely traversed and all weights have been applied. */
	if ((e = sqlite3_prepare_v2(db->dbc,"DELETE FROM graph_pending WHERE record_goff = ? AND hole_count = 0",-1,&db->sDeleteCompletedPending,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Open and memory map the graph node file. */
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
	db->gfm = (uint8_t *)mmap(NULL,(size_t)db->gfcap,PROT_READ|PROT_WRITE,MAP_FILE|MAP_SHARED,db->gfd,0);
	if (!db->gfm)
		goto exit_with_error;

	/* Open the record data file where actual records are stored. */
	snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR "records.bin",path);
	db->df = open(tmp,O_RDWR|O_CREAT,0644);
	if (db->df < 0)
		goto exit_with_error;

	db->running = true;
	db->graphThread = ZTLF_threadCreate(&_ZTLF_DB_graphThreadMain,db,false);
	db->graphThreadStarted = true;

	return 0;

exit_with_error:
	ZTLF_DB_close(db);
	return ((e) ? ZTLF_POS(e) : ZTLF_NEG(errno));
}

void ZTLF_DB_close(struct ZTLF_DB *db)
{
	char tmp[PATH_MAX];

	db->running = false;
	if (db->graphThreadStarted)
		pthread_join(db->graphThread,NULL);

	pthread_mutex_lock(&db->dbcLock);
	pthread_mutex_lock(&db->gfLock);

	ZTLF_L_trace("closing database at %s",db->path);

	if (db->df >= 0)
		close(db->df);

	if (db->dbc) {
		if (db->sAddRecord)                           sqlite3_finalize(db->sAddRecord);
		if (db->sGetMaxRecordGoff)                    sqlite3_finalize(db->sGetMaxRecordGoff);
		if (db->sGetRecordHistoryById)                sqlite3_finalize(db->sGetRecordHistoryById);
		if (db->sGetRecordGoffByHash)                 sqlite3_finalize(db->sGetRecordGoffByHash);
		if (db->sGetRecordWeightByGoff)               sqlite3_finalize(db->sGetRecordWeightByGoff);
		if (db->sGetDanglingLinks)                    sqlite3_finalize(db->sGetDanglingLinks);
		if (db->sDeleteDanglingLinks)                 sqlite3_finalize(db->sDeleteDanglingLinks);
		if (db->sDeleteWantedHash)                    sqlite3_finalize(db->sDeleteWantedHash);
		if (db->sAddDanglingLink)                     sqlite3_finalize(db->sAddDanglingLink);
		if (db->sAddWantedHash)                       sqlite3_finalize(db->sAddWantedHash);
		if (db->sAddHole)                             sqlite3_finalize(db->sAddHole);
		if (db->sFlagRecordWeightApplicationPending)  sqlite3_finalize(db->sFlagRecordWeightApplicationPending);
		if (db->sGetPeerFirstConnectTime)             sqlite3_finalize(db->sGetPeerFirstConnectTime);
		if (db->sAddUpdatePeer)                       sqlite3_finalize(db->sAddUpdatePeer);
		if (db->sAddPotentialPeer)                    sqlite3_finalize(db->sAddPotentialPeer);
		if (db->sGetRecordsForWeightApplication)      sqlite3_finalize(db->sGetRecordsForWeightApplication);
		if (db->sGetHoles)                            sqlite3_finalize(db->sGetHoles);
		if (db->sDeleteHole)                          sqlite3_finalize(db->sDeleteHole);
		if (db->sUpdatePendingHoleCount)              sqlite3_finalize(db->sUpdatePendingHoleCount);
		if (db->sDeleteCompletedPending)              sqlite3_finalize(db->sDeleteCompletedPending);
		sqlite3_close_v2(db->dbc);
	}

	if (db->gfm)
		munmap((void *)db->gfm,(size_t)db->gfcap);
	if (db->gfd >= 0)
		close(db->gfd);

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

int ZTLF_DB_putRecord(struct ZTLF_DB *db,struct ZTLF_ExpandedRecord *const er)
{
	uint8_t rwtmp[ZTLF_RECORD_MAX_SIZE + 8];
	int e = 0,result = 0;

	if ((!er)||(er->size < ZTLF_RECORD_MIN_SIZE)||(er->size > ZTLF_RECORD_MAX_SIZE)) { /* sanity checks */
		return ZTLF_NEG(EINVAL);
	}

	pthread_mutex_lock(&db->dbcLock);
	pthread_mutex_lock(&db->gfLock);

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

	/* Figure out where record will be appended to record data file. */
	int64_t doff = lseek(db->df,0,SEEK_END);
	if (doff < 0) {
		result = ZTLF_NEG(errno);
		goto exit_putRecord;
	}
	doff += 2; /* actual offset is +2 to account for size prefix before record */

	ZTLF_L_trace("adding version %llu of %s with hash %s at graph node offset %lld and data file offset %lld",(unsigned long long)er->timestamp,ZTLF_hexstr(er->r->id,32,0),ZTLF_hexstr(er->hash,32,1),(long long)goff,(long long)doff);

	/* Grow graph file if needed. */
	if ((uint64_t)(goff + ZTLF_RECORD_MAX_SIZE) >= db->gfcap) {
		ZTLF_L_trace("increasing size of graph file: %llu -> %llu",(unsigned long long)db->gfcap,(unsigned long long)(db->gfcap + ZTLF_GRAPH_FILE_CAPACITY_INCREMENT));
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
	struct ZTLF_DB_GraphNode *const graphNode = (struct ZTLF_DB_GraphNode *)(db->gfm + (uintptr_t)goff);

	/* Write record size and record to data file. Size prefix is not used by this
	 * code but allows the record data file to be parsed and used as input for e.g.
	 * bulk loading of records. */
	rwtmp[0] = (uint8_t)((er->size >> 8) & 0xff);
	rwtmp[1] = (uint8_t)(er->size & 0xff);
	memcpy(rwtmp + 2,er->r,er->size); 
	if (write(db->df,rwtmp,(size_t)(er->size + 2)) != (ssize_t)(er->size + 2)) {
		ZTLF_L_warning("error writing record %s to data file: %d (%s)",ZTLF_hexstr(er->hash,32,0),errno,strerror(errno));
		result = ZTLF_NEG(errno);
		goto exit_putRecord;
	}
	fsync(db->df);

	/* Add main record entry. */
	sqlite3_reset(db->sAddRecord);
	sqlite3_bind_int64(db->sAddRecord,1,doff);
	sqlite3_bind_int64(db->sAddRecord,2,(sqlite3_int64)er->size);
	sqlite3_bind_int64(db->sAddRecord,3,goff);
	sqlite3_bind_int64(db->sAddRecord,4,(sqlite3_int64)er->timestamp);
	sqlite3_bind_int64(db->sAddRecord,5,(sqlite3_int64)er->expiration);
	sqlite3_bind_double(db->sAddRecord,6,er->weight);
	sqlite3_bind_blob(db->sAddRecord,7,er->r->id,sizeof(er->r->id),SQLITE_STATIC);
	sqlite3_bind_blob(db->sAddRecord,8,er->r->owner,sizeof(er->r->owner),SQLITE_STATIC);
	sqlite3_bind_blob(db->sAddRecord,9,er->hash,32,SQLITE_STATIC);
	bool haveNewOwner = false;
	for(int i=0;i<2;++i) {
		if (er->metaDataType[i] == ZTLF_RECORD_METADATA_CHANGE_OWNER) {
			sqlite3_bind_blob(db->sAddRecord,10,er->metaData[i],er->metaDataSize[i],SQLITE_STATIC);
			haveNewOwner = true;
			break; /* only one of these per record is meaningful -- second is ignored if present */
		}
	}
	if (!haveNewOwner)
		sqlite3_bind_null(db->sAddRecord,10);
	int selectorColIdx = 11;
	for(int i=0;i<2;++i) {
		if (er->metaDataType[i] == ZTLF_RECORD_METADATA_SELECTOR)
			sqlite3_bind_blob(db->sAddRecord,selectorColIdx++,er->metaData[i],er->metaDataSize[i],SQLITE_STATIC);
	}
	while (selectorColIdx < 13)
		sqlite3_bind_null(db->sAddRecord,selectorColIdx++);
	if ((e = sqlite3_step(db->sAddRecord)) != SQLITE_DONE) {
		result = ZTLF_POS(e);
		goto exit_putRecord;
	}

	/* Initialize this record's graph node with its initial weight and links. */
	ZTLF_L_trace("resolving %u links from %s",er->linkCount,ZTLF_hexstr(er->hash,32,0));
	ZTLF_setdbl_le(graphNode->totalWeight,er->weight);
	graphNode->linkCount = (uint8_t)er->linkCount;
	for(unsigned int i=0,j=er->linkCount;i<j;++i) {
		const uint8_t *const l = ((const uint8_t *)er->links) + (i * 32);
		sqlite3_reset(db->sGetRecordGoffByHash);
		sqlite3_bind_blob(db->sGetRecordGoffByHash,1,l,32,SQLITE_STATIC);
		if (sqlite3_step(db->sGetRecordGoffByHash) == SQLITE_ROW) {
			ZTLF_set64_le(graphNode->linkedRecordGoff[i],sqlite3_column_int64(db->sGetRecordGoffByHash,0));
		} else {
			ZTLF_L_trace("linked record %s does not exist, adding to dangling links and adding or resetting wanted hash",ZTLF_hexstr(l,32,0));

			ZTLF_set64_le(graphNode->linkedRecordGoff[i],-1LL);

			/* Dangling links specifically document this record's unfulfilled links. */
			sqlite3_reset(db->sAddDanglingLink);
			sqlite3_bind_blob(db->sAddDanglingLink,1,l,32,SQLITE_STATIC);
			sqlite3_bind_int64(db->sAddDanglingLink,2,goff);
			sqlite3_bind_int(db->sAddDanglingLink,3,i);
			if ((e = sqlite3_step(db->sAddDanglingLink)) != SQLITE_DONE) {
				ZTLF_L_warning("database error adding dangling link: %d (%s)",e,sqlite3_errmsg(db->dbc));
			}

			/* Wanted hash records track attempts to get records. */
			sqlite3_reset(db->sAddWantedHash);
			sqlite3_bind_blob(db->sAddWantedHash,1,l,32,SQLITE_STATIC);
			if ((e = sqlite3_step(db->sAddWantedHash)) != SQLITE_DONE) {
				ZTLF_L_warning("database error adding/resetting wanted hash: %d (%s)",e,sqlite3_errmsg(db->dbc));
			}
		}
	}

	/* Update graph nodes of any records linking to this record with this record's graph node offset. */
	sqlite3_reset(db->sGetDanglingLinks);
	sqlite3_bind_blob(db->sGetDanglingLinks,1,er->hash,32,SQLITE_STATIC);
	ZTLF_L_trace("updating graph nodes of parent records with dangling links to %s",ZTLF_hexstr(er->hash,32,0));
	while (sqlite3_step(db->sGetDanglingLinks) == SQLITE_ROW) {
		const int64_t linkingGoff = sqlite3_column_int64(db->sGetDanglingLinks,0);
		struct ZTLF_DB_GraphNode *const linkingRecordGraphNode = (struct ZTLF_DB_GraphNode *)(db->gfm + (uintptr_t)linkingGoff);
		for(unsigned int j=0,k=linkingRecordGraphNode->linkCount;j<k;++j) {
			int64_t lrgoff;
			ZTLF_set64_le(lrgoff,linkingRecordGraphNode->linkedRecordGoff[j]);
			if (lrgoff < 0) {
				ZTLF_L_trace("updated graph node @%lld with pointer to this record's graph node",(long long)linkingGoff);
				ZTLF_set64_le(linkingRecordGraphNode->linkedRecordGoff[j],goff);
				break;
			}
		}
	}

	/* Delete dangling link records referencing this record. */
	sqlite3_reset(db->sDeleteDanglingLinks);
	sqlite3_bind_blob(db->sDeleteDanglingLinks,1,er->hash,32,SQLITE_STATIC);
	if ((e = sqlite3_step(db->sDeleteDanglingLinks)) != SQLITE_DONE) {
		ZTLF_L_warning("database error deleting dangling links: %d (%s)",e,sqlite3_errmsg(db->dbc));
	}

	/* Delete wanted record entries for this record. */
	sqlite3_reset(db->sDeleteWantedHash);
	sqlite3_bind_blob(db->sDeleteWantedHash,1,er->hash,32,SQLITE_STATIC);
	if ((e = sqlite3_step(db->sDeleteWantedHash)) != SQLITE_DONE) {
		ZTLF_L_warning("database error deleting wanted hash: %d (%s)",e,sqlite3_errmsg(db->dbc));
	}

	/* Flag this record as needing graph traversal and weight application. */
	if (er->linkCount > 0) {
		sqlite3_reset(db->sFlagRecordWeightApplicationPending);
		sqlite3_bind_int64(db->sFlagRecordWeightApplicationPending,1,goff);
		sqlite3_bind_int(db->sFlagRecordWeightApplicationPending,2,-1); /* hole count of -1 means new */
		if ((e = sqlite3_step(db->sFlagRecordWeightApplicationPending)) != SQLITE_DONE) {
			ZTLF_L_warning("database error flagging record as needing weight application: %d (%s)",e,sqlite3_errmsg(db->dbc));
		}
	}

exit_putRecord:
	pthread_mutex_unlock(&db->gfLock);
	pthread_mutex_unlock(&db->dbcLock);

	return result;
}

bool ZTLF_DB_hasGraphPendingRecords(struct ZTLF_DB *db)
{
	bool canHas = false;
	pthread_mutex_lock(&db->dbcLock);
	sqlite3_reset(db->sGetRecordsForWeightApplication);
	if (sqlite3_step(db->sGetRecordsForWeightApplication) == SQLITE_ROW) {
		canHas = true;
	}
	pthread_mutex_unlock(&db->dbcLock);
	return canHas;
}
