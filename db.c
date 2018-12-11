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

#define ZTLF_GRAPH_FILE_CAPACITY_INCREMENT 16777216
#define ZTLF_DATA_FILE_CAPACITY_INCREMENT 16777216

/**
 * Graph node flag indicating that this record is a suspicious-looking conflicting entry with an existing set of IDs.
 */
#define ZTLF_DB_GRAPH_NODE_FLAG_SUSPICIOUS 0x01

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
	volatile uint64_t weightL; /* least significant 16 bits of 80-bit weight */
	volatile uint16_t weightH; /* most significant 16 bits of 80-bit weight */
	uint8_t flags;             /* flags is the OR of this node's flags and the flags of all nodes below it */
	uint8_t linkCount;         /* size of linkedRecordGoff[] */
	volatile int64_t linkedRecordGoff[];
});

#define ZTLF_DB_MAX_GRAPH_NODE_SIZE (sizeof(struct ZTLF_DB_GraphNode) + (256 * sizeof(int64_t)))

/* Structure used for tracking sets of connected records under a common owner for EachByID etc. */
struct ZTLF_DB_BestRecord
{
	uint64_t weight[2]; /* 128-bit, little-endian QW order */
	uint64_t prevExp;
	uint64_t doff;
	unsigned int dlen;
};

/* Used for checking to see if a record is suspicious or not in graph thread. */
struct ZTLF_DB_BestRecordWithTimeRange
{
	uint64_t weight[2]; /* 128-bit, little-endian QW order */
	uint64_t prevExp;
	uint64_t firstTimestamp;
	uint64_t lastTimestamp;
	bool isThisOwner;
};

/*
 * record
 *   doff                     offset of record data in 'records' flat file (unique primary key)
 *   dlen                     length of record data
 *   goff                     offset of graph node in memory mapped graph file (unique key)
 *   ts                       record timestamp in seconds since epoch
 *   exp                      record expiration time in seconds since epoch
 *   score                    score of this record
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
 * linkable
 *   record_goff              graph offset of record that is now clear for linking
 *   record_ts                timestamp field mirrored from record table for fast sort/select
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
"PRAGMA cache_size = -262144;\n" \
"PRAGMA synchronous = 0;\n" \
"PRAGMA auto_vacuum = 0;\n" \
"PRAGMA foreign_keys = OFF;\n" \
"PRAGMA automatic_index = OFF;\n" \
"PRAGMA threads = 0;\n" \
\
"CREATE TABLE IF NOT EXISTS config (\"k\" TEXT PRIMARY KEY NOT NULL,\"v\" BLOB NOT NULL) WITHOUT ROWID;\n" \
\
"CREATE TABLE IF NOT EXISTS record (" \
"doff INTEGER PRIMARY KEY NOT NULL," \
"dlen INTEGER NOT NULL," \
"goff INTEGER NOT NULL," \
"ts INTEGER NOT NULL," \
"exp INTEGER NOT NULL," \
"score INTEGER NOT NULL," \
"id BLOB(32) NOT NULL," \
"owner BLOB(32) NOT NULL," \
"hash BLOB(32) NOT NULL," \
"new_owner BLOB(32)," \
"sel0 BLOB(32)," \
"sel1 BLOB(32)" \
") WITHOUT ROWID;\n" \
\
"CREATE UNIQUE INDEX IF NOT EXISTS record_goff ON record(goff);\n" \
"CREATE UNIQUE INDEX IF NOT EXISTS record_hash ON record(hash);\n" \
"CREATE INDEX IF NOT EXISTS record_id_ts ON record(id,ts);\n" \
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
"CREATE TABLE IF NOT EXISTS linkable (" \
"record_goff INTEGER PRIMARY KEY NOT NULL," \
"record_ts INTEGER NOT NULL" \
") WITHOUT ROWID;\n" \
\
"CREATE INDEX IF NOT EXISTS linkable_record_ts ON linkable(record_ts);\n" \
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

/*
 * The graph thread grabs records that need their weights applied to records below them and
 * traverses the graph along the path of links. If it encounters holes it logs them and
 * does everything it can, returning to do the parts it couldn't do on a later iteration. A
 * record will be revisited until all its weight can be applied with no holes.
 * 
 * Right now this algorithm is designed to be run in a single thread. Just creating more of
 * these threads would create a multiple-application problem. This could be fixed by using
 * a queue and enqueueing the results of sGetRecordsForWeightApplication for a pool of
 * workers. It's fast enough for now, so this can be done in the future if necessary.
 */
static void *_ZTLF_DB_graphThreadMain(void *arg)
{
	struct ZTLF_DB *const db = (struct ZTLF_DB *)arg;
	uint64_t hk[2];
	struct ZTLF_Vector_i64 recordQueue,graphTraversalQueue;
	struct ZTLF_Map128 holes;
	struct ZTLF_Map256 byOwner;
	struct ZTLF_ISet *const visited = ZTLF_ISet_new();
	ZTLF_Vector_i64_Init(&graphTraversalQueue,2097152);
	ZTLF_Vector_i64_Init(&recordQueue,1024);
	ZTLF_Map128_init(&holes,128,NULL);
	ZTLF_Map256_init(&byOwner,16,free);

	while (db->running) {
		/* Sleep briefly between each pending record query as these are somewhat expensive. */
		usleep(100000);
		if (!db->running) goto end_graph_thread;
		usleep(100000);
		if (!db->running) goto end_graph_thread;

		/* Get records that are pending because they're new or some of their holes appear filled. */
		ZTLF_Vector_i64_Clear(&recordQueue);
		pthread_mutex_lock(&db->dbLock);
		sqlite3_reset(db->sGetRecordsForWeightApplication);
		while (sqlite3_step(db->sGetRecordsForWeightApplication) == SQLITE_ROW) {
			ZTLF_Vector_i64_Append(&recordQueue,sqlite3_column_int64(db->sGetRecordsForWeightApplication,0));
		}
		pthread_mutex_unlock(&db->dbLock);

		if (recordQueue.size > 0) {
			ZTLF_L_trace("graph: found %lu records to process",recordQueue.size);
		} else {
			continue;
		}

		while ((recordQueue.size > 0)&&(db->running)) {
			const int64_t waitingGoff = recordQueue.v[recordQueue.size-1];
			--recordQueue.size;
			/* ZTLF_L_trace("graph: adjusting weights for records below graph node %lld",(long long)waitingGoff); */

			/* Get record score and any previously known holes in the graph below this node. */
			long holeCount = 0;
			uint64_t score = 0;
			ZTLF_Map128_clear(&holes);
			pthread_mutex_lock(&db->dbLock);
			sqlite3_reset(db->sGetRecordScoreByGoff);
			sqlite3_bind_int64(db->sGetRecordScoreByGoff,1,waitingGoff);
			if (sqlite3_step(db->sGetRecordScoreByGoff) == SQLITE_ROW) {
				score = (uint64_t)sqlite3_column_int64(db->sGetRecordScoreByGoff,0);
			}
			sqlite3_reset(db->sGetHoles);
			sqlite3_bind_int64(db->sGetHoles,1,waitingGoff);
			while (sqlite3_step(db->sGetHoles) == SQLITE_ROW) {
				hk[0] = (uint64_t)sqlite3_column_int64(db->sGetHoles,0);
				hk[1] = (uint64_t)sqlite3_column_int(db->sGetHoles,1);
				ZTLF_Map128_set(&holes,hk,(void *)1);
				/* ZTLF_L_trace("graph: graph below %lld previously led to hole at %llu[%llu]",(long long)waitingGoff,(unsigned long long)hk[0],(unsigned long long)hk[1]); */
				++holeCount;
			}
			pthread_mutex_unlock(&db->dbLock);

			ZTLF_ISet_clear(visited);
			ZTLF_Vector_i64_Clear(&graphTraversalQueue);

			pthread_rwlock_rdlock(&db->gfLock);

			/* Initialize queue and weight from this record's node to start graph traversal. */
			struct ZTLF_DB_GraphNode *graphNode = (struct ZTLF_DB_GraphNode *)ZTLF_MappedFile_TryGet(&db->gf,(uintptr_t)waitingGoff,ZTLF_DB_MAX_GRAPH_NODE_SIZE);
			bool nodeIncomplete = false;
			if (graphNode) {
				hk[0] = (uint64_t)waitingGoff;
				for(unsigned int i=0,j=graphNode->linkCount;i<j;++i) {
					hk[1] = (uint64_t)i;
					if (!ZTLF_Map128_get(&holes,hk)) {
						const int64_t nextGoff = ZTLF_get64_le(graphNode->linkedRecordGoff[i]);
						if (nextGoff >= 0) {
							ZTLF_Vector_i64_Append(&graphTraversalQueue,nextGoff);
						} else {
							ZTLF_L_warning("graph: found unexpected dangling link (immediate hole) in %lld",waitingGoff);
							pthread_mutex_lock(&db->dbLock);
							sqlite3_reset(db->sAddHole);
							sqlite3_bind_int64(db->sAddHole,1,waitingGoff);
							sqlite3_bind_int64(db->sAddHole,2,waitingGoff);
							sqlite3_bind_int(db->sAddHole,3,i);
							int err = sqlite3_step(db->sAddHole);
							pthread_mutex_unlock(&db->dbLock);
							if (err != SQLITE_DONE) {
								ZTLF_L_warning("graph: error adding hole record: %d (%s)",err,ZTLF_DB_LastSqliteErrorMessage(db));
							}
							nodeIncomplete = true;
						}
					}
				}
			} else {
				ZTLF_L_warning("graph: seek to known graph file offset %lld failed, database may be corrupt!",(long long)waitingGoff);
				pthread_rwlock_unlock(&db->gfLock);
				continue;
			}
			if (nodeIncomplete) {
				ZTLF_L_warning("graph: record for graph node at %lld is incomplete, skipping (this should not happen!)",(long long)waitingGoff);
				pthread_rwlock_unlock(&db->gfLock);
				continue;
			}

			/* OR of all flags of all graph nodes below this one. */
			uint8_t graphNodeFlags = 0;

			/* If there are holes then we have to make a first pass and visit all the nodes we visited last time.
			 * This is done by traversing the graph, marking visited nodes in the visited set, making no weight
			 * adjustments, and skipping where the holes were previously. This reconstructs the visited set to
			 * avoid adjusting weights on previously visited nodes a second time. */
			if (holeCount > 0) {
				/* ZTLF_L_trace("graph: node %lld has %d holes, performing no-op pass starting with %lu nodes to regenerate visited node set",waitingGoff,holeCount,graphTraversalQueue.size); */
				for(unsigned long i=0;i<graphTraversalQueue.size;) {
					const int64_t goff = graphTraversalQueue.v[i++];
					if (ZTLF_ISet_put(visited,goff)) {
						struct ZTLF_DB_GraphNode *const gn = (struct ZTLF_DB_GraphNode *)ZTLF_MappedFile_TryGet(&db->gf,(uintptr_t)goff,ZTLF_DB_MAX_GRAPH_NODE_SIZE);
						if (gn) {
							hk[0] = (uint64_t)goff;
							for(unsigned int i=0,j=gn->linkCount;i<j;++i) {
								hk[1] = (uint64_t)i;
								if (!ZTLF_Map128_get(&holes,hk)) {
									graphNodeFlags |= gn->flags;

									const int64_t nextGoff = ZTLF_get64_le(gn->linkedRecordGoff[i]);
									if (nextGoff >= 0) {
										ZTLF_Vector_i64_Append(&graphTraversalQueue,nextGoff);
									} else {
										ZTLF_L_warning("graph: found unexpected hole in graph below %lld at %lld[%u] (should have been previously marked, marking now)",(long long)waitingGoff,(long long)goff,i);
										pthread_mutex_lock(&db->dbLock);
										sqlite3_reset(db->sAddHole);
										sqlite3_bind_int64(db->sAddHole,1,waitingGoff);
										sqlite3_bind_int64(db->sAddHole,2,goff);
										sqlite3_bind_int(db->sAddHole,3,i);
										int err = sqlite3_step(db->sAddHole);
										pthread_mutex_unlock(&db->dbLock);
										if (err != SQLITE_DONE) {
											ZTLF_L_warning("graph: error adding hole record: %d (%s)",err,ZTLF_DB_LastSqliteErrorMessage(db));
										}
										++holeCount;
									}
								}
							}
						} else {
							ZTLF_L_warning("graph: seek to known graph file offset %lld failed, database may be corrupt!",(long long)goff);
						}

						if (i >= 1048576) { /* compact queue periodically to save memory */
							memmove(graphTraversalQueue.v,graphTraversalQueue.v + i,sizeof(int64_t) * (graphTraversalQueue.size -= i));
							i = 0;
						}
					}
				}

				/* Reset graph traversal queue after no-op pass. */
				ZTLF_Vector_i64_Clear(&graphTraversalQueue);

				/* Add any now-filled holes to graph traversal queue for adjustment pass and delete hole records for them. */
				ZTLF_Map128_each(&holes,{
					struct ZTLF_DB_GraphNode *const gn = (struct ZTLF_DB_GraphNode *)ZTLF_MappedFile_TryGet(&db->gf,(uintptr_t)ztlfMapKey[0],ZTLF_DB_MAX_GRAPH_NODE_SIZE);
					if (gn) {
						const int64_t goff = ZTLF_get64_le(gn->linkedRecordGoff[(uintptr_t)ztlfMapKey[1]]);
						if (goff >= 0) {
							/* ZTLF_L_trace("graph: hole below %lld at %llu[%u] is now filled with pointer to %lld",(long long)waitingGoff,(unsigned long long)ztlfMapKey[0],(unsigned int)ztlfMapKey[1],(long long)goff); */
							ZTLF_Vector_i64_Append(&graphTraversalQueue,goff);
							pthread_mutex_lock(&db->dbLock);
							sqlite3_reset(db->sDeleteHole);
							sqlite3_bind_int64(db->sDeleteHole,1,waitingGoff);
							sqlite3_bind_int64(db->sDeleteHole,2,(sqlite_int64)ztlfMapKey[0]);
							sqlite3_bind_int(db->sDeleteHole,3,(int)ztlfMapKey[1]);
							int err = sqlite3_step(db->sDeleteHole);
							pthread_mutex_unlock(&db->dbLock);
							if (err != SQLITE_DONE) {
								ZTLF_L_warning("graph: error deleting hole record: %d (%s)",err,ZTLF_DB_LastSqliteErrorMessage(db));
							}
							--holeCount;
						}
					} else {
						ZTLF_L_warning("graph: seek to known graph file offset %llu failed, database may be corrupt!",(unsigned long long)ztlfMapKey[0]);
					}
				});
			}

			/* Weight adjustment pass! If this is the first pass (no holes) we'll mark any holes we find. If this is
			 * a second pass we'll be starting at the now-filled holes we found last time. */
			for(unsigned long i=0;i<graphTraversalQueue.size;) {
				const int64_t goff = graphTraversalQueue.v[i++];
				if (ZTLF_ISet_put(visited,goff)) {
					struct ZTLF_DB_GraphNode *const gn = (struct ZTLF_DB_GraphNode *)ZTLF_MappedFile_TryGet(&db->gf,(uintptr_t)goff,ZTLF_DB_MAX_GRAPH_NODE_SIZE);
					if (gn) {
						/* Add score to graph node weight. */
						uint64_t wL = ZTLF_getu64_le(gn->weightL);
						uint16_t wH = ZTLF_getu16_le(gn->weightH);
						const uint64_t wLorig = wL;
						const uint16_t wHorig = wH;
						wH += (uint32_t)((wL += score) < wLorig);
						ZTLF_setu64_le(gn->weightL,wL);
						if (wH != wHorig) { ZTLF_setu16_le(gn->weightH,wH); }

						graphNodeFlags |= gn->flags;

						for(unsigned int i=0,j=gn->linkCount;i<j;++i) {
							const int64_t nextGoff = ZTLF_get64_le(gn->linkedRecordGoff[i]);
							if (nextGoff >= 0) {
								ZTLF_Vector_i64_Append(&graphTraversalQueue,nextGoff);
							} else {
								/* ZTLF_L_trace("graph: found hole below %lld at %lld[%u]",(long long)waitingGoff,(long long)goff,i); */
								pthread_mutex_lock(&db->dbLock);
								sqlite3_reset(db->sAddHole);
								sqlite3_bind_int64(db->sAddHole,1,waitingGoff);
								sqlite3_bind_int64(db->sAddHole,2,goff);
								sqlite3_bind_int(db->sAddHole,3,i);
								int err = sqlite3_step(db->sAddHole);
								pthread_mutex_unlock(&db->dbLock);
								if (err != SQLITE_DONE) {
									ZTLF_L_warning("graph: error adding hole record: %d (%s)",err,ZTLF_DB_LastSqliteErrorMessage(db));
								}
								++holeCount;
							}
						}
					} else {
						ZTLF_L_warning("graph: seek to known graph file offset %lld failed, database may be corrupt!",(long long)goff);
					}

					if (i >= 1048576) { /* compact queue periodically to save memory */
						memmove(graphTraversalQueue.v,graphTraversalQueue.v + i,sizeof(int64_t) * (graphTraversalQueue.size -= i));
						i = 0;
					}
				}
			}

			if (holeCount < 0) { /* sanity check, should be impossible */
				ZTLF_L_warning("graph: record with graph node at %lld has NEGATIVE hole count %ld (should not be possible!)",(long long)waitingGoff,holeCount);
				holeCount = -1; /* force this node to be picked up and processed again */
			}

			if (holeCount == 0) {
				/* If there are no more holes the record is complete. Determine if this record looks in any way
				 * suspect. If not, flag it as linkable so it will be suggested as a link for new records. Also
				 * delete pending record entry since the graph thread is done with it. */
				uint8_t rid[32],rowner[32],rhash[32];
				uint64_t o[4],no[4];
				uint64_t linkableRecordTs = 0;
				uint8_t bestOwner[32];
				uint64_t bestWeight[2] = { 0,0 };

				pthread_mutex_lock(&db->dbLock);

				sqlite3_reset(db->sGetRecordInfoByGoff);
				sqlite3_bind_int64(db->sGetRecordInfoByGoff,1,waitingGoff);
				if (sqlite3_step(db->sGetRecordInfoByGoff) == SQLITE_ROW) {
					linkableRecordTs = (uint64_t)sqlite3_column_int64(db->sGetRecordInfoByGoff,0);
					memcpy(rid,sqlite3_column_blob(db->sGetRecordInfoByGoff,1),32);
					memcpy(rowner,sqlite3_column_blob(db->sGetRecordInfoByGoff,2),32);
					memcpy(rhash,sqlite3_column_blob(db->sGetRecordInfoByGoff,3),32);
				}

				if (linkableRecordTs > 0) {
					if ((graphNodeFlags & ZTLF_DB_GRAPH_NODE_FLAG_SUSPICIOUS) == 0) {
						sqlite3_reset(db->sGetRecordHistoryById);
						sqlite3_bind_blob(db->sGetRecordHistoryById,1,rid,32,SQLITE_STATIC);
						while (sqlite3_step(db->sGetRecordHistoryById) == SQLITE_ROW) {
							const uint64_t ts = (uint64_t)sqlite3_column_int64(db->sGetRecordHistoryById,3);

							memcpy(o,sqlite3_column_blob(db->sGetRecordHistoryById,5),32);
							struct ZTLF_DB_BestRecordWithTimeRange *br = (struct ZTLF_DB_BestRecordWithTimeRange *)ZTLF_Map256_get(&byOwner,o);
							if (!br) {
								ZTLF_MALLOC_CHECK(br = (struct ZTLF_DB_BestRecordWithTimeRange *)malloc(sizeof(struct ZTLF_DB_BestRecordWithTimeRange)));
								memset(br,0,sizeof(struct ZTLF_DB_BestRecordWithTimeRange));
								ZTLF_Map256_set(&byOwner,o,(void *)br);
								br->firstTimestamp = ts;
								br->isThisOwner = (memcmp(o,rowner,32) == 0);
							}

							const void *newOwner = sqlite3_column_blob(db->sGetRecordHistoryById,6);
							if (newOwner) {
								memcpy(no,newOwner,32);
								ZTLF_Map256_rename(&byOwner,o,no);
							}

							if (ts >= br->prevExp) { /* if there's a gap in a set of records for a given owner that exceeds expiration, reset weight */
								if (br->lastTimestamp == 0)
									br->lastTimestamp = ts;
								if ((linkableRecordTs >= br->firstTimestamp)&&(linkableRecordTs <= br->lastTimestamp)) {
									/* Freeze this owner entry if the record we're interested in overlaps with its time range, since
									 * it's one of the sets we will want to compare against. */
									continue;
								} else {
									br->firstTimestamp = ts;
									br->lastTimestamp = 0;
									br->weight[0] = 0;
									br->weight[1] = 0;
								}
							}
							br->prevExp = (uint64_t)sqlite3_column_int64(db->sGetRecordHistoryById,4);

							const struct ZTLF_DB_GraphNode *const gn = (struct ZTLF_DB_GraphNode *)ZTLF_MappedFile_TryGet(&db->gf,(uintptr_t)sqlite3_column_int64(db->sGetRecordHistoryById,2),ZTLF_DB_MAX_GRAPH_NODE_SIZE);
							if (gn) {
								const uint64_t wL = ZTLF_getu64_le(gn->weightL);
								const uint64_t w0orig = br->weight[0];
								br->weight[1] += ((uint64_t)((br->weight[0] += wL) < w0orig)) + (uint64_t)(ZTLF_getu16_le(gn->weightH));
							} else {
								ZTLF_L_warning("cannot seek to known graph file offset %lld, database may be corrupt",(long long)sqlite3_column_int64(db->sGetRecordHistoryById,2));
							}
						}

						bool bestIsThisOwner = true;

						ZTLF_Map256_eachAndClear(&byOwner,{
							const struct ZTLF_DB_BestRecordWithTimeRange *const br = (const struct ZTLF_DB_BestRecordWithTimeRange *)ztlfMapValue;
							if ( (linkableRecordTs >= br->firstTimestamp) && ((linkableRecordTs <= br->lastTimestamp)||(br->lastTimestamp == 0)) ) {
								if ( (br->weight[1] > bestWeight[1]) || ((br->weight[1] == bestWeight[1])&&(br->weight[0] > bestWeight[0])) ) {
									memcpy(bestOwner,ztlfMapKey,32);
									bestWeight[0] = br->weight[0];
									bestWeight[1] = br->weight[1];
									bestIsThisOwner = br->isThisOwner;
								}
							}
						});

						if (bestIsThisOwner) {
							sqlite3_reset(db->sAddLinkable);
							sqlite3_bind_int64(db->sAddLinkable,1,waitingGoff);
							sqlite3_bind_int64(db->sAddLinkable,2,(sqlite_int64)linkableRecordTs);
							if (sqlite3_step(db->sAddLinkable) != SQLITE_DONE) {
								ZTLF_L_warning("graph: error flagging record as linkable");
							}
						} else {
							graphNodeFlags |= ZTLF_DB_GRAPH_NODE_FLAG_SUSPICIOUS;
							ZTLF_L_warning("graph: record hash %s (ID %s owner %s) with graph node at %lld flagged as suspect and not linkable: conflicts with dominant record set owned by %s",ZTLF_hexstr(rhash,32,0),ZTLF_hexstr(rid,32,1),ZTLF_hexstr(rowner,32,2),(long long)waitingGoff,ZTLF_hexstr(bestOwner,32,3));
						}
					} else {
						ZTLF_L_warning("graph: record hash %s (ID %s owner %s) with graph node at %lld flagged as suspect and not linkable: linked graph contains at least one suspect record",ZTLF_hexstr(rhash,32,0),ZTLF_hexstr(rid,32,1),ZTLF_hexstr(rowner,32,2),(long long)waitingGoff);
					}
				} else {
					graphNodeFlags |= ZTLF_DB_GRAPH_NODE_FLAG_SUSPICIOUS;
					ZTLF_L_warning("graph: record with graph node at %lld seems to lack a record ID, database may be corrupt!",(long long)waitingGoff);
				}

				sqlite3_reset(db->sDeleteCompletedPending);
				sqlite3_bind_int64(db->sDeleteCompletedPending,1,waitingGoff);
				if (sqlite3_step(db->sDeleteCompletedPending) != SQLITE_DONE) {
					ZTLF_L_warning("graph: error deleting complete pending record %lld",(long long)waitingGoff);
				}

				pthread_mutex_unlock(&db->dbLock);
			} else {
				/* If there are still holes, update the hole count and keep record in queue so it will be checked again when at least some holes are filled. */
				pthread_mutex_lock(&db->dbLock);
				sqlite3_reset(db->sUpdatePendingHoleCount);
				sqlite3_bind_int64(db->sUpdatePendingHoleCount,1,(int64_t)holeCount);
				sqlite3_bind_int64(db->sUpdatePendingHoleCount,2,waitingGoff);
				int err = sqlite3_step(db->sUpdatePendingHoleCount);
				pthread_mutex_unlock(&db->dbLock);
				if (err != SQLITE_DONE) {
					ZTLF_L_warning("graph: error updating pending hole count: %d (%s)",err,ZTLF_DB_LastSqliteErrorMessage(db));
				}
			}

			graphNode->flags = graphNodeFlags;

			pthread_rwlock_unlock(&db->gfLock);
		}
	}

end_graph_thread:
	ZTLF_Map256_destroy(&byOwner);
	ZTLF_Map128_destroy(&holes);
	ZTLF_Vector_i64_Free(&recordQueue);
	ZTLF_Vector_i64_Free(&graphTraversalQueue);
	ZTLF_ISet_free(visited);

	return NULL;
}

int ZTLF_DB_Open(struct ZTLF_DB *db,const char *path)
{
	char tmp[PATH_MAX];
	int e = 0;

	ZTLF_L_trace("opening database at %s",path);

	if (strlen(path) >= (PATH_MAX - 16))
		return ZTLF_NEG(ENAMETOOLONG);
	memset(db,0,sizeof(struct ZTLF_DB));
	strncpy(db->path,path,PATH_MAX-1);
	db->graphThreadStarted = false;
	pthread_mutex_init(&db->dbLock,NULL);
	for(int i=0;i<ZTLF_DB_GRAPH_NODE_LOCK_ARRAY_SIZE;++i)
		pthread_mutex_init(&db->graphNodeLocks[i],NULL);
	pthread_rwlock_init(&db->gfLock,NULL);
	pthread_rwlock_init(&db->dfLock,NULL);

	mkdir(path,0755);

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
	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT INTO record (doff,dlen,goff,ts,exp,score,id,owner,hash,new_owner,sel0,sel1) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",-1,&db->sAddRecord,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Get all records in hash order for database consistency checking and testing. */
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT goff,hash FROM record ORDER BY hash ASC",-1,&db->sGetAllRecords,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Get the current highest data file byte offset for any record (used to determine placement of next record). */
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT doff,dlen FROM record ORDER BY doff DESC LIMIT 1",-1,&db->sGetMaxRecordDoff,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Get the current highest graph node byte offset for any record (used to determine placement of next record). */
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT MAX(goff) FROM record",-1,&db->sGetMaxRecordGoff,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* List all complete records (with no dangling links) with a given ID in reverse timestamp (revision) order. */
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT r.doff,r.dlen,r.goff,r.ts,r.exp,r.owner,r.new_owner FROM record AS r WHERE r.id = ? AND (SELECT COUNT(1) FROM dangling_link AS dl WHERE dl.linking_record_goff = r.goff) = 0 ORDER BY r.ts ASC",-1,&db->sGetRecordHistoryById,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Get the graph node offset (byte offset in graph file) for a record. */
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT goff FROM record WHERE hash = ?",-1,&db->sGetRecordGoffByHash,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Get the score of a record by its graph node offset. */
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT score FROM record WHERE goff = ?",-1,&db->sGetRecordScoreByGoff,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Get the ID and owner of a record by its graph node offset. */
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT ts,id,owner,hash FROM record WHERE goff = ?",-1,&db->sGetRecordInfoByGoff,NULL)) != SQLITE_OK)
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
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT gp.record_goff FROM graph_pending AS gp WHERE (SELECT COUNT(1) FROM dangling_link AS dl1 WHERE dl1.linking_record_goff = gp.record_goff) = 0 AND (gp.hole_count <= 0 OR gp.hole_count != (SELECT COUNT(1) FROM hole AS h,dangling_link AS dl2 WHERE h.waiting_record_goff = gp.record_goff AND dl2.linking_record_goff = h.incomplete_goff AND dl2.linking_record_link_idx = h.incomplete_link_idx)) ORDER BY gp.record_goff ASC",-1,&db->sGetRecordsForWeightApplication,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Get known memorized holes in the graph below a given record from last graph iteration. */
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT incomplete_goff,incomplete_link_idx FROM hole WHERE waiting_record_goff = ?",-1,&db->sGetHoles,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Delete a now filled graph hole. */
	if ((e = sqlite3_prepare_v2(db->dbc,"DELETE FROM hole WHERE waiting_record_goff = ? AND incomplete_goff = ? AND incomplete_link_idx = ?",-1,&db->sDeleteHole,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Update the pending record with a new count of the number of holes in the graph beneath it. */
	if ((e = sqlite3_prepare_v2(db->dbc,"UPDATE graph_pending SET hole_count = ? WHERE record_goff = ?",-1,&db->sUpdatePendingHoleCount,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Delete pending record entry. */
	if ((e = sqlite3_prepare_v2(db->dbc,"DELETE FROM graph_pending WHERE record_goff = ?",-1,&db->sDeleteCompletedPending,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Get number of pending records. */
	if ((e = sqlite3_prepare_v2(db->dbc,"SELECT COUNT(1) FROM graph_pending",-1,&db->sGetPendingCount,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Flag a record as linkable. */
	if ((e = sqlite3_prepare_v2(db->dbc,"INSERT OR IGNORE INTO linkable (record_goff,record_ts) VALUES (?,?)",-1,&db->sAddLinkable,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/* Open and memory map graph and data files. */
	snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR "graph.bin",path);
	e = ZTLF_MappedFile_Open(&db->gf,tmp,ZTLF_GRAPH_FILE_CAPACITY_INCREMENT,ZTLF_GRAPH_FILE_CAPACITY_INCREMENT);
	if (e) {
		errno = e;
		e = 0;
		goto exit_with_error;
	}
	snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR "records.bin",path);
	e = ZTLF_MappedFile_Open(&db->df,tmp,ZTLF_GRAPH_FILE_CAPACITY_INCREMENT,ZTLF_GRAPH_FILE_CAPACITY_INCREMENT);
	if (e) {
		errno = e;
		e = 0;
		goto exit_with_error;
	}

	db->running = true;
	db->graphThread = ZTLF_threadCreate(&_ZTLF_DB_graphThreadMain,db,false);
	db->graphThreadStarted = true;

	return 0;

exit_with_error:
	ZTLF_DB_Close(db);
	return ((e) ? ZTLF_POS(e) : ZTLF_NEG(errno));
}

void ZTLF_DB_Close(struct ZTLF_DB *db)
{
	char tmp[PATH_MAX];

	db->running = false;
	if (db->graphThreadStarted)
		pthread_join(db->graphThread,NULL);

	for(int i=0;i<ZTLF_DB_GRAPH_NODE_LOCK_ARRAY_SIZE;++i)
		pthread_mutex_lock(&db->graphNodeLocks[i]);
	pthread_rwlock_wrlock(&db->gfLock);
	pthread_mutex_lock(&db->dbLock);

	ZTLF_L_trace("closing database at %s",db->path);

	if (db->dbc) {
		if (db->sAddRecord)                           sqlite3_finalize(db->sAddRecord);
		if (db->sGetAllRecords)                       sqlite3_finalize(db->sGetAllRecords);
		if (db->sGetMaxRecordDoff)                    sqlite3_finalize(db->sGetMaxRecordDoff);
		if (db->sGetMaxRecordGoff)                    sqlite3_finalize(db->sGetMaxRecordGoff);
		if (db->sGetRecordHistoryById)                sqlite3_finalize(db->sGetRecordHistoryById);
		if (db->sGetRecordGoffByHash)                 sqlite3_finalize(db->sGetRecordGoffByHash);
		if (db->sGetRecordScoreByGoff)                sqlite3_finalize(db->sGetRecordScoreByGoff);
		if (db->sGetRecordInfoByGoff)                 sqlite3_finalize(db->sGetRecordInfoByGoff);
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
		if (db->sGetPendingCount)                     sqlite3_finalize(db->sGetPendingCount);
		if (db->sAddLinkable)                         sqlite3_finalize(db->sAddLinkable);
		sqlite3_close_v2(db->dbc);
	}

	snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR "lf.pid",db->path);
	unlink(tmp);

	ZTLF_MappedFile_Close(&db->gf);
	ZTLF_MappedFile_Close(&db->df);

	pthread_mutex_unlock(&db->dbLock);
	pthread_rwlock_unlock(&db->gfLock);
	for(int i=0;i<ZTLF_DB_GRAPH_NODE_LOCK_ARRAY_SIZE;++i)
		pthread_mutex_unlock(&db->graphNodeLocks[i]);

	pthread_mutex_destroy(&db->dbLock);
	for(int i=0;i<ZTLF_DB_GRAPH_NODE_LOCK_ARRAY_SIZE;++i)
		pthread_mutex_destroy(&db->graphNodeLocks[i]);
	pthread_rwlock_destroy(&db->gfLock);
	pthread_rwlock_destroy(&db->dfLock);
}

void ZTLF_DB_EachByID(struct ZTLF_DB *const db,const void *id,void (*handler)(const uint64_t *,const struct ZTLF_Record *,unsigned int),const uint64_t cutoffTime)
{
	struct ZTLF_Map256 byOwner;
	uint64_t o[4],no[4];
	ZTLF_Map256_init(&byOwner,16,free);

	pthread_rwlock_rdlock(&db->gfLock);
	pthread_mutex_lock(&db->dbLock);

	sqlite3_reset(db->sGetRecordHistoryById);
	sqlite3_bind_blob(db->sGetRecordHistoryById,1,id,32,SQLITE_STATIC);
	while (sqlite3_step(db->sGetRecordHistoryById) == SQLITE_ROW) {
		memcpy(o,sqlite3_column_blob(db->sGetRecordHistoryById,5),32);
		struct ZTLF_DB_BestRecord *br = (struct ZTLF_DB_BestRecord *)ZTLF_Map256_get(&byOwner,o);
		if (!br) {
			ZTLF_MALLOC_CHECK(br = (struct ZTLF_DB_BestRecord *)malloc(sizeof(struct ZTLF_DB_BestRecord)));
			memset(br,0,sizeof(struct ZTLF_DB_BestRecord));
			ZTLF_Map256_set(&byOwner,o,(void *)br);
		}
		const void *newOwner = sqlite3_column_blob(db->sGetRecordHistoryById,6);
		if (newOwner) {
			memcpy(no,newOwner,32);
			ZTLF_Map256_rename(&byOwner,o,no);
		}

		const uint64_t ts = (uint64_t)sqlite3_column_int64(db->sGetRecordHistoryById,3);
		if (ts > cutoffTime) {
			break;
		} else if (ts >= br->prevExp) { /* if there's a gap in a set of records for a given owner that exceeds expiration, reset weight */
			br->weight[0] = 0;
			br->weight[1] = 0;
		}
		br->prevExp = (uint64_t)sqlite3_column_int64(db->sGetRecordHistoryById,4);

		br->doff = (uint64_t)sqlite3_column_int64(db->sGetRecordHistoryById,0);
		br->dlen = (unsigned int)sqlite3_column_int(db->sGetRecordHistoryById,1);

		const struct ZTLF_DB_GraphNode *const gn = (struct ZTLF_DB_GraphNode *)ZTLF_MappedFile_TryGet(&db->gf,(uintptr_t)sqlite3_column_int64(db->sGetRecordHistoryById,2),ZTLF_DB_MAX_GRAPH_NODE_SIZE);
		if (gn) {
			const uint64_t wL = ZTLF_getu64_le(gn->weightL);
			const uint64_t w0orig = br->weight[0];
			br->weight[1] += ((uint64_t)((br->weight[0] += wL) < w0orig)) + (uint64_t)(ZTLF_getu16_le(gn->weightH));
		} else {
			ZTLF_L_warning("cannot seek to known graph file offset %lld, database may be corrupt",(long long)sqlite3_column_int64(db->sGetRecordHistoryById,2));
		}
	}

	pthread_mutex_unlock(&db->dbLock);
	pthread_rwlock_unlock(&db->gfLock);

	const uint64_t now = ZTLF_timeMs();
	pthread_rwlock_rdlock(&db->dfLock);
	ZTLF_Map256_eachValueRO(&byOwner,{
		struct ZTLF_DB_BestRecord *const br = (struct ZTLF_DB_BestRecord *)ztlfMapValue;
		if (br->prevExp > now) {
			const void *r = ZTLF_MappedFile_TryGet(&db->df,(uintptr_t)br->doff,(uintptr_t)br->dlen);
			if (r) {
				handler(br->weight,(const struct ZTLF_Record *)r,br->dlen);
			} else {
				ZTLF_L_warning("cannot seek to expected position %lld in record data file, database may be corrupt",br->doff);
			}
		}
	});
	pthread_rwlock_unlock(&db->dfLock);

	ZTLF_Map256_destroy(&byOwner);
}

bool ZTLF_DB_LogOutgoingPeerConnectSuccess(struct ZTLF_DB *const db,const void *key_hash,const unsigned int address_type,const void *address,const unsigned int addressLength,const unsigned int port)
{
	bool r = true;
	pthread_mutex_lock(&db->dbLock);

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

	pthread_mutex_unlock(&db->dbLock);
	return r;
}

void ZTLF_DB_LogPotentialPeer(struct ZTLF_DB *const db,const void *key_hash,const unsigned int address_type,const void *address,const unsigned int addressLength,const unsigned int port)
{
	pthread_mutex_lock(&db->dbLock);
	sqlite3_reset(db->sAddPotentialPeer);
	sqlite3_bind_blob(db->sAddPotentialPeer,1,key_hash,48,SQLITE_STATIC);
	sqlite3_bind_blob(db->sAddPotentialPeer,2,address,addressLength,SQLITE_STATIC);
	sqlite3_bind_int(db->sAddPotentialPeer,3,(int)address_type);
	sqlite3_bind_int(db->sAddPotentialPeer,4,(int)port);
	sqlite3_step(db->sAddPotentialPeer);
	pthread_mutex_unlock(&db->dbLock);
}

int ZTLF_DB_PutRecord(struct ZTLF_DB *db,struct ZTLF_ExpandedRecord *const er)
{
	int e = 0,result = 0;

	if ((!er)||(er->size < ZTLF_RECORD_MIN_SIZE)||(er->size > ZTLF_RECORD_MAX_SIZE)) { /* sanity checks */
		return ZTLF_NEG(EINVAL);
	}

	pthread_rwlock_rdlock(&db->gfLock);
	pthread_mutex_lock(&db->dbLock);

	/* Locate new record's graph node and data file offset and copy new record into data file. Grow
	 * graph and data files if needed. */
	int64_t goff = 0;
	int64_t doff = 0;
	struct ZTLF_DB_GraphNode *graphNode = NULL;
	for(;;) {
		/* Place our graph node at the previous highest graph node's offset plus its size. */
		sqlite3_reset(db->sGetMaxRecordGoff);
		if (sqlite3_step(db->sGetMaxRecordGoff) == SQLITE_ROW) {
			const int64_t highestExistingGoff = sqlite3_column_int64(db->sGetMaxRecordGoff,0);
			graphNode = ZTLF_MappedFile_TryGet(&db->gf,(uintptr_t)highestExistingGoff,ZTLF_DB_MAX_GRAPH_NODE_SIZE);
			if (!graphNode) { /* sanity check, unlikely to impossible */
				ZTLF_L_warning("cannot seek to known graph file offset %lld, database may be corrupt",(long long)highestExistingGoff);
				result = ZTLF_ERR_DATABASE_MAY_BE_CORRUPT;
				goto exit_putRecord;
			} else {
				goff = highestExistingGoff + sizeof(struct ZTLF_DB_GraphNode) + (sizeof(int64_t) * (int64_t)graphNode->linkCount);
			}
		}

		/* Get pointer to graph node. If graph data file must be grown, grow and then repeat goff location determination. */
		graphNode = ZTLF_MappedFile_TryGet(&db->gf,(uintptr_t)goff,ZTLF_DB_MAX_GRAPH_NODE_SIZE);
		if (!graphNode) {
			pthread_mutex_unlock(&db->dbLock); /* unlock DB while growing to allow other holders of graph node file lock to finish so we can acquire write lock */
			pthread_rwlock_unlock(&db->gfLock);
			pthread_rwlock_wrlock(&db->gfLock);
			graphNode = (struct ZTLF_DB_GraphNode *)ZTLF_MappedFile_Get(&db->gf,(uintptr_t)goff,ZTLF_DB_MAX_GRAPH_NODE_SIZE);
			pthread_rwlock_unlock(&db->gfLock);
			if (!graphNode) {
				return ZTLF_NEG(EIO);
			}
			pthread_rwlock_rdlock(&db->gfLock);
			pthread_mutex_lock(&db->dbLock);
			continue;
		}

		/* Place record data in record data file at previous highest plus previous highest record size. */
		sqlite3_reset(db->sGetMaxRecordDoff);
		if (sqlite3_step(db->sGetMaxRecordDoff) == SQLITE_ROW) {
			doff = sqlite3_column_int64(db->sGetMaxRecordDoff,0) + sqlite3_column_int64(db->sGetMaxRecordDoff,1);
		}

		/* Copy data into record data file prefixed by record size, growing if needed. */
		pthread_rwlock_wrlock(&db->dfLock);
		uint8_t *rdata = (uint8_t *)ZTLF_MappedFile_Get(&db->df,(uintptr_t)doff,(uintptr_t)(er->size + 2));
		if (!rdata) {
			pthread_rwlock_unlock(&db->dfLock);
			result = ZTLF_NEG(EIO);
			goto exit_putRecord;
		}
		*(rdata++) = (uint8_t)((er->size >> 8) & 0xff);
		*(rdata++) = (uint8_t)(er->size & 0xff);
		doff += 2; /* size prefix isn't used here but is included so that record data file can be used to re-initialize the rest of the system or copied for distribution */
		memcpy(rdata,er->r,er->size);
		pthread_rwlock_unlock(&db->dfLock);

		break;
	}

	pthread_mutex_lock(&db->graphNodeLocks[((uintptr_t)goff) % ZTLF_DB_GRAPH_NODE_LOCK_ARRAY_SIZE]);

	/* Add main record entry. */
	sqlite3_reset(db->sAddRecord);
	sqlite3_bind_int64(db->sAddRecord,1,doff);
	sqlite3_bind_int64(db->sAddRecord,2,(sqlite3_int64)er->size);
	sqlite3_bind_int64(db->sAddRecord,3,goff);
	sqlite3_bind_int64(db->sAddRecord,4,(sqlite3_int64)er->timestamp);
	sqlite3_bind_int64(db->sAddRecord,5,(sqlite3_int64)er->expiration);
	sqlite3_bind_int64(db->sAddRecord,6,(sqlite3_int64)er->score);
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
	ZTLF_setu64_le(graphNode->weightL,er->score);
	ZTLF_setu16_le(graphNode->weightH,0);
	graphNode->flags = 0;
	graphNode->linkCount = (uint8_t)er->linkCount;
	for(unsigned int i=0,j=er->linkCount;i<j;++i) {
		const uint8_t *const l = ((const uint8_t *)er->links) + (i * 32);
		sqlite3_reset(db->sGetRecordGoffByHash);
		sqlite3_bind_blob(db->sGetRecordGoffByHash,1,l,32,SQLITE_STATIC);
		if (sqlite3_step(db->sGetRecordGoffByHash) == SQLITE_ROW) {
			ZTLF_set64_le(graphNode->linkedRecordGoff[i],sqlite3_column_int64(db->sGetRecordGoffByHash,0));
		} else {
			/* ZTLF_L_trace("linked record %s does not exist, adding to dangling links and adding or resetting wanted hash",ZTLF_hexstr(l,32,0)); */

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

	pthread_mutex_unlock(&db->graphNodeLocks[((uintptr_t)goff) % ZTLF_DB_GRAPH_NODE_LOCK_ARRAY_SIZE]);

	/* Update graph nodes of any records linking to this record with this record's graph node offset. */
	sqlite3_reset(db->sGetDanglingLinks);
	sqlite3_bind_blob(db->sGetDanglingLinks,1,er->hash,32,SQLITE_STATIC);
	while (sqlite3_step(db->sGetDanglingLinks) == SQLITE_ROW) {
		const int64_t linkingGoff = sqlite3_column_int64(db->sGetDanglingLinks,0);
		struct ZTLF_DB_GraphNode *const linkingRecordGraphNode = (struct ZTLF_DB_GraphNode *)ZTLF_MappedFile_TryGet(&db->gf,(uintptr_t)linkingGoff,ZTLF_DB_MAX_GRAPH_NODE_SIZE);
		pthread_mutex_t *const graphNodeLock = &db->graphNodeLocks[((uintptr_t)linkingGoff) % ZTLF_DB_GRAPH_NODE_LOCK_ARRAY_SIZE];
		pthread_mutex_lock(graphNodeLock);
		for(unsigned int j=0,k=linkingRecordGraphNode->linkCount;j<k;++j) {
			int64_t lrgoff;
			ZTLF_set64_le(lrgoff,linkingRecordGraphNode->linkedRecordGoff[j]);
			if (lrgoff < 0) {
				/* ZTLF_L_trace("updated graph node @%lld with pointer to this record's graph node",(long long)linkingGoff); */
				ZTLF_set64_le(linkingRecordGraphNode->linkedRecordGoff[j],goff);
				break;
			}
		}
		pthread_mutex_unlock(graphNodeLock);
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
	pthread_mutex_unlock(&db->dbLock);
	pthread_rwlock_unlock(&db->gfLock);
	return result;
}

bool ZTLF_DB_HasGraphPendingRecords(struct ZTLF_DB *db)
{
	bool canHas = false;
	pthread_mutex_lock(&db->dbLock);
	sqlite3_reset(db->sGetPendingCount);
	if (sqlite3_step(db->sGetPendingCount) == SQLITE_ROW)
		canHas = (sqlite3_column_int(db->sGetPendingCount,0) > 0);
	pthread_mutex_unlock(&db->dbLock);
	return canHas;
}

unsigned long ZTLF_DB_HashState(struct ZTLF_DB *db,uint8_t stateHash[48])
{
	unsigned long rc = 0;
	ZTLF_SHA384_CTX h;
	ZTLF_SHA384_init(&h);
	pthread_rwlock_wrlock(&db->gfLock); /* acquire exclusive lock to get the most objective result */
	pthread_mutex_lock(&db->dbLock);
	sqlite3_reset(db->sGetAllRecords);
	while (sqlite3_step(db->sGetAllRecords) == SQLITE_ROW) {
		++rc;
		const struct ZTLF_DB_GraphNode *const gn = (struct ZTLF_DB_GraphNode *)ZTLF_MappedFile_TryGet(&db->gf,(uintptr_t)sqlite3_column_int64(db->sGetAllRecords,0),ZTLF_DB_MAX_GRAPH_NODE_SIZE);
		if (gn) {
			ZTLF_SHA384_update(&h,&(gn->weightL),sizeof(gn->weightL));
			ZTLF_SHA384_update(&h,&(gn->weightH),sizeof(gn->weightH));
			ZTLF_SHA384_update(&h,sqlite3_column_blob(db->sGetAllRecords,1),32);
		}
	}
	pthread_mutex_unlock(&db->dbLock);
	pthread_rwlock_unlock(&db->gfLock);
	ZTLF_SHA384_final(&h,stateHash);
	return rc;
}
