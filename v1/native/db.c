/*
 * Copyright (c)2019 ZeroTier, Inc.
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file in the project's root directory.
 *
 * Change Date: 2023-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2.0 of the Apache License.
 */
/****/

#include "db.h"
#include "vector.h"
#include "iset.h"
#include "map.h"

/* Chunk size to increment nominal size of graph and data mmap files. */
#define ZTLF_GRAPH_FILE_CAPACITY_INCREMENT 33554432

/* Max MMAP size for SQLite -- disable on 32-bit systems */
#ifdef ZTLF_64BIT
#define ZTLF_DB_SQLITE_MMAP_SIZE "8589934592" /* 8gb */
#else
#define ZTLF_DB_SQLITE_MMAP_SIZE "0"
#endif

/* Cache size for SQLite */
#define ZTLF_DB_CACHE_SIZE "-131072"

/* A sanity limit on the number of records returned by a selector range query. */
#define ZTLF_DB_SELECTOR_QUERY_RESULT_LIMIT "4194304"

static void *_ZTLF_DB_graphThreadMain(void *arg);

/*
 * config
 *   k                        arbitrary config key
 *   v                        arbitrary config value
 *
 * record
 *   doff                     offset of record data in 'records' flat file (unique primary key)
 *   dlen                     length of record data
 *   goff                     offset of graph node in memory mapped graph file (unique key)
 *   rtype                    LF-internal record type ID
 *   ts                       record timestamp
 *   score                    score of this record (alone, not with weight from links)
 *   link_count               number of links from this record (actual links are in graph node)
 *   reputation               records will only be linked TO if greater than 0
 *   linked_count             number of records linking to this one
 *   hash                     shandwich256(record data) (unique key)
 *   id                       hash of selector IDs (a.k.a. all selector names)
 *   ckey                     CRC64 of all selector keys (a.k.a. all selector names+ordinals)
 *   owner                    owner of this record or NULL if same as previous
 *
 * cert
 *   subject_serial_no        subject serial (base62)
 *   serial_no                serial number (base62)
 *   record_doff              doff of record containing certificate
 *   certificate              DER encoded x509 certificate
 *
 * cert_revocation
 *   revoked_serial_no        revoked certificate serial (base62)
 *   record_doff              doff of record containing CRL
 *   record_dlen              dlen of record containing CRL
 *
 * limbo
 *   hash                     hash of record awaiting potential future authorization
 *   owner                    owner of record
 *   data                     record data
 *   receive_time             local record receive time in seconds since epoch
 *
 * comment
 *   subject                  subject of assertion
 *   by_record_doff           doff (key) of record containing comment
 *   assertion                assertion (see comment.go)
 *   reason                   reason (see comment.go)
 *
 * selector
 *   sel                      selector key (masked sortable ID)
 *   selidx                   selector index (which selector in record)
 *   record_ts                timestamp of record
 *   record_doff              offset of linked record
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
 *
 * pulse
 *   token                    64-bit pulse token (last in hash chain)
 *   current                  Current depth of hash chain
 *
 * pointer
 *   rowid                    Pointer record rowid (integer primary key)
 *   record_id                Parent record ID (32-byte hash)
 *   ts                       Pointer timestamp
 *   data                     Pointer data (raw blob)
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
"PRAGMA cache_size = " ZTLF_DB_CACHE_SIZE ";\n" \
"PRAGMA synchronous = 0;\n" \
"PRAGMA auto_vacuum = 0;\n" \
"PRAGMA foreign_keys = OFF;\n" \
"PRAGMA automatic_index = OFF;\n" \
"PRAGMA threads = 0;\n" \
"PRAGMA mmap_size = " ZTLF_DB_SQLITE_MMAP_SIZE ";\n" \
\
"CREATE TABLE IF NOT EXISTS config (\"k\" VARCHAR(256) PRIMARY KEY NOT NULL,\"v\" BLOB NOT NULL) WITHOUT ROWID;\n" \
\
"CREATE TABLE IF NOT EXISTS record (" \
"doff INTEGER PRIMARY KEY NOT NULL," \
"dlen INTEGER NOT NULL," \
"goff INTEGER NOT NULL," \
"rtype INTEGER NOT NULL," \
"ts INTEGER NOT NULL," \
"score INTEGER NOT NULL," \
"link_count INTEGER NOT NULL," \
"reputation INTEGER NOT NULL," \
"linked_count INTEGER NOT NULL," \
"hash BLOB NOT NULL," \
"id BLOB NOT NULL," \
"ckey INTEGER NOT NULL," \
"owner BLOB NOT NULL" \
");\n" \
\
"CREATE UNIQUE INDEX IF NOT EXISTS record_goff ON record(goff);\n" \
"CREATE UNIQUE INDEX IF NOT EXISTS record_hash ON record(hash);\n" \
"CREATE INDEX IF NOT EXISTS record_reputation_linked_count ON record(reputation,linked_count);\n" \
"CREATE INDEX IF NOT EXISTS record_id_owner_ts ON record(id,owner,ts);\n" \
"CREATE INDEX IF NOT EXISTS record_owner_ts ON record(owner,ts);\n" \
\
"CREATE TABLE IF NOT EXISTS cert (" \
"subject_serial_no TEXT NOT NULL," \
"serial_no TEXT NOT NULL," \
"record_doff INTEGER NOT NULL," \
"certificate BLOB NOT NULL," \
"PRIMARY KEY(subject_serial_no,serial_no,record_doff)" \
") WITHOUT ROWID;\n" \
\
"CREATE TABLE IF NOT EXISTS cert_revocation (" \
"revoked_serial_no TEXT NOT NULL," \
"record_doff INTEGER NOT NULL," \
"record_dlen INTEGER NOT NULL," \
"PRIMARY KEY(revoked_serial_no,record_doff,record_dlen)" \
") WITHOUT ROWID;\n" \
\
"CREATE TABLE IF NOT EXISTS limbo (" \
"hash BLOB PRIMARY KEY NOT NULL," \
"owner BLOB NOT NULL," \
"ts INTEGER NOT NULL," \
"receive_time INTEGER NOT NULL" \
") WITHOUT ROWID;\n" \
\
"CREATE INDEX IF NOT EXISTS limbo_owner ON limbo(owner);" \
\
"CREATE TABLE IF NOT EXISTS comment (" \
"subject BLOB," \
"by_record_doff INTEGER NOT NULL," \
"assertion INTEGER NOT NULL," \
"reason INTEGER NOT NULL," \
"PRIMARY KEY(subject,by_record_doff,assertion,reason)" \
") WITHOUT ROWID;\n" \
\
"CREATE TABLE IF NOT EXISTS selector (" \
"sel BLOB NOT NULL," \
"selidx INTEGER NOT NULL," \
"record_ts INTEGER NOT NULL," \
"record_doff INTEGER NOT NULL," \
"PRIMARY KEY(sel,selidx,record_ts,record_doff)" \
") WITHOUT ROWID;\n" \
\
"CREATE TABLE IF NOT EXISTS dangling_link (" \
"hash BLOB NOT NULL," \
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
"hash BLOB PRIMARY KEY NOT NULL," \
"retries INTEGER NOT NULL" \
") WITHOUT ROWID;\n" \
\
"CREATE INDEX IF NOT EXISTS wanted_retries ON wanted(retries);\n" \
\
"CREATE TABLE IF NOT EXISTS pulse (" \
"token INTEGER NOT NULL," \
"start INTEGER NOT NULL," \
"minutes INTEGER NOT NULL," \
"PRIMARY KEY(token,start)" \
") WITHOUT ROWID;\n" \
\
"ATTACH DATABASE ':memory:' AS tmp;\n" \
\
"CREATE TABLE IF NOT EXISTS tmp.rs (\"i\" INTEGER PRIMARY KEY NOT NULL);\n"

#ifdef S
#define ZTLF_oldS S
#else
#define ZTLF_oldS
#endif
#undef S
#define S(v,s) if ((e = sqlite3_prepare_v3(db->dbc,(statement = (s)),-1,SQLITE_PREPARE_PERSISTENT,&(v),NULL)) != SQLITE_OK) goto exit_with_error

int ZTLF_DB_Open(
	struct ZTLF_DB *db,
	const char *path,
	char *errbuf,
	unsigned int errbufSize,
	LogOutputCallback logger,
	void *loggerArg,
	RecordSynchronizedCallback recordSync,
	void *recordSyncArg)
{
	char tmp[PATH_MAX];
	int e = 0;
	const char *statement = NULL;

	if (strlen(path) >= (PATH_MAX - 16))
		return ZTLF_NEG(ENAMETOOLONG);
	memset(db,0,sizeof(struct ZTLF_DB));
	strncpy(db->path,path,PATH_MAX-1);
	db->df = -1;
	db->logger = logger;
	db->loggerArg = (uintptr_t)loggerArg;
	db->recordSyncCallback = recordSync;
	db->recordSyncArg = (uintptr_t)recordSyncArg;

	ZTLF_L_trace("opening database at %s",path);

	db->graphThreadStarted = 0;
	pthread_mutex_init(&db->dbLock,NULL);
	for(int i=0;i<ZTLF_DB_GRAPH_NODE_LOCK_ARRAY_SIZE;++i)
		pthread_mutex_init(&db->graphNodeLocks[i],NULL);
	pthread_rwlock_init(&db->gfLock,NULL);

	mkdir(path,0755);

	/* Save PID of running instance of LF. */
#ifndef __WINDOWS__
	snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR "lf.pid",path);
	int pidf = open(tmp,O_WRONLY|O_TRUNC);
	if (pidf >= 0) {
		/* TODO: should enter some kind of scan/recovery mode here! */
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
	snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR "node.db",path);
	if ((e = sqlite3_open_v2(tmp,&db->dbc,SQLITE_OPEN_CREATE|SQLITE_OPEN_READWRITE|SQLITE_OPEN_NOMUTEX,NULL)) != SQLITE_OK)
		goto exit_with_error;
	if ((e = sqlite3_exec(db->dbc,(ZTLF_DB_INIT_SQL),NULL,NULL,NULL)) != SQLITE_OK)
		goto exit_with_error;

	/*
	 * The following clause (and variants) is common and selects for records that
	 * are fully synchronized, meaning they have all the links below them in the
	 * graph satisfied.
	 *
	 * "AND NOT EXISTS (SELECT dl.linking_record_goff FROM dangling_link AS dl WHERE dl.linking_record_goff = r.goff) "
	 * "AND NOT EXISTS (SELECT gp.record_goff FROM graph_pending AS gp WHERE gp.record_goff = r.goff) "
	 */

	S(db->sSetConfig,
		"INSERT OR REPLACE INTO config (\"k\",\"v\") VALUES (?,?)");
	S(db->sGetConfig,
		"SELECT \"v\" FROM config WHERE \"k\" = ?");
	S(db->sAddRecord,
		"INSERT INTO record (doff,dlen,goff,rtype,ts,score,link_count,reputation,linked_count,hash,id,ckey,owner) VALUES (?,?,?,?,?,?,?,?,0,?,?,?,?)");
	S(db->sIncRecordLinkedCountByGoff,
		"UPDATE record SET linked_count = (linked_count + 1) WHERE goff = ?");
	S(db->sAddSelector,
		"INSERT OR IGNORE INTO selector (sel,selidx,record_ts,record_doff) VALUES (?,?,?,?)");
	S(db->sGetRecordCount,
		"SELECT COUNT(1) FROM record");
	S(db->sGetDataSize,
		"SELECT (doff + dlen) FROM record ORDER BY doff DESC LIMIT 1");
	S(db->sGetAllRecords,
		"SELECT goff,hash,linked_count FROM record ORDER BY hash ASC");
	S(db->sGetAllByOwner,
		"SELECT r.doff,r.dlen,r.reputation FROM record AS r WHERE "
		"r.owner = ? "
		"AND NOT EXISTS (SELECT dl.linking_record_goff FROM dangling_link AS dl WHERE dl.linking_record_goff = r.goff) "
		"AND NOT EXISTS (SELECT gp.record_goff FROM graph_pending AS gp WHERE gp.record_goff = r.goff) "
		"ORDER BY r.ts ASC"); /* this ordering is important for things like genesis record playback */
	S(db->sGetAllByIDNotOwner,
		"SELECT r.doff,r.dlen,r.reputation FROM record AS r WHERE "
		"r.id = ? "
		"AND r.owner != ? "
		"AND NOT EXISTS (SELECT dl.linking_record_goff FROM dangling_link AS dl WHERE dl.linking_record_goff = r.goff) "
		"AND NOT EXISTS (SELECT gp.record_goff FROM graph_pending AS gp WHERE gp.record_goff = r.goff) "
		"ORDER BY r.ts ASC"); /* this ordering is important for things like genesis record playback */
	S(db->sGetIDOwnerReputation,
		"SELECT r.reputation FROM record AS r WHERE "
		"r.id = ? "
		"AND r.owner = ? "
		"AND NOT EXISTS (SELECT dl.linking_record_goff FROM dangling_link AS dl WHERE dl.linking_record_goff = r.goff) "
		"AND NOT EXISTS (SELECT gp.record_goff FROM graph_pending AS gp WHERE gp.record_goff = r.goff) "
		"ORDER BY r.reputation DESC LIMIT 1"); /* get maximum reputation for ID/owner combo */
	S(db->sHaveRecordsWithIDNotOwner,
		"SELECT doff FROM record WHERE id = ? AND owner != ? LIMIT 1");
	S(db->sDemoteCollisions,
		"UPDATE record SET reputation = 0 WHERE "
		"id = ? " /* with apparently colliding ID */
		"AND owner NOT IN (" /* and an owner for this ID that doesn't have a positive reputation already in synced records */
			"SELECT DISTINCT r2.owner FROM record AS r2 WHERE "
			"r2.id = ? " /* gets same ID value as first ? */
			"AND r2.reputation > 0 "
			"AND NOT EXISTS (SELECT dl.linking_record_goff FROM dangling_link AS dl WHERE dl.linking_record_goff = r2.goff) "
			"AND NOT EXISTS (SELECT gp.record_goff FROM graph_pending AS gp WHERE gp.record_goff = r2.goff)"
		") "
		"AND reputation > 0"); /* and that isn't already zero (prevents unnecessary writes? not sure if necessary) */
	S(db->sUpdateRecordReputationByHash,
		"UPDATE record SET reputation = ? WHERE hash = ?");
	S(db->sGetLinkCandidates,
		"SELECT r.hash FROM record AS r WHERE "
		"r.reputation >= " ZTLF_DB_REPUTATION_DEFAULT_S " " /* exclude collisions or otherwise wonky records */
		"AND NOT EXISTS (SELECT dl.linking_record_goff FROM dangling_link AS dl WHERE dl.linking_record_goff = r.goff) "
		"AND NOT EXISTS (SELECT gp.record_goff FROM graph_pending AS gp WHERE gp.record_goff = r.goff) "
		"ORDER BY r.linked_count,RANDOM() LIMIT ?"); /* link preferentially to records that have fewer links to them */
	S(db->sGetRecordByHash,
		"SELECT doff,dlen,ts FROM record WHERE hash = ?");
	S(db->sGetMaxRecordDoff,
		"SELECT doff,dlen FROM record ORDER BY doff DESC LIMIT 1");
	S(db->sGetMaxRecordGoff,
		"SELECT MAX(goff) FROM record");
	S(db->sGetRecordGoffByHash,
		"SELECT goff FROM record WHERE hash = ?");
	S(db->sGetRecordInfoByGoff,
		"SELECT doff,dlen,score,reputation,hash FROM record WHERE goff = ?");
	S(db->sGetDanglingLinks,
		"SELECT linking_record_goff,linking_record_link_idx FROM dangling_link WHERE hash = ?");
	S(db->sDeleteDanglingLinks,
		"DELETE FROM dangling_link WHERE hash = ?");
	S(db->sDeleteWantedHash,
		"DELETE FROM wanted WHERE hash = ?");
	S(db->sAddDanglingLink,
		"INSERT OR IGNORE INTO dangling_link (hash,linking_record_goff,linking_record_link_idx) VALUES (?,?,?)");
	S(db->sAddWantedHash,
		"INSERT OR REPLACE INTO wanted (hash,retries) VALUES (?,0)"); /* NOTE: resets retry count every time a new record wants a record */
	S(db->sAddHole,
		"INSERT OR IGNORE INTO hole (waiting_record_goff,incomplete_goff,incomplete_link_idx) VALUES (?,?,?)");
	S(db->sFlagRecordWeightApplicationPending,
		"INSERT OR REPLACE INTO graph_pending (record_goff,hole_count) VALUES (?,?)");
	S(db->sGetRecordsForWeightApplication,
		"SELECT gp.record_goff FROM graph_pending AS gp WHERE "
		"NOT EXISTS (SELECT dl1.linking_record_goff FROM dangling_link AS dl1 WHERE dl1.linking_record_goff = gp.record_goff) "
		"AND (" /* get records that don't appear to have any remaining holes under them or with hole count <= 0 (run now) */
			"gp.hole_count <= 0 "
			"OR NOT EXISTS ("
				"SELECT h.waiting_record_goff FROM hole AS h,dangling_link AS dl2 WHERE "
				"h.waiting_record_goff = gp.record_goff "
				"AND dl2.linking_record_goff = h.incomplete_goff "
				"AND dl2.linking_record_link_idx = h.incomplete_link_idx LIMIT 1"
			")"
		")");
	S(db->sGetHoles,
		"SELECT incomplete_goff,incomplete_link_idx FROM hole WHERE waiting_record_goff = ?");
	S(db->sDeleteHole,
		"DELETE FROM hole WHERE waiting_record_goff = ? AND incomplete_goff = ? AND incomplete_link_idx = ?");
	S(db->sUpdatePendingHoleCount,
		"UPDATE graph_pending SET hole_count = ? WHERE record_goff = ?");
	S(db->sDeleteCompletedPending,
		"DELETE FROM graph_pending WHERE record_goff = ?");
	S(db->sGetPendingCount,
		"SELECT COUNT(1) FROM graph_pending AS gp");
	S(db->sHaveDanglingLinks, /* this excludes records in limbo since these could otherwise prevent us from ever being fully synchronized */
		"SELECT w.retries FROM wanted AS w,dangling_link AS dl WHERE w.retries <= ? AND dl.hash = w.hash AND NOT EXISTS (SELECT l.hash FROM limbo AS l WHERE l.hash = w.hash) LIMIT 1");
	S(db->sGetWanted, /* this excludes records in limbo since we already have those and are possibly awaiting a cert */
		"SELECT w.hash FROM wanted AS w WHERE w.retries BETWEEN ? AND ? AND NOT EXISTS (SELECT l.hash FROM limbo AS l WHERE l.hash = w.hash) ORDER BY w.retries LIMIT ?");
	S(db->sIncWantedRetries,
		"UPDATE wanted SET retries = (retries + 1) WHERE hash = ?");
	S(db->sLogComment,
		"INSERT OR IGNORE INTO comment (subject,by_record_doff,assertion,reason) VALUES (?,?,?,?)");
	S(db->sGetCommentsBySubjectAndCommentOracle,
		"SELECT c.assertion,c.reason FROM comment AS c,record AS r WHERE c.subject = ? AND r.doff = c.by_record_doff AND r.owner = ?");
	S(db->sQueryClearRecordSet,
		"DELETE FROM tmp.rs");
	S(db->sQueryOrSelectorRange,
		"INSERT OR IGNORE INTO tmp.rs SELECT record_doff AS \"i\" FROM selector WHERE "
		"sel BETWEEN ? AND ? "
		"AND selidx = ? "
		"LIMIT " ZTLF_DB_SELECTOR_QUERY_RESULT_LIMIT);
	S(db->sQueryAndSelectorRange,
		"DELETE FROM tmp.rs WHERE \"i\" NOT IN (SELECT record_doff FROM selector WHERE sel BETWEEN ? AND ? AND selidx = ?)");
	S(db->sQueryGetResults,
		"SELECT r.doff,r.dlen,r.goff,r.ts,r.reputation,r.hash,r.ckey,r.owner FROM "
		"tmp.rs AS rs,record AS r "
		"WHERE "
		"r.doff = rs.i "
		"AND r.reputation >= 0 "
		"AND NOT EXISTS (SELECT dl.linking_record_goff FROM dangling_link AS dl WHERE dl.linking_record_goff = r.goff) "
		"AND NOT EXISTS (SELECT gp.record_goff FROM graph_pending AS gp WHERE gp.record_goff = r.goff) "
		"ORDER BY r.ckey,r.owner,r.ts");
	S(db->sPutCert,
		"INSERT OR REPLACE INTO cert (subject_serial_no,serial_no,record_doff,certificate) VALUES (?,?,?,?)");
	S(db->sPutCertRevocation,
		"INSERT OR REPLACE INTO cert_revocation (revoked_serial_no,record_doff,record_dlen) VALUES (?,?,?)");
	S(db->sGetCertsBySubject, /* note: we only support a depth of 2 for certificates: owner -> intermediate -> root */
		"SELECT serial_no,certificate FROM cert WHERE subject_serial_no IN (?,(SELECT serial_no FROM cert WHERE subject_serial_no = ?))");
	S(db->sGetCertRevocationsByRevokedSerial,
		"SELECT record_doff,record_dlen FROM cert_revocation WHERE revoked_serial_no = ?");
	S(db->sMarkInLimbo,
		"INSERT OR REPLACE INTO limbo (hash,owner,ts,receive_time) VALUES (?,?,?,?)");
	S(db->sTakeFromLimbo,
		"DELETE FROM limbo WHERE hash = ?");
	S(db->sHaveRecordInLimbo,
		"SELECT hash FROM limbo WHERE hash = ?");
	S(db->sRegisterPulseToken,
		"INSERT OR IGNORE INTO pulse (token,start,minutes) VALUES (?,?,0)");
	S(db->sUpdatePulse,
		"UPDATE pulse SET minutes = ? WHERE token = ? AND start BETWEEN ? AND ? AND minutes < ?");
	S(db->sGetPulse,
		"SELECT minutes FROM pulse WHERE token = ? ORDER BY start DESC LIMIT 1");

	/* Open and memory map graph and data files. */
	snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR "graph.bin",path);
	e = ZTLF_MappedFile_Open(&db->gf,tmp,ZTLF_GRAPH_FILE_CAPACITY_INCREMENT,ZTLF_GRAPH_FILE_CAPACITY_INCREMENT);
	if (e) {
		errno = e;
		e = 0;
		goto exit_with_error;
	}
	snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR "records.lf",path);
	db->df = open(tmp,O_RDWR|O_CREAT,0644);
	if (db->df < 0) {
		ZTLF_MappedFile_Close(&db->gf);
		goto exit_with_error;
	}
	snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR "weights",path);
	e = ZTLF_SUint96_Open(&db->wf,tmp);
	if (e) {
		errno = e;
		e = 0;
		goto exit_with_error;
	}

	db->running = 1;
	if (pthread_create(&db->graphThread,NULL,_ZTLF_DB_graphThreadMain,db) != 0) {
		ZTLF_L_fatal("pthread_create() failed");
		abort();
	}
	db->graphThreadStarted = 1;

	return 0;

exit_with_error:
	if ((e)&&(errbuf)&&(errbufSize)) {
		if (statement)
			snprintf(errbuf,errbufSize,"%s [%s]",sqlite3_errmsg(db->dbc),statement);
		else strncpy(errbuf,sqlite3_errmsg(db->dbc),errbufSize);
		errbuf[errbufSize-1] = 0;
	}
	ZTLF_DB_Close(db);
	return ((e) ? ZTLF_POS(e) : ZTLF_NEG(errno));
}

#undef S
#define S ZTLF_oldS

/* Convenience function to create a hex string for logging purposes. */
static const char *ZTLF_hexstr(const void *d,const unsigned long l,const unsigned int bufno)
{
	static const char *const hexdigits = "0123456789abcdef";
	static char buf[8][128];
	unsigned long i,j;
	memset(buf[bufno],0,128);
	for(i=0,j=0;i<l;++i) {
		buf[bufno][j++] = hexdigits[((const uint8_t *)d)[i] >> 4];
		buf[bufno][j++] = hexdigits[((const uint8_t *)d)[i] & 0xf];
		if (j >= 125)
			break;
	}
	return buf[bufno];
}

/* CRC64 with Jones coefficients */
static const uint64_t _ZTLF_CRC64_TAB[256] = { 0x0000000000000000ULL,0x7ad870c830358979ULL,0xf5b0e190606b12f2ULL,0x8f689158505e9b8bULL,0xc038e5739841b68fULL,0xbae095bba8743ff6ULL,0x358804e3f82aa47dULL,0x4f50742bc81f2d04ULL,0xab28ecb46814fe75ULL,0xd1f09c7c5821770cULL,0x5e980d24087fec87ULL,0x24407dec384a65feULL,0x6b1009c7f05548faULL,0x11c8790fc060c183ULL,0x9ea0e857903e5a08ULL,0xe478989fa00bd371ULL,0x7d08ff3b88be6f81ULL,0x07d08ff3b88be6f8ULL,0x88b81eabe8d57d73ULL,0xf2606e63d8e0f40aULL,0xbd301a4810ffd90eULL,0xc7e86a8020ca5077ULL,0x4880fbd87094cbfcULL,0x32588b1040a14285ULL,0xd620138fe0aa91f4ULL,0xacf86347d09f188dULL,0x2390f21f80c18306ULL,0x594882d7b0f40a7fULL,0x1618f6fc78eb277bULL,0x6cc0863448deae02ULL,0xe3a8176c18803589ULL,0x997067a428b5bcf0ULL,0xfa11fe77117cdf02ULL,0x80c98ebf2149567bULL,0x0fa11fe77117cdf0ULL,0x75796f2f41224489ULL,0x3a291b04893d698dULL,0x40f16bccb908e0f4ULL,0xcf99fa94e9567b7fULL,0xb5418a5cd963f206ULL,0x513912c379682177ULL,0x2be1620b495da80eULL,0xa489f35319033385ULL,0xde51839b2936bafcULL,0x9101f7b0e12997f8ULL,0xebd98778d11c1e81ULL,0x64b116208142850aULL,0x1e6966e8b1770c73ULL,0x8719014c99c2b083ULL,0xfdc17184a9f739faULL,0x72a9e0dcf9a9a271ULL,0x08719014c99c2b08ULL,0x4721e43f0183060cULL,0x3df994f731b68f75ULL,0xb29105af61e814feULL,0xc849756751dd9d87ULL,0x2c31edf8f1d64ef6ULL,0x56e99d30c1e3c78fULL,0xd9810c6891bd5c04ULL,0xa3597ca0a188d57dULL,0xec09088b6997f879ULL,0x96d1784359a27100ULL,0x19b9e91b09fcea8bULL,0x636199d339c963f2ULL,0xdf7adabd7a6e2d6fULL,0xa5a2aa754a5ba416ULL,0x2aca3b2d1a053f9dULL,0x50124be52a30b6e4ULL,0x1f423fcee22f9be0ULL,0x659a4f06d21a1299ULL,0xeaf2de5e82448912ULL,0x902aae96b271006bULL,0x74523609127ad31aULL,0x0e8a46c1224f5a63ULL,0x81e2d7997211c1e8ULL,0xfb3aa75142244891ULL,0xb46ad37a8a3b6595ULL,0xceb2a3b2ba0eececULL,0x41da32eaea507767ULL,0x3b024222da65fe1eULL,0xa2722586f2d042eeULL,0xd8aa554ec2e5cb97ULL,0x57c2c41692bb501cULL,0x2d1ab4dea28ed965ULL,0x624ac0f56a91f461ULL,0x1892b03d5aa47d18ULL,0x97fa21650afae693ULL,0xed2251ad3acf6feaULL,0x095ac9329ac4bc9bULL,0x7382b9faaaf135e2ULL,0xfcea28a2faafae69ULL,0x8632586aca9a2710ULL,0xc9622c4102850a14ULL,0xb3ba5c8932b0836dULL,0x3cd2cdd162ee18e6ULL,0x460abd1952db919fULL,0x256b24ca6b12f26dULL,0x5fb354025b277b14ULL,0xd0dbc55a0b79e09fULL,0xaa03b5923b4c69e6ULL,0xe553c1b9f35344e2ULL,0x9f8bb171c366cd9bULL,0x10e3202993385610ULL,0x6a3b50e1a30ddf69ULL,0x8e43c87e03060c18ULL,0xf49bb8b633338561ULL,0x7bf329ee636d1eeaULL,0x012b592653589793ULL,0x4e7b2d0d9b47ba97ULL,0x34a35dc5ab7233eeULL,0xbbcbcc9dfb2ca865ULL,0xc113bc55cb19211cULL,0x5863dbf1e3ac9decULL,0x22bbab39d3991495ULL,0xadd33a6183c78f1eULL,0xd70b4aa9b3f20667ULL,0x985b3e827bed2b63ULL,0xe2834e4a4bd8a21aULL,0x6debdf121b863991ULL,0x1733afda2bb3b0e8ULL,0xf34b37458bb86399ULL,0x8993478dbb8deae0ULL,0x06fbd6d5ebd3716bULL,0x7c23a61ddbe6f812ULL,0x3373d23613f9d516ULL,0x49aba2fe23cc5c6fULL,0xc6c333a67392c7e4ULL,0xbc1b436e43a74e9dULL,0x95ac9329ac4bc9b5ULL,0xef74e3e19c7e40ccULL,0x601c72b9cc20db47ULL,0x1ac40271fc15523eULL,0x5594765a340a7f3aULL,0x2f4c0692043ff643ULL,0xa02497ca54616dc8ULL,0xdafce7026454e4b1ULL,0x3e847f9dc45f37c0ULL,0x445c0f55f46abeb9ULL,0xcb349e0da4342532ULL,0xb1eceec59401ac4bULL,0xfebc9aee5c1e814fULL,0x8464ea266c2b0836ULL,0x0b0c7b7e3c7593bdULL,0x71d40bb60c401ac4ULL,0xe8a46c1224f5a634ULL,0x927c1cda14c02f4dULL,0x1d148d82449eb4c6ULL,0x67ccfd4a74ab3dbfULL,0x289c8961bcb410bbULL,0x5244f9a98c8199c2ULL,0xdd2c68f1dcdf0249ULL,0xa7f41839ecea8b30ULL,0x438c80a64ce15841ULL,0x3954f06e7cd4d138ULL,0xb63c61362c8a4ab3ULL,0xcce411fe1cbfc3caULL,0x83b465d5d4a0eeceULL,0xf96c151de49567b7ULL,0x76048445b4cbfc3cULL,0x0cdcf48d84fe7545ULL,0x6fbd6d5ebd3716b7ULL,0x15651d968d029fceULL,0x9a0d8ccedd5c0445ULL,0xe0d5fc06ed698d3cULL,0xaf85882d2576a038ULL,0xd55df8e515432941ULL,0x5a3569bd451db2caULL,0x20ed197575283bb3ULL,0xc49581ead523e8c2ULL,0xbe4df122e51661bbULL,0x3125607ab548fa30ULL,0x4bfd10b2857d7349ULL,0x04ad64994d625e4dULL,0x7e7514517d57d734ULL,0xf11d85092d094cbfULL,0x8bc5f5c11d3cc5c6ULL,0x12b5926535897936ULL,0x686de2ad05bcf04fULL,0xe70573f555e26bc4ULL,0x9ddd033d65d7e2bdULL,0xd28d7716adc8cfb9ULL,0xa85507de9dfd46c0ULL,0x273d9686cda3dd4bULL,0x5de5e64efd965432ULL,0xb99d7ed15d9d8743ULL,0xc3450e196da80e3aULL,0x4c2d9f413df695b1ULL,0x36f5ef890dc31cc8ULL,0x79a59ba2c5dc31ccULL,0x037deb6af5e9b8b5ULL,0x8c157a32a5b7233eULL,0xf6cd0afa9582aa47ULL,0x4ad64994d625e4daULL,0x300e395ce6106da3ULL,0xbf66a804b64ef628ULL,0xc5bed8cc867b7f51ULL,0x8aeeace74e645255ULL,0xf036dc2f7e51db2cULL,0x7f5e4d772e0f40a7ULL,0x05863dbf1e3ac9deULL,0xe1fea520be311aafULL,0x9b26d5e88e0493d6ULL,0x144e44b0de5a085dULL,0x6e963478ee6f8124ULL,0x21c640532670ac20ULL,0x5b1e309b16452559ULL,0xd476a1c3461bbed2ULL,0xaeaed10b762e37abULL,0x37deb6af5e9b8b5bULL,0x4d06c6676eae0222ULL,0xc26e573f3ef099a9ULL,0xb8b627f70ec510d0ULL,0xf7e653dcc6da3dd4ULL,0x8d3e2314f6efb4adULL,0x0256b24ca6b12f26ULL,0x788ec2849684a65fULL,0x9cf65a1b368f752eULL,0xe62e2ad306bafc57ULL,0x6946bb8b56e467dcULL,0x139ecb4366d1eea5ULL,0x5ccebf68aecec3a1ULL,0x2616cfa09efb4ad8ULL,0xa97e5ef8cea5d153ULL,0xd3a62e30fe90582aULL,0xb0c7b7e3c7593bd8ULL,0xca1fc72bf76cb2a1ULL,0x45775673a732292aULL,0x3faf26bb9707a053ULL,0x70ff52905f188d57ULL,0x0a2722586f2d042eULL,0x854fb3003f739fa5ULL,0xff97c3c80f4616dcULL,0x1bef5b57af4dc5adULL,0x61372b9f9f784cd4ULL,0xee5fbac7cf26d75fULL,0x9487ca0fff135e26ULL,0xdbd7be24370c7322ULL,0xa10fceec0739fa5bULL,0x2e675fb4576761d0ULL,0x54bf2f7c6752e8a9ULL,0xcdcf48d84fe75459ULL,0xb71738107fd2dd20ULL,0x387fa9482f8c46abULL,0x42a7d9801fb9cfd2ULL,0x0df7adabd7a6e2d6ULL,0x772fdd63e7936bafULL,0xf8474c3bb7cdf024ULL,0x829f3cf387f8795dULL,0x66e7a46c27f3aa2cULL,0x1c3fd4a417c62355ULL,0x935745fc4798b8deULL,0xe98f353477ad31a7ULL,0xa6df411fbfb21ca3ULL,0xdc0731d78f8795daULL,0x536fa08fdfd90e51ULL,0x29b7d047efec8728ULL };
static inline uint64_t _ZTLF_CRC64(uint64_t crc,const uint8_t *s,unsigned long l)
{
	for(unsigned long j=0;j<l;++j) { crc = _ZTLF_CRC64_TAB[(uintptr_t)((uint8_t)crc ^ s[j])] ^ (crc >> 8); }
	return crc;
}

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
	struct ZTLF_ISet *const visited = ZTLF_ISet_New();
	ZTLF_Vector_i64_Init(&graphTraversalQueue,2097152);
	ZTLF_Vector_i64_Init(&recordQueue,1024);
	ZTLF_Map128_Init(&holes,128,NULL);
	LogOutputCallback logger = db->logger;
	void *loggerArg = (void *)db->loggerArg;

	while (__sync_or_and_fetch(&db->running,0)) {
		for(int i=0;i<3;++i) {
			usleep(100000);
			if (!__sync_or_and_fetch(&db->running,0)) goto end_graph_thread;
		}

		/* Get new pending records or pending records with now-filled holes. */
		ZTLF_Vector_i64_Clear(&recordQueue);
		pthread_mutex_lock(&db->dbLock);
		sqlite3_reset(db->sGetRecordsForWeightApplication);
		while (sqlite3_step(db->sGetRecordsForWeightApplication) == SQLITE_ROW) {
			ZTLF_Vector_i64_Append(&recordQueue,sqlite3_column_int64(db->sGetRecordsForWeightApplication,0));
		}
		pthread_mutex_unlock(&db->dbLock);

		if (recordQueue.size > 0) {
			ZTLF_L_trace("graph: found %lu records to process",recordQueue.size);
		} else continue;

		while ((recordQueue.size > 0)&&(__sync_or_and_fetch(&db->running,0))) {
			const int64_t waitingGoff = recordQueue.v[--recordQueue.size];
			ZTLF_L_trace("graph: adjusting weights for records below graph node %lld",(long long)waitingGoff);

			/* Get record score and any previously known holes in the graph below this node. */
			int holeCount = 0;
			uint64_t doff = 0,score = 0;
			unsigned int dlen = 0;
			int reputation = 0;
			uint8_t hash[32];
			ZTLF_Map128_Clear(&holes);
			pthread_mutex_lock(&db->dbLock);
			sqlite3_reset(db->sGetRecordInfoByGoff);
			sqlite3_bind_int64(db->sGetRecordInfoByGoff,1,waitingGoff);
			if (sqlite3_step(db->sGetRecordInfoByGoff) == SQLITE_ROW) {
				doff = (uint64_t)sqlite3_column_int64(db->sGetRecordInfoByGoff,0);
				dlen = (unsigned int)sqlite3_column_int(db->sGetRecordInfoByGoff,1);
				score = (uint64_t)sqlite3_column_int64(db->sGetRecordInfoByGoff,2);
				reputation = sqlite3_column_int(db->sGetRecordInfoByGoff,3);
				memcpy(hash,sqlite3_column_blob(db->sGetRecordInfoByGoff,4),32);
			}
			sqlite3_reset(db->sGetHoles);
			sqlite3_bind_int64(db->sGetHoles,1,waitingGoff);
			while (sqlite3_step(db->sGetHoles) == SQLITE_ROW) {
				hk[0] = (uint64_t)sqlite3_column_int64(db->sGetHoles,0);
				hk[1] = (uint64_t)sqlite3_column_int(db->sGetHoles,1);
				ZTLF_Map128_Set(&holes,hk,(void *)1);
				++holeCount;
				ZTLF_L_trace("graph: graph below %lld previously led to hole at %llu[%llu]",(long long)waitingGoff,(unsigned long long)hk[0],(unsigned long long)hk[1]);
			}
			pthread_mutex_unlock(&db->dbLock);

			ZTLF_ISet_Clear(visited);
			ZTLF_Vector_i64_Clear(&graphTraversalQueue);

			pthread_rwlock_rdlock(&db->gfLock);

			/* Initialize queue and weight from this record's node to start graph traversal. */
			struct ZTLF_DB_GraphNode *graphNode = (struct ZTLF_DB_GraphNode *)ZTLF_MappedFile_TryGet(&db->gf,(uintptr_t)waitingGoff,ZTLF_DB_MAX_GRAPH_NODE_SIZE);
			bool nodeIncomplete = false;
			if (graphNode) {
				hk[0] = (uint64_t)waitingGoff;
				for(unsigned int i=0,j=graphNode->linkCount;i<j;++i) {
					hk[1] = (uint64_t)i;
					if (!ZTLF_Map128_Get(&holes,hk)) {
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
				ZTLF_L_warning("graph: record for graph node at %lld is incomplete, skipping (this should not happen since records with immediate dangling links should be excluded!)",(long long)waitingGoff);
				pthread_rwlock_unlock(&db->gfLock);
				continue;
			}

			/* If there are holes then we have to make a first pass and visit all the nodes we visited last time.
			 * This is done by traversing the graph, marking visited nodes in the visited set, making no weight
			 * adjustments, and skipping where the holes were previously. This reconstructs the visited set to
			 * avoid adjusting weights on previously visited nodes a second time. */
			if (holeCount > 0) {
				ZTLF_L_trace("graph: node %lld has %d holes, performing no-op pass starting with %lu nodes to regenerate visited node set",waitingGoff,holeCount,graphTraversalQueue.size);
				for(unsigned long i=0;i<graphTraversalQueue.size;) {
					const int64_t goff = graphTraversalQueue.v[i++];
					if (ZTLF_ISet_Put(visited,goff)) {
						struct ZTLF_DB_GraphNode *const gn = (struct ZTLF_DB_GraphNode *)ZTLF_MappedFile_TryGet(&db->gf,(uintptr_t)goff,ZTLF_DB_MAX_GRAPH_NODE_SIZE);
						if (gn) {
							hk[0] = (uint64_t)goff;
							for(unsigned int i=0,j=gn->linkCount;i<j;++i) {
								hk[1] = (uint64_t)i;
								if (!ZTLF_Map128_Get(&holes,hk)) {
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
				ZTLF_Map128_Each(&holes,{
					struct ZTLF_DB_GraphNode *const gn = (struct ZTLF_DB_GraphNode *)ZTLF_MappedFile_TryGet(&db->gf,(uintptr_t)ztlfMapKey[0],ZTLF_DB_MAX_GRAPH_NODE_SIZE);
					if (gn) {
						const int64_t goff = ZTLF_get64_le(gn->linkedRecordGoff[(uintptr_t)ztlfMapKey[1]]);
						if (goff >= 0) {
							ZTLF_L_trace("graph: hole below %lld at %llu[%u] is now filled with pointer to %lld",(long long)waitingGoff,(unsigned long long)ztlfMapKey[0],(unsigned int)ztlfMapKey[1],(long long)goff);
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
				if (ZTLF_ISet_Put(visited,goff)) {
					struct ZTLF_DB_GraphNode *const gn = (struct ZTLF_DB_GraphNode *)ZTLF_MappedFile_TryGet(&db->gf,(uintptr_t)goff,ZTLF_DB_MAX_GRAPH_NODE_SIZE);
					if (gn) {
						/* Add score to graph node weight. */
						ZTLF_SUint96_Add(&db->wf,(uintptr_t)gn->weightsFileOffset,score,0,0);

						/* Append linked nodes to to-do queue. */
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
				ZTLF_L_warning("graph: record with graph node at %lld has NEGATIVE hole count %ld (should not be possible, may indicate databsae corruption!)",(long long)waitingGoff,holeCount);
				holeCount = -1; /* force this node to be picked up and processed again because WTF */
			}

			/* Update hole count in pending table, or delete pending record if no more holes. */
			pthread_mutex_lock(&db->dbLock);
			if (holeCount == 0) {
				sqlite3_reset(db->sDeleteCompletedPending);
				sqlite3_bind_int64(db->sDeleteCompletedPending,1,waitingGoff);
				if (sqlite3_step(db->sDeleteCompletedPending) != SQLITE_DONE) {
					ZTLF_L_warning("graph: error deleting complete pending record %lld",(long long)waitingGoff);
				}
				if (db->recordSyncCallback)
					db->recordSyncCallback(db,hash,doff,dlen,reputation,(void *)db->recordSyncArg);
			} else {
				sqlite3_reset(db->sUpdatePendingHoleCount);
				sqlite3_bind_int64(db->sUpdatePendingHoleCount,1,(int64_t)holeCount);
				sqlite3_bind_int64(db->sUpdatePendingHoleCount,2,waitingGoff);
				int err = sqlite3_step(db->sUpdatePendingHoleCount);
				if (err != SQLITE_DONE) {
					ZTLF_L_warning("graph: error updating pending hole count: %d (%s)",err,ZTLF_DB_LastSqliteErrorMessage(db));
				}
			}
			pthread_mutex_unlock(&db->dbLock);

			pthread_rwlock_unlock(&db->gfLock);
		}
	}

end_graph_thread:
	ZTLF_Map128_Destroy(&holes);
	ZTLF_Vector_i64_Free(&recordQueue);
	ZTLF_Vector_i64_Free(&graphTraversalQueue);
	ZTLF_ISet_Free(visited);

	return NULL;
}

void ZTLF_DB_Close(struct ZTLF_DB *db)
{
	char tmp[PATH_MAX];
	LogOutputCallback logger = db->logger;
	void *loggerArg = (void *)db->loggerArg;

	ZTLF_L_trace("internal C database shutting down");

	__sync_and_and_fetch(&db->running,0);
	if (__sync_or_and_fetch(&db->graphThreadStarted,0))
		pthread_join(db->graphThread,NULL);

	ZTLF_L_trace("graph thread has stopped");

	for(int i=0;i<ZTLF_DB_GRAPH_NODE_LOCK_ARRAY_SIZE;++i)
		pthread_mutex_lock(&db->graphNodeLocks[i]);
	pthread_rwlock_wrlock(&db->gfLock);
	pthread_mutex_lock(&db->dbLock);

	if (db->dbc) {
		if (db->sSetConfig)                            sqlite3_finalize(db->sSetConfig);
		if (db->sGetConfig)                            sqlite3_finalize(db->sGetConfig);
		if (db->sAddRejected)                          sqlite3_finalize(db->sAddRejected);
		if (db->sAddRecord)                            sqlite3_finalize(db->sAddRecord);
		if (db->sIncRecordLinkedCountByGoff)           sqlite3_finalize(db->sIncRecordLinkedCountByGoff);
		if (db->sAddSelector)                          sqlite3_finalize(db->sAddSelector);
		if (db->sGetRecordCount)                       sqlite3_finalize(db->sGetRecordCount);
		if (db->sGetDataSize)                          sqlite3_finalize(db->sGetDataSize);
		if (db->sGetAllRecords)                        sqlite3_finalize(db->sGetAllRecords);
		if (db->sGetAllByOwner)                        sqlite3_finalize(db->sGetAllByOwner);
		if (db->sGetAllByIDNotOwner)                   sqlite3_finalize(db->sGetAllByIDNotOwner);
		if (db->sGetIDOwnerReputation)                 sqlite3_finalize(db->sGetIDOwnerReputation);
		if (db->sHaveRecordsWithIDNotOwner)            sqlite3_finalize(db->sHaveRecordsWithIDNotOwner);
		if (db->sDemoteCollisions)                     sqlite3_finalize(db->sDemoteCollisions);
		if (db->sUpdateRecordReputationByHash)         sqlite3_finalize(db->sUpdateRecordReputationByHash);
		if (db->sGetLinkCandidates)                    sqlite3_finalize(db->sGetLinkCandidates);
		if (db->sGetRecordByHash)                      sqlite3_finalize(db->sGetRecordByHash);
		if (db->sGetMaxRecordDoff)                     sqlite3_finalize(db->sGetMaxRecordDoff);
		if (db->sGetMaxRecordGoff)                     sqlite3_finalize(db->sGetMaxRecordGoff);
		if (db->sGetRecordGoffByHash)                  sqlite3_finalize(db->sGetRecordGoffByHash);
		if (db->sGetRecordInfoByGoff)                  sqlite3_finalize(db->sGetRecordInfoByGoff);
		if (db->sGetDanglingLinks)                     sqlite3_finalize(db->sGetDanglingLinks);
		if (db->sDeleteDanglingLinks)                  sqlite3_finalize(db->sDeleteDanglingLinks);
		if (db->sDeleteWantedHash)                     sqlite3_finalize(db->sDeleteWantedHash);
		if (db->sAddDanglingLink)                      sqlite3_finalize(db->sAddDanglingLink);
		if (db->sAddWantedHash)                        sqlite3_finalize(db->sAddWantedHash);
		if (db->sAddHole)                              sqlite3_finalize(db->sAddHole);
		if (db->sFlagRecordWeightApplicationPending)   sqlite3_finalize(db->sFlagRecordWeightApplicationPending);
		if (db->sGetRecordsForWeightApplication)       sqlite3_finalize(db->sGetRecordsForWeightApplication);
		if (db->sGetHoles)                             sqlite3_finalize(db->sGetHoles);
		if (db->sDeleteHole)                           sqlite3_finalize(db->sDeleteHole);
		if (db->sUpdatePendingHoleCount)               sqlite3_finalize(db->sUpdatePendingHoleCount);
		if (db->sDeleteCompletedPending)               sqlite3_finalize(db->sDeleteCompletedPending);
		if (db->sGetPendingCount)                      sqlite3_finalize(db->sGetPendingCount);
		if (db->sHaveDanglingLinks)                    sqlite3_finalize(db->sHaveDanglingLinks);
		if (db->sGetWanted)                            sqlite3_finalize(db->sGetWanted);
		if (db->sIncWantedRetries)                     sqlite3_finalize(db->sIncWantedRetries);
		if (db->sLogComment)                           sqlite3_finalize(db->sLogComment);
		if (db->sGetCommentsBySubjectAndCommentOracle) sqlite3_finalize(db->sGetCommentsBySubjectAndCommentOracle);
		if (db->sQueryClearRecordSet)                  sqlite3_finalize(db->sQueryClearRecordSet);
		if (db->sQueryOrSelectorRange)                 sqlite3_finalize(db->sQueryOrSelectorRange);
		if (db->sQueryAndSelectorRange)                sqlite3_finalize(db->sQueryAndSelectorRange);
		if (db->sQueryGetResults)                      sqlite3_finalize(db->sQueryGetResults);
		if (db->sPutCert)                              sqlite3_finalize(db->sPutCert);
		if (db->sPutCertRevocation)                    sqlite3_finalize(db->sPutCertRevocation);
		if (db->sGetCertsBySubject)                    sqlite3_finalize(db->sGetCertsBySubject);
		if (db->sGetCertRevocationsByRevokedSerial)    sqlite3_finalize(db->sGetCertRevocationsByRevokedSerial);
		if (db->sMarkInLimbo)                          sqlite3_finalize(db->sMarkInLimbo);
		if (db->sTakeFromLimbo)                        sqlite3_finalize(db->sTakeFromLimbo);
		if (db->sHaveRecordInLimbo)                    sqlite3_finalize(db->sHaveRecordInLimbo);
		if (db->sRegisterPulseToken)                   sqlite3_finalize(db->sRegisterPulseToken);
		if (db->sUpdatePulse)                          sqlite3_finalize(db->sUpdatePulse);
		if (db->sGetPulse)                             sqlite3_finalize(db->sGetPulse);
		sqlite3_close_v2(db->dbc);
	}

	snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR "lf.pid",db->path);
	unlink(tmp);

	ZTLF_MappedFile_Close(&db->gf);
	if (db->df >= 0)
		close(db->df);
	db->df = -1;
	ZTLF_SUint96_Close(&db->wf);

	pthread_mutex_unlock(&db->dbLock);
	pthread_rwlock_unlock(&db->gfLock);
	for(int i=0;i<ZTLF_DB_GRAPH_NODE_LOCK_ARRAY_SIZE;++i)
		pthread_mutex_unlock(&db->graphNodeLocks[i]);

	pthread_mutex_destroy(&db->dbLock);
	for(int i=0;i<ZTLF_DB_GRAPH_NODE_LOCK_ARRAY_SIZE;++i)
		pthread_mutex_destroy(&db->graphNodeLocks[i]);
	pthread_rwlock_destroy(&db->gfLock);

	ZTLF_L_trace("shutdown complete");
}

struct _ZTLF_DB_GetMatching_follow
{
	uint64_t id[4];
	uint64_t owner[4];
	struct _ZTLF_DB_GetMatching_follow *next;
};

unsigned int ZTLF_DB_GetByHash(struct ZTLF_DB *db,const void *hash,uint64_t *doff,uint64_t *ts)
{
	unsigned int dlen = 0;
	pthread_mutex_lock(&db->dbLock);
	sqlite3_reset(db->sGetRecordByHash);
	sqlite3_bind_blob(db->sGetRecordByHash,1,hash,32,SQLITE_STATIC);
	if (sqlite3_step(db->sGetRecordByHash) == SQLITE_ROW) {
		*doff = (uint64_t)sqlite3_column_int64(db->sGetRecordByHash,0);
		dlen = (unsigned int)sqlite3_column_int(db->sGetRecordByHash,1);
		*ts = (uint64_t)sqlite3_column_int64(db->sGetRecordByHash,2);
	}
	pthread_mutex_unlock(&db->dbLock);
	return dlen;
}

unsigned int ZTLF_DB_GetLinks(struct ZTLF_DB *db,void *const lbuf,unsigned int cnt)
{
	if (cnt == 0) return 0;
	uint8_t *l = (uint8_t *)lbuf;
	unsigned int lc = 0;
	pthread_mutex_lock(&db->dbLock);
	sqlite3_reset(db->sGetLinkCandidates);
	sqlite3_bind_int(db->sGetLinkCandidates,1,(int)cnt);
	while (sqlite3_step(db->sGetLinkCandidates) == SQLITE_ROW) {
		memcpy(l,sqlite3_column_blob(db->sGetLinkCandidates,0),32);
		l += 32;
		++lc;
	}
	pthread_mutex_unlock(&db->dbLock);
	return lc;
}

void ZTLF_DB_UpdateRecordReputationByHash(struct ZTLF_DB *db,const void *const hash,const int reputation)
{
	pthread_mutex_lock(&db->dbLock);
	sqlite3_reset(db->sUpdateRecordReputationByHash);
	sqlite3_bind_int(db->sUpdateRecordReputationByHash,1,reputation);
	sqlite3_bind_blob(db->sUpdateRecordReputationByHash,2,hash,32,SQLITE_STATIC);
	sqlite3_step(db->sUpdateRecordReputationByHash);
	pthread_mutex_unlock(&db->dbLock);
}

int ZTLF_DB_PutRecord(
	struct ZTLF_DB *db,
	const void *rec,
	const unsigned int rsize,
	const int rtype,
	const void *owner,
	const unsigned int ownerSize,
	const void *hash,
	const void *id,
	const uint64_t ts,
	const uint64_t pulseToken,
	const uint32_t score,
	const void **selKey,
	const unsigned int selCount,
	const void *links,
	const unsigned int linkCount)
{
	int e = 0,result = 0;
	LogOutputCallback logger = db->logger;
	void *loggerArg = (void *)db->loggerArg;

	pthread_rwlock_rdlock(&db->gfLock);
	pthread_mutex_lock(&db->dbLock);

	/* Locate new record's graph node and data file offset and copy new record into data file. Grow
	 * graph and data files if needed. */
	int64_t goff = 0;
	int64_t doff = 0;
	uintptr_t woff = 0;
	struct ZTLF_DB_GraphNode *graphNode = NULL;
	for(;;) {
		/* Place our graph node at the previous highest graph node's offset plus its size. Also
		 * figure out what our offset is in the striped weights file. */
		sqlite3_reset(db->sGetMaxRecordGoff);
		if (sqlite3_step(db->sGetMaxRecordGoff) == SQLITE_ROW) {
			const int64_t highestExistingGoff = sqlite3_column_int64(db->sGetMaxRecordGoff,0);
			graphNode = ZTLF_MappedFile_TryGet(&db->gf,(uintptr_t)highestExistingGoff,ZTLF_DB_MAX_GRAPH_NODE_SIZE);
			if (!graphNode) {
				ZTLF_L_warning("cannot seek to known graph file offset %lld, database may be corrupt",(long long)highestExistingGoff);
				result = ZTLF_NEG(EIO);
				goto exit_putRecord;
			} else {
				goff = highestExistingGoff + sizeof(struct ZTLF_DB_GraphNode) + (sizeof(int64_t) * (int64_t)graphNode->linkCount);
				woff = (uintptr_t)(graphNode->weightsFileOffset + 1);
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

		/* Copy data into record data file. */
		if ((long)pwrite(db->df,rec,(size_t)rsize,(off_t)doff) != (long)rsize) {
			result = ZTLF_NEG(EIO);
			goto exit_putRecord;
		}

		break;
	}

	/* Figure out what this record's reputation should be. First, we check if
	 * there are fully synchronized records with this ID and owner. If these
	 * exist we inherit their reputation. Otherwise we check to see if there
	 * are ANY records (synchronized or not) with the same ID but a different
	 * owner. If this is the case, this record gets a zero reputation and
	 * any un-synchronized records with the same ID and owner also get a zero
	 * reputation. Collisions between un-synchronized records earn them both
	 * a zero. Note that reputation only exists on this node. It's not a part
	 * of the DAG itself and is not replicated, though it will factor into
	 * record commentary and therefore can be taken into consideration by
	 * others on a voluntary trust basis. */
	int reputation = ZTLF_DB_REPUTATION_COLLISION;
	sqlite3_reset(db->sGetIDOwnerReputation);
	sqlite3_bind_blob(db->sGetIDOwnerReputation,1,id,32,SQLITE_STATIC);
	sqlite3_bind_blob(db->sGetIDOwnerReputation,2,owner,ownerSize,SQLITE_STATIC);
	if (sqlite3_step(db->sGetIDOwnerReputation) == SQLITE_ROW) {
		reputation = sqlite3_column_int(db->sGetIDOwnerReputation,0); /* maximum reputation for ID/owner combo */
	} else {
		sqlite3_reset(db->sHaveRecordsWithIDNotOwner);
		sqlite3_bind_blob(db->sHaveRecordsWithIDNotOwner,1,id,32,SQLITE_STATIC);
		sqlite3_bind_blob(db->sHaveRecordsWithIDNotOwner,2,owner,ownerSize,SQLITE_STATIC);
		if (sqlite3_step(db->sHaveRecordsWithIDNotOwner) == SQLITE_ROW) {
			sqlite3_reset(db->sDemoteCollisions);
			sqlite3_bind_blob(db->sDemoteCollisions,1,id,32,SQLITE_STATIC);
			sqlite3_bind_blob(db->sDemoteCollisions,2,id,32,SQLITE_STATIC);
			sqlite3_step(db->sDemoteCollisions);
		} else {
			reputation = ZTLF_DB_REPUTATION_DEFAULT;
		}
	}

	/* Create composite selector key for grouping of ranged selectors on query.
	 * A secure hash is not important here since these are themselves hashes
	 * (making collisions hard) and this is only used for disambiguation of
	 * selector combos within a given owner anyway. */
	uint64_t ckey = 0;
	for(unsigned int i=0;i<selCount;++i) {
		ckey = _ZTLF_CRC64(ckey,(const uint8_t *)(selKey[i]),32);
	}

	/* Add main record entry. */
	sqlite3_reset(db->sAddRecord);
	sqlite3_bind_int64(db->sAddRecord,1,doff);
	sqlite3_bind_int64(db->sAddRecord,2,(sqlite3_int64)rsize);
	sqlite3_bind_int64(db->sAddRecord,3,goff);
	sqlite3_bind_int(db->sAddRecord,4,rtype);
	sqlite3_bind_int64(db->sAddRecord,5,(sqlite3_int64)ts);
	sqlite3_bind_int64(db->sAddRecord,6,(sqlite3_int64)score);
	sqlite3_bind_int(db->sAddRecord,7,(int)linkCount);
	sqlite3_bind_int(db->sAddRecord,8,reputation);
	sqlite3_bind_blob(db->sAddRecord,9,hash,32,SQLITE_STATIC);
	sqlite3_bind_blob(db->sAddRecord,10,id,32,SQLITE_STATIC);
	sqlite3_bind_int64(db->sAddRecord,11,(sqlite_int64)ckey);
	sqlite3_bind_blob(db->sAddRecord,12,owner,ownerSize,SQLITE_STATIC);
	if ((e = sqlite3_step(db->sAddRecord)) != SQLITE_DONE) {
		result = ZTLF_POS(e);
		goto exit_putRecord;
	}

	/* Add selectors for this record. */
	for(unsigned int i=0;i<selCount;++i) {
		sqlite3_reset(db->sAddSelector);
		sqlite3_bind_blob(db->sAddSelector,1,selKey[i],32,SQLITE_STATIC);
		sqlite3_bind_int(db->sAddSelector,2,(int)i);
		sqlite3_bind_int64(db->sAddSelector,3,(sqlite3_int64)ts);
		sqlite3_bind_int64(db->sAddSelector,4,doff);
		if (sqlite3_step(db->sAddSelector) != SQLITE_DONE) {
			ZTLF_L_warning("database error adding selector, I/O error or database corrupt!");
			break;
		}
	}

	/* Add pulse token for this record. */
	if (pulseToken) {
		sqlite3_reset(db->sRegisterPulseToken);
		sqlite3_bind_int64(db->sRegisterPulseToken,1,(sqlite3_int64)pulseToken);
		sqlite3_bind_int64(db->sRegisterPulseToken,2,(sqlite3_int64)ts);
		if (sqlite3_step(db->sRegisterPulseToken) != SQLITE_DONE) {
			ZTLF_L_warning("database error registering pulse token, I/O error or database corrupt!");
		}
	}

	pthread_mutex_t *const graphNodeLock = &(db->graphNodeLocks[((uintptr_t)goff) % ZTLF_DB_GRAPH_NODE_LOCK_ARRAY_SIZE]);
	pthread_mutex_lock(graphNodeLock);

	/* Initialize this record's graph node with its initial weight and links. */
	ZTLF_SUint96_Set(&db->wf,woff,score,0,0);
	ZTLF_setu64_le(graphNode->weightsFileOffset,woff);
	graphNode->linkCount = (uint8_t)linkCount;
	for(unsigned int i=0,j=linkCount;i<j;++i) {
		const uint8_t *const l = ((const uint8_t *)links) + (i * 32);
		sqlite3_reset(db->sGetRecordGoffByHash);
		sqlite3_bind_blob(db->sGetRecordGoffByHash,1,l,32,SQLITE_STATIC);
		if (sqlite3_step(db->sGetRecordGoffByHash) == SQLITE_ROW) {
			/* Record found, link this graph node to it and increment existing record's linked count. */
			const int64_t linkedGoff = sqlite3_column_int64(db->sGetRecordGoffByHash,0);
			sqlite3_reset(db->sIncRecordLinkedCountByGoff);
			sqlite3_bind_int64(db->sIncRecordLinkedCountByGoff,1,(sqlite_int64)linkedGoff);
			if (sqlite3_step(db->sIncRecordLinkedCountByGoff) != SQLITE_DONE) {
				ZTLF_L_warning("database error incrementing linked count in child record");
			}
			ZTLF_set64_le(graphNode->linkedRecordGoff[i],linkedGoff);
		} else {
			/* If not found log record as wanted and log dangling link to indicate that record is incomplete. */
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

	/* Update graph nodes of any records linking to this record with this record's graph node offset and increment our linked count. */
	sqlite3_reset(db->sGetDanglingLinks);
	sqlite3_bind_blob(db->sGetDanglingLinks,1,hash,32,SQLITE_STATIC);
	while (sqlite3_step(db->sGetDanglingLinks) == SQLITE_ROW) {
		const int64_t linkingGoff = sqlite3_column_int64(db->sGetDanglingLinks,0);
		const int linkingIdx = sqlite3_column_int(db->sGetDanglingLinks,1);
		struct ZTLF_DB_GraphNode *const linkingRecordGraphNode = (struct ZTLF_DB_GraphNode *)ZTLF_MappedFile_TryGet(&db->gf,(uintptr_t)linkingGoff,ZTLF_DB_MAX_GRAPH_NODE_SIZE);
		if (linkingRecordGraphNode) { /* sanity check */
			pthread_mutex_t *const linkingGraphNodeLock = &(db->graphNodeLocks[((uintptr_t)linkingGoff) % ZTLF_DB_GRAPH_NODE_LOCK_ARRAY_SIZE]);
			if (linkingGraphNodeLock != graphNodeLock)
				pthread_mutex_lock(linkingGraphNodeLock);
			if (ZTLF_get64_le(linkingRecordGraphNode->linkedRecordGoff[linkingIdx]) < 0) {
				/* ZTLF_L_trace("updated graph node @%lld with pointer to this record's graph node",(long long)linkingGoff); */
				ZTLF_set64_le(linkingRecordGraphNode->linkedRecordGoff[linkingIdx],goff);
				sqlite3_reset(db->sIncRecordLinkedCountByGoff);
				sqlite3_bind_int64(db->sIncRecordLinkedCountByGoff,1,(sqlite_int64)goff);
				if (sqlite3_step(db->sIncRecordLinkedCountByGoff) != SQLITE_DONE) {
					ZTLF_L_warning("database error incrementing linked count in record");
				}
			} else {
				ZTLF_L_warning("dangling link to graph node %lld specifies node %lld index %d but that index appears already filled, likely database corruption!",(long long)goff,(long long)linkingGoff,linkingIdx);
			}
			if (linkingGraphNodeLock != graphNodeLock)
				pthread_mutex_unlock(linkingGraphNodeLock);
		} else {
			ZTLF_L_warning("database error updating linking graph node, I/O error or database corrupt!");
		}
	}

	pthread_mutex_unlock(graphNodeLock);

	/* Delete any limbo entries for this record. */
	sqlite3_reset(db->sTakeFromLimbo);
	sqlite3_bind_blob(db->sTakeFromLimbo,1,hash,32,SQLITE_STATIC);
	if ((e = sqlite3_step(db->sTakeFromLimbo)) != SQLITE_DONE) {
		ZTLF_L_warning("database error deleting limbo entry: %d (%s)",e,sqlite3_errmsg(db->dbc));
	}

	/* Delete dangling link records referencing this record. */
	sqlite3_reset(db->sDeleteDanglingLinks);
	sqlite3_bind_blob(db->sDeleteDanglingLinks,1,hash,32,SQLITE_STATIC);
	if ((e = sqlite3_step(db->sDeleteDanglingLinks)) != SQLITE_DONE) {
		ZTLF_L_warning("database error deleting dangling links: %d (%s)",e,sqlite3_errmsg(db->dbc));
	}

	/* Delete wanted record entries for this record. */
	sqlite3_reset(db->sDeleteWantedHash);
	sqlite3_bind_blob(db->sDeleteWantedHash,1,hash,32,SQLITE_STATIC);
	if ((e = sqlite3_step(db->sDeleteWantedHash)) != SQLITE_DONE) {
		ZTLF_L_warning("database error deleting wanted hash: %d (%s)",e,sqlite3_errmsg(db->dbc));
	}

	/* Flag this record as needing graph traversal and weight application. */
	if (linkCount > 0) {
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

struct ZTLF_QueryResults *ZTLF_DB_Query(
	struct ZTLF_DB *db,
	const void **sel,
	const unsigned int *selSize,
	const unsigned int selCount,
	const void **oracles,
	const unsigned int *oracleSize,
	const unsigned int oracleCount)
{
	LogOutputCallback logger = db->logger;
	void *loggerArg = (void *)db->loggerArg;
	unsigned long rcap = 16;
	struct ZTLF_QueryResults *r = (struct ZTLF_QueryResults *)malloc(sizeof(struct ZTLF_QueryResults) + ((rcap-1) * sizeof(struct ZTLF_QueryResult)));

	pthread_mutex_lock(&db->dbLock);
	pthread_rwlock_rdlock(&db->gfLock);

	if (!r)
		goto query_error;

	sqlite3_reset(db->sQueryClearRecordSet);
	if (sqlite3_step(db->sQueryClearRecordSet) != SQLITE_DONE) {
		ZTLF_L_warning("database error clearing query record ID cache: %s",sqlite3_errmsg(db->dbc));
		goto query_error;
	}

	for(unsigned int i=0,j=0;i<selCount;++i) {
		if (i == 0) {
			/* The first iteration uses the "OR" query which adds matching records to the temporary table. */
			sqlite3_reset(db->sQueryOrSelectorRange);
			sqlite3_bind_blob(db->sQueryOrSelectorRange,1,sel[j],(int)selSize[j],SQLITE_STATIC);
			++j;
			sqlite3_bind_blob(db->sQueryOrSelectorRange,2,sel[j],(int)selSize[j],SQLITE_STATIC);
			++j;
			sqlite3_bind_int(db->sQueryOrSelectorRange,3,(int)i);
			if (sqlite3_step(db->sQueryOrSelectorRange) != SQLITE_DONE) {
				ZTLF_L_warning("database error querying selector range into record ID cache: %s",sqlite3_errmsg(db->dbc));
				goto query_error;
			}
		} else {
			/* Subsequent iterations are "AND" queries that remove non-matching records from the temporary table (set union). */
			sqlite3_reset(db->sQueryAndSelectorRange);
			sqlite3_bind_blob(db->sQueryAndSelectorRange,1,sel[j],(int)selSize[j],SQLITE_STATIC);
			++j;
			sqlite3_bind_blob(db->sQueryAndSelectorRange,2,sel[j],(int)selSize[j],SQLITE_STATIC);
			++j;
			sqlite3_bind_int(db->sQueryAndSelectorRange,3,(int)i);
			if (sqlite3_step(db->sQueryAndSelectorRange) != SQLITE_DONE) {
				ZTLF_L_warning("database error querying selector range into record ID cache (AND): %s",sqlite3_errmsg(db->dbc));
				goto query_error;
			}
		}
	}

	/* Get final results */
	r->count = -1; /* gets incremented on very first iteration */
	uint8_t lastOwner[ZTLF_DB_QUERY_MAX_OWNER_SIZE];
	sqlite_int64 lastCKey = 0;
	memset(lastOwner,0,sizeof(lastOwner));
	int lastOwnerSize = -1;
	sqlite3_reset(db->sQueryGetResults);
	while (sqlite3_step(db->sQueryGetResults) == SQLITE_ROW) { /* columns: doff,dlen,goff,ts,reputation,hash,ckey,owner */
		const void *owner = sqlite3_column_blob(db->sQueryGetResults,7);
		const int ownerSize = sqlite3_column_bytes(db->sQueryGetResults,7);
		if ((!owner)||(ownerSize <= 0)||(ownerSize > ZTLF_DB_QUERY_MAX_OWNER_SIZE))
			continue;

		struct ZTLF_QueryResult *qr;
		const sqlite_int64 ckey = sqlite3_column_int64(db->sQueryGetResults,6);
		if ((lastCKey != ckey)||(lastOwnerSize != ownerSize)||(memcmp(lastOwner,owner,ownerSize) != 0)) {
			lastCKey = ckey;
			memcpy(lastOwner,owner,ownerSize);
			lastOwnerSize = ownerSize;

			++r->count;
			if (r->count >= rcap) {
				void *tmpr = realloc(r,sizeof(struct ZTLF_QueryResults) + (((rcap * 2)-1) * sizeof(struct ZTLF_QueryResult)));
				if (!tmpr) {
					ZTLF_L_warning("out of memory!");
					goto query_error;
				}
				rcap *= 2;
				r = (struct ZTLF_QueryResults *)tmpr;
			}

			qr = &(r->results[r->count]);
			qr->ts = 0;
			qr->weightL = 0;
			qr->weightH = 0;
			qr->ownerSize = (unsigned int)ownerSize;
			qr->negativeComments = 0;
			qr->localReputation = ZTLF_DB_REPUTATION_DEFAULT; /* this gets set to minimum of all records in a group */
			qr->ckey = (uint64_t)ckey;
			memcpy(qr->owner,owner,ownerSize);
		} else {
			qr = &(r->results[r->count]);
		}

		const struct ZTLF_DB_GraphNode *const gn = (struct ZTLF_DB_GraphNode *)ZTLF_MappedFile_TryGet(&db->gf,(uintptr_t)sqlite3_column_int64(db->sQueryGetResults,2),ZTLF_DB_MAX_GRAPH_NODE_SIZE);
		if (gn) { /* sanity check, should be impossible to be NULL */
			qr->ts = (uint64_t)sqlite3_column_int64(db->sQueryGetResults,3);

			/* Add this record's weight to total weight. */
			uint32_t w96l,w96m,w96h;
			ZTLF_SUint96_Get(&db->wf,(uintptr_t)gn->weightsFileOffset,&w96l,&w96m,&w96h);
			uint64_t oldwl = qr->weightL;
			qr->weightH += (uint64_t)((qr->weightL += ((uint64_t)w96l)) < oldwl); /* add least significant 32 to least significant 64 with carry */
			oldwl = qr->weightL;
			qr->weightH += (uint64_t)((qr->weightL += (((uint64_t)w96m) << 32)) < oldwl) + (uint64_t)w96h; /* add middle 32 to least significant 64 with carry, then add most significant 32 to most significant 64 */

			qr->doff = (uint64_t)sqlite3_column_int64(db->sQueryGetResults,0);
			qr->dlen = (unsigned int)sqlite3_column_int(db->sQueryGetResults,1);

			const int rep = sqlite3_column_int(db->sQueryGetResults,4);
			if (rep < qr->localReputation)
				qr->localReputation = rep;

			if (oracleCount) {
				const void *const hash = sqlite3_column_blob(db->sQueryGetResults,5);
				for(unsigned int i=0;i<oracleCount;i++) {
					sqlite3_reset(db->sGetCommentsBySubjectAndCommentOracle);
					sqlite3_bind_blob(db->sGetCommentsBySubjectAndCommentOracle,1,hash,32,SQLITE_STATIC);
					sqlite3_bind_blob(db->sGetCommentsBySubjectAndCommentOracle,2,oracles[i],(int)oracleSize[i],SQLITE_STATIC);
					while (sqlite3_step(db->sGetCommentsBySubjectAndCommentOracle) == SQLITE_ROW) {
						if (sqlite3_column_int(db->sGetCommentsBySubjectAndCommentOracle,0) == ZTLF_DB_COMMENT_ASSERTION_RECORD_COLLIDES_WITH_CLAIMED_ID) {
							++qr->negativeComments;
						}
					}
				}
			}
		}
	}
	++r->count;

	sqlite3_reset(db->sQueryClearRecordSet);
	if (sqlite3_step(db->sQueryClearRecordSet) != SQLITE_DONE) {
		ZTLF_L_warning("database error clearing query record ID cache: %s",sqlite3_errmsg(db->dbc));
		goto query_error;
	}

	pthread_rwlock_unlock(&db->gfLock);
	pthread_mutex_unlock(&db->dbLock);

	return r;

query_error:
	pthread_rwlock_unlock(&db->gfLock);
	pthread_mutex_unlock(&db->dbLock);

	free(r);
	return NULL;
}

struct ZTLF_RecordList *ZTLF_DB_GetAllByOwner(struct ZTLF_DB *db,const void *owner,const unsigned int ownerLen)
{
	long rcap = 64;
	struct ZTLF_RecordList *r = (struct ZTLF_RecordList *)malloc(sizeof(struct ZTLF_RecordList) + (sizeof(struct ZTLF_RecordIndex) * rcap));

	pthread_mutex_lock(&db->dbLock);
	if (!r)
		goto query_error;

	r->count = 0;

	sqlite3_reset(db->sGetAllByOwner);
	sqlite3_bind_blob(db->sGetAllByOwner,1,owner,(int)ownerLen,SQLITE_STATIC);
	while (sqlite3_step(db->sGetAllByOwner) == SQLITE_ROW) {
		r->records[r->count].doff = (uint64_t)sqlite3_column_int64(db->sGetAllByOwner,0);
		r->records[r->count].dlen = (uint64_t)sqlite3_column_int64(db->sGetAllByOwner,1);
		r->records[r->count].localReputation = sqlite3_column_int(db->sGetAllByOwner,2);
		++r->count;
		if (r->count >= rcap) {
			void *const nr = realloc(r,sizeof(struct ZTLF_RecordList) + (sizeof(struct ZTLF_RecordIndex) * (rcap *= 2)));
			if (!nr)
				goto query_error;
			r = (struct ZTLF_RecordList *)nr;
		}
	}

	pthread_mutex_unlock(&db->dbLock);
	return r;

query_error:
	pthread_mutex_unlock(&db->dbLock);
	free(r);
	return NULL;
}

struct ZTLF_RecordList *ZTLF_DB_GetAllByIDNotOwner(struct ZTLF_DB *db,const void *id,const void *owner,const unsigned int ownerLen)
{
	long rcap = 64;
	struct ZTLF_RecordList *r = (struct ZTLF_RecordList *)malloc(sizeof(struct ZTLF_RecordList) + (sizeof(struct ZTLF_RecordIndex) * rcap));

	pthread_mutex_lock(&db->dbLock);
	if (!r)
		goto query_error;

	r->count = 0;

	sqlite3_reset(db->sGetAllByIDNotOwner);
	sqlite3_bind_blob(db->sGetAllByIDNotOwner,1,id,32,SQLITE_STATIC);
	sqlite3_bind_blob(db->sGetAllByIDNotOwner,2,owner,(int)ownerLen,SQLITE_STATIC);
	while (sqlite3_step(db->sGetAllByIDNotOwner) == SQLITE_ROW) {
		r->records[r->count].doff = (uint64_t)sqlite3_column_int64(db->sGetAllByIDNotOwner,0);
		r->records[r->count].dlen = (uint64_t)sqlite3_column_int64(db->sGetAllByIDNotOwner,1);
		r->records[r->count].localReputation = sqlite3_column_int(db->sGetAllByIDNotOwner,2);
		++r->count;
		if (r->count >= rcap) {
			void *const nr = realloc(r,sizeof(struct ZTLF_RecordList) + (sizeof(struct ZTLF_RecordIndex) * (rcap *= 2)));
			if (!nr)
				goto query_error;
			r = (struct ZTLF_RecordList *)nr;
		}
	}

	pthread_mutex_unlock(&db->dbLock);
	return r;

query_error:
	pthread_mutex_unlock(&db->dbLock);
	free(r);
	return NULL;
}

void ZTLF_DB_Stats(struct ZTLF_DB *db,uint64_t *recordCount,uint64_t *dataSize)
{
	int64_t rc = 0,ds = 0;
	pthread_mutex_lock(&db->dbLock);
	sqlite3_reset(db->sGetRecordCount);
	if (sqlite3_step(db->sGetRecordCount) == SQLITE_ROW)
		rc = sqlite3_column_int64(db->sGetRecordCount,0);
	sqlite3_reset(db->sGetDataSize);
	if (sqlite3_step(db->sGetDataSize) == SQLITE_ROW)
		ds = sqlite3_column_int64(db->sGetDataSize,0);
	pthread_mutex_unlock(&db->dbLock);
	*recordCount = (uint64_t)rc;
	*dataSize = (uint64_t)ds;
}

uint64_t ZTLF_DB_CRC64(struct ZTLF_DB *db)
{
	uint64_t crc = 0;
	pthread_rwlock_wrlock(&db->gfLock); /* acquire exclusive lock to get the most objective result */
	pthread_mutex_lock(&db->dbLock);
	sqlite3_reset(db->sGetAllRecords);
	while (sqlite3_step(db->sGetAllRecords) == SQLITE_ROW) {
		const struct ZTLF_DB_GraphNode *const gn = (struct ZTLF_DB_GraphNode *)ZTLF_MappedFile_TryGet(&db->gf,(uintptr_t)sqlite3_column_int64(db->sGetAllRecords,0),ZTLF_DB_MAX_GRAPH_NODE_SIZE);
		if (gn) {
			uint32_t w[3];
			ZTLF_SUint96_Get(&db->wf,(uintptr_t)gn->weightsFileOffset,w,w + 1,w + 2);
			_ZTLF_CRC64(crc,(const uint8_t *)w,sizeof(w));
			_ZTLF_CRC64(crc,(const uint8_t *)&(gn->linkCount),1);
			crc = _ZTLF_CRC64(crc,(const uint8_t *)sqlite3_column_blob(db->sGetAllRecords,1),32);
			int64_t linkedCount = (int64_t)sqlite3_column_int64(db->sGetAllRecords,2);
			_ZTLF_CRC64(crc,(const uint8_t *)&linkedCount,sizeof(linkedCount));
		}
	}
	pthread_mutex_unlock(&db->dbLock);
	pthread_rwlock_unlock(&db->gfLock);
	return crc;
}

int ZTLF_DB_HasPending(struct ZTLF_DB *db)
{
	int has = 0;
	pthread_mutex_lock(&db->dbLock);
	sqlite3_reset(db->sGetPendingCount);
	if (sqlite3_step(db->sGetPendingCount) == SQLITE_ROW)
		has = (int)sqlite3_column_int64(db->sGetPendingCount,0);
	if (has <= 0) {
		int64_t count = 0;
		sqlite3_reset(db->sGetRecordCount);
		if (sqlite3_step(db->sGetRecordCount) == SQLITE_ROW)
			count = sqlite3_column_int64(db->sGetRecordCount,0);
		if (count == 0)
			has = -1;
	}
	pthread_mutex_unlock(&db->dbLock);
	return has;
}

int ZTLF_DB_HaveDanglingLinks(struct ZTLF_DB *db,int ignoreWantedAfterNRetries)
{
	int has = 0;
	pthread_mutex_lock(&db->dbLock);
	sqlite3_reset(db->sHaveDanglingLinks);
	sqlite3_bind_int(db->sHaveDanglingLinks,1,ignoreWantedAfterNRetries);
	if (sqlite3_step(db->sHaveDanglingLinks) == SQLITE_ROW)
		has = 1;
	pthread_mutex_unlock(&db->dbLock);
	return has;
}

unsigned int ZTLF_DB_GetWanted(struct ZTLF_DB *db,void *buf,const unsigned int maxHashes,const unsigned int retryCountMin,const unsigned int retryCountMax,const int incrementRetryCount)
{
	if (maxHashes == 0)
		return 0;
	unsigned int count = 0;
	uint8_t *p = (uint8_t *)buf;

	pthread_mutex_lock(&db->dbLock);

	sqlite3_reset(db->sGetWanted);
	sqlite3_bind_int(db->sGetWanted,1,(int)retryCountMin);
	sqlite3_bind_int(db->sGetWanted,2,(int)retryCountMax);
	sqlite3_bind_int(db->sGetWanted,3,(int)maxHashes);
	while (sqlite3_step(db->sGetWanted) == SQLITE_ROW) {
		memcpy(p,sqlite3_column_blob(db->sGetWanted,0),32);
		if (incrementRetryCount) {
			sqlite3_reset(db->sIncWantedRetries);
			sqlite3_bind_blob(db->sIncWantedRetries,1,p,32,SQLITE_STATIC);
			sqlite3_step(db->sIncWantedRetries);
		}
		count++;
		p += 32;
	}

	pthread_mutex_unlock(&db->dbLock);

	return count;
}

int ZTLF_DB_LogComment(struct ZTLF_DB *db,const int64_t byRecordDoff,const int assertion,const int reason,const void *const subject,const int subjectLen)
{
	pthread_mutex_lock(&db->dbLock);
	sqlite3_reset(db->sLogComment);
	if (subjectLen > 0) {
		sqlite3_bind_blob(db->sLogComment,1,subject,subjectLen,SQLITE_STATIC);
	} else {
		sqlite3_bind_null(db->sLogComment,1);
	}
	sqlite3_bind_int64(db->sLogComment,2,byRecordDoff);
	sqlite3_bind_int(db->sLogComment,3,assertion);
	sqlite3_bind_int(db->sLogComment,4,reason);
	const int ok = sqlite3_step(db->sLogComment);
	pthread_mutex_unlock(&db->dbLock);
	return (ok == SQLITE_DONE) ? 0 : ZTLF_POS(ok);
}

int ZTLF_DB_SetConfig(struct ZTLF_DB *db,const char *key,const void *value,const unsigned int vlen)
{
	pthread_mutex_lock(&db->dbLock);
	sqlite3_reset(db->sSetConfig);
	sqlite3_bind_text(db->sSetConfig,1,key,-1,SQLITE_STATIC);
	sqlite3_bind_blob(db->sSetConfig,2,value,(int)vlen,SQLITE_STATIC);
	const int ok = sqlite3_step(db->sSetConfig);
	pthread_mutex_unlock(&db->dbLock);
	return (ok == SQLITE_DONE) ? 0 : ZTLF_POS(ok);
}

unsigned int ZTLF_DB_GetConfig(struct ZTLF_DB *db,const char *key,void *value,const unsigned int valueMaxLen)
{
	unsigned int len = 0;
	pthread_mutex_lock(&db->dbLock);
	sqlite3_reset(db->sGetConfig);
	sqlite3_bind_text(db->sGetConfig,1,key,-1,SQLITE_STATIC);
	if (sqlite3_step(db->sGetConfig) == SQLITE_ROW) {
		int l = sqlite3_column_bytes(db->sGetConfig,0);
		const void *v = sqlite3_column_blob(db->sGetConfig,0);
		if ((v)&&(l > 0)&&((unsigned int)l <= valueMaxLen)) {
			len = (unsigned int)l;
			memcpy(value,v,l);
		}
	}
	pthread_mutex_unlock(&db->dbLock);
	return len;
}

int ZTLF_DB_PutCert(
	struct ZTLF_DB *db,
	const char *serial,
	const char *subjectSerial,
	const uint64_t recordDoff,
	const void *cert,
	const unsigned int certLen)
{
	pthread_mutex_lock(&db->dbLock);
	sqlite3_reset(db->sPutCert);
	sqlite3_bind_text(db->sPutCert,1,subjectSerial,-1,SQLITE_STATIC);
	sqlite3_bind_text(db->sPutCert,2,serial,-1,SQLITE_STATIC);
	sqlite3_bind_int64(db->sPutCert,3,(sqlite_int64)recordDoff);
	sqlite3_bind_blob(db->sPutCert,4,cert,(int)certLen,SQLITE_STATIC);
	const int ok = sqlite3_step(db->sPutCert);
	pthread_mutex_unlock(&db->dbLock);
	return (ok == SQLITE_DONE) ? 0 : ZTLF_POS(ok);
}

int ZTLF_DB_PutCertRevocation(
	struct ZTLF_DB *db,
	const char *revokedSerialNumber,
	const uint64_t recordDoff,
	const unsigned int recordDlen)
{
	pthread_mutex_lock(&db->dbLock);
	sqlite3_reset(db->sPutCertRevocation);
	sqlite3_bind_text(db->sPutCertRevocation,1,revokedSerialNumber,-1,SQLITE_STATIC);
	sqlite3_bind_int64(db->sPutCertRevocation,2,(sqlite_int64)recordDoff);
	sqlite3_bind_int(db->sPutCertRevocation,3,(int)recordDlen);
	const int ok = sqlite3_step(db->sPutCertRevocation);
	pthread_mutex_unlock(&db->dbLock);
	return (ok == SQLITE_DONE) ? 0 : ZTLF_POS(ok);
}

struct ZTLF_CertificateResults *ZTLF_DB_GetCertInfo(struct ZTLF_DB *db,const char *subjectSerial)
{
	struct ZTLF_CertificateResults *cr = (struct ZTLF_CertificateResults *)malloc(sizeof(struct ZTLF_CertificateResults));
	if (!cr) {
		return cr;
	}

	cr->certificates = NULL;
	cr->crls = NULL;
	cr->certificatesLength = 0;
	cr->crlCount = 0;
	unsigned long certCap = 0,crlCap = 0;

	pthread_mutex_lock(&db->dbLock);
	sqlite3_reset(db->sGetCertsBySubject);
	sqlite3_bind_text(db->sGetCertsBySubject,1,subjectSerial,-1,SQLITE_STATIC);
	sqlite3_bind_text(db->sGetCertsBySubject,2,subjectSerial,-1,SQLITE_STATIC);
	while (sqlite3_step(db->sGetCertsBySubject) == SQLITE_ROW) {
		const char *const serial = (const char *)sqlite3_column_text(db->sGetCertsBySubject,0);
		if (serial) {
			const void *cert = sqlite3_column_blob(db->sGetCertsBySubject,1);
			const unsigned long certLen = (unsigned long)sqlite3_column_bytes(db->sGetCertsBySubject,1);
			if (cert) {
				const unsigned long newCertLen = cr->certificatesLength + certLen;
				if (newCertLen > certCap) {
					void *const old = cr->certificates;
					cr->certificates = realloc(cr->certificates,newCertLen + 16384);
					if (!cr->certificates) {
						cr->certificates = old;
						break;
					}
					if (old)
						free(old);
					certCap = newCertLen + 16384;
				}
				memcpy((void *)(((char *)cr->certificates) + cr->certificatesLength),cert,certLen);
				cr->certificatesLength = newCertLen;

				sqlite3_reset(db->sGetCertRevocationsByRevokedSerial);
				sqlite3_bind_text(db->sGetCertRevocationsByRevokedSerial,1,serial,-1,SQLITE_STATIC);
				while (sqlite3_step(db->sGetCertRevocationsByRevokedSerial) == SQLITE_ROW) {
					if (cr->crlCount <= crlCap) {
						void *const old = (void *)cr->crls;
						cr->crls = (struct ZTLF_RecordIndex *)realloc((void *)cr->crls,sizeof(struct ZTLF_RecordIndex) * (crlCap + 16));
						if (!cr->crls) {
							cr->crls = (struct ZTLF_RecordIndex *)old;
							break;
						}
						if (old)
							free(old);
						crlCap += 16;
					}
					cr->crls[cr->crlCount].doff = (uint64_t)sqlite3_column_int64(db->sGetCertRevocationsByRevokedSerial,0);
					cr->crls[cr->crlCount].dlen = (uint64_t)sqlite3_column_int64(db->sGetCertRevocationsByRevokedSerial,1);
					cr->crls[cr->crlCount].localReputation = 0; /* not used in this case */
					++cr->crlCount;
				}
			}
		}
	}
	pthread_mutex_unlock(&db->dbLock);

	return cr;
}

int ZTLF_DB_MarkInLimbo(struct ZTLF_DB *db,const void *hash,const void *owner,const unsigned int ownerSize,const uint64_t localReceiveTime,const uint64_t ts)
{
	pthread_mutex_lock(&db->dbLock);
	sqlite3_reset(db->sMarkInLimbo);
	sqlite3_bind_blob(db->sMarkInLimbo,1,hash,32,SQLITE_STATIC);
	sqlite3_bind_blob(db->sMarkInLimbo,2,owner,(int)ownerSize,SQLITE_STATIC);
	sqlite3_bind_int64(db->sMarkInLimbo,3,(sqlite_int64)ts);
	sqlite3_bind_int64(db->sMarkInLimbo,4,(sqlite_int64)localReceiveTime);
	const int ok = sqlite3_step(db->sMarkInLimbo);
	pthread_mutex_unlock(&db->dbLock);
	return (ok == SQLITE_DONE) ? 0 : ZTLF_POS(ok);
}

int ZTLF_DB_HaveRecordIncludeLimbo(struct ZTLF_DB *db,const void *hash)
{
	int have = 0;
	pthread_mutex_lock(&db->dbLock);
	sqlite3_reset(db->sGetRecordByHash);
	sqlite3_bind_blob(db->sGetRecordByHash,1,hash,32,SQLITE_STATIC);
	if (sqlite3_step(db->sGetRecordByHash) == SQLITE_ROW) {
		have = 1;
	} else {
		sqlite3_reset(db->sHaveRecordInLimbo);
		sqlite3_bind_blob(db->sHaveRecordInLimbo,1,hash,32,SQLITE_STATIC);
		if (sqlite3_step(db->sHaveRecordInLimbo) == SQLITE_ROW) {
			have = 2;
		}
	}
	pthread_mutex_unlock(&db->dbLock);
	return have;
}

int ZTLF_DB_UpdatePulse(struct ZTLF_DB *db,const uint64_t token,const uint64_t minutes,const uint64_t startRangeStart,const uint64_t startRangeEnd)
{
	int changed = 0;
	pthread_mutex_lock(&db->dbLock);
	sqlite3_reset(db->sUpdatePulse);
	sqlite3_bind_int64(db->sUpdatePulse,1,(sqlite_int64)minutes);
	sqlite3_bind_int64(db->sUpdatePulse,2,(sqlite_int64)token);
	sqlite3_bind_int64(db->sUpdatePulse,3,(sqlite_int64)startRangeStart);
	sqlite3_bind_int64(db->sUpdatePulse,4,(sqlite_int64)startRangeEnd);
	sqlite3_bind_int64(db->sUpdatePulse,5,(sqlite_int64)minutes);
	if (sqlite3_step(db->sUpdatePulse) == SQLITE_DONE) {
		changed = sqlite3_changes(db->dbc);
	}
	pthread_mutex_unlock(&db->dbLock);
	return changed;
}

uint64_t ZTLF_DB_GetPulse(struct ZTLF_DB *db,const uint64_t token)
{
	uint64_t p = 0;
	pthread_mutex_lock(&db->dbLock);
	sqlite3_reset(db->sGetPulse);
	sqlite3_bind_int64(db->sGetPulse,1,(sqlite_int64)token);
	if (sqlite3_step(db->sGetPulse) == SQLITE_ROW)
		p = (uint64_t)sqlite3_column_int64(db->sGetPulse,0);
	pthread_mutex_unlock(&db->dbLock);
	return p;
}
