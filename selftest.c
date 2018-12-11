/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#include "selftest.h"
#include "wharrgarbl.h"
#include "record.h"
#include "db.h"

#define ZTLF_SELFTEST_DB_TEST_RECORD_COUNT 1000
#define ZTLF_SELFTEST_DB_TEST_DB_COUNT 8

bool ZTLF_selftest_core(FILE *o)
{
	if (sizeof(void *) < 8) {
		fprintf(o,"WARNING: a 64-bit platform is recommended to avoid possible address space and file size constraints!" ZTLF_EOL ZTLF_EOL);
	}

	uint64_t tmp[4];
	ZTLF_secureRandom(tmp,sizeof(tmp));
	fprintf(o,"Testing cryptographic PRNG:     %.16llx%.16llx%.16llx%.16llx" ZTLF_EOL,tmp[0],tmp[1],tmp[2],tmp[3]);
	ZTLF_secureRandom(tmp,sizeof(tmp));
	fprintf(o,"                                %.16llx%.16llx%.16llx%.16llx" ZTLF_EOL,tmp[0],tmp[1],tmp[2],tmp[3]);
	ZTLF_secureRandom(tmp,sizeof(tmp));
	fprintf(o,"                                %.16llx%.16llx%.16llx%.16llx" ZTLF_EOL,tmp[0],tmp[1],tmp[2],tmp[3]);
	ZTLF_secureRandom(tmp,sizeof(tmp));
	fprintf(o,"                                %.16llx%.16llx%.16llx%.16llx" ZTLF_EOL,tmp[0],tmp[1],tmp[2],tmp[3]);
	fprintf(o,"Testing non-cryptographic PRNG: %.16llx%.16llx%.16llx%.16llx" ZTLF_EOL,ZTLF_prng(),ZTLF_prng(),ZTLF_prng(),ZTLF_prng());
	fprintf(o,"                                %.16llx%.16llx%.16llx%.16llx" ZTLF_EOL,ZTLF_prng(),ZTLF_prng(),ZTLF_prng(),ZTLF_prng());
	fprintf(o,"                                %.16llx%.16llx%.16llx%.16llx" ZTLF_EOL,ZTLF_prng(),ZTLF_prng(),ZTLF_prng(),ZTLF_prng());
	fprintf(o,"                                %.16llx%.16llx%.16llx%.16llx" ZTLF_EOL,ZTLF_prng(),ZTLF_prng(),ZTLF_prng(),ZTLF_prng());

	return true;
}

bool ZTLF_selftest_wharrgarbl(FILE *o)
{
	void *const foo = malloc(ZTLF_RECORD_WHARRGARBL_POW_ITERATION_MEMORY);

	uint8_t tmp[32];
	for(int i=0;i<32;++i)
		tmp[i] = (uint8_t)i;
	uint8_t pow[ZTLF_WHARRGARBL_POW_BYTES];

	fprintf(o,"Testing and benchmarking wharrgarbl proof of work..." ZTLF_EOL);
	fprintf(o,"-----------------------------------------------------" ZTLF_EOL);
	fprintf(o,"Difficulty (hex)  Threads    Iterations  Avg Time (s)" ZTLF_EOL);
	fprintf(o,"-----------------------------------------------------" ZTLF_EOL);
	const unsigned int thr = ZTLF_ncpus();
	for(int i=0;i<4;++i) {
		uint64_t iter = 0;
		uint64_t start = ZTLF_timeMs();
		for(int k=0;k<5;++k)
			iter += ZTLF_wharrgarbl(pow,tmp,sizeof(tmp),ZTLF_RECORD_WHARRGARBL_POW_ITERATION_DIFFICULTY,foo,ZTLF_RECORD_WHARRGARBL_POW_ITERATION_MEMORY,0);
		uint64_t end = ZTLF_timeMs();
		if (!ZTLF_wharrgarblVerify(pow,tmp,sizeof(tmp))) {
			fprintf(o,"FAILED! (verify)" ZTLF_EOL);
			free(foo);
			return false;
		}
		fprintf(o,"   %12x  %8u  %12llu   %.8f" ZTLF_EOL,ZTLF_RECORD_WHARRGARBL_POW_ITERATION_DIFFICULTY,thr,iter / 5,((double)(end - start)) / 5.0 / 1000.0);
	}

	free(foo);
	return true;
}

bool ZTLF_selftest_modelProofOfWork(FILE *o)
{
	void *const foo = malloc(ZTLF_RECORD_WHARRGARBL_POW_ITERATION_MEMORY);

	uint8_t tmp[32];
	for(int i=0;i<32;++i)
		tmp[i] = (uint8_t)i;
	uint8_t pow[ZTLF_WHARRGARBL_POW_BYTES];

	uint8_t scoringHash[48];
	double avgTime[ZTLF_RECORD_MAX_SIZE][2];
	uint64_t startTimes[ZTLF_RECORD_MAX_SIZE];
	memset(avgTime,0,sizeof(avgTime));
	const uint64_t stime = ZTLF_timeMs();
	for(unsigned int i=0;i<ZTLF_RECORD_MAX_SIZE;++i)
		startTimes[i] = stime;
	for(;;) {
		ZTLF_wharrgarbl(pow,tmp,sizeof(tmp),ZTLF_RECORD_WHARRGARBL_POW_ITERATION_DIFFICULTY,foo,ZTLF_RECORD_WHARRGARBL_POW_ITERATION_MEMORY,0);
		ZTLF_SHA384(scoringHash,pow,sizeof(pow));
		const uint32_t score = ZTLF_score(scoringHash);

		uint32_t recordLengthAchieved = score / ZTLF_RECORD_WORK_COST_DIVISOR;
		if (recordLengthAchieved > ZTLF_RECORD_MAX_SIZE)
			recordLengthAchieved = ZTLF_RECORD_MAX_SIZE;
		if (recordLengthAchieved == 0)
			continue;
		--recordLengthAchieved;

		const uint64_t now = ZTLF_timeMs();
		for(uint32_t i=0;i<=recordLengthAchieved;++i) {
			const uint64_t elapsed = now - startTimes[i];
			startTimes[i] = now;
			avgTime[i][0] += ((double)elapsed) / 1000.0;
			avgTime[i][1] += 1.0;
		}
		for(unsigned int i=32;i<=ZTLF_RECORD_MAX_SIZE;i<<=1) {
			fprintf(o,"%5u %7.2f %6u" ZTLF_EOL,i,(avgTime[i-1][1] > 0.0) ? (avgTime[i-1][0] / avgTime[i-1][1]) : 0.0,(unsigned int)avgTime[i-1][1]);
		}
		fprintf(o,ZTLF_EOL);
	}

	free(foo);

	return true;
}

struct ZTLF_TestRec
{
	uint64_t hash[4];
	struct ZTLF_RecordBuffer rb;
};

bool ZTLF_selftest_db(FILE *o,const char *p)
{
	bool success = true;
	struct ZTLF_TestRec *testRecords = malloc(ZTLF_SELFTEST_DB_TEST_RECORD_COUNT * sizeof(struct ZTLF_TestRec));
	char tmp[128],basePath[1024];;
	uint8_t links[ZTLF_RECORD_MIN_LINKS][32];
	struct ZTLF_DB testDb[ZTLF_SELFTEST_DB_TEST_DB_COUNT];
	bool testDbOpen[ZTLF_SELFTEST_DB_TEST_DB_COUNT];
	unsigned int order[ZTLF_SELFTEST_DB_TEST_RECORD_COUNT];
	struct ZTLF_ExpandedRecord er;

	for(int i=0;i<ZTLF_SELFTEST_DB_TEST_DB_COUNT;++i) testDbOpen[i] = false;

	fprintf(o,"Testing LF database and graph weight application algorithm..." ZTLF_EOL);

	unsigned char pub[ZTLF_ED25519_PUBLIC_KEY_SIZE];
	unsigned char priv[ZTLF_ED25519_PRIVATE_KEY_SIZE];
	ZTLF_secureRandom(tmp,32);
	ZTLF_Ed25519CreateKeypair(pub,priv,(const unsigned char *)tmp);

	fprintf(o,"Generating %d test records..." ZTLF_EOL,ZTLF_SELFTEST_DB_TEST_RECORD_COUNT);
	uint64_t ts = ZTLF_timeMs();
	for(unsigned int ri=0;ri<ZTLF_SELFTEST_DB_TEST_RECORD_COUNT;++ri) {
		++ts;

		unsigned int lc = 0;
		for(unsigned int x=ri;x>0;) {
			--x;
			if ((ZTLF_prng() % 2) == 0) {
				memcpy(links[lc++],testRecords[x].hash,32);
				if (lc == ZTLF_RECORD_MIN_LINKS)
					break;
			}
		}

		snprintf(tmp,sizeof(tmp),"%u",ri);
		int e = ZTLF_Record_create(&(testRecords[ri].rb),tmp,strlen(tmp),"test",4,pub,priv,links,lc,ts,ZTLF_TTL_FOREVER,true,true,NULL,NULL);
		if (e) {
			fprintf(o,"  FAILED: error generating test record: %d\n" ZTLF_EOL,e);
			success = false;
			goto selftest_db_exit;
		}

		ZTLF_Shandwich256(testRecords[ri].hash,testRecords[ri].rb.data.b,testRecords[ri].rb.size);
		/* fprintf(o,"  %s (%u links, %u bytes)" ZTLF_EOL,ZTLF_hexstr(testRecords[ri].hash,32,0),lc,testRecords[ri].rb.size); */
	}

	mkdir(p,0755);
	snprintf(basePath,sizeof(basePath),"%s" ZTLF_PATH_SEPARATOR "test-%d",p,(int)getpid());
	mkdir(basePath,0755);
	fprintf(o,"Opening %d test databases under '%s'..." ZTLF_EOL,ZTLF_SELFTEST_DB_TEST_DB_COUNT,basePath);
	for(unsigned int dbi=0;dbi<ZTLF_SELFTEST_DB_TEST_DB_COUNT;++dbi) {
		snprintf(tmp,sizeof(tmp),"%s" ZTLF_PATH_SEPARATOR "%u",basePath,dbi);
		int e = ZTLF_DB_Open(&(testDb[dbi]),tmp);
		if (e) {
			fprintf(o,"  FAILED: error opening database: %d\n" ZTLF_EOL,e);
			success = false;
			goto selftest_db_exit;
		}
		fprintf(o,"  %s" ZTLF_EOL,tmp);
		testDbOpen[dbi] = true;
	}

	fprintf(o,"Inserting records into each database in a different order..." ZTLF_EOL);
	for(unsigned int i=0;i<ZTLF_SELFTEST_DB_TEST_RECORD_COUNT;++i)
		order[i] = i;

	for(unsigned int dbi=0;dbi<ZTLF_SELFTEST_DB_TEST_DB_COUNT;++dbi) {
		for(unsigned int oi=0;oi<ZTLF_SELFTEST_DB_TEST_RECORD_COUNT;++oi) {
			const unsigned int another = ((unsigned int)ZTLF_prng()) % ZTLF_SELFTEST_DB_TEST_RECORD_COUNT;
			unsigned int x = order[oi];
			order[oi] = order[another];
			order[another] = x;
		}

		for(unsigned int oi=0;oi<ZTLF_SELFTEST_DB_TEST_RECORD_COUNT;++oi) {
			if ((oi % 1000) == 999) usleep(100000); /* sleep to make background thread in DB do partial work */
			const unsigned int ri = order[oi];
			int e = ZTLF_Record_expand(&er,&(testRecords[ri].rb.data.r),testRecords[ri].rb.size);
			if (e) {
				fprintf(o,"  FAILED: error expanding record: %d" ZTLF_EOL,e);
				success = false;
				goto selftest_db_exit;
			}
			e = ZTLF_DB_PutRecord(&testDb[dbi],&er);
			if (e) {
				fprintf(o,"  FAILED: error adding record to database: %d (%s)" ZTLF_EOL,e,(e > 0) ? ZTLF_DB_LastSqliteErrorMessage(&testDb[dbi]) : strerror(-e));
				success = false;
				goto selftest_db_exit;
			}
		}
	}

	for(unsigned int dbi=0;dbi<ZTLF_SELFTEST_DB_TEST_DB_COUNT;++dbi) {
		while (ZTLF_DB_HasGraphPendingRecords(&testDb[dbi])) {
			usleep(250000);
		}
	}

	fprintf(o,"Checking that all databases' records and record weights are the same..." ZTLF_EOL);
	uint8_t lastHash[48];
	for(unsigned int dbi=0;dbi<ZTLF_SELFTEST_DB_TEST_DB_COUNT;++dbi) {
		uint8_t hash[48];
		const unsigned long cnt = ZTLF_DB_HashState(&testDb[dbi],hash);
		fprintf(o,"  #%u hash %s record count %lu" ZTLF_EOL,dbi,ZTLF_hexstr(hash,48,0),cnt);
		if (dbi > 0) {
			if (memcmp(lastHash,hash,48)) {
				fprintf(o,"  FAILED: hash does not match previous hash, different databases yielded different results!");
				success = false;
				goto selftest_db_exit;
			}
		}
		memcpy(lastHash,hash,48);
	}

	fprintf(o,"Database looks to be working OK, closing test instances." ZTLF_EOL);

selftest_db_exit:
	for(int dbi=0;dbi<ZTLF_SELFTEST_DB_TEST_DB_COUNT;++dbi) {
		if (testDbOpen[dbi])
			ZTLF_DB_Close(&testDb[dbi]);
	}
	free(testRecords);
	return success;
}

bool ZTLF_selftest(FILE *o)
{
	if (!ZTLF_selftest_core(o)) return false;
	fprintf(o,ZTLF_EOL);
	if (!ZTLF_selftest_db(o,"lf-selftest-db-work")) return false;
	fprintf(o,ZTLF_EOL);
	if (!ZTLF_selftest_wharrgarbl(o)) return false;
	fprintf(o,ZTLF_EOL);
	return true;
}
