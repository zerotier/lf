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
	const unsigned long mem = 1024 * 1024 * 1024;
	const int trials = 32;
	void *const foo = malloc(mem);

	uint8_t tmp[32];
	for(int i=0;i<32;++i)
		tmp[i] = (uint8_t)i;
	uint8_t pow[ZTLF_WHARRGARBL_POW_BYTES];

	fprintf(o,"Testing and benchmarking wharrgarbl proof of work..." ZTLF_EOL);
	for(unsigned int rsize=64;rsize<=ZTLF_RECORD_MAX_SIZE;rsize<<=1) {
		uint32_t diff = ZTLF_Record_WharrgarblDifficultyRequired(rsize);
		uint64_t iter = 0;
		uint64_t start = ZTLF_timeMs();
		for(int k=0;k<trials;++k)
			iter += ZTLF_wharrgarbl(pow,tmp,sizeof(tmp),diff,foo,mem,0);
		uint64_t end = ZTLF_timeMs();
		if (!ZTLF_wharrgarblVerify(pow,tmp,sizeof(tmp))) {
			fprintf(o,"FAILED! (verify)" ZTLF_EOL);
			free(foo);
			return false;
		}
		fprintf(o,"  %8lx (%4u)   %12llu   %.8f" ZTLF_EOL,(unsigned long)diff,rsize,iter / (uint64_t)trials,((double)(end - start)) / (double)trials / 1000.0);
	}

	free(foo);
	return true;
}

bool ZTLF_selftest_modelProofOfWork(FILE *o)
{
	const unsigned long mem = 1024 * 1024 * 1024;
	const uint32_t startingDifficulty = 1;
	const int sampleCount = 100;
	uint8_t wout[ZTLF_WHARRGARBL_POW_BYTES];
	uint8_t junk[48];
	void *const foo = malloc(mem);

	ZTLF_secureRandom(junk,sizeof(junk));

	fprintf(o,"Modeling proof of work and empirically determining difficulties..." ZTLF_EOL ZTLF_EOL);

	fprintf(o,"Timing base difficulty of %.8lx / %lu ... ",(unsigned long)startingDifficulty,(unsigned long)startingDifficulty);
	fflush(o);
	const uint64_t minTimeStart = ZTLF_timeMs();
	for(int k=0;k<sampleCount;++k)
		ZTLF_wharrgarbl(wout,junk,sizeof(junk),startingDifficulty,foo,mem,0);
	const uint64_t minTimeEnd = ZTLF_timeMs();
	const uint64_t minTime = (minTimeEnd - minTimeStart) / (uint64_t)sampleCount;
	fprintf(o,"%llu ms" ZTLF_EOL ZTLF_EOL,(unsigned long long)minTime);

	fprintf(o,"Finding acceptable difficulties for linear time increase..." ZTLF_EOL);
	uint64_t targetTime = minTime;
	uint32_t difficulty = startingDifficulty;
	for(unsigned int targetSize=2;targetSize<=ZTLF_RECORD_MAX_SIZE;targetSize<<=1) {
		targetTime += (targetTime / 4) * 3; /* increase target time by 75% for each doubling of target size */
		fprintf(o,"  Target: %llu ms for %u bytes..." ZTLF_EOL,(unsigned long long)targetTime,targetSize);

		bool direction = true;
		double lastErr = 1.0;
		for(;;) {
			const uint32_t maxMove = (uint32_t)round(lastErr * (double)difficulty);
			if (maxMove > 5) {
				if (direction) {
					difficulty += (uint32_t)ZTLF_prng() % maxMove;
				} else {
					difficulty -= (uint32_t)ZTLF_prng() % maxMove;
				}
			} else {
				if (direction)
					++difficulty;
				else if (difficulty)
					--difficulty;
			}
			if (difficulty < startingDifficulty)
				difficulty = startingDifficulty;

			const uint64_t st = ZTLF_timeMs();
			for(int k=0;k<sampleCount;++k) {
				++junk[0];
				ZTLF_wharrgarbl(wout,junk,sizeof(junk),difficulty,foo,mem,0);
			}
			const uint64_t et = ZTLF_timeMs();
			const uint64_t t = (et - st) / (uint64_t)sampleCount;

			const double perr = fabs((double)t - (double)targetTime) / (double)targetTime;
			fprintf(o,"    Difficulty: %.8lx / %-10lu Time: %-8llu ms    Error: %f" ZTLF_EOL,(unsigned long)difficulty,(unsigned long)difficulty,(unsigned long long)t,perr);

			if (perr < 0.05) {
				break;
			}
			direction = (t < targetTime);
			lastErr = perr;
		}
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
		int e = ZTLF_Record_Create(&(testRecords[ri].rb),tmp,strlen(tmp),"test",4,pub,priv,links,lc,ts,ZTLF_TTL_FOREVER,true,true,NULL);
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
			int e = ZTLF_Record_Expand(&er,&(testRecords[ri].rb.data.r),testRecords[ri].rb.size);
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
	//if (!ZTLF_selftest_db(o,"lf-selftest-db-work")) return false;
	//fprintf(o,ZTLF_EOL);
	if (!ZTLF_selftest_wharrgarbl(o)) return false;
	fprintf(o,ZTLF_EOL);
	return true;
}
