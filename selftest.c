/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#include "selftest.h"
#include "wharrgarbl.h"
#include "record.h"

bool ZTLF_selftest_core(FILE *o)
{
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

	int icols = -1;
	char *cols = getenv("COLUMNS");
	if (cols) {
		icols = (int)strtol(cols,NULL,10);
		if (icols <= 0)
			icols = -1;
	}
	icols /= 15;
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
		for(int i=0;i<16;++i)
			fprintf(o,ZTLF_EOL);
		for(unsigned int i=0;i<ZTLF_RECORD_MAX_SIZE;++i) {
			fprintf(o,"|%5u %7.2f ",i+1,(avgTime[i][1] > 0.0) ? (avgTime[i][0] / avgTime[i][1]) : 0.0);
			if (icols > 0) {
				if ((i % icols) == (icols-1))
					fprintf(o,ZTLF_EOL);
			}
		}
		fprintf(o,ZTLF_EOL);
	}

	free(foo);

	return true;
}

bool ZTLF_selftest(FILE *o)
{
	if (!ZTLF_selftest_core(o)) return false;
	fprintf(o,ZTLF_EOL);
	if (!ZTLF_selftest_wharrgarbl(o)) return false;
	fprintf(o,ZTLF_EOL);
	return true;
}
