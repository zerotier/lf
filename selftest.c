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

#include "selftest.h"
#include "wharrgarbl.h"

bool ZTLF_selftest_core(FILE *o)
{
	uint64_t tmp[4];
	ZTLF_secureRandom(tmp,sizeof(tmp));
	fprintf(o,"Testing cryptographic PRNG: %.16llx%.16llx%.16llx%.16llx" ZTLF_EOL,tmp[0],tmp[1],tmp[2],tmp[3]);
	fprintf(o,"Testing non-cryptographic PRNG: %.16llx%.16llx%.16llx%.16llx" ZTLF_EOL,ZTLF_prng(),ZTLF_prng(),ZTLF_prng(),ZTLF_prng());
}

bool ZTLF_selftest_wharrgarbl(FILE *o)
{
	uint8_t tmp[32];
	for(int i=0;i<32;++i)
		tmp[i] = (uint8_t)i;
	uint8_t pow[ZTLF_WHARRGARBL_POW_BYTES];
	fprintf(o,"Testing and benchmarking wharrgarbl proof of work..." ZTLF_EOL);
	fprintf(o,"-----------------------------------------------------" ZTLF_EOL);
	fprintf(o,"Difficulty (hex)  Threads    Iterations  Avg Time (s)" ZTLF_EOL);
	fprintf(o,"-----------------------------------------------------" ZTLF_EOL);
	const unsigned int thr = ZTLF_ncpus();
	unsigned long mem = 1024 * 1024 * 512;
	void *foo = malloc(mem);
	for(int i=8;i<20;++i) {
		uint32_t diff32 = 1 << i;
		uint64_t iter = 0;
		uint64_t start = ZTLF_timeMs();
		for(int k=0;k<10;++k)
			iter += ZTLF_wharrgarbl(pow,tmp,sizeof(tmp),diff32,foo,mem,0);
		uint64_t end = ZTLF_timeMs();
		if (!ZTLF_wharrgarblVerify(pow,tmp,sizeof(tmp))) {
			fprintf(o,"FAILED! (verify)" ZTLF_EOL);
			free(foo);
			return false;
		}
		fprintf(o,"   %12x  %8u  %12llu   %.8f" ZTLF_EOL,diff32,thr,iter / 10,((double)(end - start)) / 10.0 / 1000.0);
	}
	free(foo);
	return true;
}
