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

#include "common.h"

uint64_t ZTLF_prng()
{
	static volatile uint64_t state[2] = {0,0};
	/* https://en.wikipedia.org/wiki/Xorshift#xorshift.2B */
	uint64_t x = state[0];
	uint64_t y = state[1];
	if ((!x)&&(!y)) {
		x = ZTLF_timeMs();
		y = (uint64_t)rand() + (uint64_t)(&state);
#ifndef __WINDOWS__
		y += (uint64_t)getpid();
#endif
	}
	state[0] = y;
	x ^= x << 23;
	const uint64_t z = x ^ y ^ (x >> 17) ^ (y >> 26);
	state[1] = z;
	return z + y + (uint64_t)rand();
}

#ifdef __WINDOWS__

unsigned int ZTLF_ncpus()
{
	static volatile unsigned int nc = 0;
	const unsigned int tmp = nc;
	if (!tmp) {
		SYSTEM_INFO info;
		GetSystemInfo(&info);
		return (nc = (info.dwNumberOfProcessors <= 0) ? (unsigned int)1 : (unsigned int)(info.dwNumberOfProcessors));
	}
	return tmp;
}

#else

unsigned int ZTLF_ncpus()
{
	static volatile unsigned int nc = 0;
	const unsigned int tmp = nc;
	if (!tmp) {
		long n = sysconf(_SC_NPROCESSORS_ONLN);
		return (nc = (n <= 0) ? (unsigned int)1 : (unsigned int)n);
	}
	return tmp;
}

void ZTLF_secureRandom(void *b,const unsigned long n)
{
	static pthread_mutex_t l = PTHREAD_MUTEX_INITIALIZER;
	static int fd = -1;
	pthread_mutex_lock(&l);
	if (fd < 0) {
		fd = open("/dev/urandom",O_RDONLY);
		if (fd < 0) {
			fprintf(stderr,"FATAL: unable to open /dev/urandom\n");
			abort();
		}
	}
	if (read(fd,b,(size_t)n) != (ssize_t)n) {
		fprintf(stderr,"FATAL: read error from /dev/urandom\n");
		abort();
	}
	pthread_mutex_unlock(&l);
}

#endif
