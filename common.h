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

#ifndef ZT_LF_COMMON_H
#define ZT_LF_COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <limits.h>
#include <string.h>
#include <memory.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#if defined(_WIN32) || defined(WIN32) || defined(_WIN64) || defined(WIN64)

#include <WinSock2.h>
#include <windows.h>

#ifndef __WINDOWS__
#define __WINDOWS__ 1
#endif

#define ZTLF_PACKED_STRUCT(D) __pragma(pack(push,1)) D __pragma(pack(pop))

static inline unsigned int ZTLF_ncpus()
{
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	if (info.dwNumberOfProcessors <= 0) {
		return 1;
	}
	return (unsigned int)(info.dwNumberOfProcessors);
}

#else /* not Windows */

#include <unistd.h>
#include <pthread/pthread.h>

#define ZTLF_PACKED_STRUCT(D) D __attribute__((packed))

static inline unsigned int ZTLF_ncpus()
{
	long n = sysconf(_SC_NPROCESSORS_ONLN);
	if (n <= 0) {
		return 1;
	}
	return (unsigned int)n;
}

#endif /* Windows or non-Windows? */

/* Assume little-endian byte order if not defined by compiler or system headers. */
/* Are there even any big-endian systems still in production outside tiny embedded chips? */
#ifndef __BYTE_ORDER__
#ifndef __ORDER_LITTLE_ENDIAN__
#define __ORDER_LITTLE_ENDIAN__ 4321
#endif
#ifndef __ORDER_BIG_ENDIAN__
#define __ORDER_BIG_ENDIAN__ 1234
#endif
#define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#if defined(__GNUC__)
#if defined(__FreeBSD__)
#define ZTLF_htonll(n) (bswap64((uint64_t)(n)))
#elif (!defined(__OpenBSD__))
#define ZTLF_htonll(n) (__builtin_bswap64((uint64_t)(n)))
#endif
#else
static inline uint64_t ZTLF_htonll(uint64_t n)
{
	return (
		((n & 0x00000000000000FFULL) << 56) |
		((n & 0x000000000000FF00ULL) << 40) |
		((n & 0x0000000000FF0000ULL) << 24) |
		((n & 0x00000000FF000000ULL) <<  8) |
		((n & 0x000000FF00000000ULL) >>  8) |
		((n & 0x0000FF0000000000ULL) >> 24) |
		((n & 0x00FF000000000000ULL) >> 40) |
		((n & 0xFF00000000000000ULL) >> 56)
	);
}
#endif
#else
#define ZTLF_htonll(n) ((uint64_t)(n))
#endif

#define ZTLF_ntohll(n) ZTLF_htonll((n))

static inline uint64_t ZTLF_timeMs()
{
#ifdef __WINDOWS__
	FILETIME ft;
	SYSTEMTIME st;
	ULARGE_INTEGER tmp;
	GetSystemTime(&st);
	SystemTimeToFileTime(&st,&ft);
	tmp.LowPart = ft.dwLowDateTime;
	tmp.HighPart = ft.dwHighDateTime;
	return (uint64_t)( ((tmp.QuadPart - 116444736000000000ULL) / 10000ULL) + st.wMilliseconds );
#else
	struct timeval tv;
	gettimeofday(&tv,(struct timezone *)0);
	return ( (1000ULL * (uint64_t)tv.tv_sec) + (uint64_t)(tv.tv_usec / 1000) );
#endif
};

uint64_t ZTLF_prng();

#endif
