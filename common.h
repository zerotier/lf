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

/* We really don't even support 32-bit systems for this, but go ahead and
 * make it work. */
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#ifndef _LARGEFILE_SOURCE
#define _LARGEFILE_SOURCE 1
#endif

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <limits.h>
#include <string.h>
#include <memory.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#ifndef MSG_DONTWAIT
#ifdef MSG_NONBLOCK
#define MSG_DONTWAIT MSG_NONBLOCK
#else
#error Neither MSG_DONTWAIT nor MSG_NONBLOCK exist
#endif
#endif

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

#if defined(_WIN32) || defined(WIN32) || defined(_WIN64) || defined(WIN64)

#include <WinSock2.h>
#include <windows.h>

#ifndef __WINDOWS__
#define __WINDOWS__ 1
#endif

#define ZTLF_PACKED_STRUCT(D) __pragma(pack(push,1)) D __pragma(pack(pop))
#define ZTLF_PATH_SEPARATOR "\\"
#define ZTLF_EOL "\r\n"

#else /* not Windows -------------------------------------------------- */

#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <pthread/pthread.h>

#ifndef MAP_FILE /* legacy flag, not used on some platforms */
#define MAP_FILE 0
#endif

#define ZTLF_PACKED_STRUCT(D) D __attribute__((packed))
#define ZTLF_PATH_SEPARATOR "/"
#define ZTLF_EOL "\n"

#endif /* Windows or non-Windows? ------------------------------------- */

#if (defined(__GNUC__) && (__GNUC__ >= 3)) || (defined(__INTEL_COMPILER) && (__INTEL_COMPILER >= 800)) || defined(__clang__)
#ifndef likely
#define likely(x) __builtin_expect((x),1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect((x),0)
#endif
#else
#ifndef likely
#define likely(x) (x)
#endif
#ifndef unlikely
#define unlikely(x) (x)
#endif
#endif

/* Assume little-endian byte order if not defined. Are there even any BE
 * systems large enough to run this still in production in 2018? */
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
#if (defined(__GNUC__) && (__GNUC__ >= 3)) || (defined(__INTEL_COMPILER) && (__INTEL_COMPILER >= 800)) || defined(__clang__)
#define ZTLF_htonll(n) ((uint64_t)(__builtin_bswap64((uint64_t)(n))))
#else
static inline uint64_t ZTLF_htonll(uint64_t n)
{
	return (
		((n & 0x00000000000000ffULL) << 56) |
		((n & 0x000000000000ff00ULL) << 40) |
		((n & 0x0000000000ff0000ULL) << 24) |
		((n & 0x00000000ff000000ULL) <<  8) |
		((n & 0x000000ff00000000ULL) >>  8) |
		((n & 0x0000ff0000000000ULL) >> 24) |
		((n & 0x00ff000000000000ULL) >> 40) |
		((n & 0xff00000000000000ULL) >> 56)
	);
}
#endif
#else
#define ZTLF_htonll(n) ((uint64_t)(n))
#endif

#define ZTLF_ntohll(n) ZTLF_htonll((n))

#define ZTLF_MALLOC_CHECK(m) if (unlikely(!((m)))) { fprintf(stderr,"FATAL: malloc() failed!\n"); abort(); }

#define ZTLF_NEG(e) (((e) <= 0) ? (e) : -(e))
#define ZTLF_POS(e) (((e) >= 0) ? (e) : -(e))

#define ZTLF_timeSec() ((uint64_t)time(NULL))

const uint32_t ZTLF_CRC32_TABLE[256];

uint64_t ZTLF_prng();
unsigned int ZTLF_ncpus();
void ZTLF_secureRandom(void *b,const unsigned long n);

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

/* https://en.wikipedia.org/wiki/Xorshift#xorshift* */
static inline uint64_t ZTLF_xorshift64star(uint64_t *const state)
{
	uint64_t x = *state;
	if (unlikely(!x))
		x = 1;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	*state = x;
	return x * 0x2545F4914F6CDD1DULL;
}

/* This is a version of xorshift64star that is designed to only be run once for e.g. hash mixing. */
static inline uint64_t ZTLF_xorshift64starOnce(uint64_t x)
{
	if (unlikely(!x))
		x = 1;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	return x * 0x2545F4914F6CDD1D;
}

static inline uint32_t ZTLF_crc32(const void *const buf,const unsigned int len)
{
	uint32_t crc = 0xffffffff;
	for(unsigned int i=0;i<len;++i) {
		crc = ZTLF_CRC32_TABLE[(crc ^ ((const uint8_t *)buf)[i]) & 0xff] ^ (crc >> 8);
	}
	return ~crc;
}

static inline bool ZTLF_allZero(const void *const d,const unsigned int len)
{
	for(int i=0;i<len;++i) {
		if (((const uint8_t *)d)[i])
			return false;
	}
	return true;
}

#endif
