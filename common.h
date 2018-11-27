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
#include <stdarg.h>
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
#define ZTLF_PATH_SEPARATOR_C '\\'
#define ZTLF_EOL "\r\n"

#else /* not Windows -------------------------------------------------- */

#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <pthread/pthread.h>
#include <sched.h>

#ifndef MAP_FILE /* legacy flag, not used on some platforms */
#define MAP_FILE 0
#endif

#define ZTLF_PACKED_STRUCT(D) D __attribute__((packed))
#define ZTLF_PATH_SEPARATOR "/"
#define ZTLF_PATH_SEPARATOR_C '/'
#define ZTLF_EOL "\n"

pthread_t ZTLF_threadCreate(void *(*threadMain)(void *),void *arg,bool lowPriority);

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

#define ZTLF_setu16(f,v) { \
	const uint16_t _setu_v = (uint16_t)(v); \
	((uint8_t *)&(f))[0] = (uint8_t)((_setu_v) >> 8); \
	((uint8_t *)&(f))[1] = (uint8_t)(_setu_v); }
#define ZTLF_setu32(f,v) { \
	const uint32_t _setu_v = (uint32_t)(v); \
	((uint8_t *)&(f))[0] = (uint8_t)((_setu_v) >> 24); \
	((uint8_t *)&(f))[1] = (uint8_t)((_setu_v) >> 16); \
	((uint8_t *)&(f))[2] = (uint8_t)((_setu_v) >> 8); \
	((uint8_t *)&(f))[3] = (uint8_t)(_setu_v); }
#define ZTLF_setu64(f,v) { \
	const uint64_t _setu_v = (uint64_t)(v); \
	((uint8_t *)&(f))[0] = (uint8_t)((_setu_v) >> 56); \
	((uint8_t *)&(f))[1] = (uint8_t)((_setu_v) >> 48); \
	((uint8_t *)&(f))[2] = (uint8_t)((_setu_v) >> 40); \
	((uint8_t *)&(f))[3] = (uint8_t)((_setu_v) >> 32); \
	((uint8_t *)&(f))[4] = (uint8_t)((_setu_v) >> 24); \
	((uint8_t *)&(f))[5] = (uint8_t)((_setu_v) >> 16); \
	((uint8_t *)&(f))[6] = (uint8_t)((_setu_v) >> 8); \
	((uint8_t *)&(f))[7] = (uint8_t)(_setu_v); }

#define ZTLF_getu16(f) ( \
	(((uint16_t)(((uint8_t *)&(f))[0])) << 8) | \
	((uint16_t)(((uint8_t *)&(f))[1])) )
#define ZTLF_getu32(f) ( \
	(((uint32_t)(((uint8_t *)&(f))[0])) << 24) | \
	(((uint32_t)(((uint8_t *)&(f))[1])) << 16) | \
	(((uint32_t)(((uint8_t *)&(f))[2])) << 8) | \
	((uint32_t)(((uint8_t *)&(f))[3])) )
#define ZTLF_getu64(f) ( \
	(((uint64_t)(((uint8_t *)&(f))[0])) << 56) | \
	(((uint64_t)(((uint8_t *)&(f))[1])) << 48) | \
	(((uint64_t)(((uint8_t *)&(f))[2])) << 40) | \
	(((uint64_t)(((uint8_t *)&(f))[3])) << 32) | \
	(((uint64_t)(((uint8_t *)&(f))[4])) << 24) | \
	(((uint64_t)(((uint8_t *)&(f))[5])) << 16) | \
	(((uint64_t)(((uint8_t *)&(f))[6])) << 8) | \
	((uint64_t)(((uint8_t *)&(f))[7])) )

/* LF internal error return codes */
#define ZTLF_ERR_NONE                         0
#define ZTLF_ERR_OUT_OF_MEMORY                1
#define ZTLF_ERR_ABORTED                      2
#define ZTLF_ERR_OBJECT_TOO_LARGE             3

/* Macro to safely assign identical primitive types to unaligned variables */
#if defined(_M_AMD64) || defined(__amd64__) || defined(__x86_64__) || defined(__amd64) || defined(__x86_64)
#define ZTLF_UNALIGNED_ASSIGN_8(d,s) (d) = (s)
#define ZTLF_UNALIGNED_ASSIGN_4(d,s) (d) = (s)
#define ZTLF_UNALIGNED_ASSIGN_2(d,s) (d) = (s)
#else
#define ZTLF_UNALIGNED_ASSIGN_8(d,s) { \
	((uint8_t *)&(d))[0] = ((const uint8_t *)&(s))[0]; \
	((uint8_t *)&(d))[1] = ((const uint8_t *)&(s))[1]; \
	((uint8_t *)&(d))[2] = ((const uint8_t *)&(s))[2]; \
	((uint8_t *)&(d))[3] = ((const uint8_t *)&(s))[3]; \
	((uint8_t *)&(d))[4] = ((const uint8_t *)&(s))[4]; \
	((uint8_t *)&(d))[5] = ((const uint8_t *)&(s))[5]; \
	((uint8_t *)&(d))[6] = ((const uint8_t *)&(s))[6]; \
	((uint8_t *)&(d))[7] = ((const uint8_t *)&(s))[7]; \
}
#define ZTLF_UNALIGNED_ASSIGN_4(d,s) { \
	((uint8_t *)&(d))[0] = ((const uint8_t *)&(s))[0]; \
	((uint8_t *)&(d))[1] = ((const uint8_t *)&(s))[1]; \
	((uint8_t *)&(d))[2] = ((const uint8_t *)&(s))[2]; \
	((uint8_t *)&(d))[3] = ((const uint8_t *)&(s))[3]; \
}
#define ZTLF_UNALIGNED_ASSIGN_2(d,s) { \
	((uint8_t *)&(d))[0] = ((const uint8_t *)&(s))[0]; \
	((uint8_t *)&(d))[1] = ((const uint8_t *)&(s))[1]; \
}
#endif

#define ZTLF_NEG(e) (((e) <= 0) ? (e) : -(e))
#define ZTLF_POS(e) (((e) >= 0) ? (e) : -(e))

#define ZTLF_timeSec() ((uint64_t)time(NULL))

uint64_t ZTLF_prng();
unsigned int ZTLF_ncpus();
void ZTLF_secureRandom(void *b,const unsigned long n);

void ZTLF_L_func(int level,const char *srcf,int line,const char *fmt,...);
#define ZTLF_L(...) ZTLF_L_func(0,__FILE__,__LINE__,__VA_ARGS__)
#define ZTLF_L_warning(...) ZTLF_L_func(-1,__FILE__,__LINE__,__VA_ARGS__)
#define ZTLF_L_fatal(...) ZTLF_L_func(-2,__FILE__,__LINE__,__VA_ARGS__)
#define ZTLF_L_verbose(...) ZTLF_L_func(1,__FILE__,__LINE__,__VA_ARGS__)
#define ZTLF_L_trace(...) ZTLF_L_func(2,__FILE__,__LINE__,__VA_ARGS__)

#define ZTLF_MALLOC_CHECK(m) if (unlikely(!((m)))) { ZTLF_L_fatal("malloc() failed!"); abort(); }

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

/* https://en.wikipedia.org/wiki/Fletcher%27s_checksum */
static inline uint16_t ZTLF_fletcher16(const uint8_t *data,unsigned int len)
{
	uint32_t c0, c1;
	unsigned int i;
	for (c0=c1=0;len>=5802;len-=5802) {
		for (i=0;i<5802;++i) {
			c0 = c0 + *data++;
			c1 = c1 + c0;
		}
		c0 = c0 % 255;
		c1 = c1 % 255;
	}
	for (i=0;i<len;++i) {
		c0 = c0 + *data++;
		c1 = c1 + c0;
	}
	c0 = c0 % 255;
	c1 = c1 % 255;
	return (uint16_t)((c1 << 8) | c0);
}

#endif
