/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

/* Uncommment to trace DB internals -- this dumps a LOT of information! */
/* #define ZTLF_TRACE 1 */

/* Only necessary on some old 32-bit machines which aren't "officially" supported, but do it anyway. */
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#ifndef _LARGEFILE_SOURCE
#define _LARGEFILE_SOURCE 1
#endif

#ifndef _BSD_SOURCE
#define _BSD_SOURCE 1
#endif

#ifndef __USE_UNIX98
#define __USE_UNIX98 1
#endif

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
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
#include <math.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/types.h>

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

/* TODO: Windows support is not complete, but we have some stubs */
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

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>

#ifndef MAP_FILE /* legacy flag, not used on some platforms */
#define MAP_FILE 0
#endif

#define ZTLF_PACKED_STRUCT(D) D __attribute__((packed))
#define ZTLF_PATH_SEPARATOR "/"
#define ZTLF_PATH_SEPARATOR_C '/'
#define ZTLF_EOL "\n"

#endif /* Windows or non-Windows? ------------------------------------- */

/* Branch optimization macros if supported, otherwise these are no-ops. */
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

/* Assume little-endian byte order if not defined. */
#ifndef __BYTE_ORDER__
#ifndef __ORDER_LITTLE_ENDIAN__
#define __ORDER_LITTLE_ENDIAN__ 4321
#endif
#ifndef __ORDER_BIG_ENDIAN__
#define __ORDER_BIG_ENDIAN__ 1234
#endif
#define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__
#endif

#if __WORDSIZE == 64 || __SIZEOF_POINTER__ == 8 || defined(__LP64__) || defined(_M_AMD64) || defined(_M_X64) || defined(__amd64__) || defined(__x86_64__) || defined(__amd64) || defined(__x86_64)
#define ZTLF_64BIT 1
#endif

/* Define a macro to byte swap 64-bit values if needed. */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#if (defined(__GNUC__) && (__GNUC__ >= 3)) || (defined(__INTEL_COMPILER) && (__INTEL_COMPILER >= 800)) || defined(__clang__)
#define ZTLF_htonll(n) ((uint64_t)(__builtin_bswap64((uint64_t)(n))))
#else
static inline uint64_t ZTLF_htonll(const uint64_t n)
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

/* Macros to safely deal with longer values in packed structures or unaligned arrays */
#if defined(_M_AMD64) || defined(_M_X64) || defined(__amd64__) || defined(__x86_64__) || defined(__amd64) || defined(__x86_64) || defined(i386) || defined(__i386) || defined(__i386__) || defined(_M_IX86)

/* x86/x64 is an alignment honey badger, so it's fastest to just type cast and get/set primitive values. */

#define ZTLF_UNALIGNED_OKAY 1

#define ZTLF_setu16(f,v) (f) = (uint16_t)htons((uint16_t)(v))
#define ZTLF_setu32(f,v) (f) = (uint32_t)htonl((uint32_t)(v))
#define ZTLF_setu64(f,v) (f) = (uint64_t)ZTLF_htonll((uint64_t)(v))

#define ZTLF_getu16(f) ((uint16_t)ntohs((uint16_t)(f)))
#define ZTLF_getu32(f) ((uint32_t)ntohl((uint32_t)(f)))
#define ZTLF_getu64(f) ((uint64_t)ZTLF_ntohll((uint64_t)(f)))

#define ZTLF_set16(f,v) (f) = (int16_t)htons((uint16_t)(v))
#define ZTLF_set32(f,v) (f) = (int32_t)htonl((uint32_t)(v))
#define ZTLF_set64(f,v) (f) = (int64_t)ZTLF_htonll((uint64_t)(v))

#define ZTLF_get16(f) ((int16_t)ntohs((uint16_t)(f)))
#define ZTLF_get32(f) ((int32_t)ntohl((uint32_t)(f)))
#define ZTLF_get64(f) ((int64_t)ZTLF_ntohll((uint64_t)(f)))

#define ZTLF_setu16_le(f,v) (f) = ((uint16_t)(v))
#define ZTLF_setu32_le(f,v) (f) = ((uint32_t)(v))
#define ZTLF_setu64_le(f,v) (f) = ((uint64_t)(v))

#define ZTLF_getu16_le(f) ((uint16_t)(f))
#define ZTLF_getu32_le(f) ((uint32_t)(f))
#define ZTLF_getu64_le(f) ((uint64_t)(f))

#define ZTLF_set16_le(f,v) (f) = ((int16_t)(v))
#define ZTLF_set32_le(f,v) (f) = ((int32_t)(v))
#define ZTLF_set64_le(f,v) (f) = ((int64_t)(v))

#define ZTLF_get16_le(f) ((int16_t)(f))
#define ZTLF_get32_le(f) ((int32_t)(f))
#define ZTLF_get64_le(f) ((int64_t)(f))

#else /* quite a few other CPUs don't like unaligned access, so assume we can't ---------------- */

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

#define ZTLF_set16(f,v) { \
	const uint16_t _setu_v = (uint16_t)(v); \
	((uint8_t *)&(f))[0] = (uint8_t)((_setu_v) >> 8); \
	((uint8_t *)&(f))[1] = (uint8_t)(_setu_v); }
#define ZTLF_set32(f,v) { \
	const uint32_t _setu_v = (uint32_t)(v); \
	((uint8_t *)&(f))[0] = (uint8_t)((_setu_v) >> 24); \
	((uint8_t *)&(f))[1] = (uint8_t)((_setu_v) >> 16); \
	((uint8_t *)&(f))[2] = (uint8_t)((_setu_v) >> 8); \
	((uint8_t *)&(f))[3] = (uint8_t)(_setu_v); }
#define ZTLF_set64(f,v) { \
	const uint64_t _setu_v = (uint64_t)(v); \
	((uint8_t *)&(f))[0] = (uint8_t)((_setu_v) >> 56); \
	((uint8_t *)&(f))[1] = (uint8_t)((_setu_v) >> 48); \
	((uint8_t *)&(f))[2] = (uint8_t)((_setu_v) >> 40); \
	((uint8_t *)&(f))[3] = (uint8_t)((_setu_v) >> 32); \
	((uint8_t *)&(f))[4] = (uint8_t)((_setu_v) >> 24); \
	((uint8_t *)&(f))[5] = (uint8_t)((_setu_v) >> 16); \
	((uint8_t *)&(f))[6] = (uint8_t)((_setu_v) >> 8); \
	((uint8_t *)&(f))[7] = (uint8_t)(_setu_v); }

#define ZTLF_get16(f) ((int16_t)( \
	(((uint16_t)(((uint8_t *)&(f))[0])) << 8) | \
	((uint16_t)(((uint8_t *)&(f))[1])) ))
#define ZTLF_get32(f) ((int32_t)( \
	(((uint32_t)(((uint8_t *)&(f))[0])) << 24) | \
	(((uint32_t)(((uint8_t *)&(f))[1])) << 16) | \
	(((uint32_t)(((uint8_t *)&(f))[2])) << 8) | \
	((uint32_t)(((uint8_t *)&(f))[3])) ))
#define ZTLF_get64(f) ((int64_t)( \
	(((uint64_t)(((uint8_t *)&(f))[0])) << 56) | \
	(((uint64_t)(((uint8_t *)&(f))[1])) << 48) | \
	(((uint64_t)(((uint8_t *)&(f))[2])) << 40) | \
	(((uint64_t)(((uint8_t *)&(f))[3])) << 32) | \
	(((uint64_t)(((uint8_t *)&(f))[4])) << 24) | \
	(((uint64_t)(((uint8_t *)&(f))[5])) << 16) | \
	(((uint64_t)(((uint8_t *)&(f))[6])) << 8) | \
	((uint64_t)(((uint8_t *)&(f))[7])) ))

#define ZTLF_setu16_le(f,v) { \
	const uint16_t _setu_v = (uint16_t)(v); \
	((uint8_t *)&(f))[0] = (uint8_t)((_setu_v)); \
	((uint8_t *)&(f))[1] = (uint8_t)((_setu_v >> 8)); }
#define ZTLF_setu32_le(f,v) { \
	const uint32_t _setu_v = (uint32_t)(v); \
	((uint8_t *)&(f))[0] = (uint8_t)(_setu_v); \
	((uint8_t *)&(f))[1] = (uint8_t)((_setu_v) >> 8); \
	((uint8_t *)&(f))[2] = (uint8_t)((_setu_v) >> 16); \
	((uint8_t *)&(f))[3] = (uint8_t)((_setu_v) >> 24); }
#define ZTLF_setu64_le(f,v) { \
	const uint64_t _setu_v = (uint64_t)(v); \
	((uint8_t *)&(f))[0] = (uint8_t)(_setu_v); \
	((uint8_t *)&(f))[1] = (uint8_t)((_setu_v) >> 8); \
	((uint8_t *)&(f))[2] = (uint8_t)((_setu_v) >> 16); \
	((uint8_t *)&(f))[3] = (uint8_t)((_setu_v) >> 24); \
	((uint8_t *)&(f))[4] = (uint8_t)((_setu_v) >> 32); \
	((uint8_t *)&(f))[5] = (uint8_t)((_setu_v) >> 40); \
	((uint8_t *)&(f))[6] = (uint8_t)((_setu_v) >> 48); \
	((uint8_t *)&(f))[7] = (uint8_t)((_setu_v) >> 56); }

#define ZTLF_getu16_le(f) ( \
	((uint16_t)(((uint8_t *)&(f))[0])) | \
	(((uint16_t)(((uint8_t *)&(f))[1])) << 8) )
#define ZTLF_getu32_le(f) ( \
	((uint32_t)(((uint8_t *)&(f))[0])) | \
	(((uint32_t)(((uint8_t *)&(f))[1])) << 8) | \
	(((uint32_t)(((uint8_t *)&(f))[2])) << 16) | \
	(((uint32_t)(((uint8_t *)&(f))[3])) << 24) )
#define ZTLF_getu64_le(f) ( \
	((uint64_t)(((uint8_t *)&(f))[0])) | \
	(((uint64_t)(((uint8_t *)&(f))[1])) << 8) | \
	(((uint64_t)(((uint8_t *)&(f))[2])) << 16) | \
	(((uint64_t)(((uint8_t *)&(f))[3])) << 24) | \
	(((uint64_t)(((uint8_t *)&(f))[4])) << 32) | \
	(((uint64_t)(((uint8_t *)&(f))[5])) << 40) | \
	(((uint64_t)(((uint8_t *)&(f))[6])) << 48) | \
	(((uint64_t)(((uint8_t *)&(f))[7])) << 56) )

#define ZTLF_set16_le(f,v) { \
	const uint16_t _setu_v = (uint16_t)(v); \
	((uint8_t *)&(f))[0] = (uint8_t)(_setu_v); \
	((uint8_t *)&(f))[1] = (uint8_t)((_setu_v) >> 8); }
#define ZTLF_set32_le(f,v) { \
	const uint32_t _setu_v = (uint32_t)(v); \
	((uint8_t *)&(f))[0] = (uint8_t)(_setu_v); \
	((uint8_t *)&(f))[1] = (uint8_t)((_setu_v) >> 8); \
	((uint8_t *)&(f))[2] = (uint8_t)((_setu_v) >> 16); \
	((uint8_t *)&(f))[3] = (uint8_t)((_setu_v) >> 24); }
#define ZTLF_set64_le(f,v) { \
	const uint64_t _setu_v = (uint64_t)(v); \
	((uint8_t *)&(f))[0] = (uint8_t)(_setu_v); \
	((uint8_t *)&(f))[1] = (uint8_t)((_setu_v) >> 8); \
	((uint8_t *)&(f))[2] = (uint8_t)((_setu_v) >> 16); \
	((uint8_t *)&(f))[3] = (uint8_t)((_setu_v) >> 24); \
	((uint8_t *)&(f))[4] = (uint8_t)((_setu_v) >> 32); \
	((uint8_t *)&(f))[5] = (uint8_t)((_setu_v) >> 40); \
	((uint8_t *)&(f))[6] = (uint8_t)((_setu_v) >> 48); \
	((uint8_t *)&(f))[7] = (uint8_t)((_setu_v) >> 56); }

#define ZTLF_get16_le(f) ((int16_t)( \
	(((uint16_t)(((uint8_t *)&(f))[0])) << 8) | \
	((uint16_t)(((uint8_t *)&(f))[1])) ))
#define ZTLF_get32_le(f) ((int32_t)( \
	(((uint32_t)(((uint8_t *)&(f))[0])) << 24) | \
	(((uint32_t)(((uint8_t *)&(f))[1])) << 16) | \
	(((uint32_t)(((uint8_t *)&(f))[2])) << 8) | \
	((uint32_t)(((uint8_t *)&(f))[3])) ))
#define ZTLF_get64_le(f) ((int64_t)( \
	((uint64_t)(((uint8_t *)&(f))[0])) | \
	(((uint64_t)(((uint8_t *)&(f))[1])) << 8) | \
	(((uint64_t)(((uint8_t *)&(f))[2])) << 16) | \
	(((uint64_t)(((uint8_t *)&(f))[3])) << 24) | \
	(((uint64_t)(((uint8_t *)&(f))[4])) << 32) | \
	(((uint64_t)(((uint8_t *)&(f))[5])) << 40) | \
	(((uint64_t)(((uint8_t *)&(f))[6])) << 48) | \
	(((uint64_t)(((uint8_t *)&(f))[7])) << 56) ))

#endif /* ---------------------------------------------------------------------------------------------- */

#define ZTLF_NEG(e) (((e) <= 0) ? (e) : -(e))
#define ZTLF_POS(e) (((e) >= 0) ? (e) : -(e))

/* These values must be the same as the log levels in Go code. */
#define ZTLF_LOG_LEVEL_FATAL 0
#define ZTLF_LOG_LEVEL_WARNING 1
#define ZTLF_LOG_LEVEL_NORMAL 2
#define ZTLF_LOG_LEVEL_VERBOSE 3
#define ZTLF_LOG_LEVEL_TRACE 4

// Arguments are: level, source file, line, message, and an externally supplied logger argument.
typedef void (*LogOutputCallback)(int,const char *,int,const char *,void *);

static inline void ZTLF_L_func(LogOutputCallback logger,void *loggerArg,int level,const char *srcf,int line,const char *fmt,...)
{
	va_list ap;
	char msg[4096];
	va_start(ap, fmt);
	(void)vsnprintf(msg,sizeof(msg),fmt,ap);
	va_end(ap);
	msg[sizeof(msg)-1] = (char)0;

	if (!srcf)
		srcf = "<unknown>";

	logger(level,srcf,line,msg,loggerArg);
}

#define ZTLF_L(...) ZTLF_L_func(logger,(void *)loggerArg,2,__FILE__,__LINE__,__VA_ARGS__)
#define ZTLF_L_warning(...) ZTLF_L_func(logger,(void *)loggerArg,1,__FILE__,__LINE__,__VA_ARGS__)
#define ZTLF_L_fatal(...) ZTLF_L_func(logger,(void *)loggerArg,0,__FILE__,__LINE__,__VA_ARGS__)
#define ZTLF_L_verbose(...) ZTLF_L_func(logger,(void *)loggerArg,3,__FILE__,__LINE__,__VA_ARGS__)
#ifdef ZTLF_TRACE
#define ZTLF_L_trace(...) ZTLF_L_func(logger,(void *)loggerArg,4,__FILE__,__LINE__,__VA_ARGS__)
#else
#define ZTLF_L_trace(...)
#endif

#define ZTLF_MALLOC_CHECK(m) if (unlikely(!((m)))) { fprintf(stderr,"malloc() failed!" ZTLF_EOL); fflush(stderr); abort(); }

#endif
