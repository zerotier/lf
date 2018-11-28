/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#include "common.h"
#include "aes.h"

/* https://en.wikipedia.org/wiki/Xorshift#xorshift.2B */
uint64_t ZTLF_prng()
{
	static volatile uint64_t state[2] = {0,0};
	uint64_t x = state[0];
	uint64_t y = state[1];
	if (unlikely(!(x|y))) {
		ZTLF_secureRandom((void *)state,sizeof(state));
		x = state[0];
		y = state[1];
	}
	x ^= x << 23;
	const uint64_t z = x ^ y ^ (x >> 17) ^ (y >> 26);
	state[0] = y;
	state[1] = z;
	return z + y;
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

#error Need ZTLF_secureRandom for Windows

#else /* non-Windows */

pthread_t ZTLF_threadCreate(void *(*threadMain)(void *),void *arg,bool lowPriority)
{
	static pthread_attr_t lpAttr;
	static volatile bool lpAttrInitialized = false;

	if (!lpAttrInitialized) {
		struct sched_param param;
		if (unlikely(pthread_attr_init(&lpAttr) != 0)) {
			ZTLF_L_fatal("pthread_attr_init() failed");
			abort();
		}
		if (unlikely(pthread_attr_getschedparam(&lpAttr,&param) != 0)) {
			ZTLF_L_fatal("pthread_attr_getschedparam() failed");
			abort();
		}
		param.sched_priority = sched_get_priority_min(SCHED_OTHER);
		if (unlikely(pthread_attr_setschedparam(&lpAttr,&param) != 0)) {
			ZTLF_L_fatal("pthread_attr_setschedparam() failed");
			abort();
		}
		lpAttrInitialized = true;
	}

	pthread_t t;
	if (pthread_create(&t,(lowPriority) ? &lpAttr : (pthread_attr_t *)0,threadMain,arg)) {
		ZTLF_L_fatal("pthread_create() failed");
		abort();
	}
	return t;
}

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
	static uint64_t state[1024];
	static unsigned long ptr = 0;
	static bool initialized = false;
	static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
	pthread_mutex_lock(&lock);
	for(unsigned long k=0;k<n;++k) {
		unsigned long p = ptr++ % sizeof(state);
		if (p == 0) {
			if (unlikely(!initialized)) {
				const int fd = open("/dev/urandom",O_RDONLY);
				if (fd < 0) {
					ZTLF_L_fatal("unable to open/read /dev/urandom");
					abort();
				}
				if (read(fd,(void *)state,sizeof(state)) != sizeof(state)) {
					close(fd);
					ZTLF_L_fatal("unable to open/read /dev/urandom");
					abort();
				}
				close(fd);
				initialized = true;
			}

			uint64_t aesiv[2];
			aesiv[0] = ZTLF_timeMs();
			aesiv[1] = (uint64_t)b + (uint64_t)n;
			ZTLF_AES256CFB aes;
			ZTLF_AES256CFB_init(&aes,state,aesiv,true);
			ZTLF_AES256CFB_crypt(&aes,state,state,sizeof(state));
			ZTLF_AES256CFB_destroy(&aes);
		}
		((uint8_t *)b)[k] = ((uint8_t *)state)[p];
	}
	pthread_mutex_unlock(&lock);
}

#endif /* Windows / non-Windows */

void ZTLF_L_func(int level,const char *srcf,int line,const char *fmt,...)
{
	static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

	va_list ap;
	char msg[1024];
	va_start(ap, fmt);
	(void)vsnprintf(msg,sizeof(msg),fmt,ap);
	va_end(ap);
	msg[sizeof(msg)-1] = (char)0;

	char ts[128];
	time_t t = time(0);
	ctime_r(&t,ts);
	ts[sizeof(ts)-1] = (char)0;
	char *tsp = ts;
	while (*tsp) {
		if ((*tsp == '\r')||(*tsp == '\n')) {
			*tsp = (char)0;
			break;
		}
		++tsp;
	}

	if (!srcf)
		srcf = "<unknown>";

	pthread_mutex_lock(&lock);
	if (level < 0) {
		fprintf(stderr,"%s (%s:%d) %s: %s" ZTLF_EOL,ts,(strrchr(srcf,ZTLF_PATH_SEPARATOR_C) != NULL) ? (strrchr(srcf,ZTLF_PATH_SEPARATOR_C) + 1) : srcf,line,((level == -1) ? "WARNING" : "FATAL"),msg);
	} else {
		if (level > 1) {
			fprintf(stdout,"%s (%s:%d) TRACE %s" ZTLF_EOL,ts,(strrchr(srcf,ZTLF_PATH_SEPARATOR_C) != NULL) ? (strrchr(srcf,ZTLF_PATH_SEPARATOR_C) + 1) : srcf,line,msg);
		} else {
			fprintf(stdout,"%s %s" ZTLF_EOL,ts,msg);
		}
	}
	pthread_mutex_unlock(&lock);
}
