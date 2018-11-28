/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#include "common.h"
#include "node.h"
#include "selftest.h"
#include "version.h"

#define ZTLF_DEFAULT_TCP_PORT 19379
#define ZTLF_DEFAULT_HTTP_PORT 19380

static volatile bool running = false;
static struct ZTLF_Node node;

static void printHelp()
{
	printf(
"LF (pronounced \"aleph\") version %d.%d.%d.%d" ZTLF_EOL
"(c)2018 ZeroTier, Inc. (MIT license)" ZTLF_EOL ZTLF_EOL
"Usage: lf [-options] <data directory>" ZTLF_EOL ZTLF_EOL
"Options:" ZTLF_EOL
"  -h                         - Display this help" ZTLF_EOL
"  -v                         - Display version" ZTLF_EOL
"  -T                         - Run internal self-test and exit" ZTLF_EOL
"  -W                         - Benchmark record PoW (CTRL+C to stop)" ZTLF_EOL
"",ZTLF_VERSION_MAJOR,ZTLF_VERSION_MINOR,ZTLF_VERSION_REVISION,ZTLF_VERSION_BUILD);
}

static void exitSignal(int sig)
{
	if (running) {
		running = false;
	}
}

int main(int argc,char **argv)
{
	for (int ch;(ch=getopt(argc,argv,"hvTW"))!=-1;) {
		switch(ch) {
			case 'v':
				printf("%d.%d.%d.%d" ZTLF_EOL,ZTLF_VERSION_MAJOR,ZTLF_VERSION_MINOR,ZTLF_VERSION_REVISION,ZTLF_VERSION_BUILD);
				return 0;
			case 'T':
				return (ZTLF_selftest(stdout) ? 0 : 1);
			case 'W':
				ZTLF_selftest_modelProofOfWork(stdout);
				return 0;
			case 'h':
			case '?':
				printHelp();
				return 0;
		}
		argc -= optind;
		argv += optind;
	}
	if (argc != 2) {
		printHelp();
		return 1;
	}

#ifndef __WINDOWS__
	signal(SIGPIPE,SIG_IGN);
	signal(SIGUSR1,SIG_IGN);
	signal(SIGUSR2,SIG_IGN);
	signal(SIGCHLD,SIG_IGN);
	signal(SIGHUP,SIG_IGN);
	signal(SIGALRM,SIG_IGN);
	signal(SIGINT,&exitSignal);
	signal(SIGTERM,&exitSignal);
	signal(SIGQUIT,&exitSignal);
#endif

	return 0;
}
