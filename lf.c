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

#define ZTLF_DEFAULT_TCP_PORT 3993

static volatile bool running = false;
static struct ZTLF_Node node;

static void printHelp()
{
	printf(
"LF (pronounced \"aleph\") version %d.%d.%d.%d" ZTLF_EOL
"(c)2018 ZeroTier, Inc. (MIT license)" ZTLF_EOL ZTLF_EOL
"Usage: lf [-options] <command> [<command arguments>]" ZTLF_EOL ZTLF_EOL
"Options:" ZTLF_EOL
"  -h                         - Display this help" ZTLF_EOL
"  -v                         - Display version" ZTLF_EOL
"  -d <path>                  - Specify alternative path for config and data" ZTLF_EOL
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

static const char *const ZTLF_PATH_DEFAULT = "/var/lib/lf";

int main(int argc,char **argv)
{
	int exitCode = 0;
	const char *lfPath = ZTLF_PATH_DEFAULT;
	if (getuid() > 0) {
		const char *homeDir = getenv("HOME");
		if ((homeDir)&&(homeDir[0])) {
			int hpl = (int)strlen(homeDir)+8;
			char *hp = (char *)malloc(hpl);
			snprintf(hp,hpl,"%s" ZTLF_PATH_SEPARATOR ".lf",homeDir);
			lfPath = hp;
		}
	}

	for (int ch;(ch=getopt(argc,argv,"hvd:TW"))!=-1;) {
		switch(ch) {
			case 'v':
				printf("%d.%d.%d.%d" ZTLF_EOL,ZTLF_VERSION_MAJOR,ZTLF_VERSION_MINOR,ZTLF_VERSION_REVISION,ZTLF_VERSION_BUILD);
				goto exit_lf;
			case 'd':
				if ((optarg)&&(strlen(optarg) > 0)) {
					char *hp = (char *)malloc(strlen(optarg)+1);
					memcpy(hp,optarg,strlen(optarg)+1);
					lfPath = hp;
				} else {
					printHelp();
					exitCode = 1;
					goto exit_lf;
				}
				break;
			case 'T':
				return (ZTLF_selftest(stdout) ? 0 : 1);
			case 'W':
				ZTLF_selftest_modelProofOfWork(stdout);
				goto exit_lf;
			case 'h':
			case '?':
				printHelp();
				goto exit_lf;
		}
		argc -= optind;
		argv += optind;
	}
	if (argc < 2) {
		printHelp();
		exitCode = 1;
		goto exit_lf;
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

	printf("%s\n",argv[0]);

exit_lf:
	if (lfPath != ZTLF_PATH_DEFAULT)
		free((void *)lfPath);
	return exitCode;
}
