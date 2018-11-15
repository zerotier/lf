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
#include "node.h"
#include "selftest.h"

static struct ZTLF_Node node;

static void printHelp()
{
}

static void exitSignal(int sig)
{
}

int main(int argc,char **argv)
{
	ZTLF_selftest_core(stdout);
	ZTLF_selftest_wharrgarbl(stdout);

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
