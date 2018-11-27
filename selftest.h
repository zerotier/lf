/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#ifndef ZTLF_SELFTEST_H
#define ZTLF_SELFTEST_H

#include "common.h"

bool ZTLF_selftest_core(FILE *o);
bool ZTLF_selftest_wharrgarbl(FILE *o);
bool ZTLF_selftest_modelProofOfWork(FILE *o);
bool ZTLF_selftest(FILE *o);

#endif
