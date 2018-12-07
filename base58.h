/* https://github.com/luke-jr/libbase58 */

/*
 * Copyright 2012-2014 Luke Dashjr
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the standard MIT license.  See COPYING for more details.
 */

#ifndef ZTLF_BASE58_H
#define ZTLF_BASE58_H

#include "common.h"

bool ZTLF_Base58Decode(void *bin, size_t *binszp, const char *b58, size_t b58sz);
bool ZTLF_Base58Encode(char *b58, size_t *b58sz, const void *data, size_t binsz);

#endif
