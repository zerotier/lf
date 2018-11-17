/*
 * Copyright 2012-2014 Luke Dashjr
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the standard MIT license.  See COPYING for more details.
 */

#ifndef ZTLF_BASE58_H
#define ZTLF_BASE58_H

#include "common.h"

bool ZTLF_b58dec(void *bin, size_t *binszp, const char *b58, size_t b58sz);
bool ZTLF_b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz);

#endif
