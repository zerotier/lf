/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 * 
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

#include "base64url.h"

static const uint8_t BASE64URL_C2SIX[256] = {64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64, 64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 63, 64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64 };
static const char *const BASE64URL_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

unsigned int ZTLF_Base64URLDecode(void *out,unsigned int outlen,const char *in)
{
	const uint8_t *bufin;
	int nprbytes;
	unsigned int n = 0;

	bufin = (const uint8_t *)in;
	while (BASE64URL_C2SIX[*(bufin++)] <= 63);
	nprbytes = (bufin - (const uint8_t *)in) - 1;
	bufin = (const uint8_t *)in;

	while (nprbytes > 4) {
		if (unlikely(n >= outlen)) return n;
		((uint8_t *)out)[n++] = (uint8_t)(BASE64URL_C2SIX[*bufin] << 2 | BASE64URL_C2SIX[bufin[1]] >> 4);
		if (unlikely(n >= outlen)) return n;
		((uint8_t *)out)[n++] = (uint8_t)(BASE64URL_C2SIX[bufin[1]] << 4 | BASE64URL_C2SIX[bufin[2]] >> 2);
		if (unlikely(n >= outlen)) return n;
		((uint8_t *)out)[n++] = (uint8_t)(BASE64URL_C2SIX[bufin[2]] << 6 | BASE64URL_C2SIX[bufin[3]]);
		bufin += 4;
		nprbytes -= 4;
	}

	if (nprbytes > 1) {
		if (unlikely(n >= outlen)) return n;
		((uint8_t *)out)[n++] = (uint8_t)(BASE64URL_C2SIX[*bufin] << 2 | BASE64URL_C2SIX[bufin[1]] >> 4);
	}
	if (nprbytes > 2) {
		if (unlikely(n >= outlen)) return n;
		((uint8_t *)out)[n++] = (uint8_t)(BASE64URL_C2SIX[bufin[1]] << 4 | BASE64URL_C2SIX[bufin[2]] >> 2);
	}
	if (nprbytes > 3) {
		if (unlikely(n >= outlen)) return n;
		((uint8_t *)out)[n++] = (uint8_t)(BASE64URL_C2SIX[bufin[2]] << 6 | BASE64URL_C2SIX[bufin[3]]);
	}

	return n;
}

unsigned int ZTLF_Base64URLEncode(char *out,unsigned int outlen,const void *in,unsigned int len)
{
	const uint8_t *inb = (const uint8_t *)in;
	char *p = out;
	char *const eof = p + outlen;
	int i;

	for (i = 0; i < len - 2; i += 3) {
		if (unlikely(p >= eof)) { out[outlen-1] = 0; return 0; }
		*p++ = BASE64URL_CHARS[(inb[i] >> 2) & 0x3F];
		if (unlikely(p >= eof)) { out[outlen-1] = 0; return 0; }
		*p++ = BASE64URL_CHARS[((inb[i] & 0x3) << 4) | ((int)(inb[i + 1] & 0xF0) >> 4)];
		if (unlikely(p >= eof)) { out[outlen-1] = 0; return 0; }
		*p++ = BASE64URL_CHARS[((inb[i + 1] & 0xF) << 2) | ((int)(inb[i + 2] & 0xC0) >> 6)];
		if (unlikely(p >= eof)) { out[outlen-1] = 0; return 0; }
		*p++ = BASE64URL_CHARS[inb[i + 2] & 0x3F];
	}

	if (i < len) {
		if (unlikely(p >= eof)) { out[outlen-1] = 0; return 0; }
		*p++ = BASE64URL_CHARS[(inb[i] >> 2) & 0x3F];
		if (i == (len - 1)) {
			if (unlikely(p >= eof)) { out[outlen-1] = 0; return 0; }
			*p++ = BASE64URL_CHARS[((inb[i] & 0x3) << 4)];
		} else {
			if (unlikely(p >= eof)) { out[outlen-1] = 0; return 0; }
			*p++ = BASE64URL_CHARS[((inb[i] & 0x3) << 4) | ((int)(inb[i + 1] & 0xF0) >> 4)];
			if (unlikely(p >= eof)) { out[outlen-1] = 0; return 0; }
			*p++ = BASE64URL_CHARS[((inb[i + 1] & 0xF) << 2)];
		}
	}

	const unsigned int l = (unsigned int)(p - out);
	if (unlikely(p >= eof)) { out[outlen-1] = 0; return 0; }
	*p++ = '\0';
	return l;
}
