/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c)2019-2021 ZeroTier, Inc.
 * https://www.zerotier.com/
 */

#ifndef ZTLF_MAPPEDFILE_H
#define ZTLF_MAPPEDFILE_H

#include "common.h"

struct ZTLF_MappedFile
{
	uintptr_t size;
	uintptr_t sizeIncrement;
	void *ptr;
	int fd;
};

static inline int ZTLF_MappedFile_Open(struct ZTLF_MappedFile *f,const char *path,const uintptr_t initialSize,const uintptr_t sizeIncrement)
{
	f->fd = open(path,O_RDWR|O_CREAT,0644);
	if (f->fd < 0)
		return errno;

	int64_t fileSize = (int64_t)lseek(f->fd,0,SEEK_END);
	if (fileSize < 0) {
		close(f->fd);
		return errno;
	}
	if (fileSize < (int64_t)initialSize) {
		if (ftruncate(f->fd,(off_t)initialSize) != 0) {
			close(f->fd);
			return errno;
		}
		f->size = initialSize;
	} else {
		f->size = (uintptr_t)fileSize;
	}
	f->sizeIncrement = sizeIncrement;

	f->ptr = mmap(NULL,(size_t)(f->size),PROT_READ|PROT_WRITE,MAP_FILE|MAP_SHARED,f->fd,0);
	if (!f->ptr) {
		close(f->fd);
		return errno;
	}

	return 0;
}

static inline void ZTLF_MappedFile_Close(struct ZTLF_MappedFile *f)
{
	if (f->ptr) {
		munmap(f->ptr,(size_t)(f->size));
		close(f->fd);
		f->ptr = NULL;
		f->fd = -1;
	}
}

static inline void *ZTLF_MappedFile_TryGet(struct ZTLF_MappedFile *f,const uintptr_t at,const uintptr_t len)
{
	if (likely((at + len) <= f->size)) {
		return (void *)(((uint8_t *)f->ptr) + at);
	}
	return NULL;
}

static inline void *ZTLF_MappedFile_Get(struct ZTLF_MappedFile *f,const uintptr_t at,const uintptr_t len)
{
	if (likely((at + len) <= f->size)) {
		return (void *)(((uint8_t *)f->ptr) + at);
	}
	if (!f->sizeIncrement)
		return NULL;
	const uintptr_t newSize = f->size + f->sizeIncrement;
	munmap(f->ptr,(size_t)(f->size));
	if (ftruncate(f->fd,(off_t)newSize) != 0) {
		f->ptr = mmap(NULL,(size_t)(f->size),PROT_READ|PROT_WRITE,MAP_FILE|MAP_SHARED,f->fd,0);
		if (!f->ptr) {
			//ZTLF_L_fatal("cannot remap mapped file after failed grow attempt: %d (%s)",errno,strerror(errno));
			abort();
		}
		return NULL;
	}
	f->ptr = mmap(NULL,(size_t)(f->size),PROT_READ|PROT_WRITE,MAP_FILE|MAP_SHARED,f->fd,0);
	if (!f->ptr) {
		//ZTLF_L_fatal("cannot remap mapped file after growing file size: %d (%s)",errno,strerror(errno));
		abort();
	}
	f->size = newSize;
	return (void *)(((uint8_t *)f->ptr) + at);
}

#endif
