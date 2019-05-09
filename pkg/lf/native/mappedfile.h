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
