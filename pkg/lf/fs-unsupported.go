// +build windows

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

package lf

import (
	"errors"
	"log"
)

// LFFSSupported is true on supported platforms
var LFFSSupported = false

// FS is a dummy with a few unused fields on LFFS unsupported platforms
type FS struct {
	owner                        *Owner
	rootSelectorName, maskingKey []byte
	maxFileSize                  int
}

// NewFS just returns an error on LFFS unsupported platforms
func NewFS(ds []LF, normalLog *log.Logger, warningLog *log.Logger, mountPoint string, rootSelectorName []byte, owner *Owner, maxFileSize int, maskingKey []byte) (*FS, error) {
	return nil, errors.New("LFFS is not supported on this platform")
}

// Close is a no-op on LFFS unsupported platforms
func (fs *FS) Close() {}

// WaitForClose is a no-op on LFFS unsupported platforms
func (fs *FS) WaitForClose() {}
