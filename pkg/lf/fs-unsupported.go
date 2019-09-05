// +build windows

/*
 * Copyright (c)2019 ZeroTier, Inc.
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file in the project's root directory.
 *
 * Change Date: 2023-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2.0 of the Apache License.
 */
/****/

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
