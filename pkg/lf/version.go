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
	"fmt"
	"strconv"
)

// LF version and software implementation name
const (
	VersionMajor    = 1
	VersionMinor    = 0
	VersionRevision = 1
	VersionBuild    = 0

	ProtocolVersion    = 1
	MinProtocolVersion = 1

	APIVersion = 1

	SoftwareName = "ZeroTier LF Reference"
	License      = "ZeroTier-BSL"
)

// Version is the version in array form.
var Version = [4]int{VersionMajor, VersionMinor, VersionRevision, VersionBuild}

// VersionStr is the version in string form.
var VersionStr = fmt.Sprintf("%d.%d.%d.%d", VersionMajor, VersionMinor, VersionRevision, VersionBuild)

// APIVersionStr is the API version in string form.
var APIVersionStr = strconv.FormatUint(uint64(APIVersion), 10)
