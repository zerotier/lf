/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c)2019-2021 ZeroTier, Inc.
 * https://www.zerotier.com/
 */

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
