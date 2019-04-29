/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import "fmt"

// LF version and software implementation name
const (
	VersionMajor    = 0
	VersionMinor    = 0
	VersionRevision = 5
	VersionBuild    = 0

	SoftwareName = "ZeroTier LF Reference"
)

// Version is the version in array form.
var Version = [4]int{VersionMajor, VersionMinor, VersionRevision, VersionBuild}

// VersionStr is the version in string form.
var VersionStr = fmt.Sprintf("%d.%d.%d.%d", VersionMajor, VersionMinor, VersionRevision, VersionBuild)
