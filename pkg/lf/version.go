package lf

import "fmt"

// LF version and software implementation name
const (
	VersionMajor    = 0
	VersionMinor    = 0
	VersionRevision = 1
	VersionBuild    = 0

	SoftwareName = "ZeroTier LF (\"Project Azathoth\")"
)

// Version is the version in array form.
var Version = [4]int{VersionMajor, VersionMinor, VersionRevision, VersionBuild}

// VersionStr is the version in string form.
var VersionStr = fmt.Sprintf("%d.%d.%d.%d", VersionMajor, VersionMinor, VersionRevision, VersionBuild)
