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
	"net"
)

// OwnerStatus is describes the status of an owner according to the current node.
type OwnerStatus struct {
	Owner                 OwnerPublic ``                  // Public portion of owner
	OwnerType             string      `json:",omitempty"` // Owner type (for convenience, can also be determine from public key itself)
	Certificates          []Blob      `json:",omitempty"` // Certificates in DER format
	RevokedCertificates   []Blob      `json:",omitempty"` // Revoked certificated in DER format
	HasCurrentCertificate bool        ``                  // True if there is at least one valid non-revoked certificate (as of current time)
	AuthRequired          bool        ``                  // True if this database requires a current certificate
	RecordCount           uint64      ``                  // Number of records in data store by this owner
	RecordBytes           uint64      ``                  // Number of bytes of records by this owner
	NewRecordLinks        []HashBlob  `json:",omitempty"` // Suggested links for a new record (for convenience to avoid multiple API calls)
	ServerTime            uint64      ``                  // Server time in seconds since epoch (time used to determine HasCurrentCertificate)
}

// Peer contains information about a peer
type Peer struct {
	IP       net.IP //
	Port     int    // -1 indicates inbound TCP connection with unknown/unreachable port
	Identity Blob   //
}

// NodeStatus contains status information about this node and the network it belongs to.
type NodeStatus struct {
	Software          string            `json:",omitempty"` // Software implementation name
	Version           [4]int            ``                  // Version of software
	APIVersion        int               ``                  // Current version of API
	MinAPIVersion     int               ``                  // Minimum API version supported
	MaxAPIVersion     int               ``                  // Maximum API version supported
	Uptime            uint64            ``                  // Node uptime in seconds
	Clock             uint64            ``                  // Node local clock in seconds since epoch
	RecordCount       uint64            ``                  // Number of records in database
	DataSize          uint64            ``                  // Total size of records in database in bytes
	FullySynchronized bool              ``                  // True if there are no dangling links (excluding abandoned ones)
	GenesisRecords    Blob              ``                  // Genesis records (those currently known)
	GenesisParameters GenesisParameters ``                  // Network parameters
	Oracle            OwnerPublic       `json:",omitempty"` // Owner public if this node is an oracle, empty otherwise
	P2PPort           int               ``                  // This node's P2P port
	LocalTestMode     bool              ``                  // If true, this node is in local test mode
	Identity          Blob              `json:",omitempty"` // This node's peer identity
	Peers             []Peer            `json:",omitempty"` // Currently connected peers
}

// LF provides a common interface for local (same Go process) or remote (HTTP/HTTPS API) nodes.
type LF interface {
	// AddRecord attempts to add a record.
	// A record won't actually show up in queries until all its dependencies are satisfied (fully synchronized).
	AddRecord(*Record) error

	// GetRecord gets a record by its 32-byte / 256-bit hash.
	GetRecord(hash []byte) (*Record, error)

	// GenesisParameters gets the parameters of this network / database.
	GenesisParameters() (*GenesisParameters, error)

	// NodeStatus gets the status of this node.
	NodeStatus() (*NodeStatus, error)

	// OwnerStatus returns information about an owner and some NewRecordLinks for new record creation.
	OwnerStatus(OwnerPublic) (*OwnerStatus, error)

	// Links gets up to RecordMaxLinks or the default minimum (according to GenesisParameters) if <=0.
	// It also returns the current node's clock as the second returned value (on success).
	Links(int) ([][32]byte, uint64, error)

	// ExecuteQuery runs this query against this node.
	ExecuteQuery(*Query) (QueryResults, error)

	// ExecuteMakeRecord runs a MakeRecordRequest against this node.
	ExecuteMakeRecord(*MakeRecord) (*Record, Pulse, bool, error)

	// ExecuteMakePulse runs a MakePulseRequest against this node.
	ExecuteMakePulse(*MakePulse) (Pulse, *Record, bool, error)

	// DoPulse processes a pulse, also announcing it to the global network if the second boolean is true (usually should be true).
	// This returns true if the pulse was accepted as novel and valid.
	DoPulse(Pulse, bool) (bool, error)

	// Connect instructs this local or remote node to connect to a peer.
	// Note that remote nodes will only accept connect from localhost or with an auth token.
	Connect(net.IP, int, []byte) error

	// IsLocal returns true for local same-Go-process nodes and false otherwise.
	IsLocal() bool
}
