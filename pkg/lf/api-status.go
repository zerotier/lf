/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

// APIStatusPeer (response) contains information about a connected peer.
type APIStatusPeer struct {
	Address   string `json:",omitempty"` // IP and port
	PublicKey Blob   `json:",omitempty"` // public key
	Inbound   bool   ``                  // true if this is an inbound connection
}

// APIProxyStatus (response, part of APIStatus) contains info about LF proxies between the client and the full node.
type APIProxyStatus struct {
	Server        string `json:",omitempty"` // URL of server being accessed through the proxy
	Software      string `json:",omitempty"` // Software implementation name of proxy
	Version       [4]int ``                  // Software version of proxy
	MinAPIVersion int    ``                  // Minimum supported API version of proxy
	MaxAPIVersion int    ``                  // Maximum supported API version of proxy
}

// APIStatus (response) contains status information about this node and the network it belongs to.
type APIStatus struct {
	Software          string            `json:",omitempty"` // Software implementation name
	Version           [4]int            ``                  // Version of software
	APIVersion        int               ``                  // Current version of API
	MinAPIVersion     int               ``                  // Minimum API version supported
	MaxAPIVersion     int               ``                  // Maximum API version supported
	Uptime            uint64            ``                  // Node uptime in seconds
	Clock             uint64            ``                  // Node local clock in seconds since epoch
	DBRecordCount     uint64            ``                  // Number of records in database
	DBSize            uint64            ``                  // Total size of records in database in bytes
	Peers             []APIStatusPeer   `json:",omitempty"` // Connected peers
	GenesisParameters GenesisParameters ``                  // Genesis record contents that define constraints for this LF network
	Proxies           []APIProxyStatus  `json:",omitempty"` // Each proxy adds itself to the front of this list
}
