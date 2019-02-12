/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"encoding/json"
)

// Genesis is the payload (JSON encoded) of the first RecordMinLinks records in a global data store.
type Genesis struct {
	Name                 string   `json:",omitempty"` // Name of this LF network / data store
	Contact              string   `json:",omitempty"` // Contact info for this network (may be empty)
	Comment              string   `json:",omitempty"` // Optional comment
	CAs                  [][]byte `json:",omitempty"` // X.509 certificates for master CAs for this data store (empty for an unbiased work-only data store)
	BannedWorkAlgorithms []uint   `json:",omitempty"` // A list of proof of work algorithms not allowed (adding the none algorithm here means PoW is always needed)
	Key                  []byte   ``                  // Static 32-byte key used to ensure that nodes in this network only connect to one another
	TimestampFloor       uint64   ``                  // Floor for network record timestamps
	RecordMinLinks       uint     ``                  // Minimum number of links required for non-genesis records
	RecordMaxValueSize   uint     ``                  // Maximum size of record values
	RecordMaxSize        uint     ``                  // Maximum size of records (up to the RecordMaxSize constant)
	SettingsAmendable    bool     ``                  // If true, genesis settings can be amended later by the same owner using the genesis private key
	CAsAmendable         bool     ``                  // If true, CAs can be amended (if present)
}

// CreateGenesisRecords creates a set of genesis records for a new LF data store.
// The number created is always sufficient to satisfy RecordMinLinks for subsequent records.
// If RecordMinLinks is zero one record is created. The first genesis record will contain
// the Genesis parameters in JSON format while subsequent records are empty.
func CreateGenesisRecords(genesisOwnerType int, genesisParameters *Genesis) ([]*Record, *Owner, error) {
	gpjson, err := json.Marshal(genesisParameters)
	if err != nil {
		return nil, nil, err
	}

	var records []*Record
	var links [][]byte
	genesisOwner, err := NewOwner(genesisOwnerType)
	if err != nil {
		return nil, nil, err
	}
	now := TimeSec()

	// Create the very first genesis record, which contains the genesis configuration structure in JSON format.
	r, err := NewRecord(gpjson, nil, nil, nil, nil, now, RecordWorkAlgorithmWharrgarbl, genesisOwner)
	if err != nil {
		return nil, nil, err
	}
	records = append(records, r)
	links = append(links, r.Hash()[:])

	// Subsequent genesis records are empty and just exist so real records can satisfy their minimum link requirement.
	for i := uint(1); i < genesisParameters.RecordMinLinks; i++ {
		r, err := NewRecord(nil, links, nil, nil, nil, now, RecordWorkAlgorithmWharrgarbl, genesisOwner)
		if err != nil {
			return nil, nil, err
		}
		records = append(records, r)
		links = append(links, r.Hash()[:])
	}

	return records, genesisOwner, nil
}
