/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"crypto/ecdsa"
	"encoding/json"
)

// Genesis is the payload (JSON encoded) of the first RecordMinLinks records in a global data store.
type Genesis struct {
	Name               string   `json:",omitempty"` // Name of this LF network / data store
	Contact            string   `json:",omitempty"` // Contact info for this network (may be empty)
	CAs                [][]byte `json:",omitempty"` // X.509 certificates for master CAs for this data store (empty for an unbiased work-only data store)
	RecordMinLinks     uint     ``                  // Minimum number of links required for non-genesis records
	RecordMaxValueSize uint     ``                  // Maximum size of record values
	Amendable          bool     ``                  // If true, genesis settings can be amended later by the same owner using the genesis private key
}

// CreateGenesisRecords creates a set of genesis records for a new LF data store.
// The number created is always sufficient to satisfy RecordMinLinks for subsequent records.
// If RecordMinLinks is zero one record is created. The first genesis record will contain
// the Genesis parameters in JSON format while subsequent records are empty.
func CreateGenesisRecords(genesisParameters *Genesis) ([]*Record, *ecdsa.PrivateKey, error) {
	gpjson, err := json.Marshal(genesisParameters)
	if err != nil {
		return nil, nil, err
	}

	var records []*Record
	var links [][]byte
	genesisOwner, genesisOwnerPrivate := GenerateOwner()
	now := TimeSec()

	r, err := NewRecord(gpjson, nil, nil, nil, genesisOwner, now, RecordWorkAlgorithmWharrgarbl, genesisOwnerPrivate)
	if err != nil {
		return nil, nil, err
	}
	records = append(records, r)
	links = append(links, r.Hash()[:])

	for i := uint(1); i < genesisParameters.RecordMinLinks; i++ {
		r, err := NewRecord(nil, links, nil, nil, genesisOwner, now, RecordWorkAlgorithmWharrgarbl, genesisOwnerPrivate)
		if err != nil {
			return nil, nil, err
		}
		records = append(records, r)
		links = append(links, r.Hash()[:])
	}

	return records, genesisOwnerPrivate, nil
}
