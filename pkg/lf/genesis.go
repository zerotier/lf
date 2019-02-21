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

// GenesisParameters is the payload (JSON encoded) of the first RecordMinLinks records in a global data store.
type GenesisParameters struct {
	Name                       string   `json:",omitempty"` // Name of this LF network / data store
	Contact                    string   `json:",omitempty"` // Contact info for this network (may be empty)
	Comment                    string   `json:",omitempty"` // Optional comment
	RootCertificateAuthorities []Blob   `json:",omitempty"` // X.509 certificates for master CAs for this data store (empty for an unbiased work-only data store)
	WorkRequired               bool     `json:""`           // Is proof of work required?
	LinkKey                    Blob256  `json:""`           // Static 32-byte key used to ensure that nodes in this network only connect to one another
	TimestampFloor             uint64   `json:""`           // Floor for network record timestamps
	RecordMinLinks             uint     `json:""`           // Minimum number of links required for non-genesis records
	RecordMaxValueSize         uint     `json:""`           // Maximum size of record values
	RecordMaxSize              uint     `json:""`           // Maximum size of records (up to the RecordMaxSize constant)
	RecordMaxForwardTimeDrift  uint     `json:""`           // Maximum number of seconds in the future a record can be timestamped
	Amendable                  []string `json:",omitempty"` // List of json field names that the genesis owner can change by posting more records
}

// CreateGenesisRecords creates a set of genesis records for a new LF data store.
// The number created is always sufficient to satisfy RecordMinLinks for subsequent records.
// If RecordMinLinks is zero one record is created. The first genesis record will contain
// the Genesis parameters in JSON format while subsequent records are empty.
func CreateGenesisRecords(genesisOwnerType int, genesisParameters *GenesisParameters) ([]*Record, *Owner, error) {
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
	r, err := NewRecord(gpjson, nil, nil, nil, nil, nil, now, RecordWorkAlgorithmWharrgarbl, genesisOwner)
	if err != nil {
		return nil, nil, err
	}
	records = append(records, r)
	links = append(links, r.Hash()[:])

	// Subsequent genesis records are empty and just exist so real records can satisfy their minimum link requirement.
	for i := uint(1); i < genesisParameters.RecordMinLinks; i++ {
		r, err := NewRecord(nil, links, nil, nil, nil, nil, now+uint64(i), RecordWorkAlgorithmWharrgarbl, genesisOwner)
		if err != nil {
			return nil, nil, err
		}
		records = append(records, r)
		links = append(links, r.Hash()[:])
	}

	return records, genesisOwner, nil
}
