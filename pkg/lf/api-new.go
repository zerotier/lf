/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"encoding/json"
	"net/http"
	"strings"
)

// APINewSelector (request, part of APINew) is a selector plain text name and an ordinal value (use zero if you don't care).
type APINewSelector struct {
	Name    []byte `json:",omitempty"` // Name of this selector (masked so as to be hidden from those that don't know it)
	Ordinal []byte `json:",omitempty"` // A sortable public value (optional)
}

// APINew (request) asks the proxy or node to perform server-side record generation and proof of work.
type APINew struct {
	Selectors          []APINewSelector `json:",omitempty"` // Plain text selector names and ordinals
	MaskingKey         []byte           `json:",omitempty"` // An arbitrary key used to mask the record's value from those that don't know what they're looking for
	OwnerPrivateKey    []byte           `json:",omitempty"` // Full owner including private key (result of owner PrivateBytes() method)
	OwnerSeed          []byte           `json:",omitempty"` // Seed to deterministically generate owner (used if ownerprivatekey is missing)
	OwnerSeedOwnerType *byte            `json:",omitempty"` // Owner type for seeded owner mode (default: Ed25519 owner)
	Links              []HashBlob       `json:",omitempty"` // Links to other records in the DAG
	Value              []byte           `json:",omitempty"` // Plain text (unmasked, uncompressed) value for this record
	Timestamp          *uint64          `json:",omitempty"` // Record timestamp in SECONDS since epoch (server time is used if zero or omitted)
}

// Run executes this API query against a remote LF node or proxy.
func (m *APINew) Run(url string) (*Record, error) {
	if strings.HasSuffix(url, "/") {
		url = url + "new"
	} else {
		url = url + "/new"
	}
	body, err := apiRun(url, m)
	if err != nil {
		return nil, err
	}
	var rec Record
	if err := json.Unmarshal(body, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (m *APINew) execute(workFunction *Wharrgarblr) (*Record, *APIError) {
	var err error
	var owner *Owner
	if len(m.OwnerPrivateKey) > 0 {
		owner, err = NewOwnerFromPrivateBytes(m.OwnerPrivateKey)
		if err != nil {
			return nil, &APIError{Code: http.StatusBadRequest, Message: "cannot derive owner format public key from x509 private key: " + err.Error()}
		}
	} else if len(m.OwnerSeed) > 0 {
		ot := OwnerTypeEd25519
		if m.OwnerSeedOwnerType != nil {
			ot = int(*m.OwnerSeedOwnerType)
		}
		owner, err = NewOwnerFromSeed(ot, m.OwnerSeed)
		if err != nil {
			return nil, &APIError{Code: http.StatusBadRequest, Message: "cannot generate owner from seed: " + err.Error()}
		}
	} else {
		return nil, &APIError{Code: http.StatusBadRequest, Message: "you must specify either 'ownerprivatekey' or 'ownerseed'"}
	}

	var ts uint64
	if m.Timestamp == nil || *m.Timestamp == 0 {
		ts = TimeSec()
	} else {
		ts = *m.Timestamp
	}

	sel := make([][]byte, len(m.Selectors))
	selord := make([][]byte, len(m.Selectors))
	for i := range m.Selectors {
		sel[i] = m.Selectors[i].Name
		selord[i] = m.Selectors[i].Ordinal
	}

	lnks := make([][32]byte, 0, len(m.Links))
	for _, l := range m.Links {
		lnks = append(lnks, l)
	}
	rec, err := NewRecord(RecordTypeDatum, m.Value, lnks, m.MaskingKey, sel, selord, nil, ts, workFunction, owner)
	if err != nil {
		return nil, &APIError{Code: http.StatusInternalServerError, Message: "record generation failed: " + err.Error()}
	}
	return rec, nil
}
