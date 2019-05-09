/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * --
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial closed-source software that incorporates or links
 * directly against ZeroTier software without disclosing the source code
 * of your own application.
 */

package lf

import (
	"crypto/x509"
	"encoding/json"
	"strings"
)

// GenesisParameters is the payload (JSON encoded) of the first RecordMinLinks records in a global data store.
type GenesisParameters struct {
	Name                       string   `json:",omitempty"` // Name of this LF network / data store
	Contact                    string   `json:",omitempty"` // Contact info for this network (may be empty)
	Comment                    string   `json:",omitempty"` // Optional comment
	RootCertificateAuthorities Blob     `json:",omitempty"` // X.509 certificate(s) for master CAs for this data store (ASN.1 records)
	CertificateRequired        bool     `json:""`           // Is a certificate required? (must be false if there are no CAs, obviously)
	WorkRequired               bool     `json:""`           // Is proof of work required? (assuming no certificate allowing reduced or no work)
	LinkKey                    [32]byte `json:""`           // Static 32-byte key used to ensure that nodes in this network only connect to one another
	TimestampFloor             uint64   `json:""`           // Floor for network record timestamps (seconds)
	RecordMinLinks             uint     `json:""`           // Minimum number of links required for non-genesis records
	RecordMaxValueSize         uint     `json:""`           // Maximum size of record values
	RecordMaxSize              uint     `json:""`           // Maximum size of records (up to the RecordMaxSize constant)
	RecordMaxForwardTimeDrift  uint     `json:""`           // Maximum number of seconds in the future a record can be timestamped
	AmendableFields            []string `json:",omitempty"` // List of json field names that the genesis owner can change by posting non-empty records

	certs       []*x509.Certificate
	initialized bool
}

// Update updates these GenesisParameters from a JSON encoded parameter set.
// This handles the initial update and then constraining later updated by AmendableFields and which fields are present.
func (gp *GenesisParameters) Update(jsonValue []byte) error {
	if len(jsonValue) == 0 {
		return nil
	}

	updFields := make(map[string]*json.RawMessage)
	err := json.Unmarshal(jsonValue, &updFields)
	if err != nil {
		return err
	}
	var ngp GenesisParameters
	err = json.Unmarshal(jsonValue, &ngp)
	if err != nil {
		return err
	}

	afields := gp.AmendableFields
	for k := range updFields {
		skip := gp.initialized
		if skip {
			for _, af := range afields {
				if strings.EqualFold(af, k) {
					skip = false
					break
				}
			}
		}
		if !skip {
			switch strings.ToLower(k) {
			case "name":
				gp.Name = ngp.Name
			case "contact":
				gp.Contact = ngp.Contact
			case "comment":
				gp.Comment = ngp.Comment
			case "rootcertificateauthorities":
				gp.RootCertificateAuthorities = ngp.RootCertificateAuthorities
				gp.certs = nil // forget previously cached certs
			case "certificaterequired":
				gp.CertificateRequired = ngp.CertificateRequired
			case "workrequired":
				gp.WorkRequired = ngp.WorkRequired
			case "linkkey":
				gp.LinkKey = ngp.LinkKey
			case "timestampfloor":
				gp.TimestampFloor = ngp.TimestampFloor
			case "recordminlinks":
				gp.RecordMinLinks = ngp.RecordMinLinks
			case "recordmaxvaluesize":
				gp.RecordMaxValueSize = ngp.RecordMaxValueSize
			case "recordmaxsize":
				gp.RecordMaxSize = ngp.RecordMaxSize
			case "recordmaxforwardtimedrift":
				gp.RecordMaxForwardTimeDrift = ngp.RecordMaxForwardTimeDrift
			case "amendablefields":
				gp.AmendableFields = ngp.AmendableFields
			}
		}
	}

	gp.initialized = true

	return nil
}

// RootCAs returns the fully deserialized root CAs in this parameter set.
func (gp *GenesisParameters) RootCAs() ([]*x509.Certificate, error) {
	if len(gp.certs) > 0 {
		return gp.certs, nil
	}
	if len(gp.RootCertificateAuthorities) == 0 {
		return nil, nil
	}
	certs, err := x509.ParseCertificates(gp.RootCertificateAuthorities)
	if err != nil {
		return nil, err
	}
	gp.certs = certs
	return certs, nil
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
	var links [][32]byte
	genesisOwner, err := NewOwner(genesisOwnerType)
	if err != nil {
		return nil, nil, err
	}
	now := TimeSec()

	var wg *Wharrgarblr
	if genesisParameters.WorkRequired {
		wg = NewWharrgarblr(RecordDefaultWharrgarblMemory, 0)
	}

	// Create the very first genesis record, which contains the genesis configuration structure in JSON format.
	r, err := NewRecord(RecordTypeGenesis, gpjson, nil, nil, nil, nil, nil, now, wg, genesisOwner)
	if err != nil {
		return nil, nil, err
	}
	records = append(records, r)
	links = append(links, r.Hash())

	// Subsequent genesis records are empty and just exist so real records can satisfy their minimum link requirement.
	for i := uint(1); i < genesisParameters.RecordMinLinks; i++ {
		r, err := NewRecord(RecordTypeGenesis, nil, links, nil, nil, nil, nil, now+uint64(i), wg, genesisOwner)
		if err != nil {
			return nil, nil, err
		}
		records = append(records, r)
		links = append(links, r.Hash())
	}

	return records, genesisOwner, nil
}
