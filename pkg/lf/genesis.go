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
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
)

// GenesisParameters is the payload (JSON encoded) of the first RecordMinLinks records in a global data store.
type GenesisParameters struct {
	ID                 [32]byte ``                  // Unique arbitrary 32-byte ID of this network (always immutable!)
	AmendableFields    []string `json:",omitempty"` // List of json field names that the genesis owner can change by posting non-empty records
	Name               string   `json:",omitempty"` // Name of this LF network / data store
	Contact            string   `json:",omitempty"` // Contact info for this network (may be empty)
	Comment            string   `json:",omitempty"` // Optional comment
	AuthCertificates   Blob     `json:",omitempty"` // X.509 certificate(s) that can sign records to bypass work requirement
	AuthRequired       bool     ``                  // If true a CA signature is required and simple proof of work is not accepted
	RecordMinLinks     uint     ``                  // Minimum number of links required for non-genesis records
	RecordMaxValueSize uint     ``                  // Maximum size of record values
	RecordMaxTimeDrift uint     ``                  // Maximum number of seconds of time drift permitted for records
	SeedPeers          []Peer   `json:",omitempty"` // Some peer nodes with static IPs to help bootstrap

	certs       []*x509.Certificate
	history     []GenesisParameters
	initialized bool
}

// Update updates these GenesisParameters from a JSON encoded parameter set, obeying AmendableFields constraints.
func (gp *GenesisParameters) Update(jsonValue []byte) (bool, error) {
	if len(jsonValue) == 0 {
		return false, nil
	}

	var ngp GenesisParameters
	err := json.Unmarshal(jsonValue, &ngp)
	if err != nil {
		return false, err
	}

	if !gp.initialized {
		*gp = ngp
		return true, nil
	}

	changed := false
	old := *gp
	for _, k := range gp.AmendableFields {
		switch strings.ToLower(k) {
		case "name":
			if gp.Name != ngp.Name {
				gp.Name = ngp.Name
				changed = true
			}
		case "contact":
			if gp.Contact != ngp.Contact {
				gp.Contact = ngp.Contact
				changed = true
			}
		case "comment":
			if gp.Comment != ngp.Comment {
				gp.Comment = ngp.Comment
				changed = true
			}
		case "authcertificates":
			if !bytes.Equal(gp.AuthCertificates, ngp.AuthCertificates) {
				gp.AuthCertificates = ngp.AuthCertificates
				gp.certs = nil // forget previously cached certs
				changed = true
			}
		case "authrequired":
			if gp.AuthRequired != ngp.AuthRequired {
				gp.AuthRequired = ngp.AuthRequired
				changed = true
			}
		case "recordminlinks":
			if gp.RecordMinLinks != ngp.RecordMinLinks {
				gp.RecordMinLinks = ngp.RecordMinLinks
				changed = true
			}
		case "recordmaxvaluesize":
			if gp.RecordMaxValueSize != ngp.RecordMaxValueSize {
				gp.RecordMaxValueSize = ngp.RecordMaxValueSize
				changed = true
			}
		case "recordmaxtimedrift":
			if gp.RecordMaxTimeDrift != ngp.RecordMaxTimeDrift {
				gp.RecordMaxTimeDrift = ngp.RecordMaxTimeDrift
				changed = true
			}
		case "seedpeers":
			if len(gp.SeedPeers) != len(ngp.SeedPeers) {
				gp.SeedPeers = ngp.SeedPeers
				changed = true
			} else {
				for i := range gp.SeedPeers {
					if !gp.SeedPeers[i].IP.Equal(ngp.SeedPeers[i].IP) || gp.SeedPeers[i].Port != ngp.SeedPeers[i].Port || !bytes.Equal(gp.SeedPeers[i].Identity, ngp.SeedPeers[i].Identity) {
						gp.SeedPeers = ngp.SeedPeers
						changed = true
						break
					}
				}
			}
		}
	}

	if changed {
		gp.history = append(gp.history, old)
	}
	gp.initialized = true

	return changed, nil
}

// SetAmendableFields validates and sets the AmendableFields field
func (gp *GenesisParameters) SetAmendableFields(fields []string) error {
	if len(fields) == 0 {
		gp.AmendableFields = nil
		return nil
	}
	gp.AmendableFields = make([]string, 0, len(fields))
	for _, f := range fields {
		af := strings.ToLower(strings.TrimSpace(f))
		switch af {
		case "name", "contact", "comment", "authcertificates", "authrequired", "recordminlinks", "recordmaxvaluesize", "recordmaxforwardtimedrift", "seedpeers", "amendablefields":
			gp.AmendableFields = append(gp.AmendableFields, af)
		default:
			return fmt.Errorf("invalid amendable field name: %s", f)
		}
	}
	return nil
}

// GetAuthCertificates returns the fully deserialized auth CAs in this parameter set.
func (gp *GenesisParameters) GetAuthCertificates() ([]*x509.Certificate, error) {
	if len(gp.certs) > 0 {
		return gp.certs, nil
	}
	if len(gp.AuthCertificates) == 0 {
		return nil, nil
	}
	certs, err := x509.ParseCertificates(gp.AuthCertificates)
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
func CreateGenesisRecords(genesisOwnerType byte, genesisParameters *GenesisParameters) ([]*Record, *Owner, error) {
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

	// Genesis records always carry PoW
	wg := NewWharrgarblr(RecordDefaultWharrgarblMemory, 0)

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
