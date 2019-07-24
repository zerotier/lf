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
	"sync"
	"sync/atomic"
	"unsafe"
)

type genesisParametersState struct {
	certs        map[string]*x509.Certificate
	revokedCerts map[string]*x509.Certificate
	history      []GenesisParameters
	lock         sync.Mutex
}

// GenesisParameters is the payload (JSON encoded) of the first records in the DAG.
type GenesisParameters struct {
	ID                      [32]byte ``                  // Unique arbitrary 32-byte ID of this network (always immutable)
	AmendableFields         []string `json:",omitempty"` // List of json field names that the genesis owner can change (always immutable)
	Name                    string   `json:",omitempty"` // Name of this LF network / data store
	Contact                 string   `json:",omitempty"` // Contact info for this network (may be empty)
	Comment                 string   `json:",omitempty"` // Optional comment
	AuthCertificates        Blob     `json:",omitempty"` // X.509 root certificates for avoiding PoW and potentially elevated trust (if elected)
	RevokedAuthCertificates Blob     `json:",omitempty"` // Revoked root certificates (this is just done by placing them here instead of CRLs)
	AuthRequired            bool     ``                  // If true a cert is required and simple PoW is not accepted
	RecordMinLinks          uint     ``                  // Minimum number of links required for non-genesis records
	RecordMaxValueSize      uint     ``                  // Maximum size of record values
	RecordMaxTimeDrift      uint     ``                  // Maximum number of seconds of time drift permitted for records

	state  unsafe.Pointer
	stateP *genesisParametersState
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

	gps := (*genesisParametersState)(atomic.LoadPointer(&gp.state))
	if gps == nil {
		*gp = ngp
		gps = new(genesisParametersState)
		atomic.StorePointer(&gp.state, unsafe.Pointer(gps))
	}
	gp.stateP = gps
	gps.lock.Lock()
	defer gps.lock.Unlock()

	old := *gp
	changed := false
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
		case "authcertificates", "revokedauthcertificates": // these are effectively the same field
			if !bytes.Equal(gp.AuthCertificates, ngp.AuthCertificates) {
				gp.AuthCertificates = ngp.AuthCertificates
				changed = true
			}
			if !bytes.Equal(gp.RevokedAuthCertificates, ngp.RevokedAuthCertificates) {
				gp.RevokedAuthCertificates = ngp.RevokedAuthCertificates
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
		}
	}

	if changed {
		gps.certs = nil
		gps.revokedCerts = nil
		old.state = unsafe.Pointer(nil)
		old.stateP = nil
		gps.history = append(gps.history, old)
	}

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
		case "name", "contact", "comment", "authcertificates", "authrequired", "recordminlinks", "recordmaxvaluesize", "recordmaxforwardtimedrift", "seedpeers":
			gp.AmendableFields = append(gp.AmendableFields, af)
		default:
			return fmt.Errorf("invalid amendable field name: %s", f)
		}
	}
	return nil
}

var emptyCertMap = make(map[string]*x509.Certificate)

// GetAuthCertificates returns the fully deserialized auth CAs in this parameter set.
// The maps returned by this function should not be modified.
func (gp *GenesisParameters) GetAuthCertificates() (map[string]*x509.Certificate, map[string]*x509.Certificate) {
	if len(gp.AuthCertificates) == 0 {
		return emptyCertMap, emptyCertMap
	}
	gps := (*genesisParametersState)(atomic.LoadPointer(&gp.state))
	if gps == nil {
		gps = new(genesisParametersState) // make this work for GenesisParamters not initialized through Update()
	}

	gps.lock.Lock()
	defer gps.lock.Unlock()
	if len(gps.certs) > 0 || len(gps.revokedCerts) > 0 {
		return gps.certs, gps.revokedCerts
	}

	certs, _ := x509.ParseCertificates(gp.AuthCertificates)
	revokedCerts, _ := x509.ParseCertificates(gp.RevokedAuthCertificates)

	gps.certs = make(map[string]*x509.Certificate)
	gps.revokedCerts = make(map[string]*x509.Certificate)
	for _, cert := range certs {
		gps.certs[Base62Encode(cert.SerialNumber.Bytes())] = cert
	}
	for _, revokedCert := range revokedCerts {
		gps.revokedCerts[Base62Encode(revokedCert.SerialNumber.Bytes())] = revokedCert
	}

	return gps.certs, gps.revokedCerts
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
	r, err := NewRecord(RecordTypeGenesis, gpjson, nil, nil, nil, nil, now, wg, genesisOwner)
	if err != nil {
		return nil, nil, err
	}
	records = append(records, r)
	links = append(links, r.Hash())

	// Subsequent genesis records are empty and just exist so real records can satisfy their minimum link requirement.
	for i := uint(1); i < genesisParameters.RecordMinLinks; i++ {
		r, err := NewRecord(RecordTypeGenesis, nil, links, nil, nil, nil, now+uint64(i), wg, genesisOwner)
		if err != nil {
			return nil, nil, err
		}
		records = append(records, r)
		links = append(links, r.Hash())
	}

	return records, genesisOwner, nil
}
