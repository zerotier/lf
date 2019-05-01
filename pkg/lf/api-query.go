/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// APIQueryRange (request, part of APIQuery) specifies a selector or selector range.
// Selector ranges can be specified in one of two ways. If KeyRange is non-empty it contains a single
// masked selector key or a range of keys. If KeyRange is empty then Name contains the plain text name
// of the selector and Range contains its ordinal range and the server will compute selector keys. The
// KeyRange method keeps selector names secret while the Name/Range method exposes them to the node or
// proxy being queried.
type APIQueryRange struct {
	Name     Blob   `json:",omitempty"` // Name of selector (plain text)
	Range    []Blob `json:",omitempty"` // Ordinal value if [1] or range if [2] in size
	KeyRange []Blob `json:",omitempty"` // Selector key or key range, overrides Name and Range if present (allows queries without revealing name)
}

// APIQuery (request) describes a query for records in the form of an ordered series of selector ranges.
type APIQuery struct {
	Range      []APIQueryRange `json:",omitempty"` // Selectors or selector range(s)
	TimeRange  []uint64        `json:",omitempty"` // If present, constrain record times to after first value (if [1]) or range (if [2])
	MaskingKey Blob            `json:",omitempty"` // Masking key to unmask record value(s) server-side (if non-empty)
}

// APIQueryResult (response, part of APIQueryResults) is a single query result.
type APIQueryResult struct {
	Record *Record `json:",omitempty"` // Record itself.
	Value  Blob    `json:",omitempty"` // Unmasked value if masking key was included
	Weight string  `json:",omitempty"` // Record weight as a 128-bit hex value
}

// APIQueryResults is a list of results to an API query.
// Each record will be the best (as determined by weight and possibly trust relationships) for each combination
// of record selectors. If there are more than one it's the application's responsibility to decide which are
// relevant or trustworthy.
type APIQueryResults []APIQueryResult

// Run executes this API query against a remote LF node or proxy
func (m *APIQuery) Run(url string) (APIQueryResults, error) {
	if strings.HasSuffix(url, "/") {
		url = url + "query"
	} else {
		url = url + "/query"
	}
	body, err := apiRun(url, &m)
	if err != nil {
		return nil, err
	}
	var qr APIQueryResults
	if err := json.Unmarshal(body, &qr); err != nil {
		return nil, err
	}
	return qr, nil
}

func (m *APIQuery) execute(n *Node) (qr APIQueryResults, err *APIError) {
	// Set up selector ranges using sender-supplied or computed selector keys.
	mm := m.Range
	if len(mm) == 0 {
		return nil, &APIError{http.StatusBadRequest, "a query requires at least one selector"}
	}
	var selectorRanges [][2][]byte
	for i := 0; i < len(mm); i++ {
		if len(mm[i].KeyRange) == 0 {
			// If KeyRange is not used the selectors' names are specified in the clear and we generate keys locally.
			if len(mm[i].Range) == 0 {
				ss := MakeSelectorKey(mm[i].Name, nil)
				selectorRanges = append(selectorRanges, [2][]byte{ss[:], ss[:]})
			} else if len(mm[i].Range) == 1 {
				ss := MakeSelectorKey(mm[i].Name, mm[i].Range[0])
				selectorRanges = append(selectorRanges, [2][]byte{ss[:], ss[:]})
			} else if len(mm[i].Range) == 2 {
				ss := MakeSelectorKey(mm[i].Name, mm[i].Range[0])
				ee := MakeSelectorKey(mm[i].Name, mm[i].Range[1])
				selectorRanges = append(selectorRanges, [2][]byte{ss[:], ee[:]})
			}
		} else {
			// Otherwise we use the sender-supplied key range which keeps names secret.
			if len(mm[i].KeyRange) == 1 {
				selectorRanges = append(selectorRanges, [2][]byte{mm[i].KeyRange[0], mm[i].KeyRange[0]})
			} else if len(mm[i].KeyRange) == 2 {
				selectorRanges = append(selectorRanges, [2][]byte{mm[i].KeyRange[0], mm[i].KeyRange[1]})
			}
		}
	}

	// Get query timestamp range (or use min..max)
	tsMin := int64(0)
	tsMax := int64(9223372036854775807)
	if len(m.TimeRange) == 1 {
		tsMin = int64(m.TimeRange[0])
	} else if len(m.TimeRange) == 2 {
		tsMin = int64(m.TimeRange[0])
		tsMax = int64(m.TimeRange[1])
	}

	// Iterate through results and store them in a temporary map by ID (hash of selector keys). This
	// lets us find the highest weighted record for each combination of selectors without wasting the
	// time to grab whole records that we don't ultimately return. Note that the C side of this code
	// handles finding the latest record (max timestamp) by owner/ID combo.
	bestByID := make(map[[32]byte]*[4]uint64)
	n.db.query(tsMin, tsMax, selectorRanges, func(ts, weightL, weightH, doff, dlen uint64, id *[32]byte, owner []byte) bool {
		rptr := bestByID[*id]
		if rptr == nil {
			bestByID[*id] = &([4]uint64{weightH, weightL, doff, dlen})
		} else {
			if rptr[0] < weightH {
				return true
			} else if rptr[0] == weightH {
				if rptr[1] < weightL {
					return true
				}
			}
			rptr[0] = weightH
			rptr[1] = weightL
			rptr[2] = doff
			rptr[3] = dlen
		}
		return true
	})

	// Actually grab the records and populate the qr[] slice.
	for _, rptr := range bestByID {
		rdata, err := n.db.getDataByOffset(rptr[2], uint(rptr[3]), nil)
		if err != nil {
			return nil, &APIError{http.StatusInternalServerError, "error retrieving record data: " + err.Error()}
		}
		rec, err := NewRecordFromBytes(rdata)
		if err != nil {
			return nil, &APIError{http.StatusInternalServerError, "error retrieving record data: " + err.Error()}
		}
		v, err := rec.GetValue(m.MaskingKey)
		if err != nil {
			v = nil
		}
		qr = append(qr, APIQueryResult{
			Record: rec,
			Value:  v,
			Weight: fmt.Sprintf("%.16x%.16x", rptr[0], rptr[1]),
		})
	}

	// Sort qr[] by selector ordinal.
	sort.Slice(qr, func(a, b int) bool {
		sa := qr[a].Record.Selectors
		sb := qr[b].Record.Selectors
		if len(sa) < len(sb) {
			return true
		}
		if len(sa) > len(sb) {
			return false
		}
		for i := 0; i < len(sa); i++ {
			c := bytes.Compare(sa[i].Ordinal, sb[i].Ordinal)
			if c < 0 {
				return true
			} else if c > 0 {
				return false
			}
		}
		return false
	})

	return
}
