/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"math"
	"net/http"
	"sort"
	"strings"
)

var troo = true

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
	Limit      int             `json:",omitempty"` // If non-zero, limit maximum lower trust records per result
}

// APIQueryResult (response, part of APIQueryResults) is a single query result.
type APIQueryResult struct {
	Hash            HashBlob ``                  // Hash of this specific unique record
	Size            int      ``                  // Size of this record in bytes
	Record          *Record  `json:",omitempty"` // Record itself.
	Value           Blob     `json:",omitempty"` // Unmasked value if masking key was included
	UnmaskingFailed *bool    `json:",omitempty"` // If true, unmasking failed due to invalid masking key in query (or invalid compressed data in valid)
	Trust           int      ``                  // Trust metric from 0 to 1000 computed from local reputation and trusted commentary
	Weight          [16]byte `json:",omitempty"` // Record weight as a 128-bit big-endian value
}

// APIQueryResults is a list of results to an API query.
// Each result is actually an array of results sorted by weight and other metrics
// of trust (descending order of trust). These member slices will never contain
// zero records, though remote code should check to prevent exceptions.
type APIQueryResults [][]APIQueryResult

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

type apiQueryResultTmp struct {
	weightL, weightH, doff, dlen uint64
	localReputation              int
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

	// Get all results grouped by ID (all selectors)
	byID := make(map[[32]byte]*[]apiQueryResultTmp)
	n.db.query(tsMin, tsMax, selectorRanges, func(ts, weightL, weightH, doff, dlen uint64, localReputation int, id *[32]byte, owner []byte) bool {
		rptr := byID[*id]
		if rptr == nil {
			tmp := make([]apiQueryResultTmp, 0, 4)
			rptr = &tmp
			byID[*id] = rptr
		}
		*rptr = append(*rptr, apiQueryResultTmp{weightL, weightH, doff, dlen, localReputation})
		return true
	})

	// Actually grab the records and populate the qr[] slice.
	for _, rptr := range byID {
		// Collate results and add to query result
		for rn := 0; rn < len(*rptr); rn++ {
			result := &(*rptr)[rn]
			rdata, err := n.db.getDataByOffset(result.doff, uint(result.dlen), nil)
			if err != nil {
				return nil, &APIError{http.StatusInternalServerError, "error retrieving record data: " + err.Error()}
			}
			rec, err := NewRecordFromBytes(rdata)
			if err != nil {
				return nil, &APIError{http.StatusInternalServerError, "error retrieving record data: " + err.Error()}
			}

			var mkinv *bool
			v, err := rec.GetValue(m.MaskingKey)
			if err != nil {
				v = nil
				mkinv = &troo
			}

			var trust float64
			if result.localReputation > 0 {
				trust = 1.0
			}
			trustInt := int(math.Round(1000.0 * trust))

			var weight [16]byte
			binary.BigEndian.PutUint64(weight[0:8], result.weightH)
			binary.BigEndian.PutUint64(weight[8:16], result.weightL)
			if rn == 0 {
				qr = append(qr, []APIQueryResult{APIQueryResult{
					Hash:            rec.Hash(),
					Size:            int(result.dlen),
					Record:          rec,
					Value:           v,
					UnmaskingFailed: mkinv,
					Trust:           trustInt,
					Weight:          weight,
				}})
			} else if m.Limit <= 0 || rn < m.Limit {
				qr[len(qr)-1] = append(qr[len(qr)-1], APIQueryResult{
					Hash:            rec.Hash(),
					Size:            int(result.dlen),
					Record:          rec,
					Value:           v,
					UnmaskingFailed: mkinv,
					Trust:           trustInt,
					Weight:          weight,
				})
			} else {
				break
			}
		}
	}

	// Sort each element in qr[] by trust metric and weight
	for _, qrr := range qr {
		sort.Slice(qrr, func(b, a int) bool {
			if qrr[a].Trust < qrr[b].Trust {
				return true
			} else if qrr[a].Trust == qrr[b].Trust {
				return bytes.Compare(qrr[a].Weight[:], qrr[b].Weight[:]) < 0
			}
			return false
		})
	}

	// Sort root qr[] by selector ordinals.
	sort.Slice(qr, func(a, b int) bool {
		sa := qr[a][0].Record.Selectors
		sb := qr[b][0].Record.Selectors
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
