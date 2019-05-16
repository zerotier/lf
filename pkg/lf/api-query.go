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
	"encoding/binary"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
)

const (
	// APIQuerySortOrderTrust sorts by a computed trust value (default)
	APIQuerySortOrderTrust = "trust"

	// APIQuerySortOrderWeight sorts by proof of work weight only
	APIQuerySortOrderWeight = "weight"

	// APIQuerySortOrderTimestamp ignores trust and weight and sorts by time
	APIQuerySortOrderTimestamp = "timestamp"
)

const trustSigDigits float64 = 10000000000.0 // rounding precision for comparing trust values and considering them "equal"

// APIQueryRange (request, part of APIQuery) specifies a selector or selector range.
// Selector ranges can be specified in one of two ways. If KeyRange is non-empty it contains a single
// masked selector key or a range of keys. If KeyRange is empty then Name contains the plain text name
// of the selector and Range contains its ordinal range and the server will compute selector keys. The
// KeyRange method keeps selector names secret while the Name/Range method exposes them to the node or
// proxy being queried.
type APIQueryRange struct {
	Name     Blob     `json:",omitempty"` // Name of selector (plain text)
	Range    []uint64 `json:",omitempty"` // Ordinal value if [1] or range if [2] in size (single ordinal of value 0 if omitted)
	KeyRange []Blob   `json:",omitempty"` // Selector key or key range, overrides Name and Range if present (allows queries without revealing name)
}

// APIQuery (request) describes a query for records in the form of an ordered series of selector ranges.
type APIQuery struct {
	Range      []APIQueryRange `json:",omitempty"` // Selectors or selector range(s)
	TimeRange  []uint64        `json:",omitempty"` // If present, constrain record times to after first value (if [1]) or range (if [2])
	MaskingKey Blob            `json:",omitempty"` // Masking key to unmask record value(s) server-side (if non-empty)
	SortOrder  string          `json:",omitempty"` // Sort order within each result (default: trust)
	Limit      *int            `json:",omitempty"` // If non-zero, limit maximum lower trust records per result
}

// APIQueryResult (response, part of APIQueryResults) is a single query result.
type APIQueryResult struct {
	Hash   HashBlob ``                  // Hash of this specific unique record
	Size   int      ``                  // Size of this record in bytes
	Record *Record  `json:",omitempty"` // Record itself.
	Value  Blob     `json:",omitempty"` // Unmasked value if masking key was included and valid
	Trust  float64  ``                  // Locally computed trust metric
	Weight [16]byte `json:",omitempty"` // Record weight as a 128-bit big-endian value
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
	maskingKey := m.MaskingKey
	var selectorRanges [][2][]byte
	for i := 0; i < len(mm); i++ {
		if len(mm[i].KeyRange) == 0 {
			// If KeyRange is not used the selectors' names are specified in the clear and we generate keys locally.
			if len(maskingKey) == 0 && i == 0 {
				maskingKey = mm[i].Name
			}
			if len(mm[i].Range) == 0 {
				ss := MakeSelectorKey(mm[i].Name, 0)
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

	// Get all results grouped by selector key
	bySelectorKey := make(map[uint64]*[]apiQueryResultTmp)
	n.db.query(tsMin, tsMax, selectorRanges, func(ts, weightL, weightH, doff, dlen uint64, localReputation int, key uint64, owner []byte) bool {
		rptr := bySelectorKey[key]
		if rptr == nil {
			tmp := make([]apiQueryResultTmp, 0, 4)
			rptr = &tmp
			bySelectorKey[key] = rptr
		}
		*rptr = append(*rptr, apiQueryResultTmp{weightL, weightH, doff, dlen, localReputation})
		return true
	})

	// Actually grab the records and populate the qr[] slice.
	for _, rptr := range bySelectorKey {
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

			v, err := rec.GetValue(maskingKey)
			if err != nil {
				v = nil
			}

			var trust float64
			if result.localReputation > 0 {
				trust = 1.0
			}

			var weight [16]byte
			binary.BigEndian.PutUint64(weight[0:8], result.weightH)
			binary.BigEndian.PutUint64(weight[8:16], result.weightL)

			if rn == 0 {
				qr = append(qr, []APIQueryResult{APIQueryResult{
					Hash:   rec.Hash(),
					Size:   int(result.dlen),
					Record: rec,
					Value:  v,
					Trust:  trust,
					Weight: weight,
				}})
			} else {
				qr[len(qr)-1] = append(qr[len(qr)-1], APIQueryResult{
					Hash:   rec.Hash(),
					Size:   int(result.dlen),
					Record: rec,
					Value:  v,
					Trust:  trust,
					Weight: weight,
				})
			}
		}
	}

	// Sort within each result
	for qri, qrr := range qr {
		if len(m.SortOrder) == 0 || m.SortOrder == APIQuerySortOrderTrust {
			sort.Slice(qrr, func(b, a int) bool {
				if qrr[a].Trust < qrr[b].Trust {
					return true
				} else if uint64(qrr[a].Trust*trustSigDigits) == uint64(qrr[b].Trust*trustSigDigits) {
					return bytes.Compare(qrr[a].Weight[:], qrr[b].Weight[:]) < 0
				}
				return false
			})
		} else if m.SortOrder == APIQuerySortOrderWeight {
			sort.Slice(qrr, func(b, a int) bool {
				return bytes.Compare(qrr[a].Weight[:], qrr[b].Weight[:]) < 0
			})
		} else if m.SortOrder == APIQuerySortOrderTimestamp {
			sort.Slice(qrr, func(b, a int) bool {
				return qrr[a].Record.Timestamp < qrr[b].Record.Timestamp
			})
		} else {
			return nil, &APIError{http.StatusBadRequest, "valid sort order values: trust (default), weight, timestamp"}
		}
		if m.Limit != nil && *m.Limit > 0 && len(qrr) > *m.Limit {
			qr[qri] = qrr[0:*m.Limit]
		}
	}

	// Sort overall results
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
			c := bytes.Compare(sa[i].Ordinal[:], sb[i].Ordinal[:])
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
