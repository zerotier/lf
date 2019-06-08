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
	"encoding/json"
	"hash/crc64"
	"math"
	"sort"
	"strings"
)

const (
	// QuerySortOrderTrust sorts by a computed trust value (default)
	QuerySortOrderTrust = "trust"

	// QuerySortOrderWeight sorts by proof of work weight only
	QuerySortOrderWeight = "weight"

	// QuerySortOrderTimestamp ignores trust and weight and sorts by time
	QuerySortOrderTimestamp = "timestamp"
)

const trustSigDigits float64 = 10000000000.0 // rounding precision for comparing trust values and considering them "equal"

// QueryRange (request, part of Query) specifies a selector or selector range.
// Selector ranges can be specified in one of two ways. If KeyRange is non-empty it contains a single
// masked selector key or a range of keys. If KeyRange is empty then Name contains the plain text name
// of the selector and Range contains its ordinal range and the server will compute selector keys. The
// KeyRange method keeps selector names secret while the Name/Range method exposes them to the node or
// proxy being queried.
type QueryRange struct {
	Name     Blob     `json:",omitempty"` // Name of selector (plain text)
	Range    []uint64 `json:",omitempty"` // Ordinal value if [1] or range if [2] in size (single ordinal of value 0 if omitted)
	KeyRange []Blob   `json:",omitempty"` // Selector key or key range, overrides Name and Range if present (allows queries without revealing name)
}

// Query (request) describes a query for records in the form of an ordered series of selector ranges.
type Query struct {
	Ranges     []QueryRange  `json:",omitempty"` // Selectors or selector range(s)
	TimeRange  []uint64      `json:",omitempty"` // If present, constrain record times to after first value (if [1]) or range (if [2])
	MaskingKey Blob          `json:",omitempty"` // Masking key to unmask record value(s) server-side (if non-empty)
	SortOrder  string        `json:",omitempty"` // Sort order within each result (default: trust)
	Limit      *int          `json:",omitempty"` // If non-zero, limit maximum lower trust records per result
	Open       *bool         `json:",omitempty"` // If true, include records with extra selectors not named in Ranges
	Oracles    []OwnerPublic `json:",omitempty"` // Trust these oracles during trust computation
}

// QueryResultWeight is a 128-bit value broken into four 32-bit valu
type QueryResultWeight [4]uint32

// Compare returns -1, 0, or 1 depending on whether b is less than, equal to, or greater than a.
func (a *QueryResultWeight) Compare(b *QueryResultWeight) int {
	if a[0] < b[0] {
		return -1
	} else if a[0] > b[0] {
		return 1
	}
	if a[1] < b[1] {
		return -1
	} else if a[1] > b[1] {
		return 1
	}
	if a[2] < b[2] {
		return -1
	} else if a[2] > b[2] {
		return 1
	}
	if a[3] < b[3] {
		return -1
	} else if a[3] > b[3] {
		return 1
	}
	return 0
}

// QueryResult is a single query result.
type QueryResult struct {
	Hash        HashBlob          ``                  // Hash of this specific unique record
	Size        int               ``                  // Size of this record in bytes
	Record      *Record           `json:",omitempty"` // Record itself.
	Value       Blob              `json:",omitempty"` // Unmasked value if masking key was included and valid
	Trust       float64           ``                  // Trust metric computed using local and oracle trust (if the latter is elected)
	LocalTrust  float64           ``                  // Local trust only
	OracleTrust float64           ``                  // Oracle trust only
	Weight      QueryResultWeight `json:",omitempty"` // Record weight as a 128-bit big-endian value decomposed into 4 32-bit integers
}

// QueryResults is a list of results to a query.
// Each result is actually an array of results sorted by weight and other metrics
// of trust (descending order of trust). These member slices will never contain
// zero records, though remote code should check to prevent exceptions.
type QueryResults [][]QueryResult

// ExecuteRemote executes this query against a remote LF node instance.
func (m *Query) ExecuteRemote(url string) (QueryResults, error) {
	if strings.HasSuffix(url, "/") {
		url = url + "query"
	} else {
		url = url + "/query"
	}
	body, err := apiRun(url, &m)
	if err != nil {
		return nil, err
	}
	var qr QueryResults
	if err := json.Unmarshal(body, &qr); err != nil {
		return nil, err
	}
	return qr, nil
}

type apiQueryResultTmp struct {
	weightL, weightH, doff, dlen uint64
	localReputation              int
	negativeComments             uint
}

// Execute executes this query against a local Node instance.
func (m *Query) Execute(n *Node) (qr QueryResults, err error) {
	// Set up selector ranges using sender-supplied or computed selector keys.
	mm := m.Ranges
	if len(mm) == 0 {
		return nil, ErrQueryRequiresSelectors
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
	if len(selectorRanges) == 0 {
		return nil, ErrQueryRequiresSelectors
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

	// Get all results grouped by selector composite key.
	bySelectorKey := make(map[uint64]*[]apiQueryResultTmp)
	n.db.query(tsMin, tsMax, selectorRanges, m.Oracles, func(ts, weightL, weightH, doff, dlen uint64, localReputation int, ckey uint64, owner []byte, negativeComments uint) bool {
		rptr := bySelectorKey[ckey]
		if rptr == nil {
			tmp := make([]apiQueryResultTmp, 0, 4)
			rptr = &tmp
			bySelectorKey[ckey] = rptr
		}
		*rptr = append(*rptr, apiQueryResultTmp{weightL, weightH, doff, dlen, localReputation, negativeComments})
		return true
	})

	// Actually grab the records and populate the qr[] slice. Also compute
	// oracle trust per ID/owner combo.
	slanderByIDOwner := make(map[uint64]float64)
	totalOracles := float64(len(m.Oracles))
	var qrIDOwnerCRC64s [][]uint64
	for _, rptr := range bySelectorKey {
		// Collate results and add to query result
		for rn := 0; rn < len(*rptr); rn++ {
			result := &(*rptr)[rn]
			rdata, err := n.db.getDataByOffset(result.doff, uint(result.dlen), nil)
			if err != nil {
				return nil, err
			}
			rec, err := NewRecordFromBytes(rdata)
			if err != nil {
				return nil, err
			}

			// Check total selector count and also filter out records that are not
			// currently approved. This means that when a CRL revokes an owner cert
			// that was used to add a record (that wasn't paid for by PoW) that
			// record is hidden from clients/users.
			currentlyApproved, _ := n.recordApprovalStatus(rec)
			if (len(rec.Selectors) != len(selectorRanges) && (m.Open == nil || !*m.Open)) || !currentlyApproved {
				continue
			}

			// Compute local trust
			var trust float64
			if result.localReputation >= dbReputationDefault {
				trust = float64(result.localReputation) / float64(dbReputationDefault)
			}

			// Compute oracle trust by determining the max fraction of oracles
			// that said something bad about a record with this ID/owner combo.
			if len(m.Oracles) > 0 {
				c64 := crc64.New(crc64ECMATable)
				recID := rec.ID()
				c64.Write(recID[:])
				c64.Write(rec.Owner)
				idOwnerC64 := c64.Sum64()
				slander := float64(result.negativeComments) / totalOracles
				if slander > slanderByIDOwner[idOwnerC64] {
					slanderByIDOwner[idOwnerC64] = slander
				}

				if rn == 0 {
					qrIDOwnerCRC64s = append(qrIDOwnerCRC64s, []uint64{idOwnerC64})
				} else {
					qrIDOwnerCRC64s[len(qrIDOwnerCRC64s)-1] = append(qrIDOwnerCRC64s[len(qrIDOwnerCRC64s)-1], idOwnerC64)
				}
			}

			var weight [4]uint32
			weight[0] = uint32(result.weightH << 32)
			weight[1] = uint32(result.weightH)
			weight[2] = uint32(result.weightL << 32)
			weight[3] = uint32(result.weightL)

			v, _ := rec.GetValue(maskingKey)
			if rn == 0 {
				qr = append(qr, []QueryResult{QueryResult{
					Hash:        rec.Hash(),
					Size:        int(result.dlen),
					Record:      rec,
					Value:       v,
					Trust:       trust,
					LocalTrust:  trust,
					OracleTrust: 1.0,
					Weight:      weight,
				}})
			} else {
				qr[len(qr)-1] = append(qr[len(qr)-1], QueryResult{
					Hash:        rec.Hash(),
					Size:        int(result.dlen),
					Record:      rec,
					Value:       v,
					Trust:       trust,
					LocalTrust:  trust,
					OracleTrust: 1.0,
					Weight:      weight,
				})
			}
		}
	}

	// Compute final trust and sort within each result.
	for qrSetIdx, qrSet := range qr {
		if len(m.Oracles) > 0 {
			for qrSetResultIdx, qrSetResult := range qrSet {
				oracleTrust := math.Max(1.0-slanderByIDOwner[qrIDOwnerCRC64s[qrSetIdx][qrSetResultIdx]], 0.0)
				if oracleTrust < qrSetResult.Trust {
					qrSet[qrSetResultIdx].Trust = oracleTrust
				}
				qrSet[qrSetResultIdx].OracleTrust = oracleTrust
			}
		}

		if len(m.SortOrder) == 0 || m.SortOrder == QuerySortOrderTrust {
			sort.Slice(qrSet, func(b, a int) bool {
				if qrSet[a].Trust < qrSet[b].Trust {
					return true
				} else if uint64(qrSet[a].Trust*trustSigDigits) == uint64(qrSet[b].Trust*trustSigDigits) {
					return qrSet[a].Weight.Compare(&qrSet[b].Weight) < 0
				}
				return false
			})
		} else if m.SortOrder == QuerySortOrderWeight {
			sort.Slice(qrSet, func(b, a int) bool {
				return qrSet[a].Weight.Compare(&qrSet[b].Weight) < 0
			})
		} else if m.SortOrder == QuerySortOrderTimestamp {
			sort.Slice(qrSet, func(b, a int) bool {
				return qrSet[a].Record.Timestamp < qrSet[b].Record.Timestamp
			})
		} else {
			return nil, ErrQueryInvalidSortOrder
		}

		if m.Limit != nil && *m.Limit > 0 && len(qrSet) > *m.Limit {
			qr[qrSetIdx] = qrSet[0:*m.Limit]
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
