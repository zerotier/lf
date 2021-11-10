/*
 * Copyright (c)2019 ZeroTier, Inc.
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file in the project's root directory.
 *
 * Change Date: 2023-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2.0 of the Apache License.
 */
/****/

package lf

import (
	"bytes"
	"crypto/x509"
	"hash/crc64"
	"math"
	"sort"
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
	Owners     []OwnerPublic `json:",omitempty"` // Restrict to these owners only
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
	Pulse       uint64            ``                  // Timestamp plus current pulse value
	Trust       float64           ``                  // Trust metric computed using local and oracle trust (if the latter is elected)
	LocalTrust  float64           ``                  // Local trust only
	OracleTrust float64           ``                  // Oracle trust only
	Weight      QueryResultWeight `json:",omitempty"` // Record weight as a 128-bit big-endian value decomposed into 4 32-bit integers
	Signed      bool              ``                  // If true, record's owner is signed and cert's timestamps match this record
}

// QueryResults is a list of results to a query.
// Each result is actually an array of results sorted by weight and other metrics
// of trust (descending order of trust). These member slices will never contain
// zero records, though remote code should check to prevent exceptions.
type QueryResults [][]QueryResult

type apiQueryResultTmp struct {
	weightL, weightH, doff, dlen uint64
	ts                           int64
	localReputation              int
	negativeComments             uint
}

func (m *Query) execute(n *Node) (qr QueryResults, err error) {
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
	if tsMin < 0 {
		tsMin = 0
	}
	if tsMax < 0 {
		tsMax = int64(9223372036854775807)
	}

	// Get all results grouped by selector composite key.
	bySelectorKey := make(map[uint64]*[]apiQueryResultTmp)
	_ = n.db.query(selectorRanges, m.Oracles, func(ts, weightL, weightH, doff, dlen uint64, localReputation int, ckey uint64, owner []byte, negativeComments uint) bool {
		includeOwner := true
		if len(m.Owners) > 0 {
			includeOwner = false
			for _, o := range m.Owners {
				if bytes.Equal(o, owner) {
					includeOwner = true
					break
				}
			}
		}
		if includeOwner {
			rptr := bySelectorKey[ckey]
			if rptr == nil {
				tmp := make([]apiQueryResultTmp, 0, 4)
				rptr = &tmp
				bySelectorKey[ckey] = rptr
			}
			*rptr = append(*rptr, apiQueryResultTmp{weightL, weightH, doff, dlen, int64(ts), localReputation, negativeComments})
		}
		return true
	})

	// Actually grab the records and populate the qr[] slice. Also compute
	// oracle trust per ID/owner combo.
	slanderByIDOwner := make(map[uint64]float64)
	totalOracles := float64(len(m.Oracles))
	ownerCertCache := make(map[uint64][]*x509.Certificate)
	var qrIDOwnerCRC64s [][]uint64
	for _, rptr := range bySelectorKey {
		// Collate results and add to query result
		for rn := 0; rn < len(*rptr); rn++ {
			result := &(*rptr)[rn]

			if result.ts < tsMin || result.ts > tsMax {
				continue
			}

			rdata, err := n.db.getDataByOffset(result.doff, uint(result.dlen), nil)
			if err != nil {
				return nil, err
			}
			rec, err := NewRecordFromBytes(rdata)
			if err != nil {
				return nil, err
			}

			if len(rec.Selectors) != len(selectorRanges) && (m.Open == nil || !*m.Open) {
				continue
			}

			// Get owner certs and check whether any non-revoked certs apply to this record.
			ownerC64 := crc64.Checksum(rec.Owner, crc64ECMATable)
			ownerCerts, haveCachedOwnerCerts := ownerCertCache[ownerC64]
			if !haveCachedOwnerCerts {
				ownerCerts, _, _ = n.GetOwnerCertificates(rec.Owner)
				ownerCertCache[ownerC64] = ownerCerts
			}
			recordIsSigned := false
			for _, cert := range ownerCerts {
				if rec.Timestamp >= uint64(cert.NotBefore.Unix()) && rec.Timestamp <= uint64(cert.NotAfter.Unix()) {
					recordIsSigned = true
					break
				}
			}
			if !recordIsSigned && (n.genesisParameters.AuthRequired || !rec.ValidateWork()) && !n.localTest {
				continue
			}

			// Compute local trust
			var localTrust float64
			if result.localReputation >= dbReputationDefault {
				localTrust = float64(result.localReputation) / float64(dbReputationDefault)
			}

			// Compute oracle trust by determining the max fraction of oracles
			// that said something bad about a record with this ID/owner combo.
			if len(m.Oracles) > 0 {
				c64 := crc64.New(crc64ECMATable)
				recID := rec.ID()
				_, _ = c64.Write(recID[:])
				_, _ = c64.Write(rec.Owner)
				idOwnerC64 := c64.Sum64()
				slander := float64(result.negativeComments) / totalOracles
				if slander > slanderByIDOwner[idOwnerC64] {
					slanderByIDOwner[idOwnerC64] = slander
				}

				if rn == 0 {
					qrIDOwnerCRC64s = append(qrIDOwnerCRC64s, []uint64{idOwnerC64})
				} else if len(qrIDOwnerCRC64s) > 0 {
					qrIDOwnerCRC64s[len(qrIDOwnerCRC64s)-1] = append(qrIDOwnerCRC64s[len(qrIDOwnerCRC64s)-1], idOwnerC64)
				}
			}

			var weight [4]uint32
			weight[0] = uint32(result.weightH >> 32)
			weight[1] = uint32(result.weightH)
			weight[2] = uint32(result.weightL >> 32)
			weight[3] = uint32(result.weightL)

			v, _ := rec.GetValue(maskingKey)
			pulse := n.db.getPulse(rec.recordBody.PulseToken) * 60 // pulse is in a resolution of minutes

			if rn == 0 {
				qr = append(qr, []QueryResult{{
					Hash:        rec.Hash(),
					Size:        int(result.dlen),
					Record:      rec,
					Value:       v,
					Pulse:       rec.recordBody.Timestamp + pulse,
					Trust:       localTrust,
					LocalTrust:  localTrust,
					OracleTrust: localTrust,
					Weight:      weight,
					Signed:      recordIsSigned,
				}})
			} else if len(qr) > 0 {
				qr[len(qr)-1] = append(qr[len(qr)-1], QueryResult{
					Hash:        rec.Hash(),
					Size:        int(result.dlen),
					Record:      rec,
					Value:       v,
					Pulse:       rec.recordBody.Timestamp + pulse,
					Trust:       localTrust,
					LocalTrust:  localTrust,
					OracleTrust: localTrust,
					Weight:      weight,
					Signed:      recordIsSigned,
				})
			}
		}
	}

	authCerts, _ := n.genesisParameters.GetAuthCertificates()
	haveAuthCerts := len(authCerts) > 0

	// Compute final trust and sort within each result.
	if len(qrIDOwnerCRC64s) > 0 {
		for qrSetIdx, qrSet := range qr {
			// Compute oracle trust and overall trust as a function of local and oracle trust if there are oracles.
			if len(m.Oracles) > 0 {
				for qrSetResultIdx := range qrSet {
					oracleTrust := math.Max(1.0-slanderByIDOwner[qrIDOwnerCRC64s[qrSetIdx][qrSetResultIdx]], 0.0)
					qrSet[qrSetResultIdx].Trust = (qrSet[qrSetResultIdx].LocalTrust + (oracleTrust * totalOracles)) / (totalOracles + 1.0)
					qrSet[qrSetResultIdx].OracleTrust = oracleTrust
				}
			}

			// If this database has auth certs, penalize records that are not signed.
			if haveAuthCerts {
				for qrSetResultIdx := range qrSet {
					if !qrSet[qrSetResultIdx].Signed {
						qrSet[qrSetResultIdx].Trust *= 0.9
					}
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
