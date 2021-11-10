/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c)2019-2021 ZeroTier, Inc.
 * https://www.zerotier.com/
 */

package lf

import (
	"bytes"
)

// doMakeRequestSetup contains common code for execute() for pulses and records
func doMakeRequestSetup(n *Node, selectors []MakeSelector, passphrase string, ownerPrivate Blob, reqMaskingKey Blob, scanForOlderRecord bool) (
	owner *Owner,
	selectorNames [][]byte,
	selectorOrdinals []uint64,
	maskingKey []byte,
	recTS, recDoff uint64,
	recDlen uint,
	err error,
) {
	if len(passphrase) > 0 {
		o, mk := PassphraseToOwnerAndMaskingKey(passphrase)
		if len(reqMaskingKey) == 0 {
			maskingKey = mk
		} else {
			maskingKey = reqMaskingKey
		}
		owner = o
	} else {
		o, e := NewOwnerFromPrivateBytes(ownerPrivate)
		if e != nil {
			err = e
			return
		}
		owner = o
	}
	if len(maskingKey) == 0 {
		maskingKey = reqMaskingKey
	}
	if len(maskingKey) == 0 && len(selectors) > 0 {
		maskingKey = selectors[0].Name
	}

	var selectorRanges [][2][]byte
	for _, sr := range selectors {
		skey := MakeSelectorKey(sr.Name, sr.Ordinal)
		selectorRanges = append(selectorRanges, [2][]byte{skey, skey})
		selectorNames = append(selectorNames, sr.Name)
		selectorOrdinals = append(selectorOrdinals, sr.Ordinal)
	}

	if scanForOlderRecord {
		_ = n.db.query(selectorRanges, nil, func(ts, _, _, doff, dlen uint64, _ int, _ uint64, recOwner []byte, _ uint) bool {
			if bytes.Equal(recOwner, owner.Public) {
				if ts > recTS {
					recTS = ts
					recDoff = doff
					recDlen = uint(dlen)
				}
			}
			return true
		})
	}

	return
}

// MakeSelector contains a plain text name and ordinal for a new record to be created server-side.
type MakeSelector struct {
	Name    Blob   `json:",omitempty"`
	Ordinal uint64 ``
}

// MakeRecord requests that the server make and submit a record.
// If Passphrase is supplied it overrides OwnerPrivate and MaskingKey and generates them deterministically.
// Otherwise OwnerPrivate must be an owner's private (and including public) key in DER or PEM format
// (auto-detected). If MaskingKey is empty it defaults to the first selector name. Note that requesting
// remote record creation reveals secrets! Nodes will not remotely create records that require proof
// of work unless the client is authorized to do so as this uses significant local compute resources
// at the node.
type MakeRecord struct {
	Selectors        []MakeSelector `json:",omitempty"` // Selectors for new record
	Value            Blob           `json:",omitempty"` // Value for new record
	OwnerPrivate     Blob           `json:",omitempty"` // Full owner with private key in DER or PEM format
	MaskingKey       Blob           `json:",omitempty"` // Masking key if specified (default: first selector, then owner)
	Passphrase       string         `json:",omitempty"` // Passphrase to override OwnerPrivate and (if empty) MaskingKey
	Timestamp        *uint64        `json:",omitempty"` // Timestamp or current time if nil
	PulseIfUnchanged *bool          `json:",omitempty"` // If true create a pulse if value matches previous record
}

// MakePulse requests server-side generation of a pulse.
type MakePulse struct {
	Selectors                    []MakeSelector `json:",omitempty"` // Selectors for record to pulse
	OwnerPrivate                 Blob           `json:",omitempty"` // Full owner with private key in DER or PEM format
	MaskingKey                   Blob           `json:",omitempty"` // Masking key if specified (default: first selector, then owner)
	Passphrase                   string         `json:",omitempty"` // Passphrase to override OwnerPrivate and (if empty) MaskingKey
	Timestamp                    *uint64        `json:",omitempty"` // Timestamp or current time if nil
	NewRecordIfPulseSpanExceeded *bool          `json:",omitempty"` // If true (or missing), create new record if pulse is later than max pulse span
}

func (m *MakeRecord) execute(n *Node) (*Record, Pulse, bool, error) {
	pulseIfUnchanged := m.PulseIfUnchanged != nil && *m.PulseIfUnchanged // default: false
	owner, selectorNames, selectorOrdinals, maskingKey, recTS, recDoff, recDlen, err := doMakeRequestSetup(n, m.Selectors, m.Passphrase, m.OwnerPrivate, m.MaskingKey, pulseIfUnchanged)
	if err != nil {
		return nil, nil, false, err
	}
	var ts uint64
	if m.Timestamp == nil {
		ts = TimeSec()
	} else {
		ts = *m.Timestamp
	}

	if recDlen > 0 {
		oldb, err := n.db.getDataByOffset(recDoff, recDlen, nil)
		if err == nil {
			old, err := NewRecordFromBytes(oldb)
			if old != nil && err == nil {
				oldv, err := old.GetValue(maskingKey)
				if err == nil && bytes.Equal(oldv, m.Value) {
					if pulseIfUnchanged {
						minutes := uint((ts - recTS) / 60)
						if minutes > 0 && minutes < RecordMaxPulseSpan {
							pulse, err := NewPulse(owner, selectorNames, selectorOrdinals, recTS, minutes)
							if err != nil {
								return nil, nil, false, err
							}
							ok, _ := n.DoPulse(pulse, true)
							return nil, pulse, ok, nil
						}
					}
					return old, nil, false, nil
				}
			}
		}
	}

	wg, err := n.recordWorkFunc(owner.Public)
	if err != nil {
		return nil, nil, false, err
	}

	l, _ := n.db.getLinks2(n.genesisParameters.RecordMinLinks)
	if uint(len(l)) < n.genesisParameters.RecordMinLinks {
		return nil, nil, false, ErrRecordInsufficientLinks
	}

	rec, err := NewRecord(RecordTypeDatum, m.Value, l, maskingKey, selectorNames, selectorOrdinals, ts, wg, owner)
	if err != nil {
		return nil, nil, false, err
	}

	err = n.AddRecord(rec)
	if err == nil {
		return rec, nil, true, nil
	}
	return nil, nil, false, err
}

func (m *MakePulse) execute(n *Node) (Pulse, *Record, bool, error) {
	newRecordIfPulseSpanExceeded := m.NewRecordIfPulseSpanExceeded == nil || *m.NewRecordIfPulseSpanExceeded // default: true
	owner, selectorNames, selectorOrdinals, maskingKey, recTS, recDoff, recDlen, err := doMakeRequestSetup(n, m.Selectors, m.Passphrase, m.OwnerPrivate, m.MaskingKey, newRecordIfPulseSpanExceeded)
	if err != nil {
		return nil, nil, false, err
	}
	var ts uint64
	if m.Timestamp == nil {
		ts = TimeSec()
	} else {
		ts = *m.Timestamp
	}

	if recTS == 0 {
		return nil, nil, false, ErrRecordNotFound
	} else if recTS > ts {
		return nil, nil, false, ErrRecordIsNewer
	}
	minutes := uint((ts - recTS) / 60)
	if minutes == 0 {
		return nil, nil, false, nil
	}
	if minutes > RecordMaxPulseSpan {
		if newRecordIfPulseSpanExceeded {
			oldb, err := n.db.getDataByOffset(recDoff, recDlen, nil)
			if err != nil {
				return nil, nil, false, err
			}
			old, err := NewRecordFromBytes(oldb)
			if err != nil {
				return nil, nil, false, err
			}
			wg, err := n.recordWorkFunc(owner.Public)
			if err != nil {
				return nil, nil, false, err
			}
			oldv, err := old.GetValue(maskingKey)
			if err != nil {
				return nil, nil, false, err
			}
			l, _ := n.db.getLinks2(n.genesisParameters.RecordMinLinks)
			if uint(len(l)) < n.genesisParameters.RecordMinLinks {
				return nil, nil, false, ErrRecordInsufficientLinks
			}
			rec, err := NewRecord(old.Type, oldv, nil, maskingKey, selectorNames, selectorOrdinals, ts, wg, owner)
			if err != nil {
				return nil, nil, false, err
			}
			err = n.AddRecord(rec)
			if err == nil {
				return nil, rec, true, nil
			}
			return nil, nil, false, err
		}
		return nil, nil, false, ErrPulseSpanExceeded
	}

	pulse, err := NewPulse(owner, selectorNames, selectorOrdinals, recTS, minutes)
	if err != nil {
		return nil, nil, false, err
	}
	ok, _ := n.DoPulse(pulse, true)
	return pulse, nil, ok, nil
}
