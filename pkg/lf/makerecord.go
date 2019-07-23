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

// MakeSelectorRequest contains a plain text name and ordinal for a new record to be created server-side.
type MakeSelectorRequest struct {
	Name    Blob   `json:",omitempty"`
	Ordinal uint64 ``
}

// MakeRecordRequest requests that the server make and submit a record.
// If Passphrase is supplied it overrides OwnerPrivate and MaskingKey and generates them deterministically.
// Otherwise OwnerPrivate must be an owner's private (and including public) key in DER or PEM format
// (auto-detected). If MaskingKey is empty it defaults to the first selector name. Note that requesting
// remote record creation reveals secrets! Nodes will not remotely create records that require proof
// of work unless the client is authorized to do so as this uses significant local compute resources
// at the node.
type MakeRecordRequest struct {
	Selectors    []MakeSelectorRequest `json:",omitempty"`
	Value        Blob                  `json:",omitempty"`
	OwnerPrivate Blob                  `json:",omitempty"`
	MaskingKey   Blob                  `json:",omitempty"`
	Passphrase   string                `json:",omitempty"`
}

func (m *MakeRecordRequest) execute(n *Node) (*Record, error) {
	var owner *Owner
	var maskingKey []byte
	if len(m.Passphrase) > 0 {
		o, mk := PassphraseToOwnerAndMaskingKey(m.Passphrase)
		if len(m.MaskingKey) == 0 {
			maskingKey = mk
		} else {
			maskingKey = m.MaskingKey
		}
		owner = o
	} else {
		o, err := NewOwnerFromPrivateBytes(m.OwnerPrivate)
		if err != nil {
			return nil, err
		}
		owner = o
	}

	var wg *Wharrgarblr
	if !n.localTest {
		hasCert, err := n.OwnerHasCurrentCertificate(owner.Public)
		if err != nil {
			return nil, err
		}
		if !hasCert {
			if n.genesisParameters.AuthRequired {
				return nil, ErrRecordCertificateRequired
			}
			wg = n.getMakeRecordWorkFunction()
		}
	}

	l, _ := n.db.getLinks2(n.genesisParameters.RecordMinLinks)
	if uint(len(l)) < n.genesisParameters.RecordMinLinks {
		return nil, ErrRecordInsufficientLinks
	}

	var selectorNames [][]byte
	var selectorOrdinals []uint64
	for _, sr := range m.Selectors {
		selectorNames = append(selectorNames, sr.Name)
		selectorOrdinals = append(selectorOrdinals, sr.Ordinal)
	}

	rec, err := NewRecord(RecordTypeDatum, m.Value, l, maskingKey, selectorNames, selectorOrdinals, TimeSec(), wg, owner)
	if err != nil {
		return nil, err
	}

	return rec, n.AddRecord(rec)
}
