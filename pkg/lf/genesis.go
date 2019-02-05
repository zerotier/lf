/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

// Genesis is the payload (JSON encoded) of the first RecordMinLinks records in a global data store.
type Genesis struct {
	RecordMinLinks     uint     ``                  // Minimum number of links required for non-genesis records
	RecordMaxValueSize uint     ``                  // Maximum size of record values
	CAs                [][]byte `json:",omitempty"` // X.509 certificates for master CAs for this data store (empty for an unbiased work-only data store)
}
