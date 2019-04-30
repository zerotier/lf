/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

// APIStatusResult contains status information about this node and the network it belongs to.
type APIStatusResult struct {
	Software           string            `json:",omitempty"` // Software implementation name
	Version            [4]int            ``                  // Version of software
	APIVersion         int               ``                  // Current version of API
	MinAPIVersion      int               ``                  // Minimum API version supported
	MaxAPIVersion      int               ``                  // Maximum API version supported
	Uptime             uint64            ``                  // Node uptime in seconds
	Clock              uint64            ``                  // Node local clock in seconds since epoch
	DBRecordCount      uint64            ``                  // Number of records in database
	DBSize             uint64            ``                  // Total size of records in database in bytes
	PeerCount          int               ``                  // Number of connected peers
	GenesisParameters  GenesisParameters ``                  // Genesis record contents that define settings for this LF network
	NodeWorkAuthorized bool              ``                  // True if full node will do work for querying user/proxy
	ProxyChain         []string          ``                  // Each proxy prepends its next URL hop to this slice
	WorkAuthorized     bool              ``                  // True if full node OR any proxy will do work for you
}

// APIStatusGet gets a status result from a URL.
func APIStatusGet(url string) (*APIStatusResult, error) {
	if strings.HasSuffix(url, "/") {
		url = url + "status"
	} else {
		url = url + "/status"
	}
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(&io.LimitedReader{R: resp.Body, N: 65536})
	if err != nil {
		return nil, err
	}
	var sr APIStatusResult
	if err := json.Unmarshal(body, &sr); err != nil {
		return nil, err
	}
	return &sr, nil
}
