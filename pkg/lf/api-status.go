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
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

// APIStatusResult contains status information about this node and the network it belongs to.
type APIStatusResult struct {
	Software            string            `json:",omitempty"` // Software implementation name
	Version             [4]int            ``                  // Version of software
	APIVersion          int               ``                  // Current version of API
	MinAPIVersion       int               ``                  // Minimum API version supported
	MaxAPIVersion       int               ``                  // Maximum API version supported
	Uptime              uint64            ``                  // Node uptime in seconds
	Clock               uint64            ``                  // Node local clock in seconds since epoch
	DBRecordCount       uint64            ``                  // Number of records in database
	DBSize              uint64            ``                  // Total size of records in database in bytes
	DBFullySynchronized bool              ``                  // True if there are no dangling links (excluding abandoned ones)
	PeerCount           int               ``                  // Number of connected peers
	GenesisParameters   GenesisParameters ``                  // Network parameters
	NodeWorkAuthorized  bool              ``                  // True if full node will do work for querying user/proxy
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
