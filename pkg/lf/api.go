/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// APIVersion is the version of the current implementation
const APIVersion = 1

var apiVersionStr = strconv.FormatInt(int64(APIVersion), 10)

// APIStatusPeer contains information about a connected peer.
type APIStatusPeer struct {
	RemoteAddress string
	Inbound       bool
}

// APIStatus contains status information about this node and the network it belongs to.
type APIStatus struct {
	Software      string          // Software implementation name
	Version       [4]int          // Version of software
	MinAPIVersion int             // Minimum API version supported
	MaxAPIVersion int             // Maximum API version supported
	Uptime        uint64          // Uptime in milliseconds since epoch
	DBRecordCount uint64          // Number of records in database
	DBSize        uint64          // Total size of records in database in bytes
	Peers         []APIStatusPeer // Connected peers
}

// APIQuerySelector specifies a selector range.
type APIQuerySelector struct {
	Selector []byte   `json:",omitempty"` // Single selector (functionally the same as range {Selector,Selector})
	Range    [][]byte `json:",omitempty"` // Selector range (must be either nil/empty or size [2])
	Or       bool     ``                  // OR previous selector? AND if false. (ignored for first selector)
}

// APIQuery describes a query for records.
type APIQuery struct {
	Selectors    []APIQuerySelector ``                  // Selectors or selector range(s)
	PlainTextKey []byte             `json:",omitempty"` // Plain-text key for first selector to have server decrypt value automatically
}

// APIError indicates an error and is returned with non-200 responses.
type APIError struct {
	Code    int    // Positive error codes simply mirror HTTP response codes, while negative ones are LF-specific
	Message string // Message indicating the reason for the error
}

func apiSetStandardHeaders(out http.ResponseWriter) {
	h := out.Header()
	h.Set("Pragma", "no-cache")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-LF-LocalTime", strconv.FormatUint(TimeMs(), 10))
	h.Set("X-LF-Version", VersionStr)
	h.Set("X-LF-APIVersion", apiVersionStr)
}

func apiSendObj(out http.ResponseWriter, req *http.Request, httpStatusCode int, obj interface{}) error {
	out.Header().Set("Content-Type", "application/json")
	out.WriteHeader(httpStatusCode)
	if req.Method == http.MethodHead {
		var cr CountingWriter
		err := json.NewEncoder(&cr).Encode(obj)
		if err != nil {
			return err
		}
		out.Header().Set("Content-Length", strconv.FormatUint(uint64(cr), 10))
		return nil
	}
	return json.NewEncoder(out).Encode(obj)
}

func apiReadObj(out http.ResponseWriter, req *http.Request, dest interface{}) (err error) {
	err = json.NewDecoder(req.Body).Decode(&dest)
	if err != nil {
		apiSendObj(out, req, http.StatusBadRequest, &APIError{Code: http.StatusBadRequest, Message: "invalid or malformed payload"})
	}
	return
}

func apiIsTrusted(n *Node, req *http.Request) bool {
	// TODO
	return true
}

func apiCreateHTTPServeMux(n *Node) *http.ServeMux {
	smux := http.NewServeMux()

	// Query for records matching one or more selectors or ranges of selectors.
	smux.HandleFunc("/query", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
		} else {
			apiSendObj(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	// Post a record, takes APIPut payload or just a raw record in binary form.
	smux.HandleFunc("/post", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
		} else {
			apiSendObj(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	// Get links for incorporation into a new record, returns up to 31 raw binary hashes. A ?count= parameter can be added to specify how many are desired.
	smux.HandleFunc("/links", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodGet || req.Method == http.MethodHead {
			desired := uint(RecordDesiredLinks)
			desiredStr := req.URL.Query().Get("count")
			if len(desiredStr) > 0 {
				tmp, _ := strconv.ParseUint(desiredStr, 10, 64)
				if tmp > 0 && tmp < uint64(RecordDesiredLinks) {
					desired = uint(tmp)
				}
			}
			_, links, _ := n.db.getLinks(desired)
			out.Header().Set("Content-Type", "application/octet-stream")
			out.Header().Set("Content-Length", strconv.FormatUint(uint64(len(links)), 10))
			out.WriteHeader(http.StatusOK)
			out.Write(links)
		} else {
			apiSendObj(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/status", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		rc, ds := n.db.stats()
		apiSendObj(out, req, http.StatusOK, &APIStatus{
			Software:      SoftwareName,
			Version:       Version,
			MinAPIVersion: APIVersion,
			MaxAPIVersion: APIVersion,
			Uptime:        n.startTime,
			DBRecordCount: rc,
			DBSize:        ds,
			Peers:         n.Peers(),
		})
	})

	smux.HandleFunc("/", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodGet || req.Method == http.MethodHead {
			if req.URL.Path == "/" {
			} else {
				apiSendObj(out, req, http.StatusNotFound, &APIError{Code: http.StatusNotFound, Message: req.URL.Path + " is not a valid path"})
			}
		} else {
			apiSendObj(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	return smux
}
