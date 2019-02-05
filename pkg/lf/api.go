/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

// APIVersion is the version of the current implementation
const APIVersion = 1

// APIMaxResponseSize is a sanity limit on the maximum size of a response from the LF HTTP API (can be increased)
const APIMaxResponseSize = 4194304

var apiVersionStr = strconv.FormatInt(int64(APIVersion), 10)

// APIStatusPeer contains information about a connected peer.
type APIStatusPeer struct {
	RemoteAddress string
	Inbound       bool
}

// APIProxyStatus contains info about the proxy through which this server was reached.
type APIProxyStatus struct {
	Server        string // URL of server being accessed through the proxy
	Software      string // Software implementation name of proxy
	Version       [4]int // Software version of proxy
	MinAPIVersion int    // Minimum supported API version of proxy
	MaxAPIVersion int    // Maximum supported API version of proxy
}

// APIStatus contains status information about this node and the network it belongs to.
type APIStatus struct {
	Software      string          ``                  // Software implementation name
	Version       [4]int          ``                  // Version of software
	MinAPIVersion int             ``                  // Minimum API version supported
	MaxAPIVersion int             ``                  // Maximum API version supported
	Uptime        uint64          ``                  // Node uptime in milliseconds since epoch
	Clock         uint64          ``                  // Node local clock in milliseconds since epoch
	DBRecordCount uint64          ``                  // Number of records in database
	DBSize        uint64          ``                  // Total size of records in database in bytes
	Peers         []APIStatusPeer ``                  // Connected peers
	ProxyStatus   *APIProxyStatus `json:",omitempty"` // Proxies can add this to describe their own config and status while still reporting that of the server
}

// APIQuerySelector specifies a selector or selector range.
type APIQuerySelector struct {
	Name  []byte   `json:",omitempty"` // Name of selector (plain text)
	Range []uint64 `json:",omitempty"` // Ordinal value if [1] or range if [2] in size (assumed to be 0 if empty)
	Or    *bool    `json:",omitempty"` // Or previous selector? AND if false. (ignored for first selector)
}

// APIQuery describes a query for records.
// It results in an array of APIQueryResult objects sorted in descending order of weight.
type APIQuery struct {
	Selectors []APIQuerySelector `` // Selectors or selector range(s)
}

// APIQueryResult is a single query result.
type APIQueryResult struct {
	Record Record // Record itself.
	Weight string // Record weight as a 128-bit hex value.
	Value  []byte // Record value if record could be unmasked.
}

// APINewSelector is a selector plain text name and an ordinal value (use zero if you don't care).
type APINewSelector struct {
	Name    []byte
	Ordinal uint64
}

// APINew instructs this server (or proxy) to create a new record locally and submit it.
// Full nodes will only do this if it's requested by authorized IPs. Normally this is done via a proxy
// and also because typically you don't want to share your owner private key with some random node.
type APINew struct {
	Selectors       []APINewSelector ``                  // Plain text selector names and ordinals
	OwnerPrivateKey []byte           ``                  // X.509 encoded private key with included public key
	Links           [][]byte         ``                  // Links to other records in the DAG (each link must be 32 bytes in size)
	Value           []byte           ``                  // Plain text value for this record
	Timestamp       *uint64          `json:",omitempty"` // Record timestamp (server time is used if zero or omitted)
}

// APIError indicates an error and is returned with non-200 responses.
type APIError struct {
	Code    int    // Positive error codes simply mirror HTTP response codes, while negative ones are LF-specific
	Message string // Message indicating the reason for the error
}

// Error implements the error interface.
func (e APIError) Error() string {
	return fmt.Sprintf("%d (%s)", e.Code, e.Message)
}

func apiRun(url string, m interface{}) ([]byte, error) {
	aq, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(aq))
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(&io.LimitedReader{R: resp.Body, N: int64(APIMaxResponseSize)})
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		var e APIError
		if err := json.Unmarshal(body, &e); err != nil {
			return nil, err
		}
		return nil, e
	}

	return body, nil
}

// Run executes this API query against a remote LF node or proxy
func (m *APIQuery) Run(url string) (*APIQueryResult, error) {
	body, err := apiRun(url, m)
	if err != nil {
		return nil, err
	}
	var qr APIQueryResult
	if err := json.Unmarshal(body, &qr); err != nil {
		return nil, err
	}
	return &qr, nil
}

func (m *APIQuery) execute(n *Node) (qr []APIQueryResult, err error) {
	var selectorRanges [][2][]byte
	var andOr []bool

	for i := 0; i < len(m.Selectors); i++ {
		if len(m.Selectors[i].Range) == 0 {
			ss := SelectorKey(m.Selectors[i].Name, 0)
			selectorRanges = append(selectorRanges, [2][]byte{ss[:], ss[:]})
		} else if len(m.Selectors[i].Range) == 1 {
			ss := SelectorKey(m.Selectors[i].Name, m.Selectors[i].Range[0])
			selectorRanges = append(selectorRanges, [2][]byte{ss[:], ss[:]})
		} else {
			ss := SelectorKey(m.Selectors[i].Name, m.Selectors[i].Range[0])
			ee := SelectorKey(m.Selectors[i].Name, m.Selectors[i].Range[1])
			selectorRanges = append(selectorRanges, [2][]byte{ss[:], ee[:]})
		}
		andOr = append(andOr, m.Selectors[i].Or != nil && *m.Selectors[i].Or)
	}

	bestByID := make(map[[32]byte]*[5]uint64)
	n.db.query(selectorRanges, andOr, func(ts, weightL, weightH, doff, dlen uint64, id *[32]byte, owner []byte) bool {
		rptr := bestByID[*id]
		if rptr == nil {
			bestByID[*id] = &([5]uint64{weightH, weightL, ts, doff, dlen})
		} else {
			if rptr[0] < weightH {
				return true
			} else if rptr[0] == weightH {
				if rptr[1] < weightL {
					return true
				} else if rptr[1] == weightL {
					if rptr[2] <= ts {
						return true
					}
				}
			}
			rptr[0] = weightH
			rptr[1] = weightL
			rptr[2] = ts
			rptr[3] = doff
			rptr[4] = dlen
		}
		return true
	})

	return
}

// Run executes this API query against a remote LF node or proxy
func (m *APINew) Run(url string) (*Record, error) {
	body, err := apiRun(url, m)
	if err != nil {
		return nil, err
	}
	var rec Record
	if err := json.Unmarshal(body, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// CreateRecord creates a record using the parameters in this APINew message object.
// This can be very time and memory intensive due to proof of work requirements. This is used inside
// the node and proxy HTTP handlers but is exposed in case there is a reason to use it locally.
func (m *APINew) CreateRecord() (*Record, error) {
	k, err := x509.ParseECPrivateKey(m.OwnerPrivateKey)
	if err != nil {
		return nil, err
	}
	kpub, err := GetOwnerPublicKey(k)
	if err != nil {
		return nil, err
	}
	var ts uint64
	if m.Timestamp == nil || *m.Timestamp == 0 {
		ts = TimeMs()
	} else {
		ts = *m.Timestamp
	}
	sel := make([][]byte, len(m.Selectors))
	selord := make([]uint64, len(m.Selectors))
	for i := range m.Selectors {
		sel[i] = m.Selectors[i].Name
		selord[i] = m.Selectors[i].Ordinal
	}
	return NewRecord(m.Value, m.Links, sel, selord, kpub, ts, RecordWorkAlgorithmWharrgarbl, k)
}

func apiSetStandardHeaders(out http.ResponseWriter) {
	h := out.Header()
	now := time.Now()
	h.Set("Cache-Control", "no-cache")
	h.Set("Pragma", "no-cache")
	h.Set("Date", now.String())
	h.Set("X-LF-TimeMs", strconv.FormatUint(uint64(now.UnixNano())/uint64(1000000), 10))
	h.Set("X-LF-Version", VersionStr)
	h.Set("X-LF-APIVersion", apiVersionStr)
	h.Set("Server", SoftwareName)
}

func apiSendObj(out http.ResponseWriter, req *http.Request, httpStatusCode int, obj interface{}) error {
	h := out.Header()
	h.Set("Content-Type", "application/json")
	if req.Method == http.MethodHead {
		out.WriteHeader(httpStatusCode)
		return nil
	}
	j, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	h.Set("Content-Length", strconv.FormatUint(uint64(len(j)), 10))
	out.WriteHeader(httpStatusCode)
	_, err = out.Write(j)
	return err
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
	// Even though this is a "getter" it must be POSTed since it's a JSON object and not a simple path.
	smux.HandleFunc("/query", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
			var m APIQuery
			if apiReadObj(out, req, &m) == nil {
			}
		} else {
			out.Header().Set("Allow", "POST, PUT")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	// Add a record, takes APINew payload.
	smux.HandleFunc("/new", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
			if apiIsTrusted(n, req) {
				var m APINew
				if apiReadObj(out, req, &m) == nil {
					rec, err := m.CreateRecord()
					if err != nil {
						apiSendObj(out, req, http.StatusBadRequest, &APIError{Code: http.StatusForbidden, Message: "record creation failed: " + err.Error()})
					} else {
						err = n.AddRecord(rec)
						if err != nil {
							apiSendObj(out, req, http.StatusBadRequest, &APIError{Code: http.StatusForbidden, Message: "record rejected or record import failed: " + err.Error()})
						} else {
							apiSendObj(out, req, http.StatusOK, rec)
						}
					}
				}
			} else {
				apiSendObj(out, req, http.StatusForbidden, &APIError{Code: http.StatusForbidden, Message: "full record creation only allowed from authorized clients"})
			}
		} else {
			out.Header().Set("Allow", "POST, PUT")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	// Add a record in raw binary form (not JSON), returns parsed record as JSON on success.
	smux.HandleFunc("/post", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
			var rec Record
			err := rec.UnmarshalFrom(req.Body)
			if err != nil {
				apiSendObj(out, req, http.StatusBadRequest, &APIError{Code: http.StatusForbidden, Message: "record deserialization failed: " + err.Error()})
			} else {
				err = n.AddRecord(&rec)
				if err != nil {
					apiSendObj(out, req, http.StatusBadRequest, &APIError{Code: http.StatusForbidden, Message: "record rejected or record import failed: " + err.Error()})
				} else {
					apiSendObj(out, req, http.StatusOK, rec)
				}
			}
		} else {
			out.Header().Set("Allow", "POST, PUT")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	// Get links for incorporation into a new record, returns up to 31 raw binary hashes. A ?count= parameter can be added to specify how many are desired.
	smux.HandleFunc("/links", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodGet || req.Method == http.MethodHead {
			desired := uint(3)
			desiredStr := req.URL.Query().Get("count")
			if len(desiredStr) > 0 {
				tmp, _ := strconv.ParseUint(desiredStr, 10, 64)
				if tmp > 0 {
					desired = uint(tmp)
				}
			}
			_, links, _ := n.db.getLinks(desired)
			out.Header().Set("Content-Type", "application/octet-stream")
			out.Header().Set("Content-Length", strconv.FormatUint(uint64(len(links)), 10))
			out.WriteHeader(http.StatusOK)
			out.Write(links)
		} else {
			out.Header().Set("Allow", "GET, HEAD")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/status", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodGet || req.Method == http.MethodHead {
			rc, ds := n.db.stats()
			now := TimeMs()
			apiSendObj(out, req, http.StatusOK, &APIStatus{
				Software:      SoftwareName,
				Version:       Version,
				MinAPIVersion: APIVersion,
				MaxAPIVersion: APIVersion,
				Uptime:        (now - n.startTime),
				Clock:         now,
				DBRecordCount: rc,
				DBSize:        ds,
				Peers:         n.Peers(),
			})
		} else {
			out.Header().Set("Allow", "GET, HEAD")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodGet || req.Method == http.MethodHead {
			if req.URL.Path == "/" {
			} else {
				apiSendObj(out, req, http.StatusNotFound, &APIError{Code: http.StatusNotFound, Message: req.URL.Path + " is not a valid path"})
			}
		} else {
			out.Header().Set("Allow", "GET, HEAD")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	return smux
}
