/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
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
	S         []byte ``                  // First selector in selector range (or single value for equality)
	E         []byte `json:",omitempty"` // Second selector in selector range or empty/nil for simple equality instead of range query
	Or        *bool  `json:",omitempty"` // OR previous selector? AND if false. (ignored for first selector)
	PlainText *bool  `json:",omitempty"` // If true these are plain text selectors and need to be converted to masked selectors before query
}

// APIQuery describes a query for records.
// It results in an array of APIQueryResult objects sorted in descending order of weight.
type APIQuery struct {
	Selectors             []APIQuerySelector ``                  // Selectors or selector range(s)
	Owners                [][]byte           `json:",omitempty"` // Owners to match in query
	PlainTextKey          []byte             `json:",omitempty"` // Plain-text key for first selector to have server or proxy decrypt masked value automatically
	IncludeSuspectRecords *bool              `json:",omitempty"` // If true, ignore reputation and trusted commentary and include suspicious records
}

// APIQueryResult is a single query result.
type APIQueryResult struct {
	Record  Record // Record itself.
	Weight  string // Record weight as a 128-bit hex value.
	Value   []byte // Record value if record is unmasked or if PlainTextKey was included in query for automatic unmasking.
	Suspect bool   // If true, this result is for some reason suspicious (e.g. low local reputation)
}

// APINew instructs this server (or proxy) to create a new record locally and submit it.
// Full nodes will only do this if it's requested by authorized IPs. Normally this is done via a proxy
// and also because typically you don't want to share your owner private key with some random node.
type APINew struct {
	PlainTextSelectors [][]byte ``                  // Array of plain text selector keys
	OwnerPrivateKey    []byte   ``                  // X.509 encoded private key with included public key
	Links              [][]byte ``                  // Links to other records in the DAG (each link must be 32 bytes in size)
	Value              []byte   ``                  // Plain text value for this record
	MaskValue          *bool    `json:",omitempty"` // If true, encrypt value using plain text key of first selector (privacy mask value)
	Timestamp          *uint64  `json:",omitempty"` // Record timestamp (server time is used if zero or omitted)
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
	return NewRecord(m.Value, m.Links, m.PlainTextSelectors, ((m.MaskValue != nil) && (*m.MaskValue == true)), kpub, ts, RecordWorkAlgorithmWharrgarbl, k)
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
		var cr CountingWriter
		err := json.NewEncoder(&cr).Encode(obj)
		if err != nil {
			return err
		}
		h.Set("Content-Length", strconv.FormatUint(uint64(cr), 10))
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
