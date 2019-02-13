/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"sort"
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
	RemoteAddress string // IP and port
	PublicKey     []byte // public key
	Inbound       bool   // true if this is an inbound connection
}

// APIProxyStatus contains info about the proxy through which this server was reached (if an LF proxy is present).
type APIProxyStatus struct {
	Server        string // URL of server being accessed through the proxy
	Software      string // Software implementation name of proxy
	Version       [4]int // Software version of proxy
	MinAPIVersion int    // Minimum supported API version of proxy
	MaxAPIVersion int    // Maximum supported API version of proxy
}

// APIStatus contains status information about this node and the network it belongs to.
type APIStatus struct {
	Software      string          // Software implementation name
	Version       [4]int          // Version of software
	MinAPIVersion int             // Minimum API version supported
	MaxAPIVersion int             // Maximum API version supported
	Uptime        uint64          // Node uptime in seconds
	Clock         uint64          // Node local clock in seconds since epoch
	DBRecordCount uint64          // Number of records in database
	DBSize        uint64          // Total size of records in database in bytes
	Peers         []APIStatusPeer // Connected peers
	Genesis       Genesis         // Genesis record contents that define constraints for this LF network
	ProxyStatus   *APIProxyStatus // Proxies can add this to describe their own config and status while still reporting that of the server
}

// APIQueryRange specifies a selector or selector range.
// Selector ranges can be specified in one of two ways. If KeyRange is non-empty it contains a single
// masked selector key or a range of keys. If KeyRange is empty then Name contains the plain text name
// of the selector and Range contains its ordinal range and the server will compute selector keys. The
// KeyRange method keeps selector names secret while the Name/Range method exposes them to the node or
// proxy being queried.
type APIQueryRange struct {
	Name     []byte   `json:",omitempty"` // Name of selector (plain text)
	Range    []uint64 `json:",omitempty"` // Ordinal value if [1] or range if [2] in size (assumed to be 0 if empty)
	KeyRange [][]byte `json:",omitempty"` // Selector key or key range, overrides Name and Range if present (allows queries without revealing name)
}

// APIQuery describes a query for records in the form of an ordered series of selector ranges.
type APIQuery struct {
	Range      []APIQueryRange ``                  // Selectors or selector range(s)
	MaskingKey []byte          `json:",omitempty"` // Masking key to unmask record value server-side (if non-empty)
}

// APIQueryResult is a single query result.
type APIQueryResult struct {
	Record *Record ``                  // Record itself.
	Value  []byte  `json:",omitempty"` // Unmasked value if masking key was included
	Weight string  ``                  // Record weight as a 128-bit hex value
}

// APIQueryResults is a list of results to an API query.
// Each record will be the best (as determined by weight and possibly trust relationships) for each combination
// of record selectors. If there are more than one it's the application's responsibility to decide which are
// relevant or trustworthy.
type APIQueryResults []APIQueryResult

// APINewSelector is a selector plain text name and an ordinal value (use zero if you don't care).
// This is used as part of the APINew API request.
type APINewSelector struct {
	Name    []byte // Name of this selector
	Ordinal uint64 // A sortable value (use 0 if you don't want to do range queries)
}

// APINew is a request to create and submit a new record.
// Nodes only allow authorized clients to do this for obvious CPU constraint reasons (proof of work).
// Usually this is executed by a proxy, a thin LF agent that sits between a client and a full node.
// Proxies are often run on the same system or within the same enclave (Amazon VPC, K8S cluster, etc.)
// as LF users. Note that this API call implicitly shares your private key so it should not be made
// against nodes or proxies that you don't control or trust or over unencrypted transport.
type APINew struct {
	Selectors       []APINewSelector ``                  // Plain text selector names and ordinals
	MaskingKey      []byte           `json:",omitempty"` // An arbitrary key used to mask the record's value from those that don't know what they're looking for
	OwnerPrivateKey []byte           ``                  // Full owner including private key (result of owner PrivateBytes() method)
	Links           [][]byte         ``                  // Links to other records in the DAG (each link must be 32 bytes in size)
	Value           []byte           ``                  // Plain text (unmasked, uncompressed) value for this record
	Timestamp       *uint64          `json:",omitempty"` // Record timestamp in SECONDS since epoch (server time is used if zero or omitted)
}

// APIError indicates an error and is returned with non-200 responses.
type APIError struct {
	Code    int    // Positive error codes simply mirror HTTP response codes, while negative ones are LF-specific
	Message string // Message indicating the reason for the error
}

// Error implements the error interface, making APIError an 'error' in the Go sense.
func (e APIError) Error() string { return fmt.Sprintf("%d (%s)", e.Code, e.Message) }

// apiRun contains common code for the Run() methods of API request objects.
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

//////////////////////////////////////////////////////////////////////////////

// Run executes this API query against a remote LF node or proxy
func (m *APIQuery) Run(url string) (*APIQueryResult, error) {
	body, err := apiRun(url, m.Range)
	if err != nil {
		return nil, err
	}
	var qr APIQueryResult
	if err := json.Unmarshal(body, &qr); err != nil {
		return nil, err
	}
	return &qr, nil
}

func (m *APIQuery) execute(n *Node) (qr []APIQueryResult, err *APIError) {
	mm := m.Range
	if len(mm) == 0 {
		return nil, &APIError{http.StatusBadRequest, "a query requires at least one selector"}
	}
	var selectorRanges [][2][]byte
	for i := 0; i < len(mm); i++ {
		if len(mm[i].KeyRange) == 0 {
			// If KeyRange is not used the selectors' names are specified in the clear and we generate keys locally.
			if len(mm[i].Range) == 0 {
				ss := MakeSelectorKey(mm[i].Name, 0)
				selectorRanges = append(selectorRanges, [2][]byte{ss[:], ss[:]})
			} else if len(mm[i].Range) == 1 {
				ss := MakeSelectorKey(mm[i].Name, mm[i].Range[0])
				selectorRanges = append(selectorRanges, [2][]byte{ss[:], ss[:]})
			} else {
				ss := MakeSelectorKey(mm[i].Name, mm[i].Range[0])
				ee := MakeSelectorKey(mm[i].Name, mm[i].Range[1])
				selectorRanges = append(selectorRanges, [2][]byte{ss[:], ee[:]})
			}
		} else {
			// Otherwise we use the sender-supplied key range which keeps names secret.
			if len(mm[i].KeyRange) == 1 {
				selectorRanges = append(selectorRanges, [2][]byte{mm[i].KeyRange[0], mm[i].KeyRange[0]})
			} else {
				selectorRanges = append(selectorRanges, [2][]byte{mm[i].KeyRange[0], mm[i].KeyRange[1]})
			}
		}
	}

	// Iterate through results and store them in a temporary map by ID (hash of selector keys). This
	// lets us find the highest weighted record for each combination of selectors without wasting the
	// time to grab whole records that we don't ultimately return. Note that the C side of this code
	// handles finding the latest record (max timestamp) by owner/ID combo.
	bestByID := make(map[[32]byte]*[4]uint64)
	n.db.query(selectorRanges, func(ts, weightL, weightH, doff, dlen uint64, id *[32]byte, owner []byte) bool {
		rptr := bestByID[*id]
		if rptr == nil {
			bestByID[*id] = &([4]uint64{weightH, weightL, doff, dlen})
		} else {
			if rptr[0] < weightH {
				return true
			} else if rptr[0] == weightH {
				if rptr[1] < weightL {
					return true
				}
			}
			rptr[0] = weightH
			rptr[1] = weightL
			rptr[2] = doff
			rptr[3] = dlen
		}
		return true
	})

	// Actually grab the records and populate the qr[] slice.
	for _, rptr := range bestByID {
		rdata, err := n.db.getDataByOffset(rptr[2], uint(rptr[3]), nil)
		if err != nil {
			return nil, &APIError{http.StatusInternalServerError, "error retrieving record data: " + err.Error()}
		}
		rec, err := NewRecordFromBytes(rdata)
		if err != nil {
			return nil, &APIError{http.StatusInternalServerError, "error retrieving record data: " + err.Error()}
		}
		var v []byte
		if len(m.MaskingKey) > 0 {
			v, err = rec.GetValue(m.MaskingKey)
		}
		if err == nil { // skip records with wrong masking key or invalid compressed data
			qr = append(qr, APIQueryResult{
				Record: rec,
				Value:  v,
				Weight: fmt.Sprintf("%.16x%.16x", rptr[0], rptr[1]),
			})
		}
	}

	// Sort qr[] by selector ordinals.
	sort.Slice(qr, func(a, b int) bool {
		sa := qr[a].Record.Selectors
		sb := qr[b].Record.Selectors
		if len(sa) < len(sb) {
			return true
		}
		if len(sa) > len(sb) {
			return false
		}
		for i := 0; i < len(sa); i++ {
			if sa[i].Ordinal < sb[i].Ordinal {
				return true
			} else if sa[i].Ordinal > sb[i].Ordinal {
				return false
			}
		}
		return false
	})

	return
}

//////////////////////////////////////////////////////////////////////////////

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

func (m *APINew) execute(workAlgorithm byte) (*Record, *APIError) {
	owner, err := NewOwnerFromPrivateBytes(m.OwnerPrivateKey)
	if err != nil {
		return nil, &APIError{Code: http.StatusBadRequest, Message: "cannot derive owner format public key from x509 private key: " + err.Error()}
	}

	var ts uint64
	if m.Timestamp == nil || *m.Timestamp == 0 {
		ts = TimeSec()
	} else {
		ts = *m.Timestamp
	}

	sel := make([][]byte, len(m.Selectors))
	selord := make([]uint64, len(m.Selectors))
	for i := range m.Selectors {
		sel[i] = m.Selectors[i].Name
		selord[i] = m.Selectors[i].Ordinal
	}

	rec, err := NewRecord(m.Value, m.Links, m.MaskingKey, sel, selord, nil, ts, workAlgorithm, owner)
	if err != nil {
		return nil, &APIError{Code: http.StatusBadRequest, Message: "record generation failed: " + err.Error()}
	}
	return rec, nil
}

//////////////////////////////////////////////////////////////////////////////

func apiSetStandardHeaders(out http.ResponseWriter) {
	h := out.Header()
	now := time.Now()
	h.Set("Cache-Control", "no-cache")
	h.Set("Pragma", "no-cache")
	h.Set("Date", now.String())
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
				results, err := m.execute(n)
				if err != nil {
					apiSendObj(out, req, err.Code, err)
				} else if len(results) == 0 {
					apiSendObj(out, req, http.StatusNotFound, &APIError{Code: http.StatusNotFound, Message: "no results found"})
				} else {
					apiSendObj(out, req, http.StatusOK, results)
				}
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
					// Pick the most preferred least banned work algorithm.
					workAlgorithm := RecordWorkAlgorithmNone
					for _, a := range recordWorkAlgorithmPreferenceOrder {
						var banned bool
						for _, b := range n.genesisConfig.BannedWorkAlgorithms {
							if a == byte(b) {
								banned = true
								break
							}
						}
						if !banned {
							workAlgorithm = a
							break
						}
					}

					rec, apiError := m.execute(workAlgorithm)
					if apiError != nil {
						apiSendObj(out, req, apiError.Code, apiError)
					} else {
						err := n.AddRecord(rec)
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
			now := TimeSec()
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
				Genesis:       n.genesisConfig,
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
