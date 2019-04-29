/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// APIVersion is the version of the current implementation's REST API
const APIVersion = 1

const (
	// APIErrorRecordRejected indicates that a posted record was considered invalid or too suspect to import.
	APIErrorRecordRejected = -1

	// APIErrorLazy indicates that this proxy or full node will not do proof of work for you.
	APIErrorLazy = -2
)

var apiVersionStr = strconv.FormatInt(int64(APIVersion), 10)

// APIMaxResponseSize is a sanity limit on the maximum size of a response from the LF HTTP API (can be increased)
const APIMaxResponseSize = 4194304

// APIMaxLinks is the maximum number of links that will be returned by /links.
const APIMaxLinks = 2048

// APIError (response) indicates an error and is returned with non-200 responses.
type APIError struct {
	Code    int    ``                  // Positive error codes simply mirror HTTP response codes, while negative ones are LF-specific
	Message string `json:",omitempty"` // Message indicating the reason for the error
}

// Error implements the error interface, making APIError an 'error' in the Go sense.
func (e APIError) Error() string {
	if len(e.Message) > 0 {
		return fmt.Sprintf("%d (%s)", e.Code, e.Message)
	}
	return strconv.FormatInt(int64(e.Code), 10)
}

//////////////////////////////////////////////////////////////////////////////

// APIPostRecord submits a raw LF record to a node or proxy.
func APIPostRecord(url string, recordData []byte) error {
	if strings.HasSuffix(url, "/") {
		url = url + "post"
	} else {
		url = url + "/post"
	}
	resp, err := http.Post(url, "application/octet-stream", bytes.NewReader(recordData))
	if err != nil {
		return err
	}
	if resp.StatusCode == 200 {
		return nil
	}
	body, err := ioutil.ReadAll(&io.LimitedReader{R: resp.Body, N: 131072})
	if err != nil {
		return APIError{Code: resp.StatusCode}
	}
	if len(body) > 0 {
		var e APIError
		if err := json.Unmarshal(body, &e); err != nil {
			return APIError{Code: resp.StatusCode, Message: "error response invalid: " + err.Error()}
		}
		return e
	}
	return APIError{Code: resp.StatusCode}
}

// APIGetLinks queries this node for links to use to build a new record.
// Passing 0 or a negative count causes the node to be asked for the default link count.
func APIGetLinks(url string, count int) ([][32]byte, error) {
	if strings.HasSuffix(url, "/") {
		url = url + "links"
	} else {
		url = url + "/links"
	}
	if count > 0 {
		url = url + "?count=" + strconv.FormatUint(uint64(count), 10)
	}
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 200 {
		body, err := ioutil.ReadAll(&io.LimitedReader{R: resp.Body, N: 131072})
		if err != nil {
			return nil, err
		}
		var l [][32]byte
		for i := 0; (i + 32) <= len(body); i += 32 {
			var h [32]byte
			copy(h[:], body[i:i+32])
			l = append(l, h)
		}
		return l, nil
	}
	return nil, APIError{Code: resp.StatusCode}
}

//////////////////////////////////////////////////////////////////////////////

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
			return nil, APIError{Code: resp.StatusCode, Message: "error response invalid: " + err.Error()}
		}
		return nil, e
	}

	return body, nil
}

func apiSetStandardHeaders(out http.ResponseWriter) {
	h := out.Header()
	h.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	h.Set("Expires", "0")
	h.Set("Pragma", "no-cache")
	h.Set("Date", time.Now().UTC().Format(time.RFC1123))
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
	var j []byte
	var err error
	if obj != nil {
		j, err = json.Marshal(obj)
		if err != nil {
			return err
		}
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

// apiCreateHTTPServeMux returns the HTTP ServeMux for LF's Node API
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
					if n.genesisParameters.WorkRequired {
						if n.apiWorkFunction == nil {
							n.apiWorkFunction = NewWharrgarblr(RecordDefaultWharrgarblMemory, 0)
						}
					} else {
						n.apiWorkFunction = nil
					}
					rec, apiError := m.execute(n.apiWorkFunction)
					if apiError != nil {
						apiSendObj(out, req, apiError.Code, apiError)
					} else {
						err := n.AddRecord(rec)
						if err != nil {
							apiSendObj(out, req, http.StatusBadRequest, &APIError{Code: APIErrorRecordRejected, Message: "record rejected or record import failed: " + err.Error()})
						} else {
							apiSendObj(out, req, http.StatusOK, nil)
						}
					}
				}
			} else {
				apiSendObj(out, req, http.StatusForbidden, &APIError{Code: APIErrorLazy, Message: "full record creation only allowed from authorized clients"})
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
				apiSendObj(out, req, http.StatusBadRequest, &APIError{Code: http.StatusBadRequest, Message: "record deserialization failed: " + err.Error()})
			} else {
				err = n.AddRecord(&rec)
				if err != nil {
					apiSendObj(out, req, http.StatusBadRequest, &APIError{Code: APIErrorRecordRejected, Message: "record rejected or record import failed: " + err.Error()})
				} else {
					apiSendObj(out, req, http.StatusOK, rec)
				}
			}
		} else {
			out.Header().Set("Allow", "POST, PUT")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	// Get links for incorporation into a new record, returns up to 2048 raw binary hashes. A ?count= parameter can be added to specify how many are desired.
	smux.HandleFunc("/links", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodGet || req.Method == http.MethodHead {
			desired := n.genesisParameters.RecordMinLinks // default is min links for this LF DAG
			desiredStr := req.URL.Query().Get("count")
			if len(desiredStr) > 0 {
				tmp, _ := strconv.ParseInt(desiredStr, 10, 64)
				if tmp <= 0 {
					tmp = 1
				}
				desired = uint(tmp)
			}
			if desired > 2048 {
				desired = 2048
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
			wa := apiIsTrusted(n, req)
			apiSendObj(out, req, http.StatusOK, &APIStatusResult{
				Software:           SoftwareName,
				Version:            Version,
				APIVersion:         APIVersion,
				MinAPIVersion:      APIVersion,
				MaxAPIVersion:      APIVersion,
				Uptime:             (now - uint64(n.startTime.Unix())),
				Clock:              now,
				DBRecordCount:      rc,
				DBSize:             ds,
				Peers:              n.Peers(),
				GenesisParameters:  n.genesisParameters,
				NodeWorkAuthorized: wa,
				WorkAuthorized:     wa,
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
				now := time.Now()
				rc, ds := n.db.stats()
				req.Header.Set("Content-Type", "text/plain")
				out.WriteHeader(200)
				out.Write([]byte(`------------------------------------------------------------------------------
LF Global Key/Value Store ` + VersionStr + `
(c)2018-2019 ZeroTier, Inc.  https://www.zerotier.com/
MIT License
------------------------------------------------------------------------------

Software:            ` + SoftwareName + `
Version:             ` + VersionStr + `
API Version:         ` + apiVersionStr + `
Uptime:              ` + (now.Sub(n.startTime)).String() + `
Clock:               ` + now.Format(time.RFC1123) + `
Network:             ` + n.genesisParameters.Name + `
Record Count:        ` + strconv.FormatUint(rc, 10) + `
Data Size:           ` + strconv.FormatUint(ds, 10) + `

------------------------------------------------------------------------------
Peer Connections
------------------------------------------------------------------------------

`))
				pl := n.Peers()
				for _, p := range pl {
					inout := "->"
					if p.Inbound {
						inout = "<-"
					}
					out.Write([]byte(fmt.Sprintf("%s %-42s %s\n", inout, p.Address, base64.URLEncoding.EncodeToString(p.PublicKey))))
				}
				out.Write([]byte("\n------------------------------------------------------------------------------\n"))
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
