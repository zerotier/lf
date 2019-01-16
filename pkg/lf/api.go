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
	"strings"

	"github.com/vmihailenco/msgpack"
)

// APIVersion is the version of the current implementation
const APIVersion = 1

var apiVersionStr = strconv.FormatInt(int64(APIVersion), 10)

// APIPeer contains information about a connected peer for APIStatus.
type APIPeer struct {
	ProtoMessagePeer
	TotalBytesSent     uint64 `msgpack:"TBS"` // Total bytes sent to this peer
	TotalBytesReceived uint64 `msgpack:"TBR"` // Total bytes received from this peer
	Latency            int    `msgpack:"L"`   // Latency in millisconds or -1 if not known
}

// APIStatus contains status information about this node and the network it belongs to.
type APIStatus struct {
	Software      string    `msgpack:"S"`    // Software implementation name
	Version       [4]int    `msgpack:"V"`    // Version of software
	MinAPIVersion int       `msgpack:"MiA"`  // Minimum API version supported
	MaxAPIVersion int       `msgpack:"MaA"`  // Maximum API version supported
	Uptime        uint64    `msgpack:"U"`    // Uptime in milliseconds since epoch
	Peers         []APIPeer `msgpack:"P"`    // Connected peer nodes (if revealed by node)
	DBRecordCount uint64    `msgpack:"DBRC"` // Number of records in database
	DBSize        uint64    `msgpack:"DBS"`  // Total size of records in database in bytes
}

// APIQuerySelector specifies a selector range.
type APIQuerySelector struct {
	Selector []byte   `msgpack:"S,omitempty" json:",omitempty"` // Single selector (functionally the same as range {Selector,Selector})
	Range    [][]byte `msgpack:"R,omitempty" json:",omitempty"` // Selector range (must be either nil/empty or size [2])
	Or       bool     `msgpack:"O"`                             // OR previous selector? AND if false. (ignored for first selector)
}

// APIQuery describes a query for records.
type APIQuery struct {
	Selectors    []APIQuerySelector `msgpack:"S"`                               // Selectors or selector range(s)
	PlainTextKey []byte             `msgpack:"PTK,omitempty" json:",omitempty"` // Plain-text key for first selector to have server decrypt value automatically
}

// APIError indicates an error and is returned with non-200 responses.
type APIError struct {
	Code    int    `msgpack:"C"` // Positive error codes simply mirror HTTP response codes, while negative ones are LF-specific
	Message string `msgpack:"M"` // Message indicating the reason for the error
}

func apiMakePeerArray(n *Node) []APIPeer {
	n.hostsLock.RLock()
	defer n.hostsLock.RUnlock()
	r := make([]APIPeer, 0, len(n.hosts))
	for i := range n.hosts {
		if n.hosts[i].Connected() {
			r = append(r, APIPeer{
				ProtoMessagePeer: ProtoMessagePeer{
					Protocol: ProtoTypeLFRawUDP,
					Port:     uint16(n.hosts[i].RemoteAddress.Port),
				},
				TotalBytesSent:     n.hosts[i].TotalBytesSent,
				TotalBytesReceived: n.hosts[i].TotalBytesReceived,
				Latency:            n.hosts[i].Latency,
			})
			r[len(r)-1].SetIP(n.hosts[i].RemoteAddress.IP)
		}
	}
	return r
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
	// If the client elects that it accepts msgpack, send that instead since it's faster and smaller.
	accept, haveAccept := req.Header["Accept"]
	if haveAccept {
		for i := range accept {
			asp := strings.FieldsFunc(accept[i], func(r rune) bool {
				return (r == ',' || r == ';' || r == ' ' || r == '\t')
			})
			for j := range asp {
				asp[j] = strings.TrimSpace(asp[j])
				if strings.Contains(asp[j], "msgpack") {
					out.Header().Set("Content-Type", asp[j])
					out.WriteHeader(httpStatusCode)
					if req.Method == http.MethodHead {
						return nil
					}
					return msgpack.NewEncoder(out).Encode(obj)
				}
			}
		}
	}
	out.Header().Set("Content-Type", "application/json")
	out.WriteHeader(httpStatusCode)
	if req.Method == http.MethodHead {
		return nil
	}
	return json.NewEncoder(out).Encode(obj)
}

func apiReadObj(out http.ResponseWriter, req *http.Request, dest interface{}) (err error) {
	// The same msgpack support is present for incoming requests and messages if set by content-type. Otherwise assume JSON.
	decodedMsgpack := false
	ct, haveCT := req.Header["Content-Type"]
	if haveCT {
		for i := range ct {
			if strings.Contains(ct[i], "msgpack") {
				err = msgpack.NewDecoder(req.Body).Decode(&dest)
				decodedMsgpack = true
			}
		}
	}
	if !decodedMsgpack {
		err = json.NewDecoder(req.Body).Decode(&dest)
	}
	if err != nil {
		apiSendObj(out, req, http.StatusBadRequest, &APIError{Code: http.StatusBadRequest, Message: "invalid or malformed payload"})
	}
	return err
}

func apiIsTrusted(n *Node, req *http.Request) bool {
	// TODO
	return true
}

func apiCreateHTTPServeMux(n *Node) *http.ServeMux {
	smux := http.NewServeMux()

	// Query for records matching one or more selectors or ranges of selectors.
	smux.HandleFunc("/q", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
		} else {
			apiSendObj(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	// Post a record, takes APIPut payload or just a raw record in binary form.
	smux.HandleFunc("/p", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
		} else {
			apiSendObj(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	// Get links for incorporation into a new record, returns up to 31 raw binary hashes. A ?count= parameter can be added to specify how many are desired.
	smux.HandleFunc("/l", func(out http.ResponseWriter, req *http.Request) {
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

	smux.HandleFunc("/peers", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodGet || req.Method == http.MethodHead {
			apiSendObj(out, req, http.StatusOK, apiMakePeerArray(n))
		} else {
			apiSendObj(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/connect", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
			if apiIsTrusted(n, req) {
				var peer APIPeer
				if apiReadObj(out, req, &peer) == nil {
					n.Try(peer.GetIP(), int(peer.Port))
					apiSendObj(out, req, http.StatusOK, &peer)
				}
			} else {
				apiSendObj(out, req, http.StatusForbidden, &APIError{Code: http.StatusForbidden, Message: "peers may only be submitted by trusted hosts"})
			}
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
			Peers:         apiMakePeerArray(n),
			DBRecordCount: rc,
			DBSize:        ds,
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
