/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
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
	Software       string    `msgpack:"S"`    // Software implementation name
	Version        [4]int    `msgpack:"V"`    // Version of software
	MinAPIVersion  int       `msgpack:"MiA"`  // Minimum API version supported
	MaxAPIVersion  int       `msgpack:"MaA"`  // Maximum API version supported
	Uptime         uint64    `msgpack:"U"`    // Uptime in milliseconds since epoch
	ConnectedPeers []APIPeer `msgpack:"CP"`   // Connected peer nodes (if revealed by node)
	DBRecordCount  uint64    `msgpack:"DBRC"` // Number of records in database
	DBSize         uint64    `msgpack:"DBS"`  // Total size of records in database in bytes
}

// APIPut (/p) is used to submit a new record revision to the global LF key/value store.
// If Data is non-nil/empty it must contain a valid and fully signed and paid for record. If
// this is present all other fields are ignored. If Data is not present the other fields contain
// the values that are required for the node to locally build and sign the record. Nodes only
// allow this (for both security and DOS reasons) from authorized clients. Use the Proxy to do
// this from other places. The Proxy accepts requests to localhosts, passed through queries,
// but intercepts puts and builds records locally and then submits them in Data to a full node.
type APIPut struct {
	Data                    []byte    `msgpack:"D,omitempty" json:",omitempty"`   // Fully encoded record data, overrides other fields if present
	Key                     []byte    `msgpack:"K,omitempty" json:",omitempty"`   // Plain text key
	Value                   []byte    `msgpack:"V,omitempty" json:",omitempty"`   // Plain text value
	Selectors               [2][]byte `msgpack:"S,omitempty" json:",omitempty"`   // Selectors
	OwnerPrivateKey         []byte    `msgpack:"OPK,omitempty" json:",omitempty"` // Owner private key to sign record
	OwnerSignatureAlgorithm byte      `msgpack:"OSA" json:",omitempty"`           // Signature algorithm for owner private key
	PlainTextValue          bool      `msgpack:"PTV"`                             // If true, do not encrypt value in record
}

// APIGet (/g) gets records by search keys.
type APIGet struct {
	Key         []byte    `msgpack:"K,omitempty" json:",omitempty"`    // Plain text key (overrides ID)
	ID          []byte    `msgpack:"ID,omitempty" json:",omitempty"`   // ID (32 bytes) (ignored if Key is given)
	Owner       []byte    `msgpack:"O,omitempty" json:",omitempty"`    // Owner (32 bytes)
	SelectorIDs [2][]byte `msgpack:"SIDs,omitempty" json:",omitempty"` // Selector IDs (32 bytes each)
}

// APIRecordDetail is sent (in an array) in response to APIGet.
type APIRecordDetail struct {
	Record Record   `msgpack:"R"`                             // Fully unpacked record
	Key    []byte   `msgpack:"K,omitempty" json:",omitempty"` // Plain-text key if supplied in query, otherwise omitted
	Value  []byte   `msgpack:"V,omitempty" json:",omitempty"` // Plain-text value if plain-text key was supplied with query, otherwise omitted
	Weight [16]byte `msgpack:"W,omitempty" json:",omitempty"` // Weight of this record as a 128-bit unsigned int in big-endian byte order
}

// APIRequestLinks is a request for links to include in a new record.
type APIRequestLinks struct {
	Count uint `msgpack:"C"` // Desired number of links
}

// APILinks is a set of links returned by APIRequestLinks
type APILinks struct {
	Links []byte `msgpack:"L"` // Array of links (size is always a multiple of 32 bytes, link count is size / 32)
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
	h.Set("X-LF-APIVersion", apiVersionStr)
}

func apiSendJSON(out http.ResponseWriter, req *http.Request, httpStatusCode int, obj interface{}) error {
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

func apiReadJSON(out http.ResponseWriter, req *http.Request, dest interface{}) (err error) {
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
		apiSendJSON(out, req, http.StatusBadRequest, &APIError{Code: http.StatusBadRequest, Message: "invalid or malformed payload"})
	}
	return err
}

func apiIsTrusted(n *Node, req *http.Request) bool {
	// TODO
	return true
}

func apiCreateHTTPServeMux(n *Node) *http.ServeMux {
	smux := http.NewServeMux()

	// Get best value by record key. The key may be /k/<key>.ext or /k/~<base64url>.ext for a base64url encoded
	// key. The extension determins what type is returned. A json or msgpack extension returns an APIRecord object.
	// The following extensions return the value with the appropriate content type: html, js, png, gif, jpg, xml,
	// css, and txt. No extension returns value with type application/octet-stream.
	smux.HandleFunc("/k/", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodGet || req.Method == http.MethodHead {
			var key []byte
			contentType := "application/octet-stream"
			fullResults := false

			keyStr := req.URL.Path[3:]
			dotIdx := strings.LastIndexByte(keyStr, '.')
			if dotIdx >= 0 {
				switch keyStr[dotIdx+1:] {
				case "json":
					contentType = "application/json"
					fullResults = true
				case "msgpack":
					contentType = "application/msgpack"
					fullResults = true
				case "html":
					contentType = "text/html"
				case "js":
					contentType = "text/javascript"
				case "png":
					contentType = "image/png"
				case "gif":
					contentType = "image/gif"
				case "jpg":
					contentType = "image/jpeg"
				case "xml":
					contentType = "text/xml"
				case "css":
					contentType = "text/css"
				case "txt":
					contentType = "text/plain"
				}
				keyStr = keyStr[0:dotIdx]
			}
			if len(keyStr) > 0 && keyStr[0] == '~' {
				key = make([]byte, base64.URLEncoding.DecodedLen(len(keyStr)))
				n, err := base64.URLEncoding.Decode(key, []byte(keyStr[1:]))
				if err != nil || n < 0 {
					apiSendJSON(out, req, http.StatusNotFound, &APIError{Code: http.StatusNotFound, Message: "invalid base64 in ~<base64> key"})
					return
				}
				key = key[0:n]
			} else {
				key = []byte(keyStr)
			}

			id, _ := RecordDeriveID(key)
			recs := n.db.getMatching(id[:], nil, nil, nil)

			if len(recs) == 0 {
				apiSendJSON(out, req, http.StatusNotFound, &APIError{Code: http.StatusNotFound, Message: "no records found"})
				return
			}

			if fullResults {
				for i := range recs {
					v, err := recs[i].Record.GetValue(key)
					if err != nil {
						apiSendJSON(out, req, http.StatusNotFound, &APIError{Code: http.StatusNotFound, Message: "record decryption or decompression failed"})
						return
					}
					recs[i].Key = key
					recs[i].Value = v
				}
				apiSendJSON(out, req, http.StatusOK, &recs)
			} else {
				h := out.Header()
				h.Set("Content-Type", contentType)
				v, err := recs[0].Record.GetValue(key)
				if err != nil {
					apiSendJSON(out, req, http.StatusNotFound, &APIError{Code: http.StatusNotFound, Message: "record decryption or decompression failed"})
					return
				}
				h.Set("X-LF-Record-ID", hex.EncodeToString(recs[0].Record.ID[:]))
				h.Set("X-LF-Record-Owner", hex.EncodeToString(recs[0].Record.Owner[:]))
				h.Set("X-LF-Record-Hash", hex.EncodeToString(recs[0].Record.Hash[:]))
				h.Set("X-LF-Record-Timestamp", strconv.FormatUint(recs[0].Record.Timestamp, 10))
				h.Set("X-LF-Record-Weight", hex.EncodeToString(recs[0].Weight[:]))
				h.Set("Content-Length", strconv.Itoa(len(v)))
				out.WriteHeader(200)
				out.Write(v)
			}
		} else {
			apiSendJSON(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	// Post a record, takes APIPut payload or just a raw record.
	smux.HandleFunc("/p", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
			// Handle submission of raw records in raw record format with no enclosing object.
			ct, haveCT := req.Header["Content-Type"]
			if haveCT {
				for i := range ct {
					if strings.Contains(ct[i], "application/x-lf-record") || strings.Contains(ct[i], "application/octet-stream") {
						var rdata [RecordMaxSize]byte
						rsize, _ := io.ReadFull(req.Body, rdata[:])
						if rsize > RecordMinSize {
							err := n.AddRecord(rdata[0:uint(rsize)])
							if err != nil {
								apiSendJSON(out, req, http.StatusBadRequest, &APIError{Code: http.StatusBadRequest, Message: "invalid record: " + err.Error()})
							}
						} else {
							apiSendJSON(out, req, http.StatusBadRequest, &APIError{Code: http.StatusBadRequest, Message: "invalid or malformed payload"})
							return
						}
					}
				}
			}

			var put APIPut
			if apiReadJSON(out, req, &put) == nil {
				if len(put.Data) > 0 {
				} else if apiIsTrusted(n, req) {
				} else {
					apiSendJSON(out, req, http.StatusForbidden, &APIError{Code: http.StatusForbidden, Message: "node will only build records locally if submitted from authorized hosts"})
				}
			}
		} else {
			apiSendJSON(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	// Get record, takes APIGet payload for parameters. (Ironically /g must be gotten with PUT or POST!)
	smux.HandleFunc("/g", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
		} else {
			apiSendJSON(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	// Raw record request, payload is raw binary 32-byte hashes rather than a JSON message.
	// The node is free to send other records in response as well, and the receiver should import
	// records in the order in which they are sent. Results are sent in binary raw form with
	// each record prefixed by a 16-bit (big-endian) record size.
	smux.HandleFunc("/r", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
		} else {
			apiSendJSON(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	// Get links, returns up to 31 raw binary hashes. A ?count= parameter can be added to specify how many are desired.
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
			apiSendJSON(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/peers", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodGet || req.Method == http.MethodHead {
			apiSendJSON(out, req, http.StatusOK, apiMakePeerArray(n))
		} else {
			apiSendJSON(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/connect", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
			if apiIsTrusted(n, req) {
				var peer APIPeer
				if apiReadJSON(out, req, &peer) == nil {
					n.Try(peer.GetIP(), int(peer.Port))
					apiSendJSON(out, req, http.StatusOK, &peer)
				}
			} else {
				apiSendJSON(out, req, http.StatusForbidden, &APIError{Code: http.StatusForbidden, Message: "peers may only be submitted by trusted hosts"})
			}
		} else {
			apiSendJSON(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/status", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		rc, ds := n.db.stats()
		var s APIStatus
		s.Software = SoftwareName
		s.Version[0] = VersionMajor
		s.Version[1] = VersionMinor
		s.Version[2] = VersionRevision
		s.Version[3] = VersionBuild
		s.MinAPIVersion = APIVersion
		s.MaxAPIVersion = APIVersion
		s.Uptime = n.startTime
		s.ConnectedPeers = apiMakePeerArray(n)
		s.DBRecordCount = rc
		s.DBSize = ds
		apiSendJSON(out, req, http.StatusOK, &s)
	})

	smux.HandleFunc("/", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodGet || req.Method == http.MethodHead {
			if req.URL.Path == "/" {
			} else {
				apiSendJSON(out, req, http.StatusNotFound, &APIError{Code: http.StatusNotFound, Message: req.URL.Path + " is not a valid path"})
			}
		} else {
			apiSendJSON(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	return smux
}
