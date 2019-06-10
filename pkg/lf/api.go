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
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	// APIErrorRecordRejected indicates that a posted record was considered invalid or too suspect to import.
	APIErrorRecordRejected = -1
)

var apiVersionStr = strconv.FormatInt(int64(APIVersion), 10)

// APIMaxResponseSize is a sanity limit on the maximum size of a response from the LF HTTP API (can be increased)
const APIMaxResponseSize = 4194304

var httpClient = http.Client{Timeout: time.Second * 60}

// APIError (response) indicates an error and is returned with non-200 responses.
type APIError struct {
	Code    int    ``                  // Positive error codes simply mirror HTTP response codes, while negative ones are LF-specific
	Message string `json:",omitempty"` // Message indicating the reason for the error
}

// Error implements the error interface, making APIError an 'error' in the Go sense.
func (e APIError) Error() string {
	if len(e.Message) > 0 {
		return fmt.Sprintf("[%d] %s", e.Code, e.Message)
	}
	return strconv.FormatInt(int64(e.Code), 10)
}

// Peer contains information about a peer
type Peer struct {
	IP       net.IP //
	Port     int    // -1 indicates inbound TCP connection with unknown/unreachable port
	Identity Blob   //
}

// APIStatusResult contains status information about this node and the network it belongs to.
type APIStatusResult struct {
	Software          string            `json:",omitempty"` // Software implementation name
	Version           [4]int            ``                  // Version of software
	APIVersion        int               ``                  // Current version of API
	MinAPIVersion     int               ``                  // Minimum API version supported
	MaxAPIVersion     int               ``                  // Maximum API version supported
	Uptime            uint64            ``                  // Node uptime in seconds
	Clock             uint64            ``                  // Node local clock in seconds since epoch
	RecordCount       uint64            ``                  // Number of records in database
	DataSize          uint64            ``                  // Total size of records in database in bytes
	FullySynchronized bool              ``                  // True if there are no dangling links (excluding abandoned ones)
	GenesisParameters GenesisParameters ``                  // Network parameters
	Oracle            OwnerPublic       `json:",omitempty"` // Owner public if this node is an oracle, empty otherwise
	P2PPort           int               ``                  // This node's P2P port
	HTTPPort          int               ``                  // This node's HTTP port
	LocalTestMode     bool              ``                  // If true, this node is in local test mode
	Identity          Blob              `json:",omitempty"` // This node's peer identity
	Peers             []Peer            `json:",omitempty"` // Currently connected peers
}

// APIOwnerInfoResult is returned from queries for owner info from /owner/@base62 URLs.
type APIOwnerInfoResult struct {
	Owner                 OwnerPublic ``                  // Public portion of owner (from query)
	Certificates          []Blob      `json:",omitempty"` // Certificates in DER format
	RevokedCertificates   []Blob      `json:",omitempty"` // Revoked certificated in DER format
	HasCurrentCertificate bool        ``                  // True if at least one certificate's time range contains the current time
	RecordCount           uint64      ``                  // Number of records in data store by this owner
	RecordBytes           uint64      ``                  // Number of bytes of records by this owner
	Links                 []HashBlob  `json:",omitempty"` // Suggested links for a new record (for convenience to avoid two API calls)
	ServerTime            uint64      ``                  // Server time in seconds since epoch
}

// MountPoint describes a FUSE lffs mount point
type MountPoint struct {
	Path             string      `json:",omitempty"`
	RootSelectorName Blob        `json:",omitempty"`
	Owner            OwnerPublic `json:",omitempty"`
	OwnerPrivate     Blob        `json:",omitempty"`
	MaskingKey       Blob        `json:",omitempty"` // masking key to override default value which is the root selector name
	Passphrase       string      `json:",omitempty"` // if present is used to deterministically compute OwnerPrivate and MaskingKey
	MaxFileSize      int
}

//////////////////////////////////////////////////////////////////////////////

// APIPostRecord submits a raw LF record to a node or proxy.
func APIPostRecord(url string, recordData []byte) error {
	if strings.HasSuffix(url, "/") {
		url = url + "post"
	} else {
		url = url + "/post"
	}
	resp, err := httpClient.Post(url, "application/octet-stream", bytes.NewReader(recordData))
	if err != nil {
		return err
	}
	if resp.StatusCode == 200 {
		return nil
	}
	body, err := ioutil.ReadAll(&io.LimitedReader{R: resp.Body, N: 131072})
	resp.Body.Close()
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

// APIPostConnect submits an Peer record to /connect.
func APIPostConnect(url string, ip net.IP, port int, identity string) error {
	if strings.HasSuffix(url, "/") {
		url = url + "connect"
	} else {
		url = url + "/connect"
	}
	var ob []byte
	if len(identity) > 0 {
		ob = Base62Decode(identity[:])
	} else {
		return ErrInvalidParameter
	}
	apiPeerJSON, err := json.Marshal(&Peer{
		IP:       ip,
		Port:     port,
		Identity: ob,
	})
	if err != nil {
		return err
	}
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(apiPeerJSON))
	if err != nil {
		return err
	}
	if resp.StatusCode == 200 {
		return nil
	}
	body, err := ioutil.ReadAll(&io.LimitedReader{R: resp.Body, N: 131072})
	resp.Body.Close()
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
// This returns links, the server time reported in the X-LF-Time header field (or -1
// if none), and an error (if any).
func APIGetLinks(url string, count int) ([][32]byte, int64, error) {
	if strings.HasSuffix(url, "/") {
		url = url + "links"
	} else {
		url = url + "/links"
	}
	if count > 0 {
		url = url + "?count=" + strconv.FormatUint(uint64(count), 10)
	}
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, -1, err
	}
	if resp.StatusCode == 200 {
		body, err := ioutil.ReadAll(&io.LimitedReader{R: resp.Body, N: 131072})
		resp.Body.Close()
		if err != nil {
			return nil, -1, err
		}
		var l [][32]byte
		for i := 0; (i + 32) <= len(body); i += 32 {
			var h [32]byte
			copy(h[:], body[i:i+32])
			l = append(l, h)
		}
		tstr := resp.Header.Get("X-LF-Time")
		if len(tstr) > 0 {
			ts, _ := strconv.ParseInt(tstr, 10, 64)
			return l, ts, nil
		}
		return l, -1, nil
	}
	return nil, -1, APIError{Code: resp.StatusCode}
}

// APIGetOwnerInfo gets information about an owner and its related certs, etc.
func APIGetOwnerInfo(url string, ownerPublic OwnerPublic) (*APIOwnerInfoResult, error) {
	if strings.HasSuffix(url, "/") {
		url = url + "owner/" + ownerPublic.String()
	} else {
		url = url + "/owner/" + ownerPublic.String()
	}
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(&io.LimitedReader{R: resp.Body, N: 65536})
	if err != nil {
		return nil, err
	}
	var sr APIOwnerInfoResult
	if err := json.Unmarshal(body, &sr); err != nil {
		return nil, err
	}
	return &sr, nil
}

// APIStatusGet gets a status result from a URL.
func APIStatusGet(url string) (*APIStatusResult, error) {
	if strings.HasSuffix(url, "/") {
		url = url + "status"
	} else {
		url = url + "/status"
	}
	resp, err := httpClient.Get(url)
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

//////////////////////////////////////////////////////////////////////////////

func apiRun(url string, m interface{}) ([]byte, error) {
	aq, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(aq))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept-Encoding", "gzip")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	bodyReader := resp.Body
	if !resp.Uncompressed && strings.Contains(resp.Header.Get("Content-Encoding"), "gzip") {
		bodyReader, err = gzip.NewReader(bodyReader)
		if err != nil {
			return nil, err
		}
	}
	defer bodyReader.Close()
	body, err := ioutil.ReadAll(&io.LimitedReader{R: bodyReader, N: int64(APIMaxResponseSize)})
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
	now := time.Now().UTC()
	h := out.Header()
	h.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	h.Set("Expires", "0")
	h.Set("Pragma", "no-cache")
	h.Set("Date", now.Format(time.RFC1123))
	h.Set("X-LF-Version", VersionStr)
	h.Set("X-LF-APIVersion", apiVersionStr)
	h.Set("X-LF-Time", strconv.FormatInt(now.Unix(), 10))
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
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return false
	}
	return net.ParseIP(ip).IsLoopback()
}

func apiCreateHTTPServeMux(n *Node) *http.ServeMux {
	smux := http.NewServeMux()

	smux.HandleFunc("/query", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
			var m Query
			if apiReadObj(out, req, &m) == nil {
				results, err := m.Execute(n)
				if err != nil {
					apiSendObj(out, req, http.StatusBadRequest, &APIError{Code: http.StatusBadRequest, Message: "query failed: " + err.Error()})
				} else {
					apiSendObj(out, req, http.StatusOK, results)
				}
			}
		} else {
			out.Header().Set("Allow", "POST, PUT")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/post", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
			var rec Record
			err := rec.UnmarshalFrom(req.Body)
			if err != nil {
				apiSendObj(out, req, http.StatusBadRequest, &APIError{Code: http.StatusBadRequest, Message: "record deserialization failed: " + err.Error()})
			} else {
				err = n.AddRecord(&rec)
				if err != nil && err != ErrDuplicateRecord {
					apiSendObj(out, req, http.StatusBadRequest, &APIError{Code: APIErrorRecordRejected, Message: "record rejected or record import failed: " + err.Error()})
				} else {
					apiSendObj(out, req, http.StatusOK, nil)
				}
			}
		} else {
			out.Header().Set("Allow", "POST, PUT")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

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
			if desired > RecordMaxLinks {
				desired = RecordMaxLinks
			}
			out.Header().Set("Content-Type", "application/octet-stream")
			out.WriteHeader(http.StatusOK)
			if desired > 0 {
				_, links, _ := n.db.getLinks(desired)
				out.Write(links)
			}
		} else {
			out.Header().Set("Allow", "GET, HEAD")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/status", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodGet || req.Method == http.MethodHead {
			var peers []Peer
			n.peersLock.RLock()
			for _, p := range n.peers {
				port := p.tcpAddress.Port
				if p.inbound {
					port = -1
				}
				peers = append(peers, Peer{
					IP:       p.tcpAddress.IP,
					Port:     port,
					Identity: p.identity,
				})
			}
			n.peersLock.RUnlock()

			rc, ds := n.db.stats()
			now := time.Now()

			var oracle OwnerPublic
			if atomic.LoadUint32(&n.commentary) != 0 {
				oracle = n.owner.Public
			}

			apiSendObj(out, req, http.StatusOK, &APIStatusResult{
				Software:          SoftwareName,
				Version:           Version,
				APIVersion:        APIVersion,
				MinAPIVersion:     APIVersion,
				MaxAPIVersion:     APIVersion,
				Uptime:            uint64(math.Round(now.Sub(n.startTime).Seconds())),
				Clock:             uint64(now.Unix()),
				RecordCount:       rc,
				DataSize:          ds,
				FullySynchronized: (atomic.LoadUint32(&n.synchronized) != 0),
				GenesisParameters: n.genesisParameters,
				Oracle:            oracle,
				P2PPort:           n.p2pPort,
				HTTPPort:          n.httpPort,
				LocalTestMode:     n.localTest,
				Identity:          n.identity,
				Peers:             peers,
			})
		} else {
			out.Header().Set("Allow", "GET, HEAD")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/connect", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
			if apiIsTrusted(n, req) {
				var m Peer
				if apiReadObj(out, req, &m) == nil {
					n.Connect(m.IP, m.Port, m.Identity)
					apiSendObj(out, req, http.StatusOK, nil)
				}
			} else {
				apiSendObj(out, req, http.StatusForbidden, &APIError{Code: http.StatusMethodNotAllowed, Message: "only trusted clients can suggest P2P endpoints"})
			}
		} else {
			out.Header().Set("Allow", "POST, PUT")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/owner/", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodGet || req.Method == http.MethodHead {
			path := req.URL.Path
			if strings.HasPrefix(path, "/owner/") { // sanity check
				path = path[7:]
				if len(path) > 0 && path[0] == '@' {
					ownerPublic, _ := NewOwnerPublicFromString(path)
					if len(ownerPublic) > 0 {
						recordCount, recordBytes := n.db.getOwnerStats(ownerPublic)
						certs, revokedCerts := n.GetOwnerCertificates(ownerPublic)
						certsBin, revokedCertsBin := make([]Blob, 0, len(certs)), make([]Blob, 0, len(revokedCerts))
						certsCurrent := false
						now := time.Now().UTC()
						for _, cert := range certs {
							certsBin = append(certsBin, cert.Raw)
							if now.After(cert.NotBefore) && now.Before(cert.NotAfter) {
								certsCurrent = true
							}
						}
						for _, revokedCert := range revokedCerts {
							revokedCertsBin = append(revokedCertsBin, revokedCert.Raw)
						}
						links, _ := n.db.getLinks2(n.genesisParameters.RecordMinLinks)
						links2 := make([]HashBlob, 0, len(links))
						for _, l := range links {
							links2 = append(links2, l)
						}
						apiSendObj(out, req, http.StatusOK, &APIOwnerInfoResult{
							Owner:                 ownerPublic,
							Certificates:          certsBin,
							RevokedCertificates:   revokedCertsBin,
							HasCurrentCertificate: certsCurrent,
							RecordCount:           recordCount,
							RecordBytes:           recordBytes,
							Links:                 links2,
							ServerTime:            uint64(now.Unix()),
						})
						return
					}
				}
			}
			apiSendObj(out, req, http.StatusNotFound, &APIError{Code: http.StatusNotFound, Message: req.URL.Path + " not found"})
		} else {
			out.Header().Set("Allow", "GET, HEAD")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodGet || req.Method == http.MethodHead {
			apiSendObj(out, req, http.StatusNotFound, &APIError{Code: http.StatusNotFound, Message: req.URL.Path + " not found"})
		} else {
			out.Header().Set("Allow", "GET, HEAD")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	return smux
}
