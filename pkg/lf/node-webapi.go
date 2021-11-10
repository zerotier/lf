/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c)2019-2021 ZeroTier, Inc.
 * https://www.zerotier.com/
 */

package lf

// This is the HTTP API parts of Node, see node.go for main object.

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

type remoteMakeResult struct {
	Pulse    Pulse   `json:",omitempty"`
	Record   *Record `json:",omitempty"`
	Accepted bool
}

type pulsePostResult struct {
	Pulse    Pulse
	Accepted bool
}

func apiSetStandardHeaders(out http.ResponseWriter) {
	now := time.Now().UTC()
	h := out.Header()
	h.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	h.Set("Expires", "0")
	h.Set("Pragma", "no-cache")
	h.Set("Date", now.Format(time.RFC1123))
	h.Set("X-LF-Version", VersionStr)
	h.Set("X-LF-APIVersion", APIVersionStr)
	h.Set("X-LF-Time", strconv.FormatInt(now.Unix(), 10))
	h.Set("Server", SoftwareName)
}

func apiSendObj(out http.ResponseWriter, req *http.Request, httpStatusCode int, obj interface{}) {
	h := out.Header()
	h.Set("Content-Type", "application/json")
	if req.Method == http.MethodHead {
		out.WriteHeader(httpStatusCode)
	}
	var j []byte
	if obj != nil {
		j, _ = json.Marshal(obj)
	}
	out.WriteHeader(httpStatusCode)
	if j != nil {
		_, _ = out.Write(j)
	}
}

func apiReadObj(out http.ResponseWriter, req *http.Request, dest interface{}) (err error) {
	err = json.NewDecoder(req.Body).Decode(&dest)
	if err != nil {
		apiSendObj(out, req, http.StatusBadRequest, &ErrAPI{Code: http.StatusBadRequest, Message: "invalid or malformed payload: " + err.Error()})
	}
	return
}

func (n *Node) apiIsTrusted(req *http.Request) bool {
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return false
	}
	return net.ParseIP(ip).IsLoopback()
}

func (n *Node) createHTTPServeMux() *http.ServeMux {
	smux := http.NewServeMux()

	smux.HandleFunc("/query", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
			var m Query
			if apiReadObj(out, req, &m) == nil {
				results, err := m.execute(n)
				if err != nil {
					apiSendObj(out, req, http.StatusBadRequest, &ErrAPI{Code: http.StatusBadRequest, Message: "query failed: " + err.Error()})
				} else {
					apiSendObj(out, req, http.StatusOK, results)
				}
			}
		} else {
			out.Header().Set("Allow", "POST, PUT")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &ErrAPI{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/post", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
			var rec Record
			err := rec.UnmarshalFrom(req.Body)
			if err != nil {
				apiSendObj(out, req, http.StatusBadRequest, &ErrAPI{Code: http.StatusBadRequest, Message: "record deserialization failed: " + err.Error()})
			} else {
				err = n.AddRecord(&rec)
				if err != nil && err != ErrDuplicateRecord {
					apiSendObj(out, req, http.StatusBadRequest, &ErrAPI{Code: 0, Message: "record rejected or record import failed: " + err.Error(), ErrTypeName: errTypeName(err)})
				} else {
					apiSendObj(out, req, http.StatusOK, rec)
				}
			}
		} else {
			out.Header().Set("Allow", "POST, PUT")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &ErrAPI{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/pulse", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
			var pbuf [PulseSize]byte
			pulse := Pulse(pbuf[:])
			_, err := io.ReadFull(req.Body, pulse[:])
			if err != nil {
				apiSendObj(out, req, http.StatusBadRequest, &ErrAPI{Code: http.StatusBadRequest, Message: "read error: " + err.Error()})
			} else {
				ok, _ := n.DoPulse(pulse, true)
				apiSendObj(out, req, http.StatusOK, &pulsePostResult{pulse, ok})
			}
		} else {
			out.Header().Set("Allow", "POST, PUT")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &ErrAPI{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/makerecord", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
			if n.apiIsTrusted(req) {
				var m MakeRecord
				if apiReadObj(out, req, &m) == nil {
					rec, pulse, ok, err := m.execute(n)
					if err != nil {
						apiSendObj(out, req, http.StatusBadRequest, &ErrAPI{Code: http.StatusBadRequest, Message: "record creation failed: " + err.Error()})
					} else {
						apiSendObj(out, req, http.StatusOK, &remoteMakeResult{pulse, rec, ok})
					}
				}
			} else {
				apiSendObj(out, req, http.StatusForbidden, &ErrAPI{Code: http.StatusMethodNotAllowed, Message: "only trusted clients can delegate record creation"})
			}
		} else {
			out.Header().Set("Allow", "POST, PUT")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &ErrAPI{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/makepulse", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
			var m MakePulse
			if apiReadObj(out, req, &m) == nil {
				pulse, rec, ok, err := m.execute(n)
				if err != nil {
					apiSendObj(out, req, http.StatusBadRequest, &ErrAPI{Code: http.StatusBadRequest, Message: "record creation failed: " + err.Error()})
				} else {
					apiSendObj(out, req, http.StatusOK, &remoteMakeResult{pulse, rec, ok})
				}
			}
		} else {
			out.Header().Set("Allow", "POST, PUT")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &ErrAPI{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/connect", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
			if n.apiIsTrusted(req) {
				var m Peer
				if apiReadObj(out, req, &m) == nil {
					_ = n.Connect(m.IP, m.Port, m.Identity)
					apiSendObj(out, req, http.StatusOK, nil)
				}
			} else {
				apiSendObj(out, req, http.StatusForbidden, &ErrAPI{Code: http.StatusMethodNotAllowed, Message: "only trusted clients can suggest P2P endpoints"})
			}
		} else {
			out.Header().Set("Allow", "POST, PUT")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &ErrAPI{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/record/raw/", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodGet || req.Method == http.MethodHead {
			urlPath := req.URL.Path
			if strings.HasPrefix(urlPath, "/record/raw/") { // sanity check
				urlPath = urlPath[12:]
				if len(urlPath) > 1 && urlPath[0] == '=' {
					recordHash := Base62Decode(urlPath[1:])
					if len(recordHash) == 32 {
						_, data, _ := n.db.getDataByHash(recordHash, nil)
						if len(data) > 0 {
							out.Header().Set("Content-Type", "application/octet-stream")
							out.WriteHeader(http.StatusOK)
							if req.Method != http.MethodHead {
								_, _ = out.Write(data)
							}
							return
						}
					}
				}
			}
			apiSendObj(out, req, http.StatusNotFound, &ErrAPI{Code: http.StatusNotFound, Message: req.URL.Path + " not found"})
		} else {
			out.Header().Set("Allow", "GET, HEAD")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &ErrAPI{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/record/", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodGet || req.Method == http.MethodHead {
			urlPath := req.URL.Path
			if strings.HasPrefix(urlPath, "/record/") { // sanity check
				urlPath = urlPath[8:]
				if len(urlPath) > 1 && urlPath[0] == '=' {
					recordHash := Base62Decode(urlPath[1:])
					if len(recordHash) == 32 {
						_, data, _ := n.db.getDataByHash(recordHash, nil)
						if len(data) > 0 {
							rec, _ := NewRecordFromBytes(data)
							if rec != nil {
								apiSendObj(out, req, http.StatusOK, rec)
								return
							}
						}
					}
				}
			}
			apiSendObj(out, req, http.StatusNotFound, &ErrAPI{Code: http.StatusNotFound, Message: req.URL.Path + " not found"})
		} else {
			out.Header().Set("Allow", "GET, HEAD")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &ErrAPI{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
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
				_, _ = out.Write(links)
			}
		} else {
			out.Header().Set("Allow", "GET, HEAD")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &ErrAPI{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/status", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodGet || req.Method == http.MethodHead {
			nodeStatus, err := n.NodeStatus()
			if err != nil {
				apiSendObj(out, req, http.StatusInternalServerError, &ErrAPI{Code: http.StatusInternalServerError, Message: err.Error(), ErrTypeName: errTypeName(err)})
			}
			apiSendObj(out, req, http.StatusOK, nodeStatus)
		} else {
			out.Header().Set("Allow", "GET, HEAD")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &ErrAPI{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/dumprecords", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodGet || req.Method == http.MethodHead {
			recordsLf, err := os.Open(path.Join(n.basePath, "records.lf"))
			if err != nil {
				apiSendObj(out, req, http.StatusInternalServerError, &ErrAPI{Code: http.StatusInternalServerError, Message: err.Error(), ErrTypeName: errTypeName(err)})
			} else {
				defer func() {
					_ = recordsLf.Close()
				}()
				out.Header().Set("Content-Type", "application/octet-stream")
				out.WriteHeader(http.StatusOK)
				_, _ = io.Copy(out, recordsLf)
			}
		} else {
			out.Header().Set("Allow", "GET, HEAD")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &ErrAPI{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/owner/", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodGet || req.Method == http.MethodHead {
			urlPath := req.URL.Path
			if strings.HasPrefix(urlPath, "/owner/") { // sanity check
				urlPath = urlPath[7:]
				if len(urlPath) > 1 && urlPath[0] == '@' {
					ownerPublic, _ := NewOwnerPublicFromString(urlPath)
					if len(ownerPublic) > 0 {
						ownerStatus, err := n.OwnerStatus(ownerPublic)
						if err != nil {
							apiSendObj(out, req, http.StatusInternalServerError, &ErrAPI{Code: http.StatusInternalServerError, Message: err.Error(), ErrTypeName: errTypeName(err)})
						}
						apiSendObj(out, req, http.StatusOK, ownerStatus)
						return
					}
				}
			}
			apiSendObj(out, req, http.StatusNotFound, &ErrAPI{Code: http.StatusNotFound, Message: req.URL.Path + " not found"})
		} else {
			out.Header().Set("Allow", "GET, HEAD")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &ErrAPI{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/", func(out http.ResponseWriter, req *http.Request) {
		apiSetStandardHeaders(out)
		if req.Method == http.MethodGet || req.Method == http.MethodHead {
			apiSendObj(out, req, http.StatusNotFound, &ErrAPI{Code: http.StatusNotFound, Message: req.URL.Path + " not found"})
		} else {
			out.Header().Set("Allow", "GET, HEAD")
			apiSendObj(out, req, http.StatusMethodNotAllowed, &ErrAPI{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	return smux
}
