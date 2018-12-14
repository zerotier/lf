package lf

import (
	"encoding/json"
	"net/http"
)

// APIVersion is the version of the current implementation
const APIVersion = uint64(0)

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
	MinAPIVersion  uint64    `msgpack:"MinA"` // Minimum API version supported
	MaxAPIVersion  uint64    `msgpack:"MaxA"` // Maximum API version supported
	Uptime         uint64    `msgpack:"U"`    // Uptime in milliseconds since epoch
	ConnectedPeers []APIPeer `msgpack:"CP"`   // Connected peer nodes (if revealed by node)
	DBRecordCount  uint64    `msgpack:"DBRC"` // Number of records in database
	DBSize         uint64    `msgpack:"DBS"`  // Total size of records in database in bytes
}

// APISearchQuery is a search query to find records by things other than key/ID.
type APISearchQuery struct {
	Key                []byte `msgpack:"K,omitempty" json:"Key,omitempty"`        // Plain text key (overrides ID)
	ID                 []byte `msgpack:"ID,omitempty" json:"ID,omitempty"`        // ID (32 bytes) (ignored if Key is given)
	Owner              []byte `msgpack:"O,omitempty" json:"Owner,omitempty"`      // Owner (32 bytes)
	Selector0          []byte `msgpack:"S0,omitempty" json:"Selector0,omitempty"` // Selector 0 (32 bytes)
	Selector1          []byte `msgpack:"S1,omitempty" json:"Selector1,omitempty"` // Selector 1 (32 bytes)
	MaxResultsPerOwner uint   `msgpack:"MRPO"`                                    // Maximum number of results per owner or 0 for unlimited
	MaxResults         uint   `msgpack:"MR"`                                      // Maximum total results or 0 for unlimited
}

// APIRecord contains a record plus several additional fields likely to be of use to the client.
type APIRecord struct {
	Data   []byte   `msgpack:"D"`                                  // Record data
	Weight [16]byte `msgpack:"W"`                                  // Weight of record as a 128-bit big-endian number
	Key    []byte   `msgpack:"K,omitempty" json:"Key,omitempty"`   // Plain-text key if supplied in query, otherwise omitted
	Value  []byte   `msgpack:"V,omitempty" json:"Value,omitempty"` // Plain-text value if plain-text key was supplied with query, otherwise omitted
}

// APIRequestLinks is a request for links to include in a new record.
type APIRequestLinks struct {
	Count uint `msgpack:"C"` // Desired number of links
}

// APILinks is a set of links returned by APIRequestLinks
type APILinks struct {
	Links []byte `msgpack:"L"` // Array of links (size is always a multiple of 32 bytes, link count is size / 32)
}

// APIError indicates an error
type APIError struct {
	Code    int    `msgpack:"C"` // Positive error codes simply mirror HTTP response codes, while negative ones are LF-specific
	Message string `msgpack:"M"` // Message indicating the reason for the error
}

func apiSendJSON(out http.ResponseWriter, httpStatusCode int, obj interface{}) {
	out.Header().Set("Content-Type", "application/json")
	out.Header().Set("Pragma", "no-cache")
	out.Header().Set("Cache-Control", "no-cache")
	out.WriteHeader(httpStatusCode)
	json.NewEncoder(out).Encode(obj)
}

func apiReadJSON(out http.ResponseWriter, req *http.Request, dest interface{}) error {
	err := json.NewDecoder(req.Body).Decode(&dest)
	if err != nil {
		apiSendJSON(out, http.StatusBadRequest, &APIError{Code: http.StatusBadRequest, Message: "invalid or malformed JSON payload"})
	}
	return err
}

func apiCreateHTTPServeMux(n *Node) *http.ServeMux {
	smux := http.NewServeMux()

	smux.HandleFunc("/hash/", func(out http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet {
		} else {
			apiSendJSON(out, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/id/", func(out http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet {
		} else {
			apiSendJSON(out, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/key/", func(out http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet {
		} else {
			apiSendJSON(out, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/post", func(out http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
		} else {
			apiSendJSON(out, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/search", func(out http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
		} else {
			apiSendJSON(out, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	smux.HandleFunc("/", func(out http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet {
			if req.URL.Path == "/" {
				var s APIStatus
				s.Software = SoftwareName
				s.Version[0] = VersionMajor
				s.Version[1] = VersionMinor
				s.Version[2] = VersionRevision
				s.Version[3] = VersionBuild
				s.MinAPIVersion = APIVersion
				s.MaxAPIVersion = APIVersion
				s.Uptime = n.startTime
				s.ConnectedPeers = nil
				s.DBRecordCount = 0
				s.DBSize = 0
				apiSendJSON(out, http.StatusOK, &s)
			} else {
				apiSendJSON(out, http.StatusNotFound, &APIError{Code: http.StatusNotFound, Message: req.URL.Path + " is not a valid path"})
			}
		} else {
			apiSendJSON(out, http.StatusMethodNotAllowed, &APIError{Code: http.StatusMethodNotAllowed, Message: req.Method + " not supported for this path"})
		}
	})

	return smux
}
