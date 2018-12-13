package lf

// Protocol message type IDs and the maximum possible type ID
const (
	// ProtoMessageTypePing indicates a ping message consisting of an 8-byte timestamp to be echoed back followed by arbitrary bytes.
	ProtoMessageTypePing = 0

	// ProtoMessageTypePong indicates a pong containing the echoed timestamp followed by a SHA384 of the original ping.
	ProtoMessageTypePong = 1

	// ProtoMessageTypePeer contains a msgpack-encoded Peer record.
	ProtoMessageTypePeer = 2

	// ProtoMessageTypeRecord contains a raw packed record.
	ProtoMessageTypeRecord = 3

	// ProtoMessageTypeRequestByHash requests a record by its 32-byte ShaSha256 hash.
	ProtoMessageTypeRequestByHash = 4

	// ProtoMessageTypeSubscribe contains an 8-byte (64-bit) bit field indicating which things this node wishes to receive unprompted.
	ProtoMessageTypeSubscribe = 5
)

// ProtoMinPingResponseInterval is the minimum interval in milliseconds between ping responses (more frequent pings are ignored)
const ProtoMinPingResponseInterval = uint64(1000)

// PeerProtocolLFUDP indicates the LF P2P UDP protocol.
const PeerProtocolLFUDP = byte(0)

// Peer stores information about another full LF node on the network.
type Peer struct {
	Protocol    byte   `msgpack:"Pr"` // currently always 0 for LF P2P UDP
	AddressType byte   `msgpack:"AT"` // 6 or 4
	IP          []byte `msgpack:"IP"`
	Port        int    `msgpack:"Po"`
	Zone        string `msgpack:"Z"`
}
