package lf

const (
	// ProtoMessageTypePing indicates a ping message consisting of an 8-byte timestamp to be echoed back followed by arbitrary bytes.
	ProtoMessageTypePing = 0

	// ProtoMessageTypePong indicates a pong containing the echoed timestamp followed by a SHA384 of the original ping.
	ProtoMessageTypePong = 1

	// ProtoMessageTypePeer contains a msgpack-encoded Peer record.
	ProtoMessageTypePeer = 2

	// ProtoMessageTypeRecord contains a raw packed record.
	ProtoMessageTypeRecord = 3

	// ProtoMessageTypeRequestByHash requests a record by its 32-byte Shandwich256 hash.
	ProtoMessageTypeRequestByHash = 4
)

// ProtoMinPingResponseInterval is the minimum interval in milliseconds between ping responses (more frequent pings are ignored)
const ProtoMinPingResponseInterval = uint64(1000)

// ProtoHostTimeout is the time after which host entries are forgotten.
const ProtoHostTimeout = uint64(120000)

// ProtoMessagePeer is the payload for a Peer message.
type ProtoMessagePeer struct {
	Protocol    byte   `msgpack:"Pr"` // currently always 0 for LF P2P UDP
	AddressType byte   `msgpack:"AT"` // 6 or 4
	IP          []byte `msgpack:"IP"`
	Port        uint16 `msgpack:"Po"`
}
