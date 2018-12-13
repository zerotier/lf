package lf

// Protocol message type IDs and the maximum possible type ID
const (
	ProtoMessageTypePing          = 0
	ProtoMessageTypePong          = 1
	ProtoMessageTypePeer          = 2
	ProtoMessageTypeRecord        = 3
	ProtoMessageTypeRequestByHash = 4
)

// ProtoMinPingResponseInterval is the minimum interval in milliseconds between ping responses (more frequent pings are ignored)
const ProtoMinPingResponseInterval = uint64(1000)

// ProtoMessagePeer is used to tell nodes what other nodes exist on the network.
type ProtoMessagePeer struct {
	AddressType byte   `msgpack:"AT"`
	Protocol    byte   `msgpack:"Pr"`
	IP          []byte `msgpack:"IP"`
	Port        int    `msgpack:"Po"`
	Zone        string `msgpack:"Z"`
}
