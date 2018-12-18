package lf

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"

	"github.com/vmihailenco/msgpack"
)

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

// ProtoTypeLFRawUDP indicates the raw UDP peer-to-peer protocol.
const ProtoTypeLFRawUDP = 0

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

// packedAddress is an IP and port packed into a uint64 array to use as a key in a map
type packedAddress [3]uint64

func (p *packedAddress) set(ip net.IP, port int) {
	(*p)[0] = (uint64(port) << 48) | uint64(len(ip))
	if len(ip) == 4 {
		(*p)[1] = 0
		(*p)[2] = uint64(binary.LittleEndian.Uint32(ip))
	} else if len(ip) == 16 {
		(*p)[1] = binary.LittleEndian.Uint64(ip[0:8])
		(*p)[2] = binary.LittleEndian.Uint64(ip[8:16])
	} else {
		(*p)[1] = 0
		(*p)[2] = 0
	}
}

// Host represents a remote host speaking the LF peer-to-peer UDP protocol.
type Host struct {
	packedAddress packedAddress
	lastPingHash  [48]byte // SHA384(last ping sent)

	queuedPeers          []*ProtoMessagePeer
	queuedRecordRequests [][32]byte
	queuedLock           sync.Mutex

	CreationTime       uint64
	LastSentPing       uint64
	LastReceivedPing   uint64
	LastReceivedPong   uint64
	LastSend           uint64
	LastReceive        uint64
	TotalBytesSent     uint64
	TotalBytesReceived uint64
	Subscriptions      uint64
	RemoteAddress      net.UDPAddr
	Latency            int
}

func (h *Host) doRecordRequest(recordHash []byte) (err error) {
	return nil
}

// handleIncomingPacket is called from Node's I/O code when UDP packets arrive.
func (h *Host) handleIncomingPacket(n *Node, data []byte) (err error) {
	defer func() {
		e := recover()
		if e != nil {
			err = fmt.Errorf("trapped unexpected error: %s", e)
		}
	}()

	r := bytes.NewReader(data)
	now := TimeMs()

	for r.Len() > 0 {
		typeAndSize, err := binary.ReadUvarint(r)
		if err != nil {
			return err
		}
		messageStart := len(data) - r.Len()
		messageType := int(typeAndSize & 31)
		messageSize := int(typeAndSize >> 5)
		multipleMessages := true
		if messageSize <= 0 { // if the very first size is zero, the packet contains only one message filling its remaining size
			messageSize = r.Len()
			multipleMessages = false
		}
		if messageStart+messageSize > len(data) {
			return errors.New("message incomplete")
		}

		switch messageType {

		case ProtoMessageTypePing:
			if messageSize >= 8 && (now-h.LastReceivedPing) <= ProtoMinPingResponseInterval {
				h.LastReceivedPing = now
				msg := data[messageStart : messageStart+messageSize]

				var pong [57]byte
				pong[0] = byte(ProtoMessageTypePong) // type, no size == one message per packet
				copy(pong[1:9], msg[0:8])
				s384 := sha512.Sum384(msg)
				copy(pong[9:57], s384[:])

				h.LastSend = now
				h.TotalBytesSent += uint64(len(pong))
				_, err = n.udpSocket.WriteToUDP(pong[:], &h.RemoteAddress)
				if err == nil {
					return err
				}
			}

		case ProtoMessageTypePong:
			if messageSize >= 56 {
				msg := data[messageStart : messageStart+messageSize]
				if bytes.Equal(msg[8:56], h.lastPingHash[:]) {
					ts := binary.BigEndian.Uint64(msg[0:8])
					if ts <= now && ts == h.LastSentPing {
						h.LastReceivedPong = now
						h.Latency = int(now - ts)

						// Do any queued things that are waiting for verification that this
						// peer really exists. This queueing exists to prevent the use of LF
						// nodes for amplification attacks.
						h.queuedLock.Lock()
						for i := range h.queuedPeers {
							n.Try(h.queuedPeers[i].IP, int(h.queuedPeers[i].Port))
						}
						h.queuedPeers = nil
						for i := range h.queuedRecordRequests {
							h.doRecordRequest(h.queuedRecordRequests[i][:])
						}
						h.queuedRecordRequests = nil
						h.queuedLock.Unlock()
					}
				}
			}

		case ProtoMessageTypePeer:
			var peer ProtoMessagePeer
			err = msgpack.NewDecoder(r).Decode(&peer)
			if err != nil {
				return err
			}
			if h.Connected() {
				n.Try(peer.IP, int(peer.Port))
			} else {
				h.queuedLock.Lock()
				if len(h.queuedPeers) < 1024 { // sanity limit
					h.queuedPeers = append(h.queuedPeers, &peer)
				}
				h.queuedLock.Unlock()
				h.Ping(n, false)
			}

		case ProtoMessageTypeRecord:
			if messageSize >= RecordMinSize {
				msg := data[messageStart : messageStart+messageSize]
				n.AddRecord(msg)
				if !h.Connected() {
					h.Ping(n, false)
				}
			}

		case ProtoMessageTypeRequestByHash:
			if messageSize == 32 {
				msg := data[messageStart : messageStart+messageSize]
				if h.Connected() {
					h.doRecordRequest(msg)
				} else {
					var rr [32]byte
					copy(rr[:], msg)
					h.queuedLock.Lock()
					if len(h.queuedRecordRequests) < 1024 { // sanity limit
						h.queuedRecordRequests = append(h.queuedRecordRequests, rr)
					}
					h.queuedLock.Unlock()
					h.Ping(n, false)
				}
			}

		}

		if !multipleMessages {
			break
		}
	}

	h.LastReceive = now
	h.TotalBytesReceived += uint64(len(data))

	return nil
}

// Connected returns true if this host has responded to a ping and was active within the timeout period.
func (h *Host) Connected() bool {
	return (h.LastReceivedPong > h.LastSentPing) && ((TimeMs() - h.LastReceive) < ProtoHostTimeout)
}

// Ping sends a ping message to the host. If force is not true this is only done if we haven't sent a ping in ProtoMinPingResponseInterval milliseconds.
func (h *Host) Ping(n *Node, force bool) error {
	ts := TimeMs()
	if force || (ts-h.LastSentPing) < ProtoMinPingResponseInterval {
		var ping [13]byte
		ping[0] = byte(ProtoMessageTypePing) // type, no size == one message per packet
		binary.BigEndian.PutUint64(ping[1:9], ts)
		binary.BigEndian.PutUint32(ping[9:13], uint32(rand.Int31()))
		h.lastPingHash = sha512.Sum384(ping[1:])
		h.LastSentPing = ts
		h.TotalBytesSent += uint64(len(ping))
		_, err := n.udpSocket.WriteToUDP(ping[:], &h.RemoteAddress)
		return err
	}
	return nil
}
