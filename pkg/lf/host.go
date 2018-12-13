package lf

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"net"

	"github.com/vmihailenco/msgpack"
)

// packedAddress is an IP and port packed into a uint64 array to use as a key in a map
type packedAddress [3]uint64

func (p *packedAddress) set(a *net.UDPAddr) {
	(*p)[0] = (uint64(a.Port) << 48) | (uint64(len(a.Zone)) << 8) | uint64(len(a.IP))
	if len(a.IP) == 4 {
		(*p)[1] = 0
		(*p)[2] = uint64(binary.LittleEndian.Uint32(a.IP))
	} else if len(a.IP) == 16 {
		(*p)[1] = binary.LittleEndian.Uint64(a.IP[0:8])
		(*p)[2] = binary.LittleEndian.Uint64(a.IP[8:16])
	} else {
		(*p)[1] = 0
		(*p)[2] = 0
	}
}

// Host represents a remote host speaking the LF peer-to-peer UDP protocol.
type Host struct {
	packedAddress packedAddress

	LastSentPing       uint64
	LastReceivedPing   uint64
	LastReceivedPong   uint64
	LastSend           uint64
	LastReceive        uint64
	FirstSend          uint64
	FirstReceive       uint64
	TotalBytesSent     uint64
	TotalBytesReceived uint64
	Subscriptions      uint64
	RemoteAddress      net.UDPAddr
	Latency            int
}

func (h *Host) handleIncomingPacket(n *Node, data []byte) error {
	r := bytes.NewReader(data)

	for {
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

		now := TimeMs()

		switch messageType {

		case ProtoMessageTypePing:
			if messageSize >= 8 && (now-h.LastReceivedPing) <= ProtoMinPingResponseInterval {
				h.LastReceivedPing = now
				msg := data[messageStart : messageStart+messageSize]

				var pong [57]byte
				copy(pong[1:9], msg[0:8])
				s384 := sha512.Sum384(msg)
				copy(pong[9:57], s384[:])
				pong[0] = byte(ProtoMessageTypePong) // type, no size == one message per packet

				h.LastSend = now
				_, err = n.udpSocket.WriteToUDP(pong[:], &h.RemoteAddress)
				if err == nil {
					return err
				}
			}

		case ProtoMessageTypePong:

		case ProtoMessageTypePeer:
			var peer ProtoMessagePeer
			mr := msgpack.NewDecoder(r)
			err = mr.Decode(&peer)
			if err != nil {
				return err
			}

		case ProtoMessageTypeRecord:
			if messageSize >= RecordMinSize && messageSize <= RecordMaxSize {
			}

		case ProtoMessageTypeRequestByHash:
			if messageSize == 32 {
			}
		}

		if !multipleMessages {
			break
		}
	}

	return nil
}
