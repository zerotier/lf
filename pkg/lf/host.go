package lf

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
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
	packedAddress           packedAddress
	queueWaitingForPong     [][]byte
	queueWaitingForPongLock sync.Mutex

	LastSentPing       uint64
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

func (h *Host) handleIncomingPacket(data []byte) error {
	r := bytes.NewReader(data)

	typeAndSize, err := binary.ReadUvarint(r)
	if err != nil {
		return err
	}

	messageType := int(typeAndSize & 31)
	messageSize := int(typeAndSize >> 5)
	multipleMessages := true
	if messageSize <= 0 { // if the very first size is zero, the packet contains only one message filling its remaining size
		messageSize = r.Len()
		multipleMessages = false
	}

	for {
		switch messageType {
		case ProtoMessageTypePing:
		case ProtoMessageTypePong:
		case ProtoMessageTypePeer:
		case ProtoMessageTypeRecord:
			if messageSize >= RecordMinSize && messageSize <= RecordMaxSize {
			}
		case ProtoMessageTypeRequestByHash:
			if messageSize == 32 {
			}
		}

		if multipleMessages {
			typeAndSize, err = binary.ReadUvarint(r)
			if err != nil {
				return err
			}
			messageType = int(typeAndSize & 31)
			messageSize = int(typeAndSize >> 5)
			if messageSize <= 0 {
				break
			}
		} else {
			break
		}
	}

	return nil
}
