/*
 * Copyright (c)2019 ZeroTier, Inc.
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file in the project's root directory.
 *
 * Change Date: 2023-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2.0 of the Apache License.
 */
/****/

package lf

// This is the P2P protocol parts of Node, see node.go for main object.

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// p2pProtoMaxMessageSize is a sanity check maximum message size for the P2P TCP protocol.
	// It prevents a huge message from causing a huge memory allocation. It can be increased.
	p2pProtoMaxMessageSize = 131072

	// p2pProtoModeAES256GCMECCP384 indicates our simple AES-256 GCM encrypted stream protocol with ECDH key exchange.
	p2pProtoModeAES256GCMECCP384 byte = 1

	p2pProtoMessageTypeNop                  byte = 0 // no operation
	p2pProtoMessageTypeHello                byte = 1 // peerHelloMsg (JSON)
	p2pProtoMessageTypeRecord               byte = 2 // binary marshaled Record
	p2pProtoMessageTypeRequestRecordsByHash byte = 3 // one or more 32-byte hashes we want
	p2pProtoMessageTypeHaveRecords          byte = 4 // one or more 32-byte hashes we have
	p2pProtoMessageTypePeer                 byte = 5 // Peer (JSON)
	p2pProtoMessageTypePulse                byte = 6 // 11-byte pulse

	// p2pProtoMaxRetries is the maximum number of times we'll try to retry a record
	p2pProtoMaxRetries = 256

	// p2pDesiredConnectionCount is how many P2P TCP connections we want to have open
	p2pDesiredConnectionCount = 32

	// Minimum interval between peer connection attempts
	p2pPeerAttemptInterval = 60

	// P2P connection attempt timeout in seconds
	p2pPeerConnectTimeout = 10

	// Maximum unsuccessful reconnection attempts before a peer is forgotten
	p2pPeerMaxAttempts = 30
)

// var p2pProtoMessageNames = []string{"Nop", "Hello", "Record", "RequestRecordsByHash", "HaveRecords", "Peer"}

// peerHelloMsg is a JSON message used to say 'hello' to other nodes via the P2P protocol.
type peerHelloMsg struct {
	ProtocolVersion       int
	MinProtocolVersion    int
	Version               [4]int
	SoftwareName          string
	P2PPort               int
	SubscribeToNewRecords bool // If true, peer wants new records
}

// connectedPeer represents a single TCP connection to another peer using the LF P2P TCP protocol
type connectedPeer struct {
	n              *Node                // Node that owns this peer
	address        string               // Address in string format
	tcpAddress     *net.TCPAddr         // IP and port
	c              *net.TCPConn         // TCP connection to this peer
	cryptor        cipher.AEAD          // AES-GCM instance
	hasRecords     map[[32]byte]uintptr // Record this peer has recently reported that it has or has sent
	hasRecordsLock sync.Mutex           //
	sendLock       sync.Mutex           // Locked while a send is in progress
	outgoingNonce  [16]byte             // Outgoing nonce (incremented for each message)
	identity       []byte               // Remote node's identity (public key)
	peerHelloMsg   peerHelloMsg         // Hello message received from peer
	inbound        bool                 // True if this is an incoming connection
}

// knownPeer contains info about a peer we know about via another peer or the API
type knownPeer struct {
	Peer

	FirstConnect              uint64 // Time (seconds) of first connection to this peer at this endpoint
	LastSuccessfulConnection  uint64 // Time (seconds) of most recent successful connection
	LastReconnectionAttempt   uint64 // Time (seconds) of most recent connection attempt (zeroed on success)
	TotalReconnectionAttempts int    // Total connection attempts (zeroed on success)
}

// updateKnownPeersOnConnectSuccess is called from p2pConnectionHandler to update n.knownPeers.
func (n *Node) updateKnownPeersOnConnectSuccess(ip net.IP, port int, identity []byte) {
	if len(identity) == 0 {
		return
	}
	if bytes.Equal(n.identity, identity) {
		return
	}

	n.knownPeersLock.Lock()
	defer n.knownPeersLock.Unlock()

	now := TimeSec()
	idStr := Base62Encode(identity)
	kp := n.knownPeers[idStr]
	if kp == nil {
		n.knownPeers[idStr] = &knownPeer{
			Peer: Peer{
				IP:       ip,
				Port:     port,
				Identity: identity,
			},
			FirstConnect:              now,
			LastSuccessfulConnection:  now,
			LastReconnectionAttempt:   0,
			TotalReconnectionAttempts: 0,
		}
	} else {
		if kp.IP.Equal(ip) && kp.Port == port {
			if kp.FirstConnect == 0 {
				kp.FirstConnect = now
			}
			kp.LastSuccessfulConnection = now
		} else {
			kp.IP = ip
			kp.Port = port
			kp.FirstConnect = now
			kp.LastSuccessfulConnection = now
		}
		kp.LastReconnectionAttempt = 0
		kp.TotalReconnectionAttempts = 0
	}
}

// writeKnownPeers writes the current known peer list
func (n *Node) writeKnownPeers() {
	n.knownPeersLock.Lock()
	defer n.knownPeersLock.Unlock()

	for knownPeerID, kp := range n.knownPeers {
		if kp.TotalReconnectionAttempts > p2pPeerMaxAttempts {
			delete(n.knownPeers, knownPeerID)
		}
	}

	_ = ioutil.WriteFile(n.peersFilePath, []byte(PrettyJSON(&n.knownPeers)), 0644)
}

// sendPeerAnnouncement sends a peer announcement to this peer for the given address and public key
func (p *connectedPeer) sendPeerAnnouncement(tcpAddr *net.TCPAddr, identity []byte) {
	var peerMsg Peer
	peerMsg.IP = tcpAddr.IP
	peerMsg.Port = tcpAddr.Port
	peerMsg.Identity = identity
	peerMsgJson, err := json.Marshal(&peerMsg)
	if err != nil {
		return
	}
	pa := make([]byte, 1, len(peerMsgJson)+1)
	pa[0] = p2pProtoMessageTypePeer
	pa = append(pa, peerMsgJson...)
	p.send(pa)
}

// send sends a message to a peer (message must be prefixed by type byte)
func (p *connectedPeer) send(msg []byte) {
	if len(msg) < 1 {
		return
	}
	p.sendLock.Lock()
	go func() {
		defer func() {
			if recover() != nil {
				if p.c != nil {
					_ = p.c.Close()
				}
			}
			p.sendLock.Unlock()
		}()

		buf := make([]byte, 10, len(msg)+32)
		buf = buf[0:binary.PutUvarint(buf, uint64(len(msg)))]

		for i := 0; i < 12; i++ { // 12 == GCM nonce size
			p.outgoingNonce[i]++
			if p.outgoingNonce[i] != 0 {
				break
			}
		}

		buf = p.cryptor.Seal(buf, p.outgoingNonce[0:12], msg, nil)
		if p.c != nil {
			_ = p.c.SetWriteDeadline(time.Now().Add(time.Second * 30))
			_, err := p.c.Write(buf)
			if err != nil {
				_ = p.c.Close()
			}
		}
	}()
}

func (n *Node) p2pConnectionHandler(c *net.TCPConn, identity []byte, inbound bool) {
	var err error
	var p *connectedPeer

	tcpAddr, tcpAddrOk := c.RemoteAddr().(*net.TCPAddr)
	if tcpAddr == nil || !tcpAddrOk {
		n.log[LogLevelWarning].Print("BUG: P2P connection RemoteAddr() did not return a TCPAddr object, connection closed")
		_ = c.Close()
		return
	}
	peerAddressStr := tcpAddr.String()

	defer func() {
		e := recover()
		if e != nil {
			n.log[LogLevelWarning].Printf("WARNING: P2P connection to %s closed: caught panic: %v", peerAddressStr, e)
		}

		_ = c.Close()

		n.connectionsInStartupLock.Lock()
		delete(n.connectionsInStartup, c)
		n.connectionsInStartupLock.Unlock()

		n.peersLock.Lock()
		if p != nil {
			j := 0
			for i := 0; i < len(n.peers); i++ {
				if n.peers[i] != p {
					if i != j {
						n.peers[j] = n.peers[i]
					}
					j++
				}
			}
			if j < len(n.peers) {
				n.peers[j] = nil
				n.peers = n.peers[0:j]
			}
		}
		n.peersLock.Unlock()

		n.backgroundThreadWG.Done()
	}()

	n.connectionsInStartupLock.Lock()
	n.connectionsInStartup[c] = true
	n.connectionsInStartupLock.Unlock()

	_ = c.SetKeepAlivePeriod(time.Second * 10)
	_ = c.SetKeepAlive(true)
	_ = c.SetLinger(0)
	_ = c.SetNoDelay(false)
	reader := bufio.NewReader(c)

	// Send our public key to remote.
	helloMessage := make([]byte, len(n.identity)+2)
	helloMessage[0] = p2pProtoModeAES256GCMECCP384
	helloMessage[1] = byte(len(n.identity))
	copy(helloMessage[2:], n.identity)
	_ = c.SetWriteDeadline(time.Now().Add(time.Second * 30))
	_, err = c.Write(helloMessage)
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}

	// Read remote public key
	_ = c.SetReadDeadline(time.Now().Add(time.Second * 30))
	_, err = io.ReadFull(reader, helloMessage[0:2])
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	if helloMessage[0] != p2pProtoModeAES256GCMECCP384 || helloMessage[1] == 0 {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: protocol mode not supported or invalid key length", peerAddressStr)
		return
	}
	remoteIdentity := make([]byte, uint(helloMessage[1]))
	_ = c.SetReadDeadline(time.Now().Add(time.Second * 30))
	_, err = io.ReadFull(reader, remoteIdentity)
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	if bytes.Equal(remoteIdentity, n.identity) {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: other side has same identity!", peerAddressStr)
		return
	}
	if !inbound && !bytes.Equal(identity, remoteIdentity) {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: remote identity (public key) does not match expected identity", peerAddressStr)
		return
	}
	helloMessage = nil

	// Perform ECDH key agreement and init encryption
	remotePubX, remotePubY, err := ECCDecompressPublicKey(elliptic.P384(), remoteIdentity)
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: invalid public key: %s", peerAddressStr, err.Error())
		return
	}
	remoteShared, err := ECDHAgreeECDSA(remotePubX, remotePubY, n.owner.Private.(*ecdsa.PrivateKey))
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: key agreement failed: %s", peerAddressStr, err.Error())
		return
	}
	for i := 0; i < 32; i++ {
		remoteShared[i] ^= n.genesisParameters.ID[i] // mangle link key with ID to avoid talking to peers not in our network
	}
	aesCipher, _ := aes.NewCipher(remoteShared[:])
	cryptor, _ := cipher.NewGCM(aesCipher)

	// Exchange encrypted nonces (16 bytes are exchanged due to AES block size but only 12 bytes are used for AES-GCM)
	// Technically encryption of the nonce is not required, but why not?
	var nonceExchangeTmp, outgoingNonce, incomingNonce [16]byte
	_, err = secureRandom.Read(outgoingNonce[:])
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	aesCipher.Encrypt(nonceExchangeTmp[:], outgoingNonce[:])
	_ = c.SetWriteDeadline(time.Now().Add(time.Second * 30))
	_, err = c.Write(nonceExchangeTmp[:])
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second * 30))
	_, err = io.ReadFull(reader, incomingNonce[:])
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	aesCipher.Decrypt(incomingNonce[:], incomingNonce[:])

	// Exchange hashes of decrypted nonces to verify correct key.
	outgoingNonceHash, incomingNonceHash := sha256.Sum256(outgoingNonce[:]), sha256.Sum256(incomingNonce[:])
	_ = c.SetWriteDeadline(time.Now().Add(time.Second * 30))
	_, err = c.Write(incomingNonceHash[0:16])
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second * 30))
	_, err = io.ReadFull(reader, nonceExchangeTmp[:])
	if !bytes.Equal(outgoingNonceHash[0:16], nonceExchangeTmp[:]) {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: challenge/response failed (key incorrect?)", peerAddressStr)
		return
	}

	p = &connectedPeer{
		n:             n,
		address:       peerAddressStr,
		tcpAddress:    tcpAddr,
		c:             c,
		cryptor:       cryptor,
		hasRecords:    make(map[[32]byte]uintptr),
		outgoingNonce: outgoingNonce,
		identity:      remoteIdentity,
		inbound:       inbound,
	}

	msgbuf, err := json.Marshal(&peerHelloMsg{
		ProtocolVersion:       ProtocolVersion,
		MinProtocolVersion:    MinProtocolVersion,
		Version:               Version,
		SoftwareName:          SoftwareName,
		P2PPort:               n.p2pPort,
		SubscribeToNewRecords: true,
	})
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	p.send(append([]byte{p2pProtoMessageTypeHello}, msgbuf...))

	n.peersLock.Lock()
	for _, existingPeer := range n.peers {
		if bytes.Equal(existingPeer.identity, remoteIdentity) {
			n.log[LogLevelNormal].Printf("P2P connection to %s closed: replaced by new link %s to same peer", existingPeer.tcpAddress.String(), peerAddressStr)
			_ = existingPeer.c.Close()
		} else {
			if !inbound {
				existingPeer.sendPeerAnnouncement(tcpAddr, p.identity)
			}
			if !existingPeer.inbound {
				p.sendPeerAnnouncement(existingPeer.tcpAddress, existingPeer.identity)
			}
		}
	}
	n.peers = append(n.peers, p)
	n.peersLock.Unlock()

	n.connectionsInStartupLock.Lock()
	delete(n.connectionsInStartup, c)
	n.connectionsInStartupLock.Unlock()

	if !inbound {
		n.updateKnownPeersOnConnectSuccess(tcpAddr.IP, tcpAddr.Port, remoteIdentity)
	}

	n.log[LogLevelNormal].Printf("P2P connection established to %s %d %s", tcpAddr.IP.String(), tcpAddr.Port, Base62Encode(remoteIdentity))

	performedInboundReachabilityTest := false
mainReaderLoop:
	for atomic.LoadUint32(&n.shutdown) == 0 {
		_ = c.SetReadDeadline(time.Now().Add(time.Second * 120))

		// Read size of message (varint)
		msgSize, err := binary.ReadUvarint(reader)
		if err != nil {
			n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
			break
		}
		if msgSize == 0 || msgSize > p2pProtoMaxMessageSize {
			n.log[LogLevelNormal].Printf("P2P connection to %s closed: invalid message size", peerAddressStr)
			break
		}

		if atomic.LoadUint32(&n.shutdown) != 0 {
			break
		}

		// Read message and 16-byte GCM tag
		if len(msgbuf) < int(msgSize)+16 {
			bs := uint(msgSize) + 16
			bs /= 4096
			bs++
			bs *= 4096
			msgbuf = make([]byte, bs)
		}
		msg := msgbuf[0 : uint(msgSize)+16]
		_, err = io.ReadFull(reader, msg)
		if err != nil {
			n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
			break
		}

		if atomic.LoadUint32(&n.shutdown) != 0 {
			break
		}

		// Increment incoming nonce to match sending side
		for i := 0; i < 12; i++ {
			incomingNonce[i]++
			if incomingNonce[i] != 0 {
				break
			}
		}

		// Decrypt and authenticate message
		msg, err = p.cryptor.Open(msg[:0], incomingNonce[0:12], msg, nil)
		if err != nil {
			n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
			break
		}
		if len(msg) < 1 {
			n.log[LogLevelNormal].Printf("P2P connection to %s closed: invalid message size", peerAddressStr)
			break
		}
		fullMsg := msg
		incomingMessageType := msg[0]
		msg = msg[1:]

		switch incomingMessageType {

		case p2pProtoMessageTypeHello:
			if len(msg) > 0 {
				err := json.Unmarshal(msg, &p.peerHelloMsg)
				if err != nil {
					n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
					break mainReaderLoop
				}

				// Test inbound connections for reachability in the opposite direction, and
				// if they are reachable learn them and announce them. This helps the network
				// as a whole learn new node addresses automatically.
				if inbound && p.peerHelloMsg.P2PPort > 0 && !performedInboundReachabilityTest {
					performedInboundReachabilityTest = true
					n.backgroundThreadWG.Add(1)
					go func() {
						testAddr := &net.TCPAddr{
							IP:   tcpAddr.IP,
							Port: p.peerHelloMsg.P2PPort,
						}
						testConn, err := net.DialTimeout("tcp", testAddr.String(), time.Second*5)
						if testConn != nil && err == nil {
							n.log[LogLevelVerbose].Printf("reverse reachability test to port %d successful for inbound connection from %s", p.peerHelloMsg.P2PPort, tcpAddr.IP.String())
							n.updateKnownPeersOnConnectSuccess(tcpAddr.IP, p.peerHelloMsg.P2PPort, remoteIdentity)
							if atomic.LoadUint32(&n.shutdown) == 0 {
								n.peersLock.RLock()
								for _, otherPeer := range n.peers {
									if &otherPeer != &p {
										otherPeer.sendPeerAnnouncement(testAddr, p.identity)
									}
								}
								n.peersLock.RUnlock()
							}
							_ = testConn.Close()
						} else {
							n.log[LogLevelVerbose].Printf("reverse reachability test to port %d unsuccessful for inbound connection from %s", p.peerHelloMsg.P2PPort, tcpAddr.IP.String())
						}
						n.backgroundThreadWG.Done()
					}()
				}
			}

		case p2pProtoMessageTypeRecord:
			if len(msg) > 0 {
				rec, err := NewRecordFromBytes(msg)
				if err == nil {
					rh := rec.Hash()
					p.hasRecordsLock.Lock()
					p.hasRecords[rh] = atomic.LoadUintptr(&n.timeTicker)
					p.hasRecordsLock.Unlock()
					_ = n.addRemoteRecord(msg, rh[:], rec, tcpAddr.IP.String())
				}
			}

		case p2pProtoMessageTypeRequestRecordsByHash:
			for len(msg) >= 32 {
				rdata := make([]byte, 1, 2048)
				rdata[0] = p2pProtoMessageTypeRecord
				_, rdata, err = n.db.getDataByHash(msg[0:32], rdata)
				if err == nil && len(rdata) > 1 {
					p.send(rdata)
				}
				msg = msg[32:]
			}

		case p2pProtoMessageTypeHaveRecords:
			for len(msg) >= 32 {
				req := make([]byte, 1, 1+len(msg))
				req[0] = p2pProtoMessageTypeRequestRecordsByHash
				var h [32]byte
				copy(h[:], msg[0:32])
				msg = msg[32:]

				n.log[LogLevelTrace].Printf("have record notification for =%s from %s", Base62Encode(h[:]), tcpAddr.IP.String())

				ticker := atomic.LoadUintptr(&n.timeTicker)
				p.hasRecordsLock.Lock()
				p.hasRecords[h] = ticker
				p.hasRecordsLock.Unlock()

				if n.db.haveRecordIncludeLimbo(h[:]) {
					n.log[LogLevelTrace].Printf("not requesting =%s from %s: already have record", Base62Encode(h[:]), tcpAddr.IP.String())
				} else {
					n.recordsRequestedLock.Lock()
					if (ticker - n.recordsRequested[h]) <= 2 {
						n.recordsRequestedLock.Unlock()
						n.log[LogLevelTrace].Printf("not requesting =%s from %s: recently requested", Base62Encode(h[:]), tcpAddr.IP.String())
						continue
					}
					n.recordsRequested[h] = ticker
					n.recordsRequestedLock.Unlock()

					req = append(req, h[:]...)
					if len(req) >= (p2pProtoMaxMessageSize - 64) {
						p.send(req)
						req = req[0:1]
					}
				}
				if len(req) > 1 {
					p.send(req)
				}
			}

		case p2pProtoMessageTypePeer:
			if len(msg) > 0 {
				var peerMsg Peer
				if json.Unmarshal(msg, &peerMsg) == nil {
					if len(peerMsg.Identity) > 0 {
						n.peersLock.RLock()
						connectionCount := len(n.peers)
						n.peersLock.RUnlock()
						n.connectionsInStartupLock.Lock()
						connectionCount += len(n.connectionsInStartup) // include this to prevent flooding attacks
						n.connectionsInStartupLock.Unlock()
						if connectionCount < p2pDesiredConnectionCount {
							_ = n.Connect(peerMsg.IP, peerMsg.Port, peerMsg.Identity)
						}
					}
				}
			}

		case p2pProtoMessageTypePulse:
			if len(msg) == 11 {
				if ok, _ := n.DoPulse(msg, false); ok {
					n.peersLock.RLock()
					for _, otherPeer := range n.peers {
						if &otherPeer != &p {
							otherPeer.send(fullMsg)
						}
					}
					n.peersLock.RUnlock()
				}
			}

		} // switch incomingMessageType

		// Note: continue is used in a few places above, so anything placed here may not
		// execute on every loop unless that logic is changed.
	}
}
