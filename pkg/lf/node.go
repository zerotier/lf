/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	secrand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NYTimes/gziphandler"
)

const (
	// p2pProtoMaxMessageSize is a sanity check maximum message size for the P2P TCP protocol.
	// It prevents a huge message from causing a huge memory allocation. It can be increased.
	p2pProtoMaxMessageSize = 262144

	// p2pProtoModeAES256CFBECCP384 indicates our simple ECC P-384 AES-256-CFB encrypted binary
	// wire protocol between nodes. Other IDs could be used in the future to select new ones.
	p2pProtoModeAES256CFBECCP384 byte = 1

	p2pProtoMessageTypeRecord               byte = 1 // binary marshaled Record
	p2pProtoMesaggeTypeRequestRecordsByHash byte = 2 // one or more 32-byte hashes we want
	p2pProtoMessageTypeHaveRecords          byte = 3 // one or more 32-byte hashes we have
	p2pProtoMessageTypePeer                 byte = 4 // <[uint16] port><[byte] type><[4-16] IP>[<public key>]
)

type peer struct {
	c               *net.TCPConn        // TCP connection to this peer
	w               cipher.StreamWriter // Encryptor for outgoing bytes
	r               cipher.StreamReader // Decryptor for incoming bytes
	hasRecords      map[[32]byte]uint64 // Record this peer has recently reported that it has or has sent
	hasRecordsLock  sync.Mutex          //
	inbound         bool                // True if this is an incoming connection
	remotePublicKey []byte              // Remote public key
}

// Node is an instance of LF
type Node struct {
	logger               *log.Logger
	linkKeyPriv          []byte
	linkKeyPubX          *big.Int
	linkKeyPubY          *big.Int
	linkKeyPub           []byte
	peers                map[string]*peer
	peersLock            sync.RWMutex
	httpTCPListener      *net.TCPListener
	httpServer           *http.Server
	p2pTCPListener       *net.TCPListener
	db                   db
	backgroundThreadWG   sync.WaitGroup
	lastSynchronizedTime uint64
	startTime            uint64
	shutdown             uintptr
}

// NewNode creates and starts a node.
func NewNode(path string, p2pPort int, httpPort int, logger *log.Logger) (*Node, error) {
	var err error
	n := new(Node)

	if logger == nil {
		n.logger = log.New(ioutil.Discard, "", log.LstdFlags)
	} else {
		n.logger = logger
	}

	priv, px, py, err := elliptic.GenerateKey(elliptic.P384(), secrand.Reader)
	if err != nil {
		return nil, err
	}
	n.linkKeyPriv = priv
	n.linkKeyPubX = px
	n.linkKeyPubY = py
	n.linkKeyPub, err = ECCCompressPublicKey(elliptic.P384(), px, py)
	if err != nil {
		return nil, err
	}

	n.peers = make(map[string]*peer)

	var ta net.TCPAddr
	ta.Port = httpPort
	n.httpTCPListener, err = net.ListenTCP("tcp", &ta)
	if err != nil {
		return nil, err
	}
	n.httpServer = &http.Server{
		MaxHeaderBytes: 4096,
		Handler:        gziphandler.GzipHandler(apiCreateHTTPServeMux(n)),
		IdleTimeout:    10 * time.Second,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   60 * time.Second}
	n.httpServer.SetKeepAlivesEnabled(true)

	ta.Port = p2pPort
	n.p2pTCPListener, err = net.ListenTCP("tcp", &ta)
	if err != nil {
		n.httpTCPListener.Close()
		return nil, err
	}

	err = n.db.open(path, logger)
	if err != nil {
		n.httpTCPListener.Close()
		n.p2pTCPListener.Close()
		return nil, err
	}

	n.backgroundThreadWG.Add(1)
	go func() {
		defer n.backgroundThreadWG.Done()
		for atomic.LoadUintptr(&n.shutdown) == 0 {
			c, _ := n.p2pTCPListener.AcceptTCP()
			if c != nil {
				n.backgroundThreadWG.Add(1)
				go p2pConnectionHandler(n, c, nil, true)
			}
		}
	}()

	n.backgroundThreadWG.Add(1)
	go func() {
		defer n.backgroundThreadWG.Done()
		n.httpServer.Serve(n.httpTCPListener)
		n.httpServer.Close()
	}()

	n.backgroundThreadWG.Add(1)
	go func() {
		defer n.backgroundThreadWG.Done()
		var lastCleanedPeerHasRecords, lastCheckedSync uint64
		for atomic.LoadUintptr(&n.shutdown) == 0 {
			time.Sleep(time.Millisecond * 250)
			now := TimeMs()

			// Clean peer "has record" map entries older than 5 minutes. Scan every minute.
			if (now - lastCleanedPeerHasRecords) > 60000 {
				lastCleanedPeerHasRecords = now
				n.peersLock.RLock()
				for _, p := range n.peers {
					p.hasRecordsLock.Lock()
					for h, ts := range p.hasRecords {
						if (now - ts) > 300000 {
							delete(p.hasRecords, h)
						}
					}
					p.hasRecordsLock.Unlock()
				}
				n.peersLock.RUnlock()
			}

			// Check every second to see if the database is in a fully synchronized (has records
			// and all record links are satisfied) state.
			if (now - lastCheckedSync) > 1000 {
				lastCheckedSync = now
				if !n.db.hasPending() {
					n.lastSynchronizedTime = now
				}
			}
		}
	}()

	return n, nil
}

// Stop terminates the running node. No methods should be called after this.
func (n *Node) Stop() {
	atomic.StoreUintptr(&n.shutdown, 1)
	n.httpServer.Close()
	n.p2pTCPListener.Close()
	n.peersLock.RLock()
	for _, p := range n.peers {
		p.c.Close()
	}
	n.peersLock.RUnlock()
	n.backgroundThreadWG.Wait()
	n.db.close()
	WharrgarblFreeGlobalMemory()
}

// Connect attempts to establish a peer-to-peer connection to a remote node.
// If the status callback is non-nil it gets called when the connection either succeeds
// (with a nil error) or fails (with an error). ErrorAlreadyConnected is returned if
// a connection already exists to this endpoint. If publicKey is non-empty it allows
// an expected (pinned) public key to be specified and the connection will be rejected
// if this key does not match.
func (n *Node) Connect(ip net.IP, port int, publicKey []byte, statusCallback func(error)) {
	n.backgroundThreadWG.Add(1)
	go func() {
		defer n.backgroundThreadWG.Done()

		var ta net.TCPAddr
		ta.IP = ip
		ta.Port = port

		n.peersLock.RLock()
		if n.peers[ta.String()] != nil {
			n.peersLock.RUnlock()
			if statusCallback != nil {
				statusCallback(ErrorAlreadyConnected)
			}
			return
		}
		n.peersLock.RUnlock()

		c, err := net.DialTCP("tcp", nil, &ta)
		if atomic.LoadUintptr(&n.shutdown) == 0 {
			if err == nil {
				n.backgroundThreadWG.Add(1)
				go p2pConnectionHandler(n, c, publicKey, false)
				if statusCallback != nil {
					statusCallback(nil)
				}
			} else {
				if statusCallback != nil {
					statusCallback(err)
				}
			}
		} else if err != nil {
			c.Close()
		}
	}()
}

// AddRecord adds a record to the database if it's valid and we do not already have it.
// If the record is new we announce that we have it to connected peers. This happens asynchronously.
func (n *Node) AddRecord(r *Record) error {
	if r == nil {
		return ErrorInvalidParameter
	}

	rhash := *r.Hash()

	// Check to see if this is a redundant record.
	if n.db.hasRecord(rhash[:]) {
		return ErrorDuplicateRecord
	}

	// Validate record's internal structure and check signatures and work.
	err := r.Validate()
	if err != nil {
		return err
	}

	// Add record to database, aborting if this generates some kind of error.
	err = n.db.putRecord(r, 0)
	if err != nil {
		return err
	}

	// Announce that we have this record to connected peers that haven't informed us that
	// they have it or sent it to us. If they don't have it they will request it.
	n.backgroundThreadWG.Add(1)
	go func() {
		defer func() {
			n.backgroundThreadWG.Done()
		}()

		msg := make([]byte, 40)
		msg[0] = p2pProtoMessageTypeHaveRecords
		msg[3] = 32 // msg[1:4] is a big-endian 24-bit length
		binary.BigEndian.PutUint32(msg[4:8], crc32.ChecksumIEEE(rhash[:]))
		copy(msg[4:], rhash[:])

		n.peersLock.RLock()
		for _, p := range n.peers {
			p.hasRecordsLock.Lock()
			_, hasRecord := p.hasRecords[rhash]
			p.hasRecordsLock.Unlock()
			if !hasRecord {
				if _, err := p.w.Write(msg); err != nil {
					p.c.Close()
				}
			}
		}
		n.peersLock.RUnlock()
	}()

	return nil
}

// Peers returns an array of peer description objects.
func (n *Node) Peers() (peers []APIStatusPeer) {
	n.peersLock.RLock()
	for a, p := range n.peers {
		peers = append(peers, APIStatusPeer{
			RemoteAddress: a,
			Inbound:       p.inbound,
		})
	}
	n.peersLock.RUnlock()
	return
}

func p2pConnectionHandler(n *Node, c *net.TCPConn, expectedPublicKey []byte, inbound bool) {
	peerAddressStr := c.RemoteAddr().String()

	defer func() {
		e := recover()
		if e != nil {
			n.logger.Printf("P2P connection to %s closed: caught panic: %v", peerAddressStr, e)
		}

		n.peersLock.Lock()
		delete(n.peers, peerAddressStr)
		n.peersLock.Unlock()

		n.backgroundThreadWG.Done()
	}()

	tcpAddr := c.RemoteAddr().(*net.TCPAddr)

	c.SetKeepAlivePeriod(time.Second * 30)
	c.SetKeepAlive(true)
	c.SetLinger(0)
	c.SetNoDelay(false)

	helloMessage := make([]byte, len(n.linkKeyPub)+18)
	_, err := secrand.Read(helloMessage[0:16])
	if err != nil {
		n.logger.Printf("P2P connection to %s closed: unable to read from secure random source", peerAddressStr)
		return
	}
	helloMessage[16] = p2pProtoModeAES256CFBECCP384
	helloMessage[17] = byte(len(n.linkKeyPub))
	copy(helloMessage[18:], n.linkKeyPub)
	_, err = c.Write(helloMessage)
	if err != nil {
		n.logger.Printf("P2P connection to %s closed: unable to write hello message", peerAddressStr)
		return
	}

	p := peer{c: c, hasRecords: make(map[[32]byte]uint64), inbound: inbound}

	var remoteHelloHdr [18]byte
	_, err = io.ReadFull(c, remoteHelloHdr[0:18])
	if err != nil {
		n.logger.Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	if remoteHelloHdr[16] != p2pProtoModeAES256CFBECCP384 || remoteHelloHdr[17] == 0 {
		n.logger.Printf("P2P connection to %s closed: protocol mode not supported (%d with key length %d)", peerAddressStr, uint(remoteHelloHdr[16]), uint(remoteHelloHdr[17]))
		return
	}
	rpk := make([]byte, uint(remoteHelloHdr[17]))
	_, err = io.ReadFull(c, rpk)
	if err != nil {
		n.logger.Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	if bytes.Equal(rpk, n.linkKeyPub) {
		n.logger.Printf("P2P connection to %s closed: detected connection to self!", peerAddressStr)
		return
	}
	if len(expectedPublicKey) > 0 && !bytes.Equal(expectedPublicKey, rpk) {
		n.logger.Printf("P2P connection to %s closed: remote public key does not match expected (pinned) public key", peerAddressStr)
		return
	}

	n.peersLock.Lock()
	for _, p2 := range n.peers {
		if len(p2.remotePublicKey) > 0 && bytes.Equal(p2.remotePublicKey, p.remotePublicKey) {
			n.logger.Printf("P2P connection to %s closed: redundant connection to already linked peer", peerAddressStr)
			n.peersLock.Unlock()
			return
		}
	}
	n.peers[peerAddressStr] = &p
	n.peersLock.Unlock()

	remotePubX, remotePubY, err := ECCDecompressPublicKey(elliptic.P384(), p.remotePublicKey)
	if err != nil {
		n.logger.Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	remoteShared, err := ECCAgree(elliptic.P384(), remotePubX, remotePubY, n.linkKeyPriv)
	if err != nil {
		n.logger.Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}

	aesCipher, _ := aes.NewCipher(remoteShared[:])
	p.r.S = cipher.NewCFBDecrypter(aesCipher, remoteHelloHdr[0:16])
	p.r.R = bufio.NewReaderSize(c, 131072)
	p.w.S = cipher.NewCFBEncrypter(aesCipher, helloMessage[0:16])
	p.w.W = c

	var verificationMessage [64]byte
	_, err = secrand.Read(verificationMessage[0:32])
	if err != nil {
		n.logger.Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	vmtmp := sha256.Sum256(verificationMessage[0:32])
	copy(verificationMessage[32:64], vmtmp[:])
	_, err = p.w.Write(verificationMessage[:])
	if err != nil {
		n.logger.Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	_, err = io.ReadFull(p.r, verificationMessage[:])
	if err != nil {
		n.logger.Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	vmtmp = sha256.Sum256(verificationMessage[0:32])
	if !bytes.Equal(verificationMessage[32:64], vmtmp[:]) {
		n.logger.Printf("P2P connection to %s closed: encryption key is incorrect", peerAddressStr)
		return
	}

	// Once we verify the link we enter a read loop where we read an 8-byte
	// message header followed by a message.
	var hdr [8]byte
	var msgbuf []byte
	announced := false
	for atomic.LoadUintptr(&n.shutdown) == 0 {
		_, err = io.ReadFull(p.r, hdr[:])
		if err != nil {
			n.logger.Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
			break
		}

		incomingMessageType := hdr[0]
		incomingMessageSize := (uint(hdr[1]) << 16) | (uint(hdr[2]) << 8) | uint(hdr[3])
		if incomingMessageSize > p2pProtoMaxMessageSize {
			n.logger.Printf("P2P connection to %s closed: message too large (%d > %d)", peerAddressStr, incomingMessageSize, p2pProtoMaxMessageSize)
			break
		}

		if incomingMessageSize > uint(len(msgbuf)) {
			mbs := incomingMessageSize
			mbs /= 4096
			mbs++
			mbs *= 4096
			msgbuf = make([]byte, mbs)
		}
		msg := msgbuf[0:incomingMessageSize]
		_, err = io.ReadFull(p.r, msg)
		if err != nil {
			n.logger.Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
			break
		}
		if atomic.LoadUintptr(&n.shutdown) != 0 {
			break
		}
		if crc32.ChecksumIEEE(msg) != binary.BigEndian.Uint32(hdr[4:8]) {
			n.logger.Printf("P2P connection to %s closed: CRC32 check failed", peerAddressStr)
			break
		}

		switch incomingMessageType {

		case p2pProtoMessageTypeRecord:
			rec, err := NewRecordFromBytes(msg)
			if err == nil {
				p.hasRecordsLock.Lock()
				p.hasRecords[*rec.Hash()] = TimeMs()
				p.hasRecordsLock.Unlock()
				n.AddRecord(rec)
			}

		case p2pProtoMesaggeTypeRequestRecordsByHash:
			for len(msg) >= 32 {
				_, rdata, err := n.db.getDataByHash(msg, nil)
				if err == nil && len(rdata) > 0 {
					hdr[0] = p2pProtoMessageTypeRecord
					putBE24(hdr[1:], uint(len(rdata)))
					binary.BigEndian.PutUint32(hdr[4:8], crc32.ChecksumIEEE(rdata))
					_, err = p.w.Write(hdr[:])
					if err != nil {
						n.logger.Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
						break
					}
					_, err = p.w.Write(rdata)
					if err != nil {
						n.logger.Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
						break
					}
				}
				msg = msg[32:]
			}

		case p2pProtoMessageTypeHaveRecords:
			var h [32]byte
			for len(msg) >= 32 {
				copy(h[:], msg[0:32])
				p.hasRecordsLock.Lock()
				p.hasRecords[h] = TimeMs()
				p.hasRecordsLock.Unlock()
				msg = msg[32:]
			}

		case p2pProtoMessageTypePeer:
			if len(msg) > 3 {
				port := binary.BigEndian.Uint16(msg[0:2])
				if msg[2] == 4 && len(msg) >= 7 {
					var publicKey []byte
					if len(msg) > 7 {
						publicKey = msg[7:]
					}
					n.Connect((net.IP)(msg[3:7]), int(port), publicKey, nil)
				} else if msg[2] == 6 && len(msg) >= 19 {
					var publicKey []byte
					if len(msg) > 19 {
						publicKey = msg[19:]
					}
					n.Connect((net.IP)(msg[3:19]), int(port), publicKey, nil)
				}
			}
		}
	}

	if inbound && !announced {
		announced = true

		var pabuf [27]byte
		var pa []byte
		pabuf[0] = p2pProtoMessageTypePeer
		ipv4 := tcpAddr.IP.To4()
		if len(ipv4) == 4 {
			pabuf[3] = 7 // size of IPv4 peer announcement message
			binary.BigEndian.PutUint16(pabuf[8:10], uint16(tcpAddr.Port))
			pabuf[10] = 4
			copy(pabuf[11:15], ipv4)
			binary.BigEndian.PutUint32(pabuf[4:8], crc32.ChecksumIEEE(pabuf[8:]))
			pa = pabuf[0:15]
		} else {
			ipv6 := tcpAddr.IP.To16()
			if len(ipv6) == 16 {
				pabuf[3] = 19
				binary.BigEndian.PutUint16(pabuf[8:10], uint16(tcpAddr.Port))
				pabuf[10] = 6
				copy(pabuf[11:27], ipv6)
				binary.BigEndian.PutUint32(pabuf[4:8], crc32.ChecksumIEEE(pabuf[8:]))
				pa = pabuf[0:27]
			}
		}

		if len(pa) > 0 {
			n.peersLock.RLock()
			for _, p2 := range n.peers {
				if p2 != &p {
					if _, err := p2.w.Write(pa); err != nil {
						p.c.Close()
					}
				}
			}
			n.peersLock.RUnlock()
		}
	}
}
