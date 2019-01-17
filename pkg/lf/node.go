/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"bytes"
	"io"
	"log"
	"net"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NYTimes/gziphandler"
)

const (
	// p2pProtoMaxMessageSize is a sanity check maximum message size for the P2P TCP protocol.
	// It prevents a huge message from causing a huge memory allocation. It can be increased.
	p2pProtoMaxMessageSize = 262144

	p2pProtoMessageTypeRecord               = byte(1)
	p2pProtoMesaggeTypeRequestRecordsByHash = byte(2)
	p2pProtoMessageTypeHaveRecords          = byte(3)
)

type peer struct {
	c              *net.TCPConn
	hasRecords     map[[32]byte]uint64
	hasRecordsLock sync.Mutex
	inbound        bool
}

// Node is an instance of LF
type Node struct {
	logger             *log.Logger
	verboseLogger      *log.Logger
	peers              map[string]*peer
	peersLock          sync.RWMutex
	tcpListener        *net.TCPListener
	db                 db
	httpServer         *http.Server
	backgroundThreadWG sync.WaitGroup
	startTime          uint64
	shutdown           uintptr
}

// NewNode creates and starts a node.
func NewNode(path string, p2pPort int, httpPort int, logger *log.Logger, verboseLogger *log.Logger) (*Node, error) {
	var err error
	n := new(Node)

	n.logger = logger
	n.verboseLogger = verboseLogger
	n.peers = make(map[string]*peer)

	var ta net.TCPAddr
	ta.Port = httpPort
	httpTCPListener, err := net.ListenTCP("tcp", &ta)
	if err != nil {
		return nil, err
	}

	ta.Port = p2pPort
	n.tcpListener, err = net.ListenTCP("tcp", &ta)
	if err != nil {
		httpTCPListener.Close()
		return nil, err
	}

	err = n.db.open(path, logger, verboseLogger)
	if err != nil {
		httpTCPListener.Close()
		n.tcpListener.Close()
		return nil, err
	}

	// Start P2P connection listener
	n.backgroundThreadWG.Add(1)
	go func() {
		for atomic.LoadUintptr(&n.shutdown) == 0 {
			c, _ := n.tcpListener.AcceptTCP()
			if c != nil {
				n.backgroundThreadWG.Add(1)
				go p2pConnectionHandler(n, c, true)
			}
		}
	}()

	// Start HTTP server
	n.httpServer = &http.Server{
		MaxHeaderBytes: 4096,
		Handler:        gziphandler.GzipHandler(apiCreateHTTPServeMux(n)),
		IdleTimeout:    10 * time.Second,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   60 * time.Second}
	n.httpServer.SetKeepAlivesEnabled(true)
	n.backgroundThreadWG.Add(1)
	go func() {
		n.httpServer.Serve(httpTCPListener)
		n.httpServer.Close()
		n.backgroundThreadWG.Done()
	}()

	// Start housekeeper
	n.backgroundThreadWG.Add(1)
	go func() {
		var lastCleanedPeerHasRecords uint64
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
		}
	}()

	return n, nil
}

// Stop terminates the running node. No methods should be called after this.
func (n *Node) Stop() {
	atomic.StoreUintptr(&n.shutdown, 1)
	n.httpServer.Close()
	n.tcpListener.Close()
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
// a connection already exists to this endpoint.
func (n *Node) Connect(ip net.IP, port int, statusCallback func(error)) {
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
				go p2pConnectionHandler(n, c, false)
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

		msg := make([]byte, 36)
		msg[0] = p2pProtoMessageTypeHaveRecords
		msg[3] = 32 // msg[1:4] is a big-endian 24-bit length
		copy(msg[4:], rhash[:])

		n.peersLock.RLock()
		for _, p := range n.peers {
			p.hasRecordsLock.Lock()
			_, hasRecord := p.hasRecords[rhash]
			p.hasRecordsLock.Unlock()
			if !hasRecord {
				if _, err := p.c.Write(msg); err != nil {
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

func p2pConnectionHandler(n *Node, c *net.TCPConn, inbound bool) {
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

	p := peer{c: c, hasRecords: make(map[[32]byte]uint64), inbound: inbound}
	n.peersLock.Lock()
	n.peers[peerAddressStr] = &p
	n.peersLock.Unlock()

	c.SetKeepAlivePeriod(time.Second * 30)
	c.SetKeepAlive(true)
	c.SetLinger(0)
	c.SetNoDelay(false)

	var hdr [4]byte
	var hdrPtr int
	for atomic.LoadUintptr(&n.shutdown) == 0 {
		rn, err := c.Read(hdr[hdrPtr:])
		if err != nil || rn <= 0 {
			if err == nil {
				n.logger.Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
			} else {
				n.logger.Printf("P2P connection to %s closed: read zero bytes", peerAddressStr)
			}
			break
		}
		hdrPtr += rn

		if hdrPtr >= len(hdr) {
			hdrPtr = 0

			incomingMessageType := hdr[0]
			incomingMessageSize := (uint(hdr[1]) << 16) | (uint(hdr[2]) << 8) | uint(hdr[3])
			if incomingMessageSize > p2pProtoMaxMessageSize {
				n.logger.Printf("P2P connection to %s closed: message too large (%d > %d)", peerAddressStr, incomingMessageSize, p2pProtoMaxMessageSize)
				break
			}

			msg := make([]byte, incomingMessageSize)
			_, err = io.ReadFull(c, msg)
			if err != nil {
				n.logger.Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
				break
			}
			if atomic.LoadUintptr(&n.shutdown) != 0 {
				break
			}

			switch incomingMessageType {
			case p2pProtoMessageTypeRecord:
				// This is the same as NewRecordFromBytes() but avoid an extra memory copy
				// and an extra unmarshal by attaching msg as the record's internally cached
				// data. This makes the stuff in AddRecord() a bit faster.
				rec := new(Record)
				err := rec.UnmarshalFrom(bytes.NewReader(msg))
				if err == nil {
					rec.data = msg

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
						_, err = c.Write(hdr[:])
						if err != nil {
							n.logger.Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
							break
						}
						_, err = c.Write(rdata)
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
			}
		}

		runtime.Gosched()
	}
}
