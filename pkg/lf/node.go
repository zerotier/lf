/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NYTimes/gziphandler"
)

const (
	// p2pProtoMaxMessageSize is a sanity check maximum message size for the P2P TCP protocol.
	// It prevents a huge message from causing a huge memory allocation. It can be increased.
	p2pProtoMaxMessageSize = 131072

	// p2pProtoModeAES256GCMECCP384 indicates our simple AES-256 GCM encrypted stream protocol with ECDH key exchange.
	p2pProtoModeAES256GCMECCP384 byte = 1

	p2pProtoMessageTypeNop                  byte = 0 // no operation, ignore payload
	p2pProtoMessageTypeRecord               byte = 1 // binary marshaled Record
	p2pProtoMesaggeTypeRequestRecordsByHash byte = 2 // one or more 32-byte hashes we want
	p2pProtoMessageTypeHaveRecords          byte = 3 // one or more 32-byte hashes we have
	p2pProtoMessageTypePeer                 byte = 4 // <[uint16] port><[byte] type><[4-16] IP>[<public key>]

	// p2pDesiredConnectionCount is how many P2P TCP connections we want to have open
	p2pDesiredConnectionCount = 64

	// DefaultHTTPPort is the default LF HTTP API port
	DefaultHTTPPort = 9980

	// DefaultP2PPort is the default LF P2P port
	DefaultP2PPort = 9908
)

var p2pProtoMessageNames = []string{"Nop", "Record", "RequestRecordsByHash", "HaveRecords", "Peer"}
var nullLogger = log.New(ioutil.Discard, "", 0)

// peer represents a single TCP connection to another peer using the LF P2P TCP protocol
type peer struct {
	n               *Node               // Node that owns this peer
	address         string              // Address in string format
	tcpAddress      *net.TCPAddr        // IP and port
	c               *net.TCPConn        // TCP connection to this peer
	cryptor         cipher.AEAD         // AES-GCM instance
	hasRecords      map[[32]byte]uint64 // Record this peer has recently reported that it has or has sent
	hasRecordsLock  sync.Mutex          //
	sendLock        sync.Mutex          //
	outgoingNonce   [16]byte            // outgoing nonce (incremented for each message)
	remotePublicKey []byte              // Remote public key in compressed/encoded format
	inbound         bool                // True if this is an incoming connection
}

// announcedPeer remembers a peer announcement we've received
type announcedPeer struct {
	learnedTime uint64
	ip          net.IP
	port        int
	publicKey   []byte
}

// Node is an instance of a full LF node supporting both P2P and HTTP access.
type Node struct {
	log                      [logLevelCount]*log.Logger // Pointers to loggers for each log level (inoperative levels point to a discard logger)
	linkKeyPriv              []byte                     // P-384 private key
	linkKeyPubX              *big.Int                   // X coordinate of P-384 public key
	linkKeyPubY              *big.Int                   // Y coordinate of P-384 public key
	linkKeyPub               []byte                     // Point compressed P-384 public key
	owner                    *Owner                     // Owner for commentary and/or "mining" records
	genesisParameters        GenesisParameters          // Genesis configuration for this node's network
	genesisOwner             []byte                     // Owner of genesis record(s)
	announcedPeers           []announcedPeer            // Peers we've received announcements for
	announcedPeersLock       sync.Mutex                 //
	connectionsInStartup     map[*net.TCPConn]bool      // Connections in startup state but not yet in peers[]
	connectionsInStartupLock sync.Mutex                 //
	peers                    map[string]*peer           // Currently connected peers by address
	peersLock                sync.RWMutex               //
	httpTCPListener          *net.TCPListener           //
	httpServer               *http.Server               //
	p2pTCPListener           *net.TCPListener           //
	apiWorkFunction          *Wharrgarblr               // Work function for API call use
	backgroundWorkFunction   *Wharrgarblr               // Work function for background work addition (if enabled)
	workFunctionLock         sync.RWMutex               //
	db                       db                         //
	backgroundThreadWG       sync.WaitGroup             // Wait group for background goroutines
	startTime                uint64                     // Time node was started in seconds since epoch
	shutdown                 uint32                     // Set to non-zero to signal all background goroutines to exit
	mine                     bool                       // If true, add work to DAG in background
}

// NewNode creates and starts a node.
func NewNode(basePath string, p2pPort int, httpPort int, logger *log.Logger, logLevel int) (n *Node, err error) {
	n = new(Node)

	initOk := false
	defer func() {
		e := recover()
		if e != nil {
			err = fmt.Errorf("unexpected panic in node init: %s", e)
		}
		if !initOk {
			n.Stop()
		}
	}()

	if logger == nil {
		logger = nullLogger
	}
	if logLevel < 0 {
		logLevel = 0
	}
	for i := 0; i <= logLevel && i < logLevelCount; i++ {
		n.log[i] = logger
	}
	for i := logLevel + 1; i < logLevelCount; i++ {
		n.log[i] = nullLogger
	}

	n.connectionsInStartup = make(map[*net.TCPConn]bool)
	n.peers = make(map[string]*peer)

	// Open node database and other related files
	err = n.db.open(basePath, n.log, func(doff uint64, dlen uint, hash *[32]byte) {
		// This is the handler passed to 'db' to be called when records are fully synchronized, meaning
		// they have all their dependencies met and are ready to be replicated.
		if atomic.LoadUint32(&n.shutdown) == 0 {
			go func() {
				if atomic.LoadUint32(&n.shutdown) != 0 {
					return
				}

				defer func() {
					e := recover()
					if e != nil {
						n.log[LogLevelWarning].Printf("WARNING: unexpected panic replicating synchronized record: %s", e)
					}
				}()

				var msg [33]byte
				msg[0] = p2pProtoMessageTypeHaveRecords
				copy(msg[1:], hash[:])

				n.peersLock.RLock()
				if len(n.peers) > 0 {
					n.log[LogLevelVerbose].Printf("record %x fully synchronized, announcing to %d peers", *hash, len(n.peers))
					for _, p := range n.peers {
						p.hasRecordsLock.Lock()
						_, hasRecord := p.hasRecords[*hash]
						p.hasRecordsLock.Unlock()
						if !hasRecord {
							p.send(msg[:])
						}
					}
				} else {
					n.log[LogLevelVerbose].Printf("record %x fully synchronized", *hash)
				}
				n.peersLock.RUnlock()
			}()
		}
	})
	if err != nil {
		return nil, err
	}

	// Load or generate the node's P2P link key
	n.linkKeyPriv = n.db.getConfig("link-p384.private")
	linkKeyPubXBytes := n.db.getConfig("link-p384.pubX")
	linkKeyPubYBytes := n.db.getConfig("link-p384.pubY")
	if len(n.linkKeyPriv) == 0 || len(linkKeyPubXBytes) == 0 || len(linkKeyPubYBytes) == 0 {
		n.linkKeyPriv, n.linkKeyPubX, n.linkKeyPubY, err = elliptic.GenerateKey(elliptic.P384(), secrand.Reader)
		if err != nil {
			return nil, err
		}
		n.db.setConfig("link-p384.private", n.linkKeyPriv)
		n.db.setConfig("link-p384.pubX", n.linkKeyPubX.Bytes())
		n.db.setConfig("link-p384.pubY", n.linkKeyPubY.Bytes())
	} else {
		n.linkKeyPubX = new(big.Int).SetBytes(linkKeyPubXBytes)
		n.linkKeyPubY = new(big.Int).SetBytes(linkKeyPubYBytes)
	}
	n.linkKeyPub, err = ECCCompressPublicKey(elliptic.P384(), n.linkKeyPubX, n.linkKeyPubY)
	if err != nil {
		return nil, err
	}

	// Load or generate the node's owner key
	ownerBytes := n.db.getConfig("owner-ed25519.private")
	if len(ownerBytes) > 0 {
		n.owner, err = NewOwnerFromPrivateBytes(ownerBytes)
		if err != nil {
			n.owner = nil
			err = nil
		}
	}
	if n.owner == nil {
		n.owner, err = NewOwner(OwnerTypeEd25519)
		if err != nil {
			return nil, err
		}
		n.db.setConfig("owner-ed25519.private", n.owner.PrivateBytes())
	}

	// Listen for HTTP connections
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
		WriteTimeout:   60 * time.Second,
	}
	n.httpServer.SetKeepAlivesEnabled(true)

	// Listen for P2P connections
	ta.Port = p2pPort
	n.p2pTCPListener, err = net.ListenTCP("tcp", &ta)
	if err != nil {
		return nil, err
	}

	n.log[LogLevelNormal].Printf("listening on port %d for HTTP and %d for LF P2P", httpPort, p2pPort)

	// Load genesis.lf or use compiled-in defaults for global LF network
	var genesisReader io.Reader
	genesisPath := path.Join(basePath, "genesis.lf")
	genesisFile, err := os.Open(genesisPath)
	if err == nil && genesisFile != nil {
		n.log[LogLevelNormal].Print("loading and checking initial genesis records from genesis.lf")
		genesisReader = genesisFile
	} else {
		n.log[LogLevelNormal].Print("loading and checking initial genesis records from internal defaults (no genesis.lf found)")
		genesisReader = bytes.NewReader(SolGenesisRecords)
	}
	for {
		var r Record
		err := r.UnmarshalFrom(genesisReader)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if len(n.genesisOwner) == 0 {
			n.genesisOwner = r.Owner
		}

		if bytes.Equal(n.genesisOwner, r.Owner) { // sanity check
			rh := r.Hash()
			if !n.db.hasRecord(rh[:]) {
				n.log[LogLevelNormal].Printf("genesis record %x not found in database, initializing", *rh)
				err = n.db.putRecord(&r)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	if genesisFile == nil {
		ioutil.WriteFile(genesisPath, SolGenesisRecords, 0644)
	} else {
		genesisFile.Close()
	}
	if len(n.genesisOwner) == 0 {
		return nil, errors.New("no default genesis records found; database cannot be initialized and/or genesis record lineage cannot be determined")
	}

	// Load any genesis records after those in genesis.lf (or compiled in default)
	n.log[LogLevelNormal].Printf("loading genesis records from genesis owner %x", n.genesisOwner)
	n.db.getAllByOwner(n.genesisOwner, func(doff, dlen uint64) bool {
		rdata, _ := n.db.getDataByOffset(doff, uint(dlen), nil)
		if len(rdata) > 0 {
			gr, err := NewRecordFromBytes(rdata)
			if gr != nil && err == nil {
				rv, _ := gr.GetValue(nil)
				if len(rv) > 0 {
					n.log[LogLevelNormal].Printf("applying genesis configuration update from record %x", *gr.Hash())
					n.genesisParameters.Update(rv)
				}
			}
		}
		return true
	})
	if len(n.genesisParameters.AmendableFields) > 0 {
		n.log[LogLevelNormal].Printf("network '%s' permits changes to configuration fields %v by owner %x", n.genesisParameters.Name, n.genesisParameters.AmendableFields, n.genesisOwner)
	} else {
		n.log[LogLevelNormal].Printf("network '%s' genesis configuration is immutable (via any in-band mechanism)", n.genesisParameters.Name)
	}

	// Start P2P connection listener
	n.backgroundThreadWG.Add(1)
	go func() {
		defer n.backgroundThreadWG.Done()
		for atomic.LoadUint32(&n.shutdown) == 0 && n.p2pTCPListener != nil {
			c, _ := n.p2pTCPListener.AcceptTCP()
			if atomic.LoadUint32(&n.shutdown) != 0 {
				if c != nil {
					c.Close()
				}
				break
			}
			if c != nil {
				n.backgroundThreadWG.Add(1)
				go p2pConnectionHandler(n, c, nil, true)
			}
		}
	}()

	// Start HTTP server
	n.backgroundThreadWG.Add(1)
	go func() {
		defer n.backgroundThreadWG.Done()
		n.httpServer.Serve(n.httpTCPListener)
		if n.httpServer != nil {
			n.httpServer.Close()
		}
	}()

	// Start background housekeeping thread
	n.backgroundThreadWG.Add(1)
	go func() {
		defer n.backgroundThreadWG.Done()
		var lastCleanedPeerHasRecords, lastCleanedAnnouncedPeers, lastAttemptedConnections uint64
		for atomic.LoadUint32(&n.shutdown) == 0 {
			time.Sleep(time.Second)
			if atomic.LoadUint32(&n.shutdown) != 0 {
				break
			}
			now := TimeMs()

			// Clean peer "has record" map entries older than 5 minutes.
			if (now - lastCleanedPeerHasRecords) > 120000 {
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

			// Clean announced peer list of peers we learned about more than 10 minutes ago.
			if (now - lastCleanedAnnouncedPeers) > 120000 {
				lastCleanedAnnouncedPeers = now
				var newAP []announcedPeer
				n.announcedPeersLock.Lock()
				if len(n.announcedPeers) > 4096 { // sanity check to prevent insanity
					n.announcedPeers = n.announcedPeers[4096:]
				}
				for _, ap := range n.announcedPeers {
					if (now - ap.learnedTime) < 600000 {
						newAP = append(newAP, ap)
					}
				}
				n.announcedPeers = newAP
				n.announcedPeersLock.Unlock()
			}

			// If we don't have enough connections, try to make more to peers we've learned about.
			if (now - lastAttemptedConnections) > 10000 {
				n.peersLock.RLock()
				peerCount := len(n.peers)
				n.peersLock.RUnlock()
				n.announcedPeersLock.Lock()
				for c := peerCount; c < p2pDesiredConnectionCount; c++ {
					if len(n.announcedPeers) == 0 {
						break
					}
					pidx := rand.Int() % len(n.announcedPeers)
					ip := n.announcedPeers[pidx].ip
					port := n.announcedPeers[pidx].port
					n.Connect(ip, port, n.announcedPeers[pidx].publicKey, func(err error) {
						if err != nil && err != ErrAlreadyConnected {
							n.log[LogLevelNormal].Printf("P2P connection to %s:%d failed: %s", ip, port, err.Error())
						}
					})
					n.announcedPeers = append(n.announcedPeers[:pidx], n.announcedPeers[pidx+1:]...)
				}
				n.announcedPeersLock.Unlock()
			}
		}
	}()

	// Start background work and record adding thread
	n.backgroundThreadWG.Add(1)
	go func() {
		defer n.backgroundThreadWG.Done()
		time.Sleep(5 * time.Second) // wait for other stuff to come up
		for atomic.LoadUint32(&n.shutdown) == 0 {
			time.Sleep(time.Millisecond * 500)
			if n.mine && atomic.LoadUint32(&n.shutdown) == 0 {
				minLinks := n.genesisParameters.RecordMinLinks
				if minLinks == 0 {
					minLinks = 1
				}
				links, err := n.db.getLinks2(minLinks)
				if err == nil && len(links) > 0 {
					rec, err := NewRecord(nil, links, nil, nil, nil, nil, TimeSec(), n.getBackgroundWorkFunction(), 0, n.owner)
					if atomic.LoadUint32(&n.shutdown) != 0 {
						if err == nil {
							n.AddRecord(rec)
						} else {
							n.log[LogLevelWarning].Printf("WARNING: error creating record: %s", err.Error())
						}
					}
				} else {
					n.log[LogLevelWarning].Printf("WARNING: database error getting links or %d links not available", n.genesisParameters.RecordMinLinks)
				}
			}
		}
	}()

	n.startTime = TimeSec()
	initOk = true

	return n, nil
}

// Stop terminates the running node, blocking until all gorountines are done.
// No methods should be called after this and the Node should be discarded.
func (n *Node) Stop() {
	n.log[LogLevelNormal].Printf("shutting down")
	if atomic.SwapUint32(&n.shutdown, 1) == 0 {
		n.workFunctionLock.RLock()
		if n.backgroundWorkFunction != nil {
			n.backgroundWorkFunction.Abort()
		}
		n.workFunctionLock.RUnlock()

		n.connectionsInStartupLock.Lock()
		if n.connectionsInStartup != nil {
			for c := range n.connectionsInStartup {
				c.Close()
			}
		}
		n.connectionsInStartupLock.Unlock()

		n.peersLock.RLock()
		if n.peers != nil {
			for _, p := range n.peers {
				if p.c != nil {
					p.c.Close()
				}
			}
		}
		n.peersLock.RUnlock()

		if n.httpServer != nil {
			n.httpServer.Close()
		}
		if n.p2pTCPListener != nil {
			n.p2pTCPListener.Close()
		}

		n.backgroundThreadWG.Wait()

		n.httpServer = nil
		n.httpTCPListener = nil
		n.p2pTCPListener = nil

		n.connectionsInStartupLock.Lock()
		n.connectionsInStartup = nil
		n.connectionsInStartupLock.Unlock()

		n.peersLock.Lock()
		n.peers = nil
		n.peersLock.Unlock()

		n.db.close()
	}
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
				statusCallback(ErrAlreadyConnected)
			}
			return
		}
		n.peersLock.RUnlock()

		c, err := net.DialTCP("tcp", nil, &ta)
		if atomic.LoadUint32(&n.shutdown) == 0 {
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
		} else if c != nil {
			c.Close()
		}
	}()
}

// AddRecord adds a record to the database if it's valid and we do not already have it.
// If the record is a duplicate this returns ErrorDuplicateRecord.
func (n *Node) AddRecord(r *Record) error {
	if r == nil {
		return ErrInvalidParameter
	}

	rdata := r.Bytes()
	rhash := r.Hash()

	// Check to see if we already have this record.
	if n.db.hasRecord(rhash[:]) {
		return ErrDuplicateRecord
	}

	// Check various record constraints such as sizes, timestamp, etc. This is done first
	// because these checks are simple and fast while signature checks are CPU intensive.
	if len(rdata) > RecordMaxSize || uint(len(rdata)) > n.genesisParameters.RecordMaxSize {
		return ErrRecordTooLarge
	}
	if uint(len(r.Value)) > n.genesisParameters.RecordMaxValueSize {
		return ErrRecordValueTooLarge
	}
	if r.LinkCount() < n.genesisParameters.RecordMinLinks {
		return ErrRecordInsufficientLinks
	}
	if r.Timestamp > (TimeSec() + uint64(n.genesisParameters.RecordMaxForwardTimeDrift)) {
		return ErrRecordViolatesSpecialRelativity
	}
	if r.Timestamp < n.genesisParameters.TimestampFloor {
		return ErrRecordTooOld
	}
	if r.WorkAlgorithm == RecordWorkAlgorithmNone && n.genesisParameters.WorkRequired {
		return ErrRecordInsufficientWork
	}
	if len(r.Certificate) > 0 && len(n.genesisParameters.RootCertificateAuthorities) == 0 { // don't let people shove crap into cert field if it's not used
		return ErrRecordCertificateInvalid
	}
	if len(r.Certificate) == 0 && n.genesisParameters.CertificateRequired {
		return ErrRecordCertificateRequired
	}

	// Validate record's internal structure and check signatures and work.
	err := r.Validate()
	if err != nil {
		return err
	}

	n.log[LogLevelTrace].Printf("TRACE: new record: %x", *rhash)

	// Add record to database, aborting if this generates some kind of error.
	err = n.db.putRecord(r)
	if err != nil {
		return err
	}

	return nil
}

// Peers returns an array of peer description objects suitable for return via the API.
func (n *Node) Peers() (peers []APIStatusPeer) {
	n.peersLock.RLock()
	for a, p := range n.peers {
		peers = append(peers, APIStatusPeer{
			Address:   a,
			PublicKey: p.remotePublicKey,
			Inbound:   p.inbound,
		})
	}
	n.peersLock.RUnlock()
	return
}

// getAPIWorkFunction gets (creating if needed) the work function for API calls.
func (n *Node) getAPIWorkFunction() (wf *Wharrgarblr) {
	n.workFunctionLock.RLock()
	if n.apiWorkFunction != nil {
		wf = n.apiWorkFunction
		n.workFunctionLock.RUnlock()
		return
	}
	n.workFunctionLock.RUnlock()

	if n.genesisParameters.WorkRequired {
		n.workFunctionLock.Lock()
		if n.apiWorkFunction != nil {
			wf = n.apiWorkFunction
			n.workFunctionLock.Unlock()
			return
		}
		n.apiWorkFunction = NewWharrgarblr(RecordDefaultWharrgarblMemory, runtime.NumCPU())
		wf = n.apiWorkFunction
		n.workFunctionLock.Unlock()
	}

	return
}

// getBackgroundWorkFunction gets (creating if needed) the work function for background work addition.
func (n *Node) getBackgroundWorkFunction() (wf *Wharrgarblr) {
	n.workFunctionLock.RLock()
	if n.backgroundWorkFunction != nil {
		wf = n.backgroundWorkFunction
		n.workFunctionLock.RUnlock()
		return
	}
	n.workFunctionLock.RUnlock()

	if n.genesisParameters.WorkRequired {
		n.workFunctionLock.Lock()
		if n.backgroundWorkFunction != nil {
			wf = n.backgroundWorkFunction
			n.workFunctionLock.Unlock()
			return
		}
		n.backgroundWorkFunction = NewWharrgarblr(RecordDefaultWharrgarblMemory, runtime.NumCPU()-1) // -1 to leave one thread always for other stuff
		wf = n.backgroundWorkFunction
		n.workFunctionLock.Unlock()
	}

	return
}

// sendPeerAnnouncement sends a peer announcement to this peer for the given address and public key
func (p *peer) sendPeerAnnouncement(tcpAddr *net.TCPAddr, publicKey []byte) error {
	pa := make([]byte, 1, 256)
	pa[0] = p2pProtoMessageTypePeer
	ipv4 := tcpAddr.IP.To4()
	if len(ipv4) == 4 {
		pa = append(pa, byte((tcpAddr.Port>>8)&0xff))
		pa = append(pa, byte(tcpAddr.Port&0xff))
		pa = append(pa, 4)
		pa = append(pa, ipv4...)
		pa = append(pa, publicKey...)
	} else {
		ipv6 := tcpAddr.IP.To16()
		if len(ipv6) == 16 {
			pa = append(pa, byte((tcpAddr.Port>>8)&0xff))
			pa = append(pa, byte(tcpAddr.Port&0xff))
			pa = append(pa, 6)
			pa = append(pa, ipv6...)
			pa = append(pa, publicKey...)
		}
	}
	if len(pa) > 1 {
		return p.send(pa)
	}
	return ErrInvalidParameter
}

// send sends a message to a peer (message must be prefixed by type byte)
func (p *peer) send(msg []byte) error {
	p.sendLock.Lock()

	if len(msg) < 1 {
		return ErrInvalidParameter
	}

	if int(msg[0]) < len(p2pProtoMessageNames) {
		p.n.log[LogLevelTrace].Printf("TRACE: P2P >> %s %d %s", p.address, len(msg)-1, p2pProtoMessageNames[msg[0]])
	} else {
		p.n.log[LogLevelTrace].Printf("TRACE: P2P >> %s %d unknown message type %d", p.address, len(msg)-1, msg[0])
	}

	for i := 0; i < 12; i++ {
		p.outgoingNonce[i]++
		if p.outgoingNonce[i] != 0 {
			break
		}
	}

	buf := make([]byte, 10, len(msg)+32)
	buf = buf[0:binary.PutUvarint(buf, uint64(len(msg)))]
	buf = p.cryptor.Seal(buf, p.outgoingNonce[0:12], msg, nil)

	_, err := p.c.Write(buf)
	if err != nil {
		p.c.Close()
		p.sendLock.Unlock()
		return err
	}

	p.sendLock.Unlock()
	return nil
}

func p2pConnectionHandler(n *Node, c *net.TCPConn, expectedPublicKey []byte, inbound bool) {
	peerAddressStr := c.RemoteAddr().String()

	defer func() {
		e := recover()
		if e != nil {
			n.log[LogLevelWarning].Printf("WARNING: P2P connection to %s closed: caught panic: %v", peerAddressStr, e)
		}

		c.Close()

		n.connectionsInStartupLock.Lock()
		delete(n.connectionsInStartup, c)
		n.connectionsInStartupLock.Unlock()

		n.peersLock.Lock()
		delete(n.peers, peerAddressStr)
		n.peersLock.Unlock()

		n.backgroundThreadWG.Done()
	}()

	n.connectionsInStartupLock.Lock()
	n.connectionsInStartup[c] = true
	n.connectionsInStartupLock.Unlock()

	tcpAddr, tcpAddrOk := c.RemoteAddr().(*net.TCPAddr)
	if tcpAddr == nil || !tcpAddrOk {
		n.log[LogLevelWarning].Print("BUG: P2P connection RemoteAddr() did not return a TCPAddr object, connection closed")
		return
	}
	publicAddress := ipIsGlobalPublicUnicast(tcpAddr.IP)

	c.SetKeepAlivePeriod(time.Second * 30)
	c.SetKeepAlive(true)
	c.SetLinger(0)
	c.SetNoDelay(false)
	reader := bufio.NewReaderSize(c, 16384)

	// Exchange public keys (prefixed by connection mode and key length)
	helloMessage := make([]byte, len(n.linkKeyPub)+2)
	helloMessage[0] = p2pProtoModeAES256GCMECCP384
	helloMessage[1] = byte(len(n.linkKeyPub))
	copy(helloMessage[2:], n.linkKeyPub)
	_, err := c.Write(helloMessage)
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	_, err = io.ReadFull(reader, helloMessage[0:2])
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	if helloMessage[0] != p2pProtoModeAES256GCMECCP384 || helloMessage[1] == 0 {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: protocol mode not supported or invalid key length", peerAddressStr)
		return
	}
	rpk := make([]byte, uint(helloMessage[1]))
	_, err = io.ReadFull(reader, rpk)
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	if bytes.Equal(rpk, n.linkKeyPub) {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: other side has same link key! connected to self or link key stolen or accidentally duplicated.", peerAddressStr)
		return
	}
	if len(expectedPublicKey) > 0 && !bytes.Equal(expectedPublicKey, rpk) {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: remote public key does not match expected (pinned) public key", peerAddressStr)
		return
	}
	helloMessage = nil

	// Perform ECDH key agreement and init encryption
	remotePubX, remotePubY, err := ECCDecompressPublicKey(elliptic.P384(), rpk)
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: invalid public key: %s", peerAddressStr, err.Error())
		return
	}
	remoteShared, err := ECDHAgree(elliptic.P384(), remotePubX, remotePubY, n.linkKeyPriv)
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: key agreement failed: %s", peerAddressStr, err.Error())
		return
	}
	if len(n.genesisParameters.LinkKey) == 32 {
		for i := 0; i < 32; i++ {
			remoteShared[i] ^= n.genesisParameters.LinkKey[i]
		}
	}
	aesCipher, _ := aes.NewCipher(remoteShared[:])
	cryptor, _ := cipher.NewGCM(aesCipher)

	// Exchange encrypted nonces (16 bytes are exchanged due to AES block size but only 12 bytes are used for AES-GCM)
	// Technically encryption of the nonce is not required, but why not?
	var encryptedOutgoingNonce, outgoingNonce, incomingNonce [16]byte
	_, err = secrand.Read(outgoingNonce[:])
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	aesCipher.Encrypt(encryptedOutgoingNonce[:], outgoingNonce[:])
	_, err = c.Write(encryptedOutgoingNonce[:])
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	_, err = io.ReadFull(reader, incomingNonce[:])
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	aesCipher.Decrypt(incomingNonce[:], incomingNonce[:])

	// Add peer connection to node peers[] map and also announce this peer to other peers (if this
	// is an outbound connection) and announce other outbound peers to this one.
	p := peer{
		n:               n,
		address:         peerAddressStr,
		tcpAddress:      tcpAddr,
		c:               c,
		cryptor:         cryptor,
		hasRecords:      make(map[[32]byte]uint64),
		outgoingNonce:   outgoingNonce,
		remotePublicKey: rpk,
		inbound:         inbound,
	}
	n.peersLock.Lock()
	for _, pa := range n.peers {
		if bytes.Equal(pa.remotePublicKey, rpk) {
			if inbound { // if this connection is inbound, keep the other one as it is more informative (tells us proper IP/port)
				n.log[LogLevelNormal].Printf("P2P connection to %s closed: closing redundant link (peer has same link key).", peerAddressStr)
				n.peersLock.Unlock()
				return
			}
			n.log[LogLevelNormal].Printf("P2P connection to %s closed: closing redundant link (peer has same link key).", pa.address)
			pa.c.Close()
		}

		if !inbound && publicAddress {
			pa.sendPeerAnnouncement(tcpAddr, p.remotePublicKey)
		}

		if !pa.inbound && ipIsGlobalPublicUnicast(pa.tcpAddress.IP) {
			err = p.sendPeerAnnouncement(pa.tcpAddress, pa.remotePublicKey)
			if err != nil {
				n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
				n.peersLock.Unlock()
				return
			}
		}
	}
	n.peers[peerAddressStr] = &p
	n.peersLock.Unlock()

	n.connectionsInStartupLock.Lock()
	delete(n.connectionsInStartup, c)
	n.connectionsInStartupLock.Unlock()

	n.log[LogLevelNormal].Printf("P2P connection established to %s / %x", peerAddressStr, p.remotePublicKey)

	var msgbuf []byte
	for atomic.LoadUint32(&n.shutdown) == 0 {
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
		incomingMessageType := msg[0]
		msg = msg[1:]

		if int(incomingMessageType) < len(p2pProtoMessageNames) {
			n.log[LogLevelTrace].Printf("P2P << %s %d %s", peerAddressStr, len(msg), p2pProtoMessageNames[incomingMessageType])
		} else {
			n.log[LogLevelTrace].Printf("P2P << %s %d unknown message type %d", peerAddressStr, len(msg), incomingMessageType)
		}

		switch incomingMessageType {

		case p2pProtoMessageTypeRecord:
			if len(msg) > 0 {
				rec, err := NewRecordFromBytes(msg)
				if err == nil {
					p.hasRecordsLock.Lock()
					p.hasRecords[*rec.Hash()] = TimeMs()
					p.hasRecordsLock.Unlock()
					n.AddRecord(rec)
				}
			}

		case p2pProtoMesaggeTypeRequestRecordsByHash:
			for len(msg) >= 32 {
				rdata := make([]byte, 1, 4096)
				rdata[0] = p2pProtoMessageTypeRecord
				_, rdata, err = n.db.getDataByHash(msg[0:32], rdata)
				if err == nil && len(rdata) > 1 {
					p.send(rdata)
				}
				msg = msg[32:]
			}

		case p2pProtoMessageTypeHaveRecords:
			var h [32]byte
			req := make([]byte, 1, 256)
			req[0] = p2pProtoMesaggeTypeRequestRecordsByHash
			for len(msg) >= 32 {
				copy(h[:], msg[0:32])

				p.hasRecordsLock.Lock()
				p.hasRecords[h] = TimeMs()
				p.hasRecordsLock.Unlock()

				if !n.db.hasRecord(h[:]) {
					req = append(req, h[:]...)
					if len(req) >= (p2pProtoMaxMessageSize - 64) {
						p.send(req)
						req = req[0:1]
					}
				}

				msg = msg[32:]
			}
			if len(req) > 1 {
				p.send(req)
			}

		case p2pProtoMessageTypePeer:
			n.peersLock.RLock()
			peerCount := len(n.peers)
			n.peersLock.RUnlock()
			if peerCount < p2pDesiredConnectionCount && len(msg) > 3 {
				port := binary.BigEndian.Uint16(msg[0:2])
				var ip net.IP
				var publicKey []byte
				if msg[2] == 4 && len(msg) >= 7 {
					ip = msg[3:7]
					if len(msg) > 7 {
						publicKey = msg[7:]
					}
				} else if msg[2] == 6 && len(msg) >= 19 {
					ip = msg[3:19]
					if len(msg) > 19 {
						publicKey = msg[19:]
					}
				}
				if len(ip) > 0 {
					dupe := false
					n.announcedPeersLock.Lock()
					for _, ap := range n.announcedPeers {
						if bytes.Equal(ap.publicKey, publicKey) && bytes.Equal(ap.ip, ip) && ap.port == int(port) {
							dupe = true
							break
						}
					}
					if !dupe {
						n.announcedPeers = append(n.announcedPeers, announcedPeer{
							learnedTime: TimeMs(),
							ip:          ip,
							port:        int(port),
							publicKey:   publicKey,
						})
					}
					n.announcedPeersLock.Unlock()
				}
			}

		} // switch incomingMessageType
	}
}
