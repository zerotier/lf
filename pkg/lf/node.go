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
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
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
	"sort"
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

	p2pProtoMessageTypeNop                  byte = 0 // no operation
	p2pProtoMessageTypeHello                byte = 1 // peerHelloMsg (JSON)
	p2pProtoMessageTypeRecord               byte = 2 // binary marshaled Record
	p2pProtoMesaggeTypeRequestRecordsByHash byte = 3 // one or more 32-byte hashes we want
	p2pProtoMessageTypeHaveRecords          byte = 4 // one or more 32-byte hashes we have
	p2pProtoMessageTypePeer                 byte = 5 // APIPeer (JSON)

	// p2pDesiredConnectionCount is how many P2P TCP connections we want to have open
	p2pDesiredConnectionCount = 64

	// DefaultHTTPPort is the default LF HTTP API port
	DefaultHTTPPort = 9980

	// DefaultP2PPort is the default LF P2P port
	DefaultP2PPort = 9908
)

var p2pProtoMessageNames = []string{"Nop", "Hello", "Record", "RequestRecordsByHash", "HaveRecords", "Peer"}
var nullLogger = log.New(ioutil.Discard, "", 0)

// peerHelloMsg is a JSON message used to say 'hello' to other nodes via the P2P protocol.
type peerHelloMsg struct {
	ProtocolVersion       int
	MinProtocolVersion    int
	Version               [4]int
	SoftwareName          string
	SubscribeToNewRecords bool // If true, peer wants new records
}

// peer represents a single TCP connection to another peer using the LF P2P TCP protocol
type peer struct {
	n               *Node                // Node that owns this peer
	address         string               // Address in string format
	tcpAddress      *net.TCPAddr         // IP and port
	c               *net.TCPConn         // TCP connection to this peer
	cryptor         cipher.AEAD          // AES-GCM instance
	hasRecords      map[[32]byte]uintptr // Record this peer has recently reported that it has or has sent
	hasRecordsLock  sync.Mutex           //
	sendLock        sync.Mutex           //
	outgoingNonce   [16]byte             // outgoing nonce (incremented for each message)
	remotePublicKey []byte               // Remote public key in compressed/encoded format
	peerHelloMsg    peerHelloMsg         // Hello message received from peer
	inbound         bool                 // True if this is an incoming connection
}

// knownPeer contains info about a peer we know about via another peer or the API
type knownPeer struct {
	APIPeer
	FirstConnect               uint64
	LastFailedConnection       uint64
	LastSuccessfulConnection   uint64
	TotalFailedConnections     uint64
	TotalSuccessfulConnections uint64
}

// Node is an instance of a full LF node supporting both P2P and HTTP access.
type Node struct {
	basePath      string                     //
	peersFilePath string                     //
	log           [logLevelCount]*log.Logger // Pointers to loggers for each log level (inoperative levels point to a discard logger)

	linkKeyPriv []byte   // P-384 private key
	linkKeyPubX *big.Int // X coordinate of P-384 public key
	linkKeyPubY *big.Int // Y coordinate of P-384 public key
	linkKeyPub  []byte   // Point compressed P-384 public key
	owner       *Owner   // Owner for commentary and/or "mining" records

	genesisParameters GenesisParameters // Genesis configuration for this node's network
	genesisOwner      []byte            // Owner of genesis record(s)

	knownPeers               []knownPeer           // Peers we know about
	knownPeersLock           sync.Mutex            //
	connectionsInStartup     map[*net.TCPConn]bool // Connections in startup state but not yet in peers[]
	connectionsInStartupLock sync.Mutex            //
	peers                    map[string]*peer      // Currently connected peers by address
	peersLock                sync.RWMutex          //
	recordsRequested         map[[32]byte]uintptr  // When records were last requested
	recordsRequestedLock     sync.Mutex            //

	httpTCPListener *net.TCPListener
	httpServer      *http.Server
	p2pTCPListener  *net.TCPListener

	apiWorkFunction        *Wharrgarblr
	backgroundWorkFunction *Wharrgarblr
	workFunctionLock       sync.RWMutex

	db                 db             //
	backgroundThreadWG sync.WaitGroup // used to wait for all goroutines
	startTime          time.Time      // time node started
	timeTicker         uintptr        // ticks approximately every second
	shutdown           uint32         // set to non-zero to cause many routines to exit
	judge              uint32         // set to non-zero to add work and render judgements
}

// NewNode creates and starts a node.
func NewNode(basePath string, p2pPort int, httpPort int, logger *log.Logger, logLevel int) (*Node, error) {
	n := new(Node)

	n.basePath = basePath
	n.peersFilePath = path.Join(basePath, "peers.json")
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

	initOk := false
	defer func() {
		if !initOk {
			n.Stop()
		}
	}()

	n.connectionsInStartup = make(map[*net.TCPConn]bool)
	n.peers = make(map[string]*peer)
	n.recordsRequested = make(map[[32]byte]uintptr)

	// Open node database and other related files
	err := n.db.open(basePath, n.log, func(doff uint64, dlen uint, hash *[32]byte) {
		// This is the handler passed to 'db' to be called when records are fully synchronized, meaning
		// they have all their dependencies met and are ready to be replicated.
		if atomic.LoadUint32(&n.shutdown) == 0 {
			go func() {
				if atomic.LoadUint32(&n.shutdown) != 0 {
					return
				}

				defer func() {
					e := recover()
					if e != nil && atomic.LoadUint32(&n.shutdown) != 0 {
						n.log[LogLevelWarning].Printf("WARNING: unexpected panic replicating synchronized record: %s", e)
					}
				}()

				var msg [33]byte
				msg[0] = p2pProtoMessageTypeHaveRecords
				copy(msg[1:], hash[:])

				n.peersLock.RLock()
				if len(n.peers) > 0 {
					for _, p := range n.peers {
						if p.peerHelloMsg.SubscribeToNewRecords {
							p.hasRecordsLock.Lock()
							_, hasRecord := p.hasRecords[*hash]
							p.hasRecordsLock.Unlock()
							if !hasRecord {
								p.send(msg[:])
							}
						}
					}
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
	n.log[LogLevelNormal].Printf("my node public key: %s", base64.RawURLEncoding.EncodeToString(n.linkKeyPub))

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
				n.log[LogLevelNormal].Printf("genesis record %x not found in database, initializing", rh)
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
					n.log[LogLevelNormal].Printf("applying genesis configuration update from record %x", gr.Hash())
					n.genesisParameters.Update(rv)
				}
			} else if err != nil {
				n.log[LogLevelWarning].Print("error unmarshaling genesis record: " + err.Error())
			}
		}
		return true
	})
	if len(n.genesisParameters.AmendableFields) > 0 {
		n.log[LogLevelNormal].Printf("network '%s' permits changes to configuration fields %v by owner %x", n.genesisParameters.Name, n.genesisParameters.AmendableFields, n.genesisOwner)
	} else {
		n.log[LogLevelNormal].Printf("network '%s' genesis configuration is immutable (via any in-band mechanism)", n.genesisParameters.Name)
	}

	// Load peers.json if present
	peersJSON, err := ioutil.ReadFile(n.peersFilePath)
	if err == nil && len(peersJSON) > 0 {
		if json.Unmarshal(peersJSON, &n.knownPeers) != nil {
			n.knownPeers = nil
		}
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

		// Init this in background if it isn't already to speed up node readiness
		WharrgarblInitTable(path.Join(n.basePath, "wharrgarbl-table.bin"))

		for atomic.LoadUint32(&n.shutdown) == 0 {
			time.Sleep(time.Second)
			if atomic.LoadUint32(&n.shutdown) != 0 {
				break
			}
			ticker := atomic.AddUintptr(&n.timeTicker, 1)

			// Clean record tracking entries of items older than 5 minutes.
			if (ticker % 120) == 0 {
				n.peersLock.RLock()
				for _, p := range n.peers {
					p.hasRecordsLock.Lock()
					for h, ts := range p.hasRecords {
						if (ticker - ts) > 300 {
							delete(p.hasRecords, h)
						}
					}
					p.hasRecordsLock.Unlock()
				}
				n.peersLock.RUnlock()

				n.recordsRequestedLock.Lock()
				for h, t := range n.recordsRequested {
					if (ticker - t) > 300 {
						delete(n.recordsRequested, h)
					}
				}
				n.recordsRequestedLock.Unlock()
			}

			// Periodically announce that we have a few recent records to prompt syncing
			if (ticker % 10) == 0 {
				_, links, err := n.db.getLinks(4)
				if err == nil && len(links) >= 32 {
					hr := make([]byte, 1, 1+len(links))
					hr[0] = p2pProtoMessageTypeHaveRecords
					hr = append(hr, links...)

					n.peersLock.RLock()
					for _, p := range n.peers {
						p.send(hr)
					}
					n.peersLock.RUnlock()
				}
			}

			// Peroidically write peers.json
			if (ticker % 120) == 0 {
				n.writeKnownPeers()
			}

			// If we don't have enough connections, try to make more to peers we've learned about.
			if (ticker % 10) == 5 {
				n.peersLock.RLock()
				connectionCount := len(n.peers)
				n.peersLock.RUnlock()

				if connectionCount < p2pDesiredConnectionCount {
					wantMore := p2pDesiredConnectionCount - connectionCount
					n.knownPeersLock.Lock()
					if len(n.knownPeers) > 0 {
						visited := make(map[int]bool)
						for k := 0; k < wantMore; k++ {
							idx := rand.Int() % len(n.knownPeers)
							if _, have := visited[idx]; !have {
								kp := &n.knownPeers[idx]
								n.Connect(kp.IP, kp.Port, kp.PublicKeyBytes())
								visited[idx] = true
							}
						}
					}
					n.knownPeersLock.Unlock()
				}
			}
		}
	}()

	// Start background thread to add work to DAG and render judgements (if enabled).
	n.backgroundThreadWG.Add(1)
	go func() {
		defer n.backgroundThreadWG.Done()
		for k := 0; k < 10 && atomic.LoadUint32(&n.shutdown) == 0; k++ { // wait 10s for other stuff to come up
			time.Sleep(time.Second)
		}

		numLinks := uint(16)
		for atomic.LoadUint32(&n.shutdown) == 0 {
			time.Sleep(time.Second) // 1s pause between each judgement
			if atomic.LoadUint32(&n.judge) != 0 && atomic.LoadUint32(&n.shutdown) == 0 {
				if numLinks < n.genesisParameters.RecordMinLinks {
					numLinks = n.genesisParameters.RecordMinLinks
				}
				if numLinks < 3 {
					numLinks = 3
				}
				if numLinks > 256 { // sanity limit
					numLinks = 256
				}
				links, err := n.db.getLinks2(numLinks)

				if err == nil && len(links) > 0 {
					// TODO: actual judgement commentary is not implemented yet, so this just adds work for now!
					startTime := TimeMs()
					rec, err := NewRecord(nil, links, nil, nil, nil, nil, TimeSec(), n.getBackgroundWorkFunction(), n.owner)
					endTime := TimeMs()
					if atomic.LoadUint32(&n.shutdown) != 0 {
						if err == nil {
							n.AddRecord(rec)

							// Tune number of links (and thus average record size) to try to make records that take about two
							// minutes of work to create. Linking more parent records is generally always good, but we want
							// an acceptable new record generation rate too.
							duration := endTime - startTime
							if duration < 120000 {
								numLinks++
							} else if duration > 120000 && numLinks > 0 {
								numLinks--
							}
						} else {
							n.log[LogLevelWarning].Printf("WARNING: error creating record: %s", err.Error())
						}
					}
				}
			}
		}
	}()

	// Add server's local URL to client config if there aren't any configured URLs.
	clientConfigPath := path.Join(basePath, ClientConfigName)
	var cc ClientConfig
	cc.Load(clientConfigPath)
	if len(cc.Urls) == 0 {
		cc.Urls = []string{fmt.Sprintf("http://127.0.0.1:%d", httpPort)}
		cc.Save(clientConfigPath)
	}

	n.startTime = time.Now()
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

		n.writeKnownPeers()
	}
}

// Connect attempts to establish a peer-to-peer connection to a remote node.
func (n *Node) Connect(ip net.IP, port int, publicKey []byte) {
	n.backgroundThreadWG.Add(1)
	go func() {
		defer n.backgroundThreadWG.Done()

		var ta net.TCPAddr
		ta.IP = ip
		ta.Port = port

		n.peersLock.RLock()
		if n.peers[ta.String()] != nil {
			n.peersLock.RUnlock()
			return
		}
		n.peersLock.RUnlock()

		n.log[LogLevelNormal].Printf("P2P attempting to connect to %s / %s", ta.String(), base64.RawURLEncoding.EncodeToString(publicKey))

		c, err := net.DialTCP("tcp", nil, &ta)
		if atomic.LoadUint32(&n.shutdown) == 0 {
			if err == nil {
				n.backgroundThreadWG.Add(1)
				go p2pConnectionHandler(n, c, publicKey, false)
			} else {
				n.log[LogLevelNormal].Printf("P2P connection to %s failed: %s", ta.String(), err.Error())
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
	if uint(len(r.Links)) < n.genesisParameters.RecordMinLinks {
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
	if r.Certificate != nil && len(n.genesisParameters.RootCertificateAuthorities) == 0 { // don't let people shove crap into cert field if it's not used
		return ErrRecordCertificateInvalid
	}
	if r.Certificate == nil && n.genesisParameters.CertificateRequired {
		return ErrRecordCertificateRequired
	}

	// Validate record's internal structure and check signatures and work.
	err := r.Validate()
	if err != nil {
		return err
	}

	// Add record to database, aborting if this generates some kind of error.
	err = n.db.putRecord(r)
	if err != nil {
		return err
	}

	return nil
}

// SetJudgeEnabled sets whether or not background CPU power is used to render judgements.
// The default is false for new nodes. If true, nearly all background CPU is used
// to publish records that add work to the DAG and render judgements on any records
// that appear suspect. These can be included in query results to allow end users to
// decide what records they trust in the event of a conflict.
func (n *Node) SetJudgeEnabled(j bool) {
	jj := uint32(0)
	if j {
		jj = 1
	}
	atomic.StoreUint32(&n.judge, jj)
}

// writeKnownPeers writes the current known peer list
func (n *Node) writeKnownPeers() {
	n.knownPeersLock.Lock()
	defer n.knownPeersLock.Unlock()
	if len(n.knownPeers) > 0 {
		sort.Slice(n.knownPeers, func(a, b int) bool {
			return n.knownPeers[b].TotalSuccessfulConnections < n.knownPeers[a].TotalSuccessfulConnections
		})
		ioutil.WriteFile(n.peersFilePath, []byte(PrettyJSON(&n.knownPeers)), 0644)
	} else {
		ioutil.WriteFile(n.peersFilePath, []byte("[]"), 0644)
	}
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
// This is used in rendering judgements and yields a work function that leaves one spare core on
// systems with more than one CPU core.
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
	var peerMsg APIPeer
	peerMsg.IP = tcpAddr.IP
	peerMsg.Port = tcpAddr.Port
	if len(publicKey) > 0 {
		peerMsg.PublicKey = base64.RawURLEncoding.EncodeToString(publicKey)
	}
	json, err := json.Marshal(&peerMsg)
	if err != nil {
		return err
	}
	pa := make([]byte, 1, len(json)+1)
	pa[0] = p2pProtoMessageTypePeer
	pa = append(pa, json...)
	return p.send(pa)
}

// send sends a message to a peer (message must be prefixed by type byte)
func (p *peer) send(msg []byte) (err error) {
	p.sendLock.Lock()
	defer func() {
		e := recover()
		p.sendLock.Unlock()
		if e != nil {
			err = fmt.Errorf("unexpected panic in send: %s", e)
		}
	}()

	if len(msg) < 1 {
		err = ErrInvalidParameter
		return
	}

	if int(msg[0]) < len(p2pProtoMessageNames) {
		p.n.log[LogLevelTrace].Printf("TRACE: P2P >> %s %d %s", p.address, len(msg)-1, p2pProtoMessageNames[msg[0]])
	} else {
		p.n.log[LogLevelTrace].Printf("TRACE: P2P >> %s %d unknown message type %d", p.address, len(msg)-1, msg[0])
	}

	for i := 0; i < 12; i++ { // 12 == GCM standard nonce size
		p.outgoingNonce[i]++
		if p.outgoingNonce[i] != 0 {
			break
		}
	}

	buf := make([]byte, 10, len(msg)+32)
	buf = buf[0:binary.PutUvarint(buf, uint64(len(msg)))]
	buf = p.cryptor.Seal(buf, p.outgoingNonce[0:12], msg, nil)

	_, err = p.c.Write(buf)
	if err != nil {
		p.c.Close()
	}
	return
}

// updateKnownPeersWithConnectResult is called from p2pConnectionHandler to update n.knownPeers
func (n *Node) updateKnownPeersWithConnectResult(ip net.IP, port int, publicKey []byte, success bool) {
	n.knownPeersLock.Lock()
	defer n.knownPeersLock.Unlock()
	now := TimeMs()

	ip4 := ip.To4()
	if len(ip4) == 4 {
		ip = ip4
	}

	// Update success or failure info for known peer record if we already have one.
	for _, kp := range n.knownPeers {
		if kp.IP.Equal(ip) && kp.Port == port && bytes.Equal(kp.PublicKeyBytes(), publicKey) {
			if success {
				if kp.FirstConnect == 0 {
					kp.FirstConnect = now
				}
				kp.LastSuccessfulConnection = now
				kp.TotalSuccessfulConnections++
			} else {
				kp.LastFailedConnection = now
				kp.TotalFailedConnections++
			}
			return
		}
	}

	// If there's no known peer record, create only on success.
	if success {
		n.knownPeers = append(n.knownPeers, knownPeer{
			APIPeer: APIPeer{
				IP:        ip,
				Port:      port,
				PublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
			},
			FirstConnect:               now,
			LastSuccessfulConnection:   now,
			TotalSuccessfulConnections: 1,
		})
	}
}

func p2pConnectionHandler(n *Node, c *net.TCPConn, expectedPublicKey []byte, inbound bool) {
	var err error
	var p *peer
	var msgbuf []byte
	peerAddressStr := c.RemoteAddr().String()
	tcpAddr, tcpAddrOk := c.RemoteAddr().(*net.TCPAddr)
	if tcpAddr == nil || !tcpAddrOk {
		n.log[LogLevelWarning].Print("BUG: P2P connection RemoteAddr() did not return a TCPAddr object, connection closed")
		return
	}
	publicAddress := ipIsGlobalPublicUnicast(tcpAddr.IP)
	success := false

	defer func() {
		e := recover()
		if e != nil {
			n.log[LogLevelWarning].Printf("WARNING: P2P connection to %s closed: caught panic: %v", peerAddressStr, e)
		}

		if !success {
			n.updateKnownPeersWithConnectResult(tcpAddr.IP, tcpAddr.Port, nil, false)
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

	c.SetKeepAlivePeriod(time.Second * 30)
	c.SetKeepAlive(true)
	c.SetLinger(0)
	c.SetNoDelay(false)
	reader := bufio.NewReader(c)

	// Exchange public keys (prefixed by connection mode and key length)
	helloMessage := make([]byte, len(n.linkKeyPub)+2)
	helloMessage[0] = p2pProtoModeAES256GCMECCP384
	helloMessage[1] = byte(len(n.linkKeyPub))
	copy(helloMessage[2:], n.linkKeyPub)
	_, err = c.Write(helloMessage)
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
	p = &peer{
		n:               n,
		address:         peerAddressStr,
		tcpAddress:      tcpAddr,
		c:               c,
		cryptor:         cryptor,
		hasRecords:      make(map[[32]byte]uintptr),
		outgoingNonce:   outgoingNonce,
		remotePublicKey: rpk,
		inbound:         inbound,
	}
	n.peersLock.Lock()
	for _, pa := range n.peers {
		if bytes.Equal(pa.remotePublicKey, rpk) {
			n.log[LogLevelNormal].Printf("P2P connection to %s closed: closing redundant link (peer has same link key).", peerAddressStr)
			return
		}

		if !inbound && publicAddress {
			pa.sendPeerAnnouncement(tcpAddr, p.remotePublicKey)
		}

		if !pa.inbound && ipIsGlobalPublicUnicast(pa.tcpAddress.IP) {
			p.sendPeerAnnouncement(pa.tcpAddress, pa.remotePublicKey)
		}
	}
	n.peers[peerAddressStr] = p
	n.peersLock.Unlock()

	n.connectionsInStartupLock.Lock()
	delete(n.connectionsInStartup, c)
	n.connectionsInStartupLock.Unlock()

	msgbuf, err = json.Marshal(&peerHelloMsg{
		ProtocolVersion:       ProtocolVersion,
		MinProtocolVersion:    MinProtocolVersion,
		Version:               Version,
		SoftwareName:          SoftwareName,
		SubscribeToNewRecords: true,
	})
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	p.send(append([]byte{p2pProtoMessageTypeHello}, msgbuf...))

	success = true
	if !inbound {
		n.updateKnownPeersWithConnectResult(tcpAddr.IP, tcpAddr.Port, rpk, true)
	}

	n.log[LogLevelNormal].Printf("P2P connection established to %s / %s", peerAddressStr, base64.RawURLEncoding.EncodeToString(rpk))

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
			n.log[LogLevelTrace].Printf("TRACE: P2P << %s %d %s", peerAddressStr, len(msg), p2pProtoMessageNames[incomingMessageType])
		} else {
			n.log[LogLevelTrace].Printf("TRACE: P2P << %s %d unknown message type %d", peerAddressStr, len(msg), incomingMessageType)
		}

		switch incomingMessageType {

		case p2pProtoMessageTypeHello:
			if len(msg) > 0 {
				json.Unmarshal(msg, &p.peerHelloMsg)
			}

		case p2pProtoMessageTypeRecord:
			if len(msg) > 0 {
				rec, err := NewRecordFromBytes(msg)
				if err == nil {
					p.hasRecordsLock.Lock()
					p.hasRecords[rec.Hash()] = atomic.LoadUintptr(&n.timeTicker)
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
			for len(msg) >= 32 {
				req := make([]byte, 1, 1+len(msg))
				req[0] = p2pProtoMesaggeTypeRequestRecordsByHash
				var h [32]byte
				copy(h[:], msg[0:32])
				msg = msg[32:]
				if !n.db.hasRecord(h[:]) {
					ticker := atomic.LoadUintptr(&n.timeTicker)

					n.recordsRequestedLock.Lock()
					if (ticker - n.recordsRequested[h]) <= 1 {
						n.recordsRequestedLock.Unlock()
						continue
					}
					n.recordsRequested[h] = ticker
					n.recordsRequestedLock.Unlock()

					p.hasRecordsLock.Lock()
					p.hasRecords[h] = ticker
					p.hasRecordsLock.Unlock()

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
				var peerMsg APIPeer
				if json.Unmarshal(msg, &peerMsg) == nil {
					if len(peerMsg.PublicKey) > 0 {
						var tmp net.TCPAddr
						tmp.IP = peerMsg.IP
						tmp.Port = peerMsg.Port
						n.peersLock.RLock()
						_, alreadyConnected := n.peers[tmp.String()]
						connectionCount := len(n.peers)
						n.peersLock.RUnlock()
						n.connectionsInStartupLock.Lock()
						connectionCount += len(n.connectionsInStartup) // include this to prevent flooding attacks
						n.connectionsInStartupLock.Unlock()
						if !alreadyConnected && connectionCount < p2pDesiredConnectionCount {
							n.Connect(peerMsg.IP, peerMsg.Port, peerMsg.PublicKeyBytes())
							time.Sleep(time.Millisecond * 50) // also helps limit flooding, giving connects time to update connections in startup map
						}
					}
				}
			}

		} // switch incomingMessageType
	}
}
