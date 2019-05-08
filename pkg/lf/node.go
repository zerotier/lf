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
	"container/list"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
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

	// p2pProtoMaxRetries is the maximum number of times we'll try to retry a record
	p2pProtoMaxRetries = 256

	// p2pDesiredConnectionCount is how many P2P TCP connections we want to have open
	p2pDesiredConnectionCount = 64

	// Delete peers that haven't been used in this long.
	p2pPeerExpiration = 432000000 // 5 days

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
	P2PPort               int
	HTTPPort              int
	SubscribeToNewRecords bool // If true, peer wants new records
}

// peer represents a single TCP connection to another peer using the LF P2P TCP protocol
type peer struct {
	n              *Node                // Node that owns this peer
	address        string               // Address in string format
	tcpAddress     *net.TCPAddr         // IP and port
	c              *net.TCPConn         // TCP connection to this peer
	cryptor        cipher.AEAD          // AES-GCM instance
	hasRecords     map[[32]byte]uintptr // Record this peer has recently reported that it has or has sent
	hasRecordsLock sync.Mutex           //
	sendLock       sync.Mutex           //
	outgoingNonce  [16]byte             // outgoing nonce (incremented for each message)
	remotePublic   []byte               // Remote node public in byte array format
	peerHelloMsg   peerHelloMsg         // Hello message received from peer
	inbound        bool                 // True if this is an incoming connection
}

// knownPeer contains info about a peer we know about via another peer or the API
type knownPeer struct {
	APIPeer
	FirstConnect               uint64
	LastSuccessfulConnection   uint64
	TotalSuccessfulConnections int64
}

// Node is an instance of a full LF node supporting both P2P and HTTP access.
type Node struct {
	basePath      string                     //
	peersFilePath string                     //
	p2pPort       int                        //
	httpPort      int                        //
	log           [logLevelCount]*log.Logger // Pointers to loggers for each log level (inoperative levels point to a discard logger)

	owner             *Owner            // Owner for commentary, key also currently used for ECDH on link
	ownerPrivateKey   *ecdsa.PrivateKey // ECDSA private key for owner
	ownerRawPublicKey []byte            // Compressed public key from owner key, used as link key

	genesisParameters          GenesisParameters // Genesis configuration for this node's network
	genesisOwner               []byte            // Owner of genesis record(s)
	lastGenesisRecordTimestamp uint64            //

	knownPeers               []*knownPeer          // Peers we know about
	knownPeersLock           sync.Mutex            //
	connectionsInStartup     map[*net.TCPConn]bool // Connections in startup state but not yet in peers[]
	connectionsInStartupLock sync.Mutex            //
	peers                    map[string]*peer      // Currently connected peers by address
	peersLock                sync.RWMutex          //
	recordsRequested         map[[32]byte]uintptr  // When records were last requested
	recordsRequestedLock     sync.Mutex            //
	comments                 *list.List            // Accumulates commentary if commentary is enabled
	commentsLock             sync.Mutex            //

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
	synchronized       uint32         // set to non-zero when database is synchronized
	shutdown           uint32         // set to non-zero to cause many routines to exit
	commentary         uint32         // set to non-zero to add work and render commentary
}

// NewNode creates and starts a node.
func NewNode(basePath string, p2pPort int, httpPort int, logger *log.Logger, logLevel int) (*Node, error) {
	n := new(Node)

	n.basePath = basePath
	n.peersFilePath = path.Join(basePath, "peers.json")
	n.p2pPort = p2pPort
	n.httpPort = httpPort

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
	n.comments = list.New()

	// Open node database and associated flat data files.
	err := n.db.open(basePath, n.log, n.handleSynchronizedRecord)
	if err != nil {
		return nil, err
	}

	// Load or generate this node's public owner / public key.
	ownerPath := path.Join(basePath, "node-p384.secret")
	ownerBytes, _ := ioutil.ReadFile(ownerPath)
	if len(ownerBytes) > 0 {
		n.owner, err = NewOwnerFromPrivateBytes(ownerBytes)
		if err != nil {
			n.owner = nil
			err = nil
		}
	}
	if n.owner == nil {
		n.owner, err = NewOwner(OwnerTypeNistP384)
		if err != nil {
			return nil, err
		}
		err = ioutil.WriteFile(ownerPath, n.owner.PrivateBytes(), 0600)
		if err != nil {
			return nil, err
		}
	}
	n.ownerPrivateKey = n.owner.getPrivateECDSA()
	if n.ownerPrivateKey == nil {
		return nil, ErrInvalidPrivateKey
	}
	n.ownerRawPublicKey, err = ECCCompressPublicKey(elliptic.P384(), n.ownerPrivateKey.PublicKey.X, n.ownerPrivateKey.PublicKey.Y)
	if err != nil {
		return nil, err
	}

	// Write base62 public, which isn't used here but is useful for user use in scripts etc.
	nodePublicStr := Base62Encode(n.owner.Bytes())
	ioutil.WriteFile(path.Join(basePath, "node-p384.public"), []byte(nodePublicStr), 0644)

	// Listen for HTTP connections
	var ta net.TCPAddr
	ta.Port = httpPort
	n.httpTCPListener, err = net.ListenTCP("tcp", &ta)
	if err != nil {
		return nil, err
	}
	n.httpServer = &http.Server{
		MaxHeaderBytes: 4096,
		Handler:        httpGzipHandler(apiCreateHTTPServeMux(n)),
		IdleTimeout:    10 * time.Second,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   30 * time.Second,
	}
	n.httpServer.SetKeepAlivesEnabled(true)

	// Listen for P2P connections
	ta.Port = p2pPort
	n.p2pTCPListener, err = net.ListenTCP("tcp", &ta)
	if err != nil {
		return nil, err
	}

	n.log[LogLevelNormal].Printf("@%s listening on P2P port %d and HTTP port %d", nodePublicStr, p2pPort, httpPort)

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
				n.log[LogLevelNormal].Printf("adding genesis record =%s (not already in database)", Base62Encode(rh[:]))
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
	n.log[LogLevelNormal].Printf("loading genesis records from genesis owner @%s", Base62Encode(n.genesisOwner))
	gotGenesis := false
	n.db.getAllByOwner(n.genesisOwner, func(doff, dlen uint64, reputation int) bool {
		rdata, _ := n.db.getDataByOffset(doff, uint(dlen), nil)
		if len(rdata) > 0 {
			gr, err := NewRecordFromBytes(rdata)
			if gr != nil && err == nil && gr.GetType() == RecordTypeGenesis {
				if n.handleGenesisRecord(gr) {
					gotGenesis = true
				}
			} else if err != nil {
				n.log[LogLevelWarning].Print("error unmarshaling genesis record: " + err.Error())
			}
		}
		return true
	})
	if !gotGenesis {
		return nil, errors.New("no genesis records found or none readable")
	}
	if len(n.genesisParameters.AmendableFields) > 0 {
		n.log[LogLevelNormal].Printf("network '%s' permits changes to configuration fields %v by owner @%s", n.genesisParameters.Name, n.genesisParameters.AmendableFields, Base62Encode(n.genesisOwner))
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
				go n.p2pConnectionHandler(c, nil, true)
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
		n.backgroundWorkerMain()
	}()

	// Start background thread to add work to DAG and render commentary (if enabled)
	n.backgroundThreadWG.Add(1)
	go func() {
		defer n.backgroundThreadWG.Done()
		n.commentaryGeneratorMain()
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
func (n *Node) Connect(ip net.IP, port int, identity []byte) {
	n.backgroundThreadWG.Add(1)
	go func() {
		defer n.backgroundThreadWG.Done()

		ta := net.TCPAddr{
			IP:   ip,
			Port: port,
		}

		n.peersLock.RLock()
		if n.peers[ta.String()] != nil {
			n.peersLock.RUnlock()
			return
		}
		n.peersLock.RUnlock()

		nodePublicOwner, err := NewOwnerFromBytes(identity)
		if err != nil {
			n.log[LogLevelNormal].Printf("P2P connection to %s failed: %s", ta.String(), err.Error())
			return
		}

		n.log[LogLevelNormal].Printf("P2P attempting to connect to %s %d @%s", ip.String(), port, Base62Encode(identity))

		conn, err := net.DialTimeout("tcp", ta.String(), time.Second*10)
		if atomic.LoadUint32(&n.shutdown) == 0 {
			if err == nil {
				n.backgroundThreadWG.Add(1)
				go n.p2pConnectionHandler(conn.(*net.TCPConn), nodePublicOwner, false)
			} else {
				n.log[LogLevelNormal].Printf("P2P connection to %s failed: %s", ta.String(), err.Error())
			}
		} else if conn != nil {
			conn.Close()
		}
	}()
}

// AddRecord adds a record to the database if it's valid and we do not already have it.
// ErrDuplicateRecord is returned if this record is already in the database. This function
// is the entry point for all but genesis records and it and the functions it calls are
// where all record validation and commentary generating logic lives.
func (n *Node) AddRecord(r *Record) error {
	if r == nil {
		return ErrInvalidParameter
	}

	rhash := r.Hash()
	rtype := r.GetType()

	// Check to see if we already have this record.
	if n.db.hasRecord(rhash[:]) {
		return ErrDuplicateRecord
	}

	// Check basic constraints first since this is less CPU intensive than signature
	// and work validation.
	if rtype == RecordTypeGenesis && !bytes.Equal(r.Owner, n.genesisOwner) {
		return ErrRecordProhibited
	}

	// Genesis records can only come from the genesis owner
	// Is record too big according to protocol or genesis parameter constraints?
	rsize := uint(r.SizeBytes())
	if rsize > RecordMaxSize || rsize > n.genesisParameters.RecordMaxSize {
		return ErrRecordTooLarge
	}

	// Is value too big?
	if uint(len(r.Value)) > n.genesisParameters.RecordMaxValueSize {
		return ErrRecordValueTooLarge
	}

	// Check links: not too few, not too many, must be sorted, no duplicates
	if uint(len(r.Links)) < n.genesisParameters.RecordMinLinks {
		return ErrRecordInsufficientLinks
	}
	if len(r.Links) > RecordMaxLinks {
		return ErrRecordTooManyLinks
	}
	for i := 1; i < len(r.Links); i++ {
		if bytes.Compare(r.Links[i-1][:], r.Links[i][:]) >= 0 {
			return ErrRecordInvalidLinks
		}
	}

	// Not too many selectors
	if len(r.Selectors) > RecordMaxSelectors {
		return ErrRecordTooManySelectors
	}

	// Timestamp must be within a sane range
	if r.Timestamp > (TimeSec() + uint64(n.genesisParameters.RecordMaxForwardTimeDrift)) {
		return ErrRecordViolatesSpecialRelativity
	}
	if r.Timestamp < n.genesisParameters.TimestampFloor {
		return ErrRecordTooOld
	}

	// Work must be present if work is required
	if r.WorkAlgorithm == RecordWorkAlgorithmNone && n.genesisParameters.WorkRequired {
		return ErrRecordInsufficientWork
	}

	// Sanity check certificate field: no certs if no roots, must have cert if required
	if r.Certificate != nil && len(n.genesisParameters.RootCertificateAuthorities) == 0 {
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

// SetCommentaryEnabled sets whether or not background CPU power is used to render commentary.
// The default is false for new nodes. If true, nearly all background CPU is used
// to publish records that add work to the DAG and render commentary on any records
// that appear suspect. These can be included in query results to allow end users to
// decide what records they trust in the event of a conflict.
func (n *Node) SetCommentaryEnabled(j bool) {
	jj := uint32(0)
	if j {
		jj = 1
	}
	atomic.StoreUint32(&n.commentary, jj)
	if !j {
		n.commentsLock.Lock()
		n.comments = list.New()
		n.commentsLock.Unlock()
	}
}

// handleGenesisRecord handles new genesis records when starting up or if they arrive over the net.
func (n *Node) handleGenesisRecord(gr *Record) bool {
	grHash := gr.Hash()
	grHashStr := Base62Encode(grHash[:])
	rv, err := gr.GetValue(nil)
	if err != nil {
		n.log[LogLevelWarning].Printf("WARNING: genesis record =%s contains an invalid value, ignoring!", grHashStr)
	} else if len(rv) > 0 {
		if atomic.LoadUint64(&n.lastGenesisRecordTimestamp) < gr.Timestamp {
			n.log[LogLevelNormal].Printf("applying genesis configuration update from record =%s", grHashStr)
			n.genesisParameters.Update(rv)
			atomic.StoreUint64(&n.lastGenesisRecordTimestamp, gr.Timestamp)
			return true
		}
		n.log[LogLevelNormal].Printf("ignoring genesis configuration update from record =%s: timestamp %d <= latest timestamp %d", grHashStr, gr.Timestamp, n.lastGenesisRecordTimestamp)
	}
	return false
}

// handleSynchronizedRecord is called by db when records' dependencies are fully satisfied all through the DAG.
func (n *Node) handleSynchronizedRecord(doff uint64, dlen uint, reputation int, hash *[32]byte) {
	// This is the handler passed to 'db' to be called when records are fully synchronized, meaning
	// they have all their dependencies met and are ready to be replicated.
	n.backgroundThreadWG.Add(1)
	go func() {
		if atomic.LoadUint32(&n.shutdown) != 0 {
			return
		}

		defer func() {
			e := recover()
			if e != nil && atomic.LoadUint32(&n.shutdown) != 0 {
				n.log[LogLevelWarning].Printf("WARNING: unexpected panic replicating synchronized record: %s", e)
			}
			n.backgroundThreadWG.Done()
		}()

		recordHashStr := Base62Encode(hash[:])
		rdata, err := n.db.getDataByOffset(doff, dlen, nil)
		if len(rdata) > 0 && err == nil {
			r, err := NewRecordFromBytes(rdata)
			if err == nil {
				// If this record's local reputation is bad, check and see if we have any good
				// reputation local records with the same ID and owner. If so and if commenting
				// is enabled, generate a comment record that we will publish under our owner.
				if reputation <= 0 && atomic.LoadUint32(&n.commentary) != 0 {
					rid := r.ID()
					n.db.getAllByIDNotOwner(rid[:], r.Owner, func(_, _ uint64, reputation int) bool {
						if reputation > 0 { // a positive reputation fully synchronized record with a different owner exists
							n.commentsLock.Lock()
							n.comments.PushBack(&comment{
								subject:   hash[:],
								assertion: commentAssertionRecordCollidesWithClaimedID,
								reason:    commentReasonAutomaticallyFlagged,
							})
							n.commentsLock.Unlock()
							return false // done scanning, all we need is one
						}
						return true
					})
				}

				// Certain record types get special handling when they're synchronized.
				switch r.GetType() {
				case RecordTypeGenesis:
					n.handleGenesisRecord(r)
				case RecordTypeCommentary:
					cdata, err := r.GetValue(nil)
					if err == nil && len(cdata) > 0 {
						var c comment
						for len(cdata) > 0 {
							cdata, err = c.readFrom(cdata)
							if err == nil {
								n.log[LogLevelVerbose].Printf("commentary: @%s: %s", Base62Encode(r.Owner), c.string())
								n.db.logComment(doff, int(c.assertion), int(c.reason), c.subject)
							} else {
								break
							}
						}
					}
				}

				// Announce that we have this record to connected peers (rumor/gossip propagation)
				var msg [33]byte
				msg[0] = p2pProtoMessageTypeHaveRecords
				copy(msg[1:], hash[:])
				announcementCount := 0
				n.peersLock.RLock()
				if len(n.peers) > 0 {
					for _, p := range n.peers {
						if atomic.LoadUint32(&n.shutdown) != 0 {
							break
						}
						if p.peerHelloMsg.SubscribeToNewRecords {
							p.hasRecordsLock.Lock()
							_, hasRecord := p.hasRecords[*hash]
							p.hasRecordsLock.Unlock()
							if !hasRecord {
								p.send(msg[:])
								announcementCount++
							}
						}
					}
				}
				n.peersLock.RUnlock()

				n.log[LogLevelNormal].Printf("sync: =%s synchronized (subjective reputation %d), announced to %d peers", recordHashStr, reputation, announcementCount)
			} else {
				n.log[LogLevelWarning].Printf("WARNING: record =%s deserialization error: %s (is your node version too old?)", recordHashStr, err.Error())
			}
		} else {
			n.log[LogLevelWarning].Printf("WARNING: unable to read record at byte index %d in data file", doff)
		}
	}()
}

// backgroundWorkerMain is run in a background gorountine to do various housekeeping tasks.
func (n *Node) backgroundWorkerMain() {
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

		// Peroidically clean and write peers.json
		if (ticker % 120) == 0 {
			n.writeKnownPeers()
		}

		// Request wanted records (if connected), requesting newly wanted records with
		// zero retries immediately and then requesting records with higher numbers of
		// retries less often.
		if (ticker % 30) == 0 {
			n.requestWantedRecords(1, p2pProtoMaxRetries)
		} else {
			n.requestWantedRecords(0, 0)
		}

		// If we don't have enough connections, try to make more to peers we've learned about.
		if (ticker % 10) == 5 {
			n.peersLock.RLock()
			connectionCount := len(n.peers) // this value is used in the next block too
			n.peersLock.RUnlock()
			if connectionCount < p2pDesiredConnectionCount {
				wantMore := p2pDesiredConnectionCount - connectionCount
				n.knownPeersLock.Lock()
				if len(n.knownPeers) > 0 {
					visited := make(map[int]bool)
					for k := 0; k < wantMore; k++ {
						idx := rand.Int() % len(n.knownPeers)
						if _, have := visited[idx]; !have {
							kp := n.knownPeers[idx]
							n.Connect(kp.IP, kp.Port, kp.Identity)
							visited[idx] = true
						}
					}
				}
				n.knownPeersLock.Unlock()
			}
		}

		// Periodically check and update database full sync state.
		if (ticker % 5) == 0 {
			if n.db.haveDanglingLinks(p2pProtoMaxRetries) {
				if atomic.SwapUint32(&n.synchronized, 0) == 1 {
					n.log[LogLevelVerbose].Println("sync: database no longer fully synchronized (as of now)")
				}
			} else {
				if atomic.SwapUint32(&n.synchronized, 1) == 0 {
					n.log[LogLevelVerbose].Println("sync: database fully synchronized! (as of now)")
				}
			}
		}
	}
}

// commentaryGeneratorMain is run to generate commentary and add work to the DAG (if enabled).
func (n *Node) commentaryGeneratorMain() {
	var err error
	desiredMinOverhead := 1024
	for atomic.LoadUint32(&n.shutdown) == 0 {
		time.Sleep(time.Second) // 1s pause between each new record
		if atomic.LoadUint32(&n.commentary) != 0 && atomic.LoadUint32(&n.shutdown) == 0 {
			overhead := desiredMinOverhead

			var commentary []byte
			commentCount := 0
			n.commentsLock.Lock()
			for n.comments.Len() > 0 {
				f := n.comments.Front()
				c := f.Value.(*comment)
				s := c.sizeBytes()
				if len(commentary)+s > int(n.genesisParameters.RecordMaxValueSize) {
					break
				}
				commentary, err = c.appendTo(commentary)
				if err != nil {
					commentary = nil
					break
				}
				commentCount++
				overhead -= s
				n.comments.Remove(f)
			}
			n.commentsLock.Unlock()

			if overhead < 0 {
				overhead = 0
			}
			nlinks := uint(overhead / 32)
			if nlinks < n.genesisParameters.RecordMinLinks {
				nlinks = n.genesisParameters.RecordMinLinks
			}
			if nlinks < 1 {
				nlinks = 1
			} else if nlinks > RecordMaxLinks {
				nlinks = RecordMaxLinks
			}
			links, err := n.db.getLinks2(nlinks)

			if err == nil && len(links) > 0 {
				startTime := TimeMs()
				rec, err := NewRecord(RecordTypeCommentary, commentary, links, nil, nil, nil, nil, TimeSec(), n.getBackgroundWorkFunction(), n.owner)
				endTime := TimeMs()
				if err == nil {
					err = n.AddRecord(rec)
					if err == nil {
						// Tune desired overhead to attempt to achieve a commentary rate of one
						// new record every two minutes.
						duration := endTime - startTime
						if duration < 120000 {
							desiredMinOverhead += 32
						} else if duration > 120000 && desiredMinOverhead > 32 {
							desiredMinOverhead -= 32
						}

						rhash := rec.Hash()
						n.log[LogLevelVerbose].Printf("commentary: =%s submitted with %d comments and %d links (generation took %f seconds)", Base62Encode(rhash[:]), commentCount, len(links), float64(duration)/1000.0)
					} else {
						n.log[LogLevelWarning].Printf("WARNING: error creating record: %s", err.Error())
					}
				} else {
					n.log[LogLevelWarning].Printf("WARNING: error creating record: %s", err.Error())
				}
			}
		}
	}
}

// requestWantedRecords requests wanted records within the given inclusive retry bound.
func (n *Node) requestWantedRecords(minRetries, maxRetries int) {
	n.peersLock.RLock()
	defer n.peersLock.RUnlock()
	if len(n.peers) == 0 {
		return // don't do anything if there are no open connections
	}
	count, hashes := n.db.getWanted(256, minRetries, maxRetries, true)
	if len(hashes) >= 32 {
		var p *peer
		for _, pp := range n.peers { // exploits the random map iteration order in Go
			p = pp
			break
		}
		if p != nil {
			n.log[LogLevelNormal].Printf("sync: requesting %d wanted records from %s (retry count range %d-%d)", count, p.address, minRetries, maxRetries)
			n.backgroundThreadWG.Add(1)
			go func() {
				defer func() {
					_ = recover()
					n.backgroundThreadWG.Done()
				}()
				req := make([]byte, 1, len(hashes)+1)
				req[0] = p2pProtoMesaggeTypeRequestRecordsByHash
				req = append(req, hashes...)
				p.send(req)
			}()
		}
	}
}

// writeKnownPeers writes the current known peer list
func (n *Node) writeKnownPeers() {
	n.knownPeersLock.Lock()
	defer n.knownPeersLock.Unlock()
	if len(n.knownPeers) > 0 {
		// Clean old peers before writing
		var p []*knownPeer
		now := TimeMs()
		for _, kp := range n.knownPeers {
			if (now - kp.LastSuccessfulConnection) < p2pPeerExpiration {
				p = append(p, kp)
			}
		}
		if len(p) != len(n.knownPeers) {
			n.knownPeers = p
		}

		// Peers are sorted in descending order of first connection
		sort.Slice(n.knownPeers, func(b, a int) bool {
			return n.knownPeers[b].FirstConnect < n.knownPeers[a].FirstConnect
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
func (n *Node) getBackgroundWorkFunction() (wf *Wharrgarblr) {
	n.workFunctionLock.RLock()
	if n.backgroundWorkFunction != nil {
		wf = n.backgroundWorkFunction
		n.workFunctionLock.RUnlock()
		return
	}
	n.workFunctionLock.RUnlock()

	if n.genesisParameters.WorkRequired {
		// For background commentary generation don't use every core on N-core systems.
		threads := runtime.NumCPU()
		if threads >= 3 {
			threads -= 2
		} else {
			threads = 1
		}
		n.workFunctionLock.Lock()
		if n.backgroundWorkFunction != nil {
			wf = n.backgroundWorkFunction
			n.workFunctionLock.Unlock()
			return
		}
		n.backgroundWorkFunction = NewWharrgarblr(RecordDefaultWharrgarblMemory, threads)
		wf = n.backgroundWorkFunction
		n.workFunctionLock.Unlock()
	}

	return
}

// sendPeerAnnouncement sends a peer announcement to this peer for the given address and public key
func (p *peer) sendPeerAnnouncement(tcpAddr *net.TCPAddr, identity []byte) error {
	var peerMsg APIPeer
	peerMsg.IP = tcpAddr.IP
	peerMsg.Port = tcpAddr.Port
	peerMsg.Identity = identity
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

	for i := 0; i < 12; i++ { // 12 == GCM standard nonce size
		p.outgoingNonce[i]++
		if p.outgoingNonce[i] != 0 {
			break
		}
	}

	buf := make([]byte, 10, len(msg)+32)
	buf = buf[0:binary.PutUvarint(buf, uint64(len(msg)))]
	buf = p.cryptor.Seal(buf, p.outgoingNonce[0:12], msg, nil)

	p.c.SetWriteDeadline(time.Now().Add(time.Second * 30))
	_, err = p.c.Write(buf)
	if err != nil {
		p.c.Close()
	}
	return
}

// updateKnownPeersWithConnectResult is called from p2pConnectionHandler to update n.knownPeers
func (n *Node) updateKnownPeersWithConnectResult(ip net.IP, port int, identity *Owner) bool {
	n.knownPeersLock.Lock()
	defer n.knownPeersLock.Unlock()
	now := TimeMs()
	idBytes := identity.Bytes()

	if bytes.Equal(idBytes, n.owner.Bytes()) {
		return true
	}

	for _, kp := range n.knownPeers {
		if kp.IP.Equal(ip) && kp.Port == port && bytes.Equal(kp.Identity, idBytes) {
			if kp.FirstConnect == 0 {
				kp.FirstConnect = now
			}
			kp.LastSuccessfulConnection = now
			kp.TotalSuccessfulConnections++
			return true
		}
	}

	n.knownPeers = append(n.knownPeers, &knownPeer{
		APIPeer: APIPeer{
			IP:       ip,
			Port:     port,
			Identity: idBytes,
		},
		FirstConnect:               now,
		LastSuccessfulConnection:   now,
		TotalSuccessfulConnections: 1,
	})

	return false
}

func (n *Node) p2pConnectionHandler(c *net.TCPConn, nodePublic *Owner, inbound bool) {
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

	var expectedRawPublicBytes []byte
	if nodePublic != nil {
		expectedRawPublicBytes = nodePublic.rawPublicKeyBytes()
	}

	c.SetKeepAlivePeriod(time.Second * 10)
	c.SetKeepAlive(true)
	c.SetLinger(0)
	c.SetNoDelay(false)
	reader := bufio.NewReader(c)

	// Exchange public keys (prefixed by connection mode and key length)
	helloMessage := make([]byte, len(n.ownerRawPublicKey)+2)
	helloMessage[0] = p2pProtoModeAES256GCMECCP384
	helloMessage[1] = byte(len(n.ownerRawPublicKey))
	copy(helloMessage[2:], n.ownerRawPublicKey)
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
	remoteRawPublicKey := make([]byte, uint(helloMessage[1]))
	_, err = io.ReadFull(reader, remoteRawPublicKey)
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	if bytes.Equal(remoteRawPublicKey, n.ownerRawPublicKey) {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: other side has same link key! connected to self or link key stolen or accidentally duplicated.", peerAddressStr)
		return
	}
	if len(expectedRawPublicBytes) > 0 && !bytes.Equal(expectedRawPublicBytes, remoteRawPublicKey) {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: remote public key does not match expected (pinned) public key", peerAddressStr)
		return
	}
	helloMessage = nil

	// Perform ECDH key agreement and init encryption
	remotePubX, remotePubY, err := ECCDecompressPublicKey(elliptic.P384(), remoteRawPublicKey)
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: invalid public key: %s", peerAddressStr, err.Error())
		return
	}
	remotePublicOwner, err := newOwnerFromP384(remotePubX, remotePubY)
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: invalid public key: %s", peerAddressStr, err.Error())
		return
	}
	remotePublicOwnerBytes := remotePublicOwner.Bytes()
	remotePublicStr := Base62Encode(remotePublicOwnerBytes)
	remoteShared, err := ECDHAgreeECDSA(remotePubX, remotePubY, n.ownerPrivateKey)
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
	_, err = secureRandom.Read(outgoingNonce[:])
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

	p = &peer{
		n:             n,
		address:       peerAddressStr,
		tcpAddress:    tcpAddr,
		c:             c,
		cryptor:       cryptor,
		hasRecords:    make(map[[32]byte]uintptr),
		outgoingNonce: outgoingNonce,
		remotePublic:  remotePublicOwnerBytes,
		inbound:       inbound,
	}

	msgbuf, err = json.Marshal(&peerHelloMsg{
		ProtocolVersion:       ProtocolVersion,
		MinProtocolVersion:    MinProtocolVersion,
		Version:               Version,
		SoftwareName:          SoftwareName,
		P2PPort:               n.p2pPort,
		HTTPPort:              n.httpPort,
		SubscribeToNewRecords: true,
	})
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	p.send(append([]byte{p2pProtoMessageTypeHello}, msgbuf...))

	// Check to make sure this isn't a redundant connection, announce this
	// peer to other peers (if outbound), and announce other peers to this
	// peer. Then if everything is okay add to peers map.
	n.peersLock.Lock()
	redundant := false
	for _, existingPeer := range n.peers {
		if bytes.Equal(existingPeer.remotePublic, remotePublicOwnerBytes) {
			redundant = true
		}
		if !inbound && publicAddress {
			existingPeer.sendPeerAnnouncement(tcpAddr, p.remotePublic)
		}
		if !existingPeer.inbound && ipIsGlobalPublicUnicast(existingPeer.tcpAddress.IP) {
			p.sendPeerAnnouncement(existingPeer.tcpAddress, existingPeer.remotePublic)
		}
	}
	if redundant {
		if !inbound {
			n.updateKnownPeersWithConnectResult(tcpAddr.IP, tcpAddr.Port, remotePublicOwner) // we can still remember this peer
		}
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: closing redundant link to already connected peer", peerAddressStr)
		return
	}
	n.peers[peerAddressStr] = p
	n.peersLock.Unlock()

	n.connectionsInStartupLock.Lock()
	delete(n.connectionsInStartup, c)
	n.connectionsInStartupLock.Unlock()

	if !inbound {
		n.updateKnownPeersWithConnectResult(tcpAddr.IP, tcpAddr.Port, remotePublicOwner)
	}

	n.log[LogLevelNormal].Printf("P2P connection established to %s %d @%s", tcpAddr.IP.String(), tcpAddr.Port, remotePublicStr)

	performedInboundReachabilityTest := false
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

		switch incomingMessageType {

		case p2pProtoMessageTypeHello:
			if len(msg) > 0 {
				json.Unmarshal(msg, &p.peerHelloMsg)

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
							n.updateKnownPeersWithConnectResult(tcpAddr.IP, p.peerHelloMsg.P2PPort, remotePublicOwner)
							if atomic.LoadUint32(&n.shutdown) == 0 {
								n.peersLock.RLock()
								for _, otherPeer := range n.peers {
									if &otherPeer != &p {
										otherPeer.sendPeerAnnouncement(testAddr, p.remotePublic)
									}
								}
								n.peersLock.RUnlock()
							}
							testConn.Close()
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
					if len(peerMsg.Identity) > 0 {
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
							n.Connect(peerMsg.IP, peerMsg.Port, peerMsg.Identity)
							time.Sleep(time.Millisecond * 50) // also helps limit flooding, giving connects time to update connections in startup map
						}
					}
				}
			}

		} // switch incomingMessageType
	}
}
