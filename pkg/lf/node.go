/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * --
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial closed-source software that incorporates or links
 * directly against ZeroTier software without disclosing the source code
 * of your own application.
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
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
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
	p2pProtoMessageTypePeer                 byte = 5 // Peer (JSON)

	// p2pProtoMaxRetries is the maximum number of times we'll try to retry a record
	p2pProtoMaxRetries = 256

	// p2pDesiredConnectionCount is how many P2P TCP connections we want to have open
	p2pDesiredConnectionCount = 32

	// Delete peers that haven't been used in this long.
	p2pPeerExpiration = 1000 * 60 * 60 * 24 * 3 // 3 days

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
	FirstConnect               uint64
	LastSuccessfulConnection   uint64
	TotalSuccessfulConnections int64
}

// Node is an instance of a full LF node supporting both P2P and HTTP access.
type Node struct {
	basePath         string
	peersFilePath    string
	p2pPort          int
	httpPort         int
	localTest        bool
	log              [logLevelCount]*log.Logger
	httpTCPListener  *net.TCPListener
	httpServer       *http.Server
	p2pTCPListener   *net.TCPListener
	workFunction     *Wharrgarblr
	workFunctionLock sync.Mutex
	mountPoints      map[string]*FS
	mountPointsLock  sync.Mutex
	db               db

	owner        *Owner // Owner for commentary, key also currently used for ECDH on link
	identity     []byte // Compressed public key from owner
	identityStr  string // Identity in base62 format
	apiAuthToken string // Secret auth token for HTTP API privileged commands

	genesisParameters          GenesisParameters // Genesis configuration for this node's network
	genesisOwner               OwnerPublic       // Owner of genesis record(s)
	lastGenesisRecordTimestamp uint64            //

	knownPeers               map[string]*knownPeer // Peers we know about by base62-encoded identity
	knownPeersLock           sync.Mutex            //
	connectionsInStartup     map[*net.TCPConn]bool // Connections in startup state but not yet in peers[]
	connectionsInStartupLock sync.Mutex            //
	peers                    []*connectedPeer      // Currently connected peers by randomized FNV hash of identity
	peersLock                sync.RWMutex          //

	recordsRequested     map[[32]byte]uintptr // When records were last requested
	recordsRequestedLock sync.Mutex           //

	comments     *list.List // Accumulates commentary if commentary is enabled
	commentsLock sync.Mutex //

	backgroundThreadWG sync.WaitGroup // used to wait for all goroutines
	startTime          time.Time      // time node started
	timeTicker         uintptr        // ticks approximately every second
	synchronized       uint32         // set to non-zero when database is synchronized
	shutdown           uint32         // set to non-zero to cause many routines to exit
	commentary         uint32         // set to non-zero to add work and render commentary
}

//////////////////////////////////////////////////////////////////////////////

// NewNode creates and starts a node.
func NewNode(basePath string, p2pPort int, httpPort int, logger *log.Logger, logLevel int, localTest bool) (*Node, error) {
	n := new(Node)

	n.basePath = basePath
	n.peersFilePath = path.Join(basePath, "peers.json")
	n.p2pPort = p2pPort
	n.httpPort = httpPort
	n.localTest = localTest
	n.mountPoints = make(map[string]*FS)
	n.knownPeers = make(map[string]*knownPeer)
	n.connectionsInStartup = make(map[*net.TCPConn]bool)
	n.recordsRequested = make(map[[32]byte]uintptr)
	n.comments = list.New()
	n.startTime = time.Now()

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

	n.log[LogLevelNormal].Printf("--- node starting up at %s", n.startTime.String())

	err := n.db.open(basePath, n.log, n.handleSynchronizedRecord)
	if err != nil {
		return nil, err
	}

	// Load or generate this node's identity, which is an owner that it uses to generate
	// commentary if enabled and also a key pair for P2P key agreement.
	ownerPath := path.Join(basePath, "identity-secret.pem")
	ownerBytes, _ := ioutil.ReadFile(ownerPath)
	if len(ownerBytes) > 0 {
		pb, _ := pem.Decode(ownerBytes)
		if pb != nil {
			n.owner, err = NewOwnerFromPrivateBytes(pb.Bytes)
			if err != nil {
				n.owner = nil
				err = nil
			}
		}
	}
	if n.owner == nil {
		n.owner, err = NewOwner(OwnerTypeNistP384)
		if err != nil {
			return nil, err
		}
		priv, err := n.owner.PrivateBytes()
		if err != nil {
			return nil, err
		}
		err = ioutil.WriteFile(ownerPath, []byte(pem.EncodeToMemory(&pem.Block{Type: OwnerPrivatePEMType, Bytes: priv})), 0600)
		if err != nil {
			return nil, err
		}
	}
	n.identity, err = ECDSACompressPublicKey(&n.owner.Private.(*ecdsa.PrivateKey).PublicKey)
	if err != nil {
		return nil, err
	}
	n.identityStr = Base62Encode(n.identity)

	// Load or generate authtoken.secret for API.
	authTokenPath := path.Join(basePath, "authtoken.secret")
	authTokenBytes, _ := ioutil.ReadFile(authTokenPath)
	if len(authTokenBytes) > 0 {
		n.apiAuthToken = string(authTokenBytes)
	} else {
		var junk [24]byte
		secureRandom.Read(junk[:])
		n.apiAuthToken = Base62Encode(junk[:])
		err = ioutil.WriteFile(authTokenPath, []byte(n.apiAuthToken), 0600)
		if err != nil {
			return nil, err
		}
	}

	if httpPort > 0 {
		n.httpTCPListener, err = net.ListenTCP("tcp", &net.TCPAddr{Port: httpPort})
		if err != nil {
			return nil, err
		}
		n.httpServer = &http.Server{
			MaxHeaderBytes: 4096,
			ErrorLog:       n.log[LogLevelWarning],
			Handler:        httpCompressionHandler(apiCreateHTTPServeMux(n)),
			IdleTimeout:    10 * time.Second,
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   30 * time.Second,
		}
		n.httpServer.SetKeepAlivesEnabled(true)
	}

	if p2pPort > 0 && !n.localTest {
		n.p2pTCPListener, err = net.ListenTCP("tcp", &net.TCPAddr{Port: p2pPort})
		if err != nil {
			return nil, err
		}
	}

	if n.localTest {
		n.log[LogLevelNormal].Print("--- running in local test mode, p2p disabled, proof of work optional")
	}
	if n.p2pTCPListener != nil {
		n.log[LogLevelNormal].Printf("P2P port: %d identity: %s", p2pPort, n.identityStr)
	}
	if n.httpTCPListener != nil {
		n.log[LogLevelNormal].Printf("HTTP API port: %d", httpPort)
	}
	n.log[LogLevelNormal].Printf("oracle commentary owner: %s (if generated)", n.owner.String())

	// Load genesis.lf or use compiled-in defaults for global LF network
	var genesisReader io.Reader
	genesisPath := path.Join(basePath, "genesis.lf")
	genesisFile, err := os.Open(genesisPath)
	if err == nil && genesisFile != nil {
		genesisReader = genesisFile
	} else {
		genesisReader = bytes.NewReader(SolGenesisRecords)
	}
	haveInitialGenesisRecords := true
	for {
		var r Record
		err := r.UnmarshalFrom(genesisReader)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("invalid initial genesis record(s): " + err.Error())
		}

		if len(n.genesisOwner) == 0 {
			n.genesisOwner = r.Owner
		}

		if bytes.Equal(n.genesisOwner, r.Owner) { // sanity check
			rh := r.Hash()
			if !n.db.hasRecord(rh[:]) {
				haveInitialGenesisRecords = false
				n.log[LogLevelNormal].Printf("adding initial genesis record =%s", Base62Encode(rh[:]))
				err = n.db.putRecord(&r)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	if !haveInitialGenesisRecords {
		if genesisFile == nil {
			n.log[LogLevelNormal].Print("genesis.lf not found, used compiled-in defaults for global public network node")
			ioutil.WriteFile(genesisPath, SolGenesisRecords, 0644)
		} else {
			n.log[LogLevelNormal].Print("genesis.lf found, initial genesis records loaded")
			genesisFile.Close()
		}
	}
	if len(n.genesisOwner) == 0 {
		return nil, errors.New("no default genesis records found; database cannot be initialized and/or genesis record lineage cannot be determined")
	}

	// Load and replay genesis records, passing them through handler to bring network config to current state.
	n.log[LogLevelNormal].Printf("replaying genesis records by genesis owner @%s", Base62Encode(n.genesisOwner))
	gotGenesis := false
	n.db.getAllByOwner(n.genesisOwner, func(doff, dlen uint64, reputation int) bool {
		rdata, _ := n.db.getDataByOffset(doff, uint(dlen), nil)
		if len(rdata) > 0 {
			gr, err := NewRecordFromBytes(rdata)
			if gr != nil && err == nil && gr.Type == RecordTypeGenesis {
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

	// Load peers.json if present
	peersJSON, err := ioutil.ReadFile(n.peersFilePath)
	if err == nil && len(peersJSON) > 0 {
		if json.Unmarshal(peersJSON, &n.knownPeers) != nil {
			n.knownPeers = make(map[string]*knownPeer)
		}
	}

	if n.p2pTCPListener != nil {
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
	}

	if n.httpTCPListener != nil {
		n.backgroundThreadWG.Add(1)
		go func() {
			defer n.backgroundThreadWG.Done()
			n.httpServer.Serve(n.httpTCPListener)
			if n.httpServer != nil {
				n.httpServer.Close()
			}
		}()
	}

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

	// Add server's local URL to client config if it's not there already.
	if n.httpTCPListener != nil {
		clientConfigPath := path.Join(basePath, ClientConfigName)
		var cc ClientConfig
		cc.Load(clientConfigPath)
		myURL := fmt.Sprintf("http://127.0.0.1:%d", httpPort)
		haveURL := false
		for _, u := range cc.URLs {
			if u == myURL {
				haveURL = true
				break
			}
		}
		if !haveURL {
			cc.URLs = append([]string{myURL}, cc.URLs...)
			cc.Save(clientConfigPath)
		}
	}

	initOk = true

	n.log[LogLevelNormal].Print("--- node startup successful")

	go func() {
		var mounts []MountPoint
		mj, _ := ioutil.ReadFile(path.Join(basePath, "mounts.json"))
		if len(mj) > 0 {
			err := json.Unmarshal(mj, &mounts)
			if err != nil {
				n.log[LogLevelWarning].Printf("WARNING: lffs: ignoring mounts.json due to JSON parse error: %s", err.Error())
			}
			for _, mp := range mounts {
				if atomic.LoadUint32(&n.shutdown) != 0 {
					break
				}
				var owner *Owner
				var maskingKey []byte
				if len(mp.Passphrase) > 0 {
					pp := []byte(mp.Passphrase)
					mkh := sha256.Sum256(pp)
					mkh = sha256.Sum256(mkh[:]) // double hash to ensure difference from seededprng
					maskingKey = mkh[:]
					owner, err = NewOwnerFromSeed(OwnerTypeEd25519, pp)
					if err != nil {
						n.log[LogLevelWarning].Printf("WARNING: lffs: cannot mount %s: error generating owner from passphrase: %s", mp.Path, err.Error())
						continue
					}
				} else {
					if len(mp.OwnerPrivate) > 0 {
						owner, err = NewOwnerFromPrivateBytes(mp.OwnerPrivate)
						if err != nil {
							n.log[LogLevelWarning].Printf("WARNING: lffs: cannot mount %s: invalid owner private key: %s", mp.Path, err.Error())
							continue
						}
					}
					if len(mp.MaskingKey) > 0 {
						maskingKey = mp.MaskingKey
					}
				}
				_, err = n.Mount(owner, mp.MaxFileSize, mp.Path, mp.RootSelectorName, maskingKey)
				if err != nil {
					n.log[LogLevelWarning].Printf("WARNING: lffs: cannot mount %s: %s", mp.Path, err.Error())
				}
			}
		}
	}()

	return n, nil
}

// Stop terminates the running node, blocking until all gorountines are done.
// No methods should be called after this and the Node should be discarded.
func (n *Node) Stop() {
	n.log[LogLevelNormal].Printf("shutting down")
	if atomic.SwapUint32(&n.shutdown, 1) == 0 {
		n.mountPointsLock.Lock()
		for mpp, mp := range n.mountPoints {
			mp.Close()
			delete(n.mountPoints, mpp)
		}
		n.mountPointsLock.Unlock()

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

		n.workFunctionLock.Lock()
		if n.workFunction != nil {
			n.workFunction.Abort()
		}
		n.workFunctionLock.Unlock()

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

// Mount mounts the data store under a given root selector name into the host filesystem using FUSE.
func (n *Node) Mount(owner *Owner, maxFileSize int, mountPoint string, rootSelectorName []byte, maskingKey []byte) (*FS, error) {
	n.mountPointsLock.Lock()
	defer n.mountPointsLock.Unlock()
	if _, have := n.mountPoints[mountPoint]; have {
		return nil, ErrAlreadyMounted
	}
	if owner == nil {
		owner = n.owner
	}
	fs, err := NewFS(n, mountPoint, rootSelectorName, owner, maxFileSize, nil, maskingKey)
	if err != nil {
		return nil, err
	}
	n.mountPoints[mountPoint] = fs
	return fs, nil
}

// Unmount unmounts a mount point or does nothing if not mounted.
func (n *Node) Unmount(mountPoint string) error {
	n.mountPointsLock.Lock()
	defer n.mountPointsLock.Unlock()
	fs := n.mountPoints[mountPoint]
	delete(n.mountPoints, mountPoint)
	if fs != nil {
		go fs.Close()
	}
	return nil
}

// Mounts returns a list of mount points for this node.
func (n *Node) Mounts(includeSecrets bool) (m []MountPoint) {
	n.mountPointsLock.Lock()
	for p, fs := range n.mountPoints {
		var op Blob
		var mk Blob
		if includeSecrets {
			op, _ = fs.owner.PrivateBytes()
			mk = fs.maskingKey
		}
		m = append(m, MountPoint{
			Path:             p,
			RootSelectorName: fs.rootSelectorName,
			Owner:            fs.owner.Public,
			OwnerPrivate:     op,
			MaskingKey:       mk,
			MaxFileSize:      fs.maxFileSize,
		})
	}
	n.mountPointsLock.Unlock()
	return
}

// GetHTTPHandler gets the HTTP handler for this Node.
// If you want to handle requests via e.g. a Lets Encrypt HTTPS server you can use
// this to get the handler to pass to your server.
func (n *Node) GetHTTPHandler() http.Handler { return n.httpServer.Handler }

// ConnectedPeerCount returns the number of active P2P connections.
func (n *Node) ConnectedPeerCount() int {
	n.peersLock.RLock()
	c := len(n.peers)
	n.peersLock.RUnlock()
	return c
}

// Connect attempts to establish a peer-to-peer connection to a remote node.
func (n *Node) Connect(ip net.IP, port int, identity []byte) {
	if n.localTest || bytes.Equal(identity, n.identity) {
		return
	}

	n.peersLock.RLock()
	for _, p := range n.peers {
		if bytes.Equal(identity, p.identity) {
			n.peersLock.RUnlock()
			return
		}
	}
	n.peersLock.RUnlock()

	n.backgroundThreadWG.Add(1)
	go func() {
		defer n.backgroundThreadWG.Done()

		n.log[LogLevelVerbose].Printf("P2P attempting to connect to %s %d %s", ip.String(), port, Base62Encode(identity))

		ta := net.TCPAddr{IP: ip, Port: port}
		conn, err := net.DialTimeout("tcp", ta.String(), time.Second*10)
		if atomic.LoadUint32(&n.shutdown) == 0 {
			if err == nil {
				n.backgroundThreadWG.Add(1)
				go n.p2pConnectionHandler(conn.(*net.TCPConn), identity, false)
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

	// Check to see if we already have this record.
	if n.db.hasRecord(rhash[:]) {
		return ErrDuplicateRecord
	}

	// Check basic constraints first since this is less CPU intensive than signature
	// and work validation.

	// Genesis records and config updates can only come from the genesis owner.
	if r.Type == RecordTypeGenesis && !bytes.Equal(r.Owner, n.genesisOwner) {
		return ErrRecordProhibited
	}

	// Genesis records can only come from the genesis owner
	// Is record too big according to protocol or genesis parameter constraints?
	rsize := uint(r.SizeBytes())
	if rsize > RecordMaxSize {
		return ErrRecordTooLarge
	}

	// Is value too big?
	if uint(r.ValueDataSize()) > n.genesisParameters.RecordMaxValueSize {
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

	// Timestamp must not be too far in the future
	if r.Timestamp > (TimeSec() + uint64(n.genesisParameters.RecordMaxTimeDrift)) {
		return ErrRecordViolatesSpecialRelativity
	}

	// Validate record's internal structure and check signatures and work.
	err := r.Validate(n.localTest) // ignore work in local test mode
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

func (n *Node) getWorkFunction() *Wharrgarblr {
	var wf *Wharrgarblr
	n.workFunctionLock.Lock()
	if n.workFunction != nil {
		wf = n.workFunction
	} else {
		n.workFunction = NewWharrgarblr(RecordDefaultWharrgarblMemory, runtime.NumCPU()-1)
		wf = n.workFunction
	}
	n.workFunctionLock.Unlock()
	return wf
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
				n.log[LogLevelWarning].Printf("WARNING: BUG: unexpected panic handling synchronized record: %s", e)
			}
			n.backgroundThreadWG.Done()
		}()

		rdata, err := n.db.getDataByOffset(doff, dlen, nil)
		if len(rdata) > 0 && err == nil {
			r, err := NewRecordFromBytes(rdata)
			if err == nil {
				// Check to make sure this record only links to records that are older than it to within
				// permitted fuzziness for network. (Only bother if reputation is above this threshold.)
				if reputation > dbReputationTemporalViolation {
					for li := range r.Links {
						ok, linkTS := n.db.getRecordTimestampByHash(r.Links[li][:])
						if ok {
							if linkTS > r.Timestamp && (linkTS-r.Timestamp) > uint64(n.genesisParameters.RecordMaxTimeDrift) {
								n.log[LogLevelVerbose].Printf("record %s reputation adjusted from %d to %d since it links to records newer than itself", r.HashString(), reputation, dbReputationTemporalViolation)
								reputation = dbReputationTemporalViolation
								n.db.updateRecordReputationByHash(hash[:], reputation)
								break
							}
						} else {
							n.log[LogLevelFatal].Printf("FATAL: I/O error or database corruption: record %s was reported by database as synchronized, but is not since link =%s is missing!", r.HashString(), Base62Encode(r.Links[li][:]))
							go n.Stop()
							return
						}
					}
				}

				// If record looks like a collision and if we have other records that have a positive reputation,
				// generate a commentary record indicating that this record is suspect.
				if reputation <= dbReputationCollision && atomic.LoadUint32(&n.commentary) != 0 {
					rid := r.ID()
					n.db.getAllByIDNotOwner(rid[:], r.Owner, func(_, _ uint64, alreadyHaveReputation int) bool {
						if alreadyHaveReputation > reputation {
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
				switch r.Type {
				case RecordTypeGenesis:
					n.handleGenesisRecord(r)
				case RecordTypeCommentary:
					cdata, err := r.GetValue(nil)
					if err == nil && len(cdata) > 0 {
						var c comment
						for len(cdata) > 0 {
							cdata, err = c.readFrom(cdata)
							if err == nil {
								n.log[LogLevelVerbose].Printf("comment: @%s: %s", Base62Encode(r.Owner), c.string())
								n.db.logComment(doff, int(c.assertion), int(c.reason), c.subject)
							} else {
								break
							}
						}
					}
					//case RecordTypeCertificate: // TODO: not implemented yet
				}

				// If record is of good reputation, announce that we have it to peers. Low reputation records
				// are not announced, but peers can still request them. This causes them to propagate more
				// slowly, increasing the odds of other less synchronized nodes also flagging them as
				// suspect for temporal heuristic reasons.
				if reputation >= dbReputationDefault {
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

					n.log[LogLevelNormal].Printf("sync: %s with local reputation %d (announced to %d peers)", r.HashString(), reputation, announcementCount)
				} else {
					n.log[LogLevelNormal].Printf("sync: %s with local reputation %d (not announced due to below normal reputation)", r.HashString(), reputation)
				}
			} else {
				n.log[LogLevelWarning].Printf("WARNING: could your node be really old? record =%s reputation adjusted from %d to %d since an error occured deserializing it (%s)", Base62Encode(hash[:]), reputation, dbReputationRecordDeserializationFailed, err.Error())
				n.db.updateRecordReputationByHash(hash[:], dbReputationRecordDeserializationFailed)
			}
		} else {
			n.log[LogLevelFatal].Printf("FATAL: I/O error or database corruption: unable to read record at byte index %d with size %d in data file (%s)", doff, dlen, err.Error())
			go n.Stop()
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

		if !n.localTest {
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
				_, links, err := n.db.getLinks(2)
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
			if (ticker % 5) == 1 {
				n.peersLock.RLock()
				connectedCount := len(n.peers)
				n.peersLock.RUnlock()
				if connectedCount < p2pDesiredConnectionCount {
					n.knownPeersLock.Lock()
					if len(n.knownPeers) > 0 {
						var kp *knownPeer
						for _, kp2 := range n.knownPeers { // exploits Go's random map iteration order
							kp = kp2
							break
						}
						n.Connect(kp.IP, kp.Port, kp.Identity)
					} else {
						sp := n.genesisParameters.SeedPeers
						if len(sp) > 0 {
							spp := &sp[rand.Int()%len(sp)]
							n.Connect(spp.IP, spp.Port, spp.Identity)
						}
					}
					n.knownPeersLock.Unlock()
				}
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
	minWorkDifficulty := uint64(0x000f0000)
	for atomic.LoadUint32(&n.shutdown) == 0 {
		time.Sleep(time.Second) // 1s pause between each new record
		if atomic.LoadUint32(&n.commentary) != 0 && atomic.LoadUint32(&n.shutdown) == 0 {
			minWorkDifficultyThisIteration := minWorkDifficulty
			var commentary []byte
			commentCount := 0
			n.commentsLock.Lock()
			for n.comments.Len() > 0 {
				f := n.comments.Front()
				c := f.Value.(*comment)
				s := c.sizeBytes()
				if len(commentary)+s > int(n.genesisParameters.RecordMaxValueSize) {
					minWorkDifficultyThisIteration = 0 // if we have a lot of commentary, don't do extra work this time and get it out there!
					break
				}
				var err error
				commentary, err = c.appendTo(commentary)
				if err != nil {
					commentary = nil
					break
				}
				commentCount++
				n.comments.Remove(f)
			}
			n.commentsLock.Unlock()

			links, err := n.db.getLinks2(RecordMaxLinks)

			if err == nil && len(links) > 0 {
				var rb RecordBuilder
				var rec *Record
				startTime := time.Now()
				err = rb.Start(RecordTypeCommentary, commentary, links, nil, nil, nil, n.owner.Public, nil, TimeSec())
				if err == nil {
					err = rb.AddWork(n.getWorkFunction(), uint32(minWorkDifficultyThisIteration))
					if err == nil {
						rec, err = rb.Complete(n.owner)
					}
				}
				endTime := time.Now()

				if err == nil {
					err = n.AddRecord(rec)
					if err == nil {
						// Tune desired overhead to attempt to achieve a commentary rate of one
						// new record every five minutes. Actual results will vary a lot due to
						// the probabilistic nature of the work function.
						duration := endTime.Sub(startTime).Seconds()
						if minWorkDifficultyThisIteration == minWorkDifficulty { // only adjust when we've run at the desired min difficulty
							if duration < 300.0 {
								minWorkDifficulty += 0x00005000
								if minWorkDifficulty > 0xffffffff {
									minWorkDifficulty = 0xffffffff
								}
							} else if minWorkDifficulty > 0x00010000 {
								minWorkDifficulty -= 0x00005000
							}
						}

						n.log[LogLevelVerbose].Printf("oracle: %s submitted with %d comments (minimum difficulty %.8x created in %f seconds)", rec.HashString(), commentCount, minWorkDifficulty, duration)
					} else {
						n.log[LogLevelWarning].Printf("WARNING: error adding commentary record: %s", err.Error())
					}
				} else {
					n.log[LogLevelWarning].Printf("WARNING: error creating commentary record: %s", err.Error())
				}
			}
		} else {
			// If commentary is disabled, go ahead and let go of work function RAM.
			n.workFunctionLock.Lock()
			n.workFunction = nil
			n.workFunctionLock.Unlock()
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
		var p *connectedPeer
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

// updateKnownPeersWithConnectResult is called from p2pConnectionHandler to update n.knownPeers
func (n *Node) updateKnownPeersWithConnectResult(ip net.IP, port int, identity []byte) {
	if len(identity) == 0 {
		return
	}
	if bytes.Equal(n.identity, identity) {
		return
	}

	n.knownPeersLock.Lock()
	defer n.knownPeersLock.Unlock()

	now := TimeMs()

	idStr := Base62Encode(identity)
	kp := n.knownPeers[idStr]
	if kp == nil {
		kp = &knownPeer{
			Peer: Peer{
				IP:       ip,
				Port:     port,
				Identity: identity,
			},
			FirstConnect:               now,
			LastSuccessfulConnection:   now,
			TotalSuccessfulConnections: 1,
		}
		n.knownPeers[idStr] = kp
	} else {
		if kp.IP.Equal(ip) {
			kp.Port = port
			if kp.FirstConnect == 0 {
				kp.FirstConnect = now
			}
			kp.LastSuccessfulConnection = now
			kp.TotalSuccessfulConnections++
		} else {
			kp.IP = ip
			kp.Port = port
			kp.FirstConnect = now
			kp.LastSuccessfulConnection = now
			kp.TotalSuccessfulConnections = 1
		}
	}
}

// writeKnownPeers writes the current known peer list
func (n *Node) writeKnownPeers() {
	n.knownPeersLock.Lock()
	defer n.knownPeersLock.Unlock()

	now := TimeMs()
	for kpid, kp := range n.knownPeers {
		if (now - kp.LastSuccessfulConnection) > p2pPeerExpiration {
			delete(n.knownPeers, kpid)
		}
	}

	ioutil.WriteFile(n.peersFilePath, []byte(PrettyJSON(&n.knownPeers)), 0644)
}

// sendPeerAnnouncement sends a peer announcement to this peer for the given address and public key
func (p *connectedPeer) sendPeerAnnouncement(tcpAddr *net.TCPAddr, identity []byte) {
	var peerMsg Peer
	peerMsg.IP = tcpAddr.IP
	peerMsg.Port = tcpAddr.Port
	peerMsg.Identity = identity
	json, err := json.Marshal(&peerMsg)
	if err != nil {
		return
	}
	pa := make([]byte, 1, len(json)+1)
	pa[0] = p2pProtoMessageTypePeer
	pa = append(pa, json...)
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
					p.c.Close()
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
			p.c.SetWriteDeadline(time.Now().Add(time.Second * 30))
			_, err := p.c.Write(buf)
			if err != nil {
				p.c.Close()
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
		c.Close()
		return
	}
	peerAddressStr := tcpAddr.String()

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

	c.SetKeepAlivePeriod(time.Second * 10)
	c.SetKeepAlive(true)
	c.SetLinger(0)
	c.SetNoDelay(false)
	reader := bufio.NewReader(c)

	// Send our public key to remote.
	helloMessage := make([]byte, len(n.identity)+2)
	helloMessage[0] = p2pProtoModeAES256GCMECCP384
	helloMessage[1] = byte(len(n.identity))
	copy(helloMessage[2:], n.identity)
	c.SetWriteDeadline(time.Now().Add(time.Second * 30))
	_, err = c.Write(helloMessage)
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}

	// Read remote public key
	c.SetReadDeadline(time.Now().Add(time.Second * 30))
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
	c.SetReadDeadline(time.Now().Add(time.Second * 30))
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
	c.SetWriteDeadline(time.Now().Add(time.Second * 30))
	_, err = c.Write(nonceExchangeTmp[:])
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	c.SetReadDeadline(time.Now().Add(time.Second * 30))
	_, err = io.ReadFull(reader, incomingNonce[:])
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	aesCipher.Decrypt(incomingNonce[:], incomingNonce[:])

	// Exchange hashes of decrypted nonces to verify correct key.
	outgoingNonceHash, incomingNonceHash := sha256.Sum256(outgoingNonce[:]), sha256.Sum256(incomingNonce[:])
	c.SetWriteDeadline(time.Now().Add(time.Second * 30))
	_, err = c.Write(incomingNonceHash[0:16])
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	c.SetReadDeadline(time.Now().Add(time.Second * 30))
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
		HTTPPort:              n.httpPort,
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
			existingPeer.c.Close()
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
		n.updateKnownPeersWithConnectResult(tcpAddr.IP, tcpAddr.Port, remoteIdentity)
	}

	n.log[LogLevelNormal].Printf("P2P connection established to %s %d %s", tcpAddr.IP.String(), tcpAddr.Port, Base62Encode(remoteIdentity))

	performedInboundReachabilityTest := false
mainReaderLoop:
	for atomic.LoadUint32(&n.shutdown) == 0 {
		c.SetReadDeadline(time.Now().Add(time.Second * 120))

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
							n.updateKnownPeersWithConnectResult(tcpAddr.IP, p.peerHelloMsg.P2PPort, remoteIdentity)
							if atomic.LoadUint32(&n.shutdown) == 0 {
								n.peersLock.RLock()
								for _, otherPeer := range n.peers {
									if &otherPeer != &p {
										otherPeer.sendPeerAnnouncement(testAddr, p.identity)
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
							n.Connect(peerMsg.IP, peerMsg.Port, peerMsg.Identity)
						}
					}
				}
			}

		} // switch incomingMessageType
	}
}
