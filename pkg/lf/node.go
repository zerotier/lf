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
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
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
	// DefaultHTTPPort is the default LF HTTP API port
	DefaultHTTPPort = 9980

	// DefaultP2PPort is the default LF P2P port
	DefaultP2PPort = 9908

	// MinFreeDiskSpace is the minimum free space on the device holding LF's data files before which the node will gracefully stop.
	MinFreeDiskSpace = 67108864
)

var nullLogger = log.New(ioutil.Discard, "", 0)

// Node is an instance of a full LF node supporting both P2P and HTTP access.
type Node struct {
	basePath                   string
	peersFilePath              string
	p2pPort                    int
	httpPort                   int
	localTest                  bool
	log                        [logLevelCount]*log.Logger
	httpTCPListener            *net.TCPListener
	httpServer                 *http.Server
	p2pTCPListener             *net.TCPListener
	workFunction               *Wharrgarblr
	workFunctionLock           sync.Mutex
	makeRecordWorkFunction     *Wharrgarblr
	makeRecordWorkFunctionLock sync.Mutex
	mountPoints                map[string]*FS
	mountPointsLock            sync.Mutex
	db                         db

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

	ownerCertificates     map[string][2][]*x509.Certificate // Owner certificate cache
	ownerCertificatesLock sync.Mutex                        //

	comments     *list.List // Accumulates commentary if commentary is enabled
	commentsLock sync.Mutex //

	limboLock          sync.Mutex     // I/O lock for files in limbo/ subfolder
	backgroundThreadWG sync.WaitGroup // used to wait for all goroutines
	startTime          time.Time      // time node started
	runningLock        sync.Mutex     // Locked after start, can be waited on to wait for Stop()
	timeTicker         uintptr        // ticks approximately every second
	synchronized       uint32         // set to non-zero when database is synchronized
	shutdown           uint32         // set to non-zero to cause many routines to exit
	commentary         uint32         // set to non-zero to add work and render commentary
}

//////////////////////////////////////////////////////////////////////////////
// Public functions and methods
//////////////////////////////////////////////////////////////////////////////

// NewNode creates and starts a node.
func NewNode(basePath string, p2pPort int, httpPort int, logger *log.Logger, logLevel int, localTest bool) (*Node, error) {
	os.MkdirAll(basePath, 0755)

	if localTest {
		basePath = path.Join(basePath, "localtest")
		os.MkdirAll(basePath, 0755)
	}

	freeDiskSpace, _ := getFreeSpaceOnDevice(basePath)
	if freeDiskSpace < MinFreeDiskSpace {
		return nil, fmt.Errorf("insufficient free space on device containing '%s' (%d < %d)", basePath, freeDiskSpace, MinFreeDiskSpace)
	}

	n := new(Node)

	n.runningLock.Lock()

	n.basePath = basePath
	n.peersFilePath = path.Join(basePath, "peers.json")
	n.p2pPort = p2pPort
	n.httpPort = httpPort
	n.localTest = localTest
	n.mountPoints = make(map[string]*FS)
	n.knownPeers = make(map[string]*knownPeer)
	n.connectionsInStartup = make(map[*net.TCPConn]bool)
	n.recordsRequested = make(map[[32]byte]uintptr)
	n.ownerCertificates = make(map[string][2][]*x509.Certificate)
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

	n.log[LogLevelNormal].Printf("--- node starting up at %s ---", n.startTime.String())

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
			Handler:        httpCompressionHandler(n.createHTTPServeMux()),
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
		n.log[LogLevelNormal].Print("NOTICE: running in local test mode: p2p disabled, proof of work optional")
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
	go n.backgroundThreadMaintenance()

	// Start background thread to add work to DAG and render commentary (if enabled)
	n.backgroundThreadWG.Add(1)
	go n.backgroundThreadOracle()

	// Set server's client.json URL list to point to itself
	if n.httpTCPListener != nil {
		clientConfigPath := path.Join(basePath, ClientConfigName)
		var cc ClientConfig
		cc.Load(clientConfigPath)
		cc.URLs = []RemoteNode{RemoteNode(fmt.Sprintf("http://127.0.0.1:%d", httpPort))}
		cc.Save(clientConfigPath)
	}

	initOk = true

	// Read and apply mounts.json after node is running
	go func() {
		time.Sleep(time.Second)

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
					owner, maskingKey = PassphraseToOwnerAndMaskingKey(mp.Passphrase)
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

	n.log[LogLevelNormal].Print("--- node startup successful ---")

	return n, nil
}

// Stop terminates the running node, blocking until all gorountines are done.
// No methods should be called after this and the Node should be discarded.
func (n *Node) Stop() {
	n.log[LogLevelNormal].Printf("--- shutting down ---")
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
		n.makeRecordWorkFunctionLock.Lock()
		if n.makeRecordWorkFunction != nil {
			n.makeRecordWorkFunction.Abort()
		}
		n.makeRecordWorkFunctionLock.Unlock()

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

		n.runningLock.Unlock()
	}
}

// WaitForStop stops the calling gorountine until the node stops or is stopped.
func (n *Node) WaitForStop() {
	n.runningLock.Lock()
	n.runningLock.Unlock()
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
	fs, err := NewFS([]LF{n}, n.log[LogLevelNormal], n.log[LogLevelWarning], mountPoint, rootSelectorName, owner, maxFileSize, maskingKey)
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
func (n *Node) Connect(ip net.IP, port int, identity []byte) error {
	if n.localTest || bytes.Equal(identity, n.identity) {
		return nil
	}

	n.peersLock.RLock()
	for _, p := range n.peers {
		if bytes.Equal(identity, p.identity) {
			n.peersLock.RUnlock()
			return nil
		}
	}
	n.peersLock.RUnlock()

	n.backgroundThreadWG.Add(1)
	go func() {
		defer n.backgroundThreadWG.Done()

		n.log[LogLevelVerbose].Printf("P2P attempting to connect to %s %d %s", ip.String(), port, Base62Encode(identity))

		ta := net.TCPAddr{IP: ip, Port: port}
		conn, err := net.DialTimeout("tcp", ta.String(), time.Second*p2pPeerConnectTimeout)
		if atomic.LoadUint32(&n.shutdown) == 0 {
			if err == nil {
				n.backgroundThreadWG.Add(1)
				go n.p2pConnectionHandler(conn.(*net.TCPConn), identity, false)
			} else {
				n.log[LogLevelVerbose].Printf("P2P connection to %s failed: %s", ta.String(), err.Error())
			}
		} else if conn != nil {
			conn.Close()
		}
	}()

	return nil
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

	// Genesis records and config updates can only come from the genesis owner.
	if r.Type == RecordTypeGenesis && !bytes.Equal(r.Owner, n.genesisOwner) {
		return ErrRecordProhibited
	}

	// Is value too big?
	if uint(r.ValueDataSize()) > n.genesisParameters.RecordMaxValueSize {
		return ErrRecordValueTooLarge
	}

	// Are there enough links?
	if uint(len(r.Links)) < n.genesisParameters.RecordMinLinks {
		return ErrRecordInsufficientLinks
	}

	// Timestamp must not be too far in the future
	if r.Timestamp > (TimeSec() + uint64(n.genesisParameters.RecordMaxTimeDrift)) {
		return ErrRecordViolatesSpecialRelativity
	}

	// Validate record's internal structure and check cryptographic signatures.
	err := r.Validate()
	if err != nil {
		return err
	}

	// Check this record's approval status via either PoW or certificates. Note
	// that we accept records into the DAG even if they were approved by later
	// revoked (via CRLs) certificates. This maintains DAG linkage integrity.
	// If we didn't do it this way a CRL could break the DAG. Revoked records do
	// get hidden in query results so they effectively disappear for users.
	_, recordEverApproved := n.recordApprovalStatus(r)
	if !recordEverApproved {
		return ErrRecordNotApproved
	}

	// Add record to database if it passes all checks
	err = n.db.putRecord(r)
	if err != nil {
		return err
	}

	return nil
}

// GetRecord gets a record from its exact hash.
func (n *Node) GetRecord(hash []byte) (*Record, error) {
	if len(hash) != 32 {
		return nil, ErrInvalidParameter
	}
	_, data, err := n.db.getDataByHash(hash, nil)
	if err != nil {
		return nil, err
	}
	return NewRecordFromBytes(data)
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

// GetOwnerCertificates returns all valid non-revoked top-level certificates for a record owner.
func (n *Node) GetOwnerCertificates(owner OwnerPublic) (certs []*x509.Certificate, revokedCerts []*x509.Certificate, err error) {
	if len(owner) == 0 {
		return
	}

	defer func() {
		e := recover()
		if e != nil {
			n.log[LogLevelWarning].Printf("WARNING: panic in GetOwnerCertificate(): %v (bug, but also probably indicates bad cert in data store)", e)
			err = fmt.Errorf("panic in GetOwnerCertificates(): %v", e)
		}
	}()

	ownerSubjectSerialNo := Base62Encode(owner)

	n.ownerCertificatesLock.Lock()
	cachedCerts := n.ownerCertificates[ownerSubjectSerialNo]
	n.ownerCertificatesLock.Unlock()
	if len(cachedCerts[0]) > 0 || len(cachedCerts[1]) > 0 {
		certs = cachedCerts[0]
		revokedCerts = cachedCerts[1]
		return
	}

	certsBySerialNo, crlsByRevokedSerialNo := n.db.getCertInfo(ownerSubjectSerialNo)
	rootsBySerialNo, revokedRootsBySerialNo := n.genesisParameters.GetAuthCertificates()

	// First we check to see if the owner is in fact the root CA. This is special cased
	// since root CAs are not themselves stored directly in the DAG as Certificate records.
	for _, rootCert := range rootsBySerialNo {
		if (rootCert.KeyUsage & x509.KeyUsageDigitalSignature) != 0 {
			pub, _ := rootCert.PublicKey.(*ecdsa.PublicKey)
			ownerPub, _ := NewOwnerPublicFromECDSAPublicKey(pub)
			if bytes.Equal(ownerPub, owner) {
				certs = append(certs, rootCert)
			}
		}
	}
	for _, rootCert := range revokedRootsBySerialNo {
		if (rootCert.KeyUsage & x509.KeyUsageDigitalSignature) != 0 {
			pub, _ := rootCert.PublicKey.(*ecdsa.PublicKey)
			ownerPub, _ := NewOwnerPublicFromECDSAPublicKey(pub)
			if bytes.Equal(ownerPub, owner) {
				revokedCerts = append(certs, rootCert)
			}
		}
	}

	// The LF CA model currently supports one level of intermediate certificates. These
	// must be issued by a root CA and can in turn issue owner certificates. Root CAs
	// can also directly issue owner certificates. CRLs can be issued by the same cert
	// that issued the certificate being revoked provided it has the CRL key usage flag.

	for _, ownerCert := range certsBySerialNo {
		if ownerCert.Subject.SerialNumber == ownerSubjectSerialNo && (ownerCert.KeyUsage|x509.KeyUsageDigitalSignature) != 0 {
			ownerCertIssuer := rootsBySerialNo[ownerCert.Issuer.SerialNumber]
			ownerCertIssuerRevoked := false

			if ownerCertIssuer == nil {
				ownerCertIssuer = revokedRootsBySerialNo[ownerCert.Issuer.SerialNumber]
				ownerCertIssuerRevoked = true
			}

			if ownerCertIssuer == nil {
				intermediate := certsBySerialNo[ownerCert.Issuer.SerialNumber]
				if intermediate != nil {
					intermediateIssuer := rootsBySerialNo[intermediate.Issuer.SerialNumber]

					if intermediateIssuer == nil {
						intermediateIssuer = revokedRootsBySerialNo[intermediate.Issuer.SerialNumber]
						ownerCertIssuerRevoked = true
					}

					if intermediateIssuer != nil &&
						intermediateIssuer.IsCA &&
						(intermediateIssuer.KeyUsage&x509.KeyUsageCertSign) != 0 &&
						intermediate.NotBefore.After(intermediateIssuer.NotBefore) &&
						intermediateIssuer.NotAfter.After(intermediate.NotBefore) &&
						intermediate.CheckSignatureFrom(intermediateIssuer) == nil {
						if !ownerCertIssuerRevoked {
							intCrls := crlsByRevokedSerialNo[ownerCert.Issuer.SerialNumber]
							if (intermediateIssuer.KeyUsage & x509.KeyUsageCRLSign) != 0 {
								for _, crl := range intCrls {
									if intermediateIssuer.CheckCRLSignature(crl) == nil {
										ownerCertIssuerRevoked = true
										break
									}
								}
							}
						}
						ownerCertIssuer = intermediate
					}
				}
			}

			if ownerCertIssuer != nil &&
				ownerCertIssuer.IsCA &&
				(ownerCertIssuer.KeyUsage&x509.KeyUsageCertSign) != 0 &&
				ownerCert.NotBefore.After(ownerCertIssuer.NotBefore) &&
				ownerCertIssuer.NotAfter.After(ownerCert.NotBefore) &&
				ownerCert.CheckSignatureFrom(ownerCertIssuer) == nil {
				ownerCertCrls := crlsByRevokedSerialNo[Base62Encode(ownerCert.SerialNumber.Bytes())]
				ownerCertRevoked := ownerCertIssuerRevoked
				if !ownerCertRevoked && (ownerCertIssuer.KeyUsage&x509.KeyUsageCRLSign) != 0 {
					for _, crl := range ownerCertCrls {
						if ownerCertIssuer.CheckCRLSignature(crl) == nil {
							ownerCertRevoked = true
							break
						}
					}
				}
				if ownerCertRevoked {
					revokedCerts = append(revokedCerts, ownerCert)
				} else {
					certs = append(certs, ownerCert)
				}
			}
		}
	}

	sort.Slice(certs, func(a, b int) bool { return certs[a].NotBefore.Before(certs[b].NotBefore) })
	sort.Slice(revokedCerts, func(a, b int) bool { return revokedCerts[a].NotBefore.Before(revokedCerts[b].NotBefore) })

	n.ownerCertificatesLock.Lock()
	n.ownerCertificates[ownerSubjectSerialNo] = [2][]*x509.Certificate{certs, revokedCerts}
	n.ownerCertificatesLock.Unlock()

	return
}

// OwnerHasCurrentCertificate returns true if this owner has a certificate valid at the current time and not revoked.
func (n *Node) OwnerHasCurrentCertificate(ownerPublic OwnerPublic) (bool, error) {
	certs, _, _ := n.GetOwnerCertificates(ownerPublic)
	now := time.Now().UTC()
	for _, cert := range certs {
		if now.After(cert.NotBefore) && now.Before(cert.NotAfter) {
			return true, nil
		}
	}
	return false, nil
}

// NodeStatus returns a NodeStatus with information about this node.
func (n *Node) NodeStatus() (*NodeStatus, error) {
	var peers []Peer
	n.peersLock.RLock()
	for _, p := range n.peers {
		port := p.tcpAddress.Port
		if p.inbound {
			port = -1
		}
		peers = append(peers, Peer{
			IP:       p.tcpAddress.IP,
			Port:     port,
			Identity: p.identity,
		})
	}
	n.peersLock.RUnlock()

	rc, ds := n.db.stats()
	now := time.Now()

	var oracle OwnerPublic
	if atomic.LoadUint32(&n.commentary) != 0 {
		oracle = n.owner.Public
	}

	return &NodeStatus{
		Software:          SoftwareName,
		Version:           Version,
		APIVersion:        APIVersion,
		MinAPIVersion:     APIVersion,
		MaxAPIVersion:     APIVersion,
		Uptime:            uint64(math.Round(now.Sub(n.startTime).Seconds())),
		Clock:             uint64(now.Unix()),
		RecordCount:       rc,
		DataSize:          ds,
		FullySynchronized: (atomic.LoadUint32(&n.synchronized) != 0),
		GenesisParameters: n.genesisParameters,
		Oracle:            oracle,
		P2PPort:           n.p2pPort,
		LocalTestMode:     n.localTest,
		Identity:          n.identity,
		Peers:             peers,
	}, nil
}

// OwnerStatus returns an OwnerStatus object for an owner.
func (n *Node) OwnerStatus(ownerPublic OwnerPublic) (*OwnerStatus, error) {
	recordCount, recordBytes := n.db.getOwnerStats(ownerPublic)
	certs, revokedCerts, err := n.GetOwnerCertificates(ownerPublic)
	if err != nil {
		return nil, err
	}
	certsBin, revokedCertsBin := make([]Blob, 0, len(certs)), make([]Blob, 0, len(revokedCerts))
	certsCurrent := false
	now := time.Now().UTC()
	for _, cert := range certs {
		certsBin = append(certsBin, cert.Raw)
		if now.After(cert.NotBefore) && now.Before(cert.NotAfter) {
			certsCurrent = true
		}
	}
	for _, revokedCert := range revokedCerts {
		revokedCertsBin = append(revokedCertsBin, revokedCert.Raw)
	}
	links, _ := n.db.getLinks2(n.genesisParameters.RecordMinLinks)
	return &OwnerStatus{
		Owner:                 ownerPublic,
		Certificates:          certsBin,
		RevokedCertificates:   revokedCertsBin,
		HasCurrentCertificate: certsCurrent,
		RecordCount:           recordCount,
		RecordBytes:           recordBytes,
		NewRecordLinks:        CastArraysToHashBlobs(links),
		ServerTime:            uint64(now.Unix()),
	}, nil
}

// Links gets up to RecordMaxLinks links.
func (n *Node) Links(count int) ([][32]byte, uint64, error) {
	if count <= 0 {
		count = int(n.genesisParameters.RecordMinLinks)
	}
	if count > RecordMaxLinks {
		count = RecordMaxLinks
	}
	l, err := n.db.getLinks2(uint(count))
	if err != nil {
		return nil, 0, err
	}
	return l, TimeSec(), nil
}

// GenesisParameters gets the parameters for this network that were specified in genesis record(s).
func (n *Node) GenesisParameters() (*GenesisParameters, error) {
	gp := new(GenesisParameters)
	*gp = n.genesisParameters
	return gp, nil
}

// ExecuteQuery executes a query against this local node.
func (n *Node) ExecuteQuery(query *Query) (QueryResults, error) {
	return query.execute(n)
}

// ExecuteMakeRecord executes a MakeRecord against this local node.
func (n *Node) ExecuteMakeRecord(mr *MakeRecord) (*Record, Pulse, bool, error) {
	return mr.execute(n)
}

// ExecuteMakePulse executes a MakePulse against this local node.
func (n *Node) ExecuteMakePulse(mr *MakePulse) (Pulse, *Record, bool, error) {
	return mr.execute(n)
}

// IsLocal implements IsLocal in the LF interface, always returns true for Node.
func (n *Node) IsLocal() bool { return true }

// DoPulse updates pulse times for any tokens matching this message and returns whether any updates actually occurred.
// Updates are only accepted if they are for records whose timestamps plus the pulse's number of minutes are within
// RecordMaxTimeDrift seconds of the current clock. This is an anti-flooding mechanism to prevent gratuitous pulses
// from being used to waste bandwidth on the network. Updates are no-ops if the pulse in question has already been
// updated to an equal or higher minute count.
func (n *Node) DoPulse(pulse Pulse, announce bool) (bool, error) {
	if len(pulse) >= PulseSize {
		key := pulse.Key()
		if key != 0 {
			minutes := pulse.Minutes()
			startRangeMid := TimeSec() - uint64(minutes*60)
			if n.db.updatePulse(pulse.Token(), uint64(minutes), startRangeMid-uint64(n.genesisParameters.RecordMaxTimeDrift), startRangeMid+uint64(n.genesisParameters.RecordMaxTimeDrift)) {
				if announce {
					var msg [PulseSize + 1]byte
					msg[0] = p2pProtoMessageTypePulse
					copy(msg[1:], pulse)
					n.peersLock.RLock()
					for _, p := range n.peers {
						p.send(msg[:])
					}
					n.peersLock.RUnlock()
				}
				return true, nil
			}
		}
		return false, nil
	}
	return false, ErrInvalidObject
}

//////////////////////////////////////////////////////////////////////////////
// Background tasks that are registered with backgroundThreadWG
//////////////////////////////////////////////////////////////////////////////

// handleSynchronizedRecord is called by db when records' dependencies are fully satisfied all through the DAG.
// This is the handler passed to 'db' to be called when records are fully synchronized, meaning they have all
// their dependencies met and are ready to be replicated. It backgrounds itself immediately to avoid blocking
// the database.
func (n *Node) handleSynchronizedRecord(doff uint64, dlen uint, reputation int, hash *[32]byte) {
	n.backgroundThreadWG.Add(1)
	go func() {
		defer func() {
			e := recover()
			if e != nil && atomic.LoadUint32(&n.shutdown) != 0 {
				n.log[LogLevelWarning].Printf("WARNING: BUG: unexpected panic handling synchronized record: %s", e)
			}
			n.backgroundThreadWG.Done()
		}()

		if atomic.LoadUint32(&n.shutdown) != 0 {
			return
		}

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
								n.log[LogLevelVerbose].Printf("record %s reputation adjusted from %d to %d since it links to records newer than itself (different is beyond max time drift of %d seconds)", r.HashString(), reputation, dbReputationTemporalViolation, n.genesisParameters.RecordMaxTimeDrift)
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
					cdata, _ := r.GetValue(nil)
					if len(cdata) > 0 {
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

				case RecordTypeCertificate:
					cdata, _ := r.GetValue([]byte(RecordCertificateMaskingKey))
					if len(cdata) > 0 {
						certs, _ := x509.ParseCertificates(cdata)
						if len(certs) > 0 {
							for _, cert := range certs {
								err := n.db.putCert(cert, doff)
								if err != nil {
									n.log[LogLevelWarning].Printf("WARNING: error adding certificate to database: %s", err.Error())
								}

								n.ownerCertificatesLock.Lock()
								delete(n.ownerCertificates, cert.Subject.SerialNumber)
								n.ownerCertificatesLock.Unlock()

								n.log[LogLevelNormal].Printf("certificate: new certificate %s issued by %s for subject %s", Base62Encode(cert.SerialNumber.Bytes()), cert.Issuer.SerialNumber, cert.Subject.SerialNumber)

								ownerPublic, _ := NewOwnerPublicFromString("@" + cert.Subject.SerialNumber)
								if len(ownerPublic) > 0 {
									n.backgroundThreadWG.Add(1)
									go n.backgroundTaskProcessRecordsInLimbo(ownerPublic)
								}
							}
						}
					}

				case RecordTypeCRL:
					cdata, _ := r.GetValue([]byte(RecordCertificateMaskingKey))
					if len(cdata) > 0 {
						crl, _ := x509.ParseCRL(cdata)
						if crl != nil {
							for _, revoked := range crl.TBSCertList.RevokedCertificates {
								revokedSerial := Base62Encode(revoked.SerialNumber.Bytes())
								n.db.putCertRevocation(revokedSerial, doff, dlen)
								n.log[LogLevelNormal].Printf("certificate: new CRL from \"%s\" revokes %s", crl.TBSCertList.Issuer.String(), revokedSerial)
							}

							// TODO: right now this just nukes the cert cache. This could be made more fine grained.
							n.ownerCertificatesLock.Lock()
							n.ownerCertificates = make(map[string][2][]*x509.Certificate)
							n.ownerCertificatesLock.Unlock()
						}
					}
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

					n.log[LogLevelVerbose].Printf("sync: %s with local reputation %d (announced to %d peers)", r.HashString(), reputation, announcementCount)
				} else {
					n.log[LogLevelVerbose].Printf("sync: %s with local reputation %d (not announced due to below normal reputation)", r.HashString(), reputation)
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

func (n *Node) backgroundThreadMaintenance() {
	defer n.backgroundThreadWG.Done()

	// Init this in background if it isn't already to speed up node readiness
	WharrgarblInitTable(path.Join(n.basePath, "wharrgarbl-table.bin"))

	for atomic.LoadUint32(&n.shutdown) == 0 {
		time.Sleep(time.Second)
		if atomic.LoadUint32(&n.shutdown) != 0 {
			break
		}
		ticker := atomic.AddUintptr(&n.timeTicker, 1)

		// Check free disk space to avoid corruption if the target device fills up
		if (ticker % 30) == 3 {
			freeDiskSpace, _ := getFreeSpaceOnDevice(n.basePath)
			if freeDiskSpace < MinFreeDiskSpace {
				n.log[LogLevelFatal].Printf("FATAL: insufficient free space detected on device containing '%s' (%d < %d)", n.basePath, freeDiskSpace, MinFreeDiskSpace)
				go n.Stop()
				break
			}
		}

		if !n.localTest {
			// Clean record tracking entries of items older than 5 minutes.
			if (ticker % 120) == 5 {
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

			// Announce some recent records to help keep nodes in sync during periods of low activity
			if (ticker % 10) == 7 {
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
			if (ticker % 120) == 11 {
				n.writeKnownPeers()
			}

			// Request wanted records (if connected), requesting newly wanted records with
			// zero retries immediately and then requesting records with higher numbers of
			// retries less often.
			if (ticker % 30) == 17 {
				n.requestWantedRecords(1, p2pProtoMaxRetries)
			} else {
				n.requestWantedRecords(0, 0)
			}

			// If we don't have enough connections, try to make more to peers we've learned about.
			if (ticker % 10) == 1 {
				n.peersLock.RLock()
				if len(n.peers) < p2pDesiredConnectionCount {
					n.knownPeersLock.Lock()
					if len(n.knownPeers) > 0 {
						now := TimeSec()
					tryKnownPeers:
						for _, kp := range n.knownPeers { // exploits Go's random map iteration order
							if (now-kp.LastReconnectionAttempt) < p2pPeerAttemptInterval || (now-kp.LastReconnectionAttempt) > (p2pPeerAttemptInterval*uint64(len(n.knownPeers))) {
								for _, cp := range n.peers {
									if bytes.Equal(cp.identity, kp.Identity) {
										continue tryKnownPeers
									}
								}
								kp.LastReconnectionAttempt = now
								kp.TotalReconnectionAttempts++
								n.Connect(kp.IP, kp.Port, kp.Identity)
								break
							}
						}
					} else {
						var sp []Peer
						if bytes.Equal(SolNetworkID[:], n.genesisParameters.ID[:]) {
							sp = SolSeedPeers
						}
						if len(sp) > 0 {
							spp := &sp[rand.Int()%len(sp)]
							n.Connect(spp.IP, spp.Port, spp.Identity)
						}
					}
					n.knownPeersLock.Unlock()
				}
				n.peersLock.RUnlock()
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

// backgroundThreadOracle is run to generate commentary and add work to the DAG (if enabled).
func (n *Node) backgroundThreadOracle() {
	defer n.backgroundThreadWG.Done()

	minWorkDifficulty := uint64(0x000f0000)
	for atomic.LoadUint32(&n.shutdown) == 0 {
		time.Sleep(time.Second) // 1s pause between each new record
		if atomic.LoadUint32(&n.commentary) != 0 && atomic.LoadUint32(&n.shutdown) == 0 {
			minWorkDifficultyThisIteration := minWorkDifficulty
			var commentary []byte
			commentCount := 0
			n.commentsLock.Lock()
			for n.comments.Len() > 0 {
				minWorkDifficultyThisIteration = 0 // push commentary out immediately, then return to adding work

				f := n.comments.Front()
				c := f.Value.(*comment)
				s := c.sizeBytes()
				if len(commentary)+s > int(n.genesisParameters.RecordMaxValueSize) {
					break
				}
				var err error
				prevCommentary := commentary
				commentary, err = c.appendTo(commentary)
				if err != nil {
					commentary = prevCommentary
					break
				}
				commentCount++
				n.comments.Remove(f)
			}
			n.commentsLock.Unlock()

			links, err := n.db.getLinks2(RecordMaxLinks)

			if err == nil && len(links) > 0 {
				var wf *Wharrgarblr
				n.workFunctionLock.Lock()
				if n.workFunction != nil {
					wf = n.workFunction
				} else {
					n.workFunction = NewWharrgarblr(RecordDefaultWharrgarblMemory, runtime.NumCPU()-1) // leave one spare thread on multi-thread CPUs
					wf = n.workFunction
				}
				n.workFunctionLock.Unlock()

				var rb RecordBuilder
				var rec *Record
				startTime := time.Now()
				err = rb.Start(RecordTypeCommentary, commentary, links, nil, nil, nil, n.owner.Public, 0, uint64(startTime.Unix()))
				if err == nil {
					err = rb.AddWork(wf, uint32(minWorkDifficultyThisIteration))
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

						ll := LogLevelVerbose
						if commentCount > 0 {
							ll = LogLevelNormal
						}
						n.log[ll].Printf("oracle: %s submitted with %d comments (minimum difficulty %.8x, created in %f seconds)", rec.HashString(), commentCount, minWorkDifficulty, duration)
					} else {
						n.log[LogLevelWarning].Printf("WARNING: error adding commentary record: %s", err.Error())
					}
				} else {
					n.log[LogLevelWarning].Printf("WARNING: error creating commentary record: %s", err.Error())
				}
			}
		} else {
			// If commentary is disabled, let go of work function RAM
			n.workFunctionLock.Lock()
			n.workFunction = nil
			n.workFunctionLock.Unlock()
		}
	}
}

// processRecordsInLimbo attempts to add any records in limbo for an owner.
func (n *Node) backgroundTaskProcessRecordsInLimbo(ownerPublic OwnerPublic) {
	ownerStr := ownerPublic.String()
	fp := path.Join(n.basePath, "limbo", ownerStr)
	n.limboLock.Lock()

	defer func() {
		e := recover()
		if e != nil {
			n.log[LogLevelWarning].Printf("WARNING: BUG: caught panic in background records in limbo processing task for owner %s: %v", ownerStr, e)
		}
		n.limboLock.Unlock()
		n.backgroundThreadWG.Done()
	}()

	finfo, _ := os.Stat(fp)
	if finfo == nil {
		return
	}
	f, err := os.Open(fp)
	if err != nil {
		n.log[LogLevelWarning].Printf("WARNING: sync: records in limbo in %s cannot be read for processing: %s", fp, err.Error())
		return
	}
	if f == nil {
		return
	}

	n.log[LogLevelNormal].Printf("sync: processing records in limbo for owner %s", ownerStr)

	bf := bufio.NewReader(f)
	var rec Record
	var numFound, numNotYetApproved int
	for rec.UnmarshalFrom(bf) == nil {
		numFound++
		err := n.AddRecord(&rec)
		if err != nil && err == ErrRecordNotApproved {
			numNotYetApproved++
		}
	}
	f.Close()

	if numNotYetApproved == 0 {
		n.log[LogLevelNormal].Printf("sync: all %d records in limbo for owner %s added", numFound, ownerStr)
		os.Remove(fp)
	} else {
		n.log[LogLevelNormal].Printf("sync: %d records remain in limbo for owner %s", numNotYetApproved, ownerStr)
		// TODO: eventually forget records in limbo?
	}
}

//////////////////////////////////////////////////////////////////////////////
// Miscellaneous internal methods
//////////////////////////////////////////////////////////////////////////////

// recordWorkFunc returns the work function this record needs, nil if none, or an error if there will be a problem creating this record.
func (n *Node) recordWorkFunc(owner OwnerPublic) (*Wharrgarblr, error) {
	if !n.localTest {
		hasCert, err := n.OwnerHasCurrentCertificate(owner)
		if err != nil {
			return nil, err
		}
		if !hasCert {
			if n.genesisParameters.AuthRequired {
				return nil, ErrRecordCertificateRequired
			}
			return n.getMakeRecordWorkFunction(), nil
		}
	}
	return nil, nil
}

// recordIsSigned returns the certificate that signed a record (if any) and whether or not it was revoked by a CRL.
func (n *Node) recordIsSigned(owner OwnerPublic, recordTimestamp uint64) (*x509.Certificate, bool) {
	certs, revokedCerts, _ := n.GetOwnerCertificates(owner)
	for _, cert := range certs {
		if recordTimestamp >= uint64(cert.NotBefore.Unix()) && recordTimestamp <= uint64(cert.NotAfter.Unix()) {
			return cert, false
		}
	}
	for _, revokedCert := range revokedCerts {
		if recordTimestamp >= uint64(revokedCert.NotBefore.Unix()) && recordTimestamp <= uint64(revokedCert.NotAfter.Unix()) {
			return revokedCert, true
		}
	}
	return nil, false
}

// recordApprovalStatus checks this record's current approval status.
// The first result is whether the record is currently approved. The second shows whether
// the record was ever approved. Both are always true for PoW-approved records. Certificate
// approved records can return (false, true) if they were approved by a certificate that
// was later revoked via a CRL.
func (n *Node) recordApprovalStatus(rec *Record) (bool, bool) {
	if rec == nil {
		return false, false
	}
	if n.localTest {
		return true, true
	}
	if !n.genesisParameters.AuthRequired && rec.ValidateWork() {
		return true, true
	}
	cert, revoked := n.recordIsSigned(rec.Owner, rec.Timestamp)
	return (cert != nil && !revoked), (cert != nil)
}

// handleGenesisRecord handles new genesis records when starting up or if they arrive over the net.
func (n *Node) handleGenesisRecord(gr *Record) bool {
	grHash := gr.Hash()
	grHashStr := Base62Encode(grHash[:])
	rv, err := gr.GetValue(nil)
	if err != nil {
		n.log[LogLevelWarning].Printf("WARNING: genesis record =%s contains an invalid value, ignoring!", grHashStr)
	} else {
		if len(rv) > 0 && atomic.LoadUint64(&n.lastGenesisRecordTimestamp) < gr.Timestamp {
			n.log[LogLevelNormal].Printf("applying genesis configuration update from record =%s", grHashStr)
			n.genesisParameters.Update(rv)
			atomic.StoreUint64(&n.lastGenesisRecordTimestamp, gr.Timestamp)
			return true
		}
	}
	return false
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
		if len(n.peers) > 0 {
			p = n.peers[rand.Int()%len(n.peers)]
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
				req[0] = p2pProtoMessageTypeRequestRecordsByHash
				req = append(req, hashes...)
				p.send(req)
			}()
		}
	}
}

// getMakeRecordWorkFunction returns a work function that can be used to locally make records for LFFS or MakeRecord requests.
func (n *Node) getMakeRecordWorkFunction() *Wharrgarblr {
	n.makeRecordWorkFunctionLock.Lock()
	if n.makeRecordWorkFunction == nil {
		n.makeRecordWorkFunction = NewWharrgarblr(RecordDefaultWharrgarblMemory, 0)
	}
	wf := n.makeRecordWorkFunction
	n.makeRecordWorkFunctionLock.Unlock()
	return wf
}
