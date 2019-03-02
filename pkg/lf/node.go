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
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NYTimes/gziphandler"
)

const (
	// p2pProtoMaxMessageSize is a sanity check maximum message size for the P2P TCP protocol.
	// It prevents a huge message from causing a huge memory allocation. It can be increased.
	p2pProtoMaxMessageSize = 262144

	// p2pProtoModeAES256GCMECCP384 indicates our simple AES-256 GCM encrypted stream protocol with ECDH key exchange.
	p2pProtoModeAES256GCMECCP384 byte = 1

	p2pProtoMessageTypeRecord               byte = 1 // binary marshaled Record
	p2pProtoMesaggeTypeRequestRecordsByHash byte = 2 // one or more 32-byte hashes we want
	p2pProtoMessageTypeHaveRecords          byte = 3 // one or more 32-byte hashes we have
	p2pProtoMessageTypePeer                 byte = 4 // <[uint16] port><[byte] type><[4-16] IP>[<public key>]

	// p2pDesiredConnectionCount is how many TCP connections we want to have open (will stop connecting to announced peers after this)
	p2pDesiredConnectionCount = 32

	// DefaultHTTPPort is the default LF HTTP API port
	DefaultHTTPPort = 9980

	// DefaultP2PPort is the default LF P2P port
	DefaultP2PPort = 9908
)

var nullLogger = log.New(ioutil.Discard, "", log.LstdFlags)

type peer struct {
	c               *net.TCPConn        // TCP connection to this peer
	cryptor         cipher.AEAD         // AES-GCM instance
	hasRecords      map[[32]byte]uint64 // Record this peer has recently reported that it has or has sent
	hasRecordsLock  sync.Mutex          //
	remotePublicKey []byte              // Remote public key
	inbound         bool                // True if this is an incoming connection
}

// Node is an instance of a full LF node.
type Node struct {
	log                [logLevelCount]*log.Logger //
	linkKeyPriv        []byte                     // P-384 private key
	linkKeyPubX        *big.Int                   // X coordinate of P-384 public key
	linkKeyPubY        *big.Int                   // Y coordinate of P-384 public key
	linkKeyPub         []byte                     // Point compressed P-384 public key
	owner              *Owner                     // Owner for commentary and/or "mining" records
	genesisParameters  GenesisParameters          // Genesis configuration for this node's network
	genesisOwner       []byte                     // Owner of genesis record(s)
	peers              map[string]*peer           // Currently connected peers by address
	peersLock          sync.RWMutex               //
	httpTCPListener    *net.TCPListener           //
	httpServer         *http.Server               //
	p2pTCPListener     *net.TCPListener           //
	db                 db                         //
	backgroundThreadWG sync.WaitGroup             // Wait group for background goroutines
	startTime          uint64                     // Time node was started in seconds since epoch
	shutdown           uintptr                    // Set to non-zero to signal all background goroutines to exit
}

type linkKeyJSON struct {
	Private Blob
	PublicX Blob
	PublicY Blob
}

// NewNode creates and starts a node.
func NewNode(basePath string, p2pPort int, httpPort int, logger *log.Logger, logLevel int) (n *Node, err error) {
	n = new(Node)

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

	var priv []byte
	var px, py *big.Int
	lkfn := path.Join(basePath, "link-p384.secret")
	lkd, _ := ioutil.ReadFile(lkfn)
	if len(lkd) > 0 {
		var lkj linkKeyJSON
		err = json.Unmarshal(lkd, &lkj)
		if err != nil {
			err = nil
		} else {
			priv = lkj.Private
			px = new(big.Int).SetBytes(lkj.PublicX)
			py = new(big.Int).SetBytes(lkj.PublicY)
		}
	}
	if px == nil || py == nil || !elliptic.P384().IsOnCurve(px, py) || len(priv) == 0 {
		priv, px, py, err = elliptic.GenerateKey(elliptic.P384(), secrand.Reader)
		if err != nil {
			return nil, err
		}
		var lkj linkKeyJSON
		lkj.Private = priv
		lkj.PublicX = px.Bytes()
		lkj.PublicY = py.Bytes()
		lkd, err = json.Marshal(&lkj)
		if err != nil {
			return nil, err
		}
		err = ioutil.WriteFile(lkfn, lkd, 0600)
		if err != nil {
			return nil, err
		}
	}
	n.linkKeyPriv = priv
	n.linkKeyPubX = px
	n.linkKeyPubY = py
	n.linkKeyPub, err = ECCCompressPublicKey(elliptic.P384(), px, py)
	if err != nil {
		return nil, err
	}

	ofn := path.Join(basePath, "owner-ed25519.secret")
	ownerBytes, _ := ioutil.ReadFile(ofn)
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
		ownerBytes = n.owner.PrivateBytes()
		err = ioutil.WriteFile(ofn, ownerBytes, 0600)
		if err != nil {
			return nil, err
		}
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
		WriteTimeout:   60 * time.Second,
	}
	n.httpServer.SetKeepAlivesEnabled(true)

	ta.Port = p2pPort
	n.p2pTCPListener, err = net.ListenTCP("tcp", &ta)
	if err != nil {
		n.httpTCPListener.Close()
		return nil, err
	}

	n.log[LogLevelNormal].Printf("listening on %d for HTTP, %d for LF P2P", httpPort, p2pPort)

	err = n.db.open(basePath, n.log)
	if err != nil {
		n.httpTCPListener.Close()
		n.p2pTCPListener.Close()
		return nil, err
	}

	var genesisReader io.Reader
	genesisFile, err := os.Open(path.Join(basePath, "genesis.lf"))
	if err == nil && genesisFile != nil {
		n.log[LogLevelNormal].Print("found genesis.lf, using alternative genesis records instead of compiled-in default")
		genesisReader = genesisFile
	} else {
		genesisReader = bytes.NewReader(SolGenesisRecords)
	}
	for {
		var r Record
		err := r.UnmarshalFrom(genesisReader)
		if err == io.EOF {
			break
		}
		if err != nil {
			n.httpTCPListener.Close()
			n.p2pTCPListener.Close()
			return nil, err
		}

		if len(n.genesisOwner) == 0 {
			n.genesisOwner = r.Owner
		}

		if bytes.Equal(n.genesisOwner, r.Owner) { // sanity check
			rh := r.Hash()
			if !n.db.hasRecord(rh[:]) {
				n.log[LogLevelNormal].Printf("genesis record %x not found in database, initializing", *rh)
				err = n.db.putRecord(&r, 0)
				if err != nil {
					n.httpTCPListener.Close()
					n.p2pTCPListener.Close()
					return nil, err
				}
			}
		}
	}
	if genesisFile != nil {
		genesisFile.Close()
	}
	if len(n.genesisOwner) == 0 {
		n.httpTCPListener.Close()
		n.p2pTCPListener.Close()
		return nil, errors.New("no default genesis records found; database cannot be initialized and/or genesis record lineage cannot be determined")
	}

	n.log[LogLevelNormal].Printf("loading genesis records for genesis owner %x", n.genesisOwner)
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

	n.backgroundThreadWG.Add(1)
	go func() {
		defer n.backgroundThreadWG.Done()
		for atomic.LoadUintptr(&n.shutdown) == 0 {
			time.Sleep(time.Millisecond * 100)
			if n.genesisParameters.RecordMinLinks > 0 {
				links, err := n.db.getLinks2(n.genesisParameters.RecordMinLinks)
				if err == nil && uint(len(links)) >= n.genesisParameters.RecordMinLinks {
					workAlgorithm := RecordWorkAlgorithmNone
					if n.genesisParameters.WorkRequired {
						workAlgorithm = RecordWorkAlgorithmWharrgarbl
					}
					rec, err := NewRecord(nil, links, nil, nil, nil, nil, TimeSec(), workAlgorithm, 0, n.owner)
					if err == nil {
						n.AddRecord(rec)
					} else {
						n.log[LogLevelWarning].Printf("WARNING: error creating record: %s", err.Error())
					}
				} else {
					n.log[LogLevelWarning].Printf("WARNING: database error getting links or %d links not available", n.genesisParameters.RecordMinLinks)
				}
			}
		}
	}()

	n.startTime = TimeSec()

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
	WharrgarblFreeMemory()
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
		} else if c != nil {
			c.Close()
		}
	}()
}

// AddRecord adds a record to the database if it's valid and we do not already have it.
// If the record is a duplicate this returns ErrorDuplicateRecord.
func (n *Node) AddRecord(r *Record) error {
	if r == nil {
		return ErrorInvalidParameter
	}

	rdata := r.Bytes()
	rhash := r.Hash()

	// Check to see if we already have this record.
	if n.db.hasRecord(rhash[:]) {
		return ErrorDuplicateRecord
	}

	// Check various record constraints such as sizes, timestamp, etc. This is done first
	// because these checks are simple and fast.
	if len(rdata) > RecordMaxSize || uint(len(rdata)) > n.genesisParameters.RecordMaxSize {
		return ErrorRecordTooLarge
	}
	if uint(len(r.Value)) > n.genesisParameters.RecordMaxValueSize {
		return ErrorRecordValueTooLarge
	}
	if r.LinkCount() < n.genesisParameters.RecordMinLinks {
		return ErrorRecordInsufficientLinks
	}
	if r.Timestamp > (TimeSec() + uint64(n.genesisParameters.RecordMaxForwardTimeDrift)) {
		return ErrorRecordViolatesSpecialRelativity
	}
	if r.Timestamp < n.genesisParameters.TimestampFloor {
		return ErrorRecordTooOld
	}
	if r.WorkAlgorithm == RecordWorkAlgorithmNone && n.genesisParameters.WorkRequired {
		return ErrorRecordInsufficientWork
	}
	if len(r.Certificate) > 0 && len(n.genesisParameters.RootCertificateAuthorities) == 0 { // don't let people shove crap into cert field if it's not used
		return ErrorRecordCertificateInvalid
	}
	if len(r.Certificate) == 0 && n.genesisParameters.CertificateRequired {
		return ErrorRecordCertificateRequired
	}

	// Validate record's internal structure and check signatures and work.
	err := r.Validate()
	if err != nil {
		return err
	}

	// Check to see if there's another fully synchronized and reputation=0 record with the
	// same ID. If so, flag this one.
	reputation := 0
	rid := r.ID()
	if n.db.haveSynchronizedWithID(rid[:], r.Owner) {
		reputation = dbRecordReputationFlagCollidesWithSynchronizedID
	}

	n.log[LogLevelTrace].Printf("TRACE: new record: %x", *rhash)

	// Add record to database, aborting if this generates some kind of error.
	err = n.db.putRecord(r, reputation)
	if err != nil {
		return err
	}

	/*
		// Announce that we have this record to connected peers that haven't informed us that
		// they have it or sent it to us. If they don't have it they will request it.
		n.backgroundThreadWG.Add(1)
		go func() {
			defer func() {
				n.backgroundThreadWG.Done()
			}()

			msg := make([]byte, 1, 33)
			msg[0] = p2pProtoMessageTypeHaveRecords
			msg = append(msg, rhash[:]...)

			n.peersLock.RLock()
			for _, p := range n.peers {
				p.hasRecordsLock.Lock()
				_, hasRecord := p.hasRecords[*rhash]
				p.hasRecordsLock.Unlock()
				if !hasRecord {
					p.send(msg)
				}
			}
			n.peersLock.RUnlock()
		}()
	*/

	return nil
}

// Peers returns an array of peer description objects.
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

// send sends a message to a peer (message must be prefixed by type byte)
func (p *peer) send(msg []byte) error {
	// format: <12-byte IV><varint size of msg><msg + 16 byte tag>
	buf := make([]byte, 22, len(msg)+64)
	_, err := secrand.Read(buf[0:12])
	if err != nil {
		panic(err)
	}
	buf = buf[0 : 12+binary.PutUvarint(buf[12:], uint64(len(msg)))]
	buf = p.cryptor.Seal(buf, buf[0:12], msg, nil)
	_, err = p.c.Write(buf)
	if err != nil {
		p.c.Close()
		return err
	}
	return nil
}

func p2pConnectionHandler(n *Node, c *net.TCPConn, expectedPublicKey []byte, inbound bool) {
	peerAddressStr := c.RemoteAddr().String()

	defer func() {
		e := recover()
		if e != nil {
			n.log[LogLevelNormal].Printf("P2P connection to %s closed: caught panic: %v", peerAddressStr, e)
		}

		n.peersLock.Lock()
		delete(n.peers, peerAddressStr)
		n.peersLock.Unlock()

		n.backgroundThreadWG.Done()
	}()

	tcpAddr := c.RemoteAddr().(*net.TCPAddr)
	if tcpAddr == nil { // sanity check against core library code changes
		panic("nil TCP RemoteAddr")
	}

	c.SetKeepAlivePeriod(time.Second * 30)
	c.SetKeepAlive(true)
	c.SetLinger(0)
	c.SetNoDelay(false)
	reader := bufio.NewReaderSize(c, 16384) // reduce system calls to read from socket, also simplifies some read code

	helloMessage := make([]byte, len(n.linkKeyPub)+2)
	helloMessage[0] = p2pProtoModeAES256GCMECCP384
	helloMessage[1] = byte(len(n.linkKeyPub))
	copy(helloMessage[2:], n.linkKeyPub)
	_, err := c.Write(helloMessage)
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: unable to write hello message", peerAddressStr)
		return
	}

	_, err = io.ReadFull(reader, helloMessage[0:2])
	if err != nil {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
		return
	}
	if helloMessage[0] != p2pProtoModeAES256GCMECCP384 || helloMessage[0] == 0 {
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
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: detected connection to self!", peerAddressStr)
		return
	}
	if len(expectedPublicKey) > 0 && !bytes.Equal(expectedPublicKey, rpk) {
		n.log[LogLevelNormal].Printf("P2P connection to %s closed: remote public key does not match expected (pinned) public key", peerAddressStr)
		return
	}

	p := peer{
		c:               c,
		hasRecords:      make(map[[32]byte]uint64),
		remotePublicKey: rpk,
		inbound:         inbound,
	}
	n.peersLock.Lock()
	for _, p2 := range n.peers {
		if bytes.Equal(p2.remotePublicKey, rpk) {
			n.log[LogLevelNormal].Printf("P2P connection to %s closed: redundant connection to already linked peer", peerAddressStr)
			n.peersLock.Unlock()
			return
		}
	}
	n.peers[peerAddressStr] = &p
	n.peersLock.Unlock()

	remotePubX, remotePubY, err := ECCDecompressPublicKey(elliptic.P384(), p.remotePublicKey)
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
	p.cryptor, _ = cipher.NewGCM(aesCipher)

	var msgIv [12]byte
	var msgbuf []byte
	announced := false
	for atomic.LoadUintptr(&n.shutdown) == 0 {
		// Read 12-byte GCM IV
		_, err = io.ReadFull(reader, msgIv[:])
		if err != nil {
			n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
			break
		}

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

		// Read message and 16-byte GCM tag
		if len(msgbuf) < int(msgSize)+16 {
			bs := uint(msgSize)
			bs /= 4096
			bs += 2
			bs *= 4096
			msgbuf = make([]byte, bs)
		}
		msg := msgbuf[0 : uint(msgSize)+16]
		_, err = io.ReadFull(reader, msg)
		if err != nil {
			n.log[LogLevelNormal].Printf("P2P connection to %s closed: %s", peerAddressStr, err.Error())
			break
		}

		if atomic.LoadUintptr(&n.shutdown) != 0 {
			break
		}

		// Decrypt and authenticate message
		msg, err = p.cryptor.Open(msg[:0], msgIv[:], msg, nil)
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
					n.Connect((net.IP)(msg[3:7]), int(port), publicKey, func(err error) {
						n.log[LogLevelNormal].Printf("connected to peer %s:%d (learned from peer %s)", ip.String(), port, peerAddressStr)
					})
				}
			}
		}
	}

	if inbound && !announced {
		announced = true

		pa := make([]byte, 1, 256)
		pa[0] = p2pProtoMessageTypePeer
		ipv4 := tcpAddr.IP.To4()
		if len(ipv4) == 4 {
			pa = append(pa, byte((tcpAddr.Port>>8)&0xff))
			pa = append(pa, byte(tcpAddr.Port&0xff))
			pa = append(pa, 4)
			pa = append(pa, ipv4...)
			pa = append(pa, p.remotePublicKey...)
		} else {
			ipv6 := tcpAddr.IP.To16()
			if len(ipv6) == 16 {
				pa = append(pa, byte((tcpAddr.Port>>8)&0xff))
				pa = append(pa, byte(tcpAddr.Port&0xff))
				pa = append(pa, 6)
				pa = append(pa, ipv6...)
				pa = append(pa, p.remotePublicKey...)
			}
		}

		if len(pa) > 1 {
			n.peersLock.RLock()
			for _, p2 := range n.peers {
				if p2 != &p {
					p2.send(pa)
				}
			}
			n.peersLock.RUnlock()
		}
	}
}
