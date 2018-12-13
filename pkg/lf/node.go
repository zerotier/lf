package lf

import (
	"net"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Node is an instance of LF
type Node struct {
	udpSocket          *net.UDPConn
	httpServer         *http.Server
	backgroundThreadWG sync.WaitGroup

	db DB

	hosts       []*Host
	hostsByAddr map[packedAddress]*Host
	hostsLock   sync.RWMutex

	shutdown uintptr
}

// NewNode creates and starts a node.
func NewNode(path string, port int) (*Node, error) {
	var err error
	var n Node

	var laddr net.UDPAddr
	laddr.Port = int(port)
	n.udpSocket, err = net.ListenUDP("udp", &laddr)
	if err != nil {
		return nil, err
	}

	var ta net.TCPAddr
	ta.Port = int(port)
	httpTCPListener, err := net.ListenTCP("tcp", &ta)
	if err != nil {
		return nil, err
	}

	err = n.db.Open(path)
	if err != nil {
		return nil, err
	}

	n.hostsByAddr = make(map[packedAddress]*Host)

	n.backgroundThreadWG.Add(runtime.NumCPU())
	for tc := 0; tc < runtime.NumCPU(); tc++ {
		go func() {
			var buf [16384]byte
			var mapKey packedAddress
			for atomic.LoadUintptr(&n.shutdown) == 0 {
				bytes, addr, err := n.udpSocket.ReadFromUDP(buf[:])
				if bytes > 0 && err == nil {
					mapKey.set(addr)
					n.hostsLock.RLock()
					h := n.hostsByAddr[mapKey]
					n.hostsLock.RUnlock()
					if h == nil {
						h = &Host{
							packedAddress: mapKey,
							FirstReceive:  TimeMs(),
							RemoteAddress: *addr,
							Latency:       -1}
						n.hostsLock.Lock()
						n.hosts = append(n.hosts, h)
						n.hostsByAddr[mapKey] = h
						n.hostsLock.Unlock()
					}
					h.handleIncomingPacket(&n, buf[0:bytes])
				}
			}
			n.backgroundThreadWG.Done()
		}()
	}

	smux := http.NewServeMux()

	smux.HandleFunc("/hash/", func(out http.ResponseWriter, req *http.Request) {
	})
	smux.HandleFunc("/id/", func(out http.ResponseWriter, req *http.Request) {
	})
	smux.HandleFunc("/key/", func(out http.ResponseWriter, req *http.Request) {
	})
	smux.HandleFunc("/post", func(out http.ResponseWriter, req *http.Request) {
	})
	smux.HandleFunc("/search", func(out http.ResponseWriter, req *http.Request) {
	})
	smux.HandleFunc("/", func(out http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/" {
		}
	})

	n.httpServer = &http.Server{
		MaxHeaderBytes: 4096,
		Handler:        smux,
		IdleTimeout:    10 * time.Second,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second}
	n.httpServer.SetKeepAlivesEnabled(true)
	n.backgroundThreadWG.Add(1)
	go func() {
		n.httpServer.Serve(httpTCPListener)
		n.httpServer.Close()
		n.backgroundThreadWG.Done()
	}()

	n.backgroundThreadWG.Add(1)
	go func() {
		for atomic.LoadUintptr(&n.shutdown) == 0 {
			time.Sleep(time.Second)
		}
	}()

	return &n, nil
}

// Stop terminates the running node. No methods should be called after this.
func (n *Node) Stop() {
	atomic.StoreUintptr(&n.shutdown, 1)
	n.udpSocket.Close()
	n.httpServer.Close()
	n.backgroundThreadWG.Wait()
}
