package lf

import (
	"net"
	"runtime"
	"sync"
	"sync/atomic"
)

// Node is an instance of LF
type Node struct {
	udpSocket   *net.UDPConn
	udpReaderWG sync.WaitGroup

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

	err = n.db.Open(path)
	if err != nil {
		return nil, err
	}

	n.hostsByAddr = make(map[packedAddress]*Host)

	n.udpReaderWG.Add(runtime.NumCPU())
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
			n.udpReaderWG.Done()
		}()
	}

	return &n, nil
}

// Stop terminates the running node. No methods should be called after this.
func (n *Node) Stop() {
	atomic.StoreUintptr(&n.shutdown, 1)
	n.udpReaderWG.Wait()
}
