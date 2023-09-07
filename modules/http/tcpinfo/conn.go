package tcpinfo

import (
	"log"
	"net"
	"sync"
)

// Caches TCPInfo before closing the connection for later GetTCPInfo() calls
type ConnWrapper struct {
	net.Conn
	err  error
	info *TCPInfo
	// svc is nil iff conn is closed
	svc   *TCPInfoService
	mu    sync.RWMutex
	ecnFb bool
}

var _ net.Conn = &ConnWrapper{}

// May only be called before transmitting any data on c
func (svc *TCPInfoService) WrapConn(c net.Conn) (*ConnWrapper, error) {
	ecnFb, err := DidECNFallback(c)
	if err != nil {
		return nil, err
	}
	err = svc.RegisterConn(c)
	if err != nil {
		return nil, err
	}
	return &ConnWrapper{Conn: c, svc: svc, ecnFb: ecnFb}, nil
}

func (c *ConnWrapper) getTCPInfoChecked() (*TCPInfo, error) {
	info, err := c.svc.GetTCPInfo(c.Conn)
	if info != nil {
		info.Ecn_Fallback = c.ecnFb
	}
	return info, err
}

func (c *ConnWrapper) GetTCPInfo() (*TCPInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.svc != nil {
		return c.getTCPInfoChecked()
	}
	return c.info, c.err
}

func (c *ConnWrapper) Close() error {
	c.mu.Lock()
	if c.svc != nil {
		c.info, c.err = c.getTCPInfoChecked()
		if err := c.svc.DeregisterConn(c.Conn); err != nil {
			log.Printf("ERROR: TCPInfoService.DeregisterConn failed (potential map leak): %v", err)
		}
		c.svc = nil
	}
	c.mu.Unlock()
	return c.Conn.Close()
}
