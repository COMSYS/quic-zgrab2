//go:build !linux
// +build !linux

// macOS has TCP_CONNECTION_INFO, but x/sys/unix doesn't support it

package tcpinfo

import (
	"net"
)

type TCPInfo struct {
	// Real value is unknown, but TCPInfo is never instantiated
	Ecn_Fallback bool
}

type TCPInfoService struct{}

// NewTCPInfoService() needs to return a non-nil pointer for ConnWrapper to work.
// dummySvc provides a global address for this purpose.
var dummySvc TCPInfoService

func NewTCPInfoService(uint32) (*TCPInfoService, error) {
	return &dummySvc, nil
}

func (svc *TCPInfoService) Close() error {
	return nil
}

func (svc *TCPInfoService) RegisterConn(net.Conn) error {
	return nil
}

func (svc *TCPInfoService) DeregisterConn(net.Conn) error {
	return nil
}

func (svc *TCPInfoService) GetTCPInfo(net.Conn) (*TCPInfo, error) {
	return nil, nil
}

func DidECNFallback(net.Conn) (bool, error) {
	return false, nil
}
