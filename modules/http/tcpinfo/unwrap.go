package tcpinfo

import (
	"fmt"
	"net"
	"syscall"

	"github.com/zmap/zgrab2"
)

func unwrapSyscallConn(c net.Conn) (syscall.Conn, error) {
	for {
		// Unwrap c until we find a syscall.Conn
		switch realC := c.(type) {
		case syscall.Conn:
			return realC, nil
		case *zgrab2.TimeoutConnection:
			c = realC.Conn
		default:
			return nil, fmt.Errorf("unknown dynamic Conn type %T in unwrapSyscallConn", c)
		}
	}
}

func unwrapRawConn(c net.Conn) (syscall.RawConn, error) {
	sc, err := unwrapSyscallConn(c)
	if err == nil {
		return sc.SyscallConn()
	}
	return nil, err
}
