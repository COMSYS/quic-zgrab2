package defs

import (
	"github.com/zmap/zgrab2/lib/http"
	"github.com/zmap/zgrab2/modules/http/tcpinfo"
)

type AddrDomain struct {
	IP      string
	Targets []string
	Host    string
}

// A Results object is returned by the HTTP module's Scanner.Scan()
// implementation.
type Results struct {
	// Result is the final HTTP response in the RedirectResponseChain
	Response *http.Response `json:"response,omitempty"`

	// RedirectResponseChain is non-empty is the scanner follows a redirect.
	// It contains all redirect response prior to the final response.
	RedirectResponseChain []*http.Response `json:"redirect_response_chain,omitempty"`

	// DialedAddrs lists the addresses connected to by the HTTP client
	DialedAddrs []AddrDomain `json:"dialed_addrs,omitempty"`

	// ConnInfos contains a TCPInfo struct for every connection, ordered the same as DialedAddrs.
	// Entries may be nil, e.g., if the OS doesn't implement getsockopt(TCP_INFO).
	ConnInfos []*tcpinfo.TCPInfo `json:"conn_infos,omitempty"`
}
