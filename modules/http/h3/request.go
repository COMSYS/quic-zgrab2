package h3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/lucas-clemente/quic-go/qlog"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/http/blocklist"
	"github.com/zmap/zgrab2/modules/http/defs"
)

var ErrTooManyRedirects = errors.New("Too many h3 redirects")
var ErrRedirectWithCreds = errors.New("h3 redirect contains credentials")

type KV struct {
	Name   string
	Value  interface{}
	Conn   []byte            `json:"Conn,omitempty"`
	Stream *logging.StreamID `json:"Stream,omitempty"`
}

type ArrayWriterConn struct {
	io.WriteCloser
	aw     *ArrayWriter
	connID []byte
}

func (awc *ArrayWriterConn) Write(p []byte) (n int, err error) {
	awc.aw.AddKV(&KV{Name: "qlog", Value: string(p), Conn: awc.connID})
	return len(p), nil
}

func (awc *ArrayWriterConn) Close() error {
	return nil
}

type KeyLogWriter struct {
	aw *ArrayWriter
}

func (klw KeyLogWriter) Write(p []byte) (n int, err error) {
	klw.aw.AddKV(&KV{Name: "keylog", Value: string(p)})
	return len(p), nil
}

type ArrayWriter struct {
	array        []interface{}
	mutex        sync.Mutex
	canBeWritten bool
}

func NewArrayWriter() *ArrayWriter {
	return &ArrayWriter{
		canBeWritten: true,
	}
}

func (aw *ArrayWriter) ForConn(_ logging.Perspective, connID []byte) io.WriteCloser {
	return &ArrayWriterConn{
		aw:     aw,
		connID: connID,
	}
}

func (aw *ArrayWriter) AddTypeConn(i interface{}, connID []byte) {
	aw.AddKV(&KV{Name: fmt.Sprintf("%T", i), Value: i, Conn: connID})
}

func (aw *ArrayWriter) AddTypeConnStream(i interface{}, connID []byte, stream logging.StreamID) {
	aw.AddKV(&KV{Name: fmt.Sprintf("%T", i), Value: i, Conn: connID, Stream: &stream})
}

func (aw *ArrayWriter) AddType(i interface{}) {
	aw.AddKV(&KV{Name: fmt.Sprintf("%T", i), Value: i})
}

func (aw *ArrayWriter) AddKV(kv *KV) {
	aw.mutex.Lock()
	defer aw.mutex.Unlock()
	if aw.canBeWritten {
		aw.array = append(aw.array, kv)
	}
}

func (aw *ArrayWriter) Add(name string, i interface{}) {
	aw.AddKV(&KV{Name: name, Value: i})
}

func (aw *ArrayWriter) GetArray() []interface{} {
	aw.mutex.Lock()
	defer aw.mutex.Unlock()
	aw.canBeWritten = false
	return aw.array
}

type ourRequest struct {
	*http.Request
	//hack to ignore fields, such that the marshaller is happy
	GetBody  int `json:",omitempty"`
	Cancel   int `json:",omitempty"`
	Response int `json:",omitempty"`
}

type ourResponse struct {
	*http.Response
	BodySha256 string `json:",omitempty"`
	BodyLength int64
	Body       string `json:",omitempty"`
	Request    ourRequest
}

func readToHash(flags *defs.Flags, res *http.Response) (length int64, body string, hash []byte) {
	readLen := int64(flags.MaxSize) * 1024
	if res.ContentLength >= 0 && res.ContentLength < readLen {
		readLen = res.ContentLength
	}
	if readLen == 0 {
		return 0, "", nil
	}

	b := new(bytes.Buffer)
	length, _ = io.CopyN(b, res.Body, readLen)
	body = b.String()

	if length > 0 {
		m := sha256.New()
		m.Write(b.Bytes())
		hash = m.Sum(nil)
	}
	return length, body, hash
}

func (aw *ArrayWriter) AddResponse(kind string, resp *http.Response, flags *defs.Flags) {
	length, _, hash := readToHash(flags, resp)
	resp.Body.Close()

	or := ourResponse{
		Response: resp, BodySha256: hex.EncodeToString(hash),
		BodyLength: length, Request: ourRequest{Request: resp.Request},
	}
	aw.Add(kind, or)
}

type ourUDPAddr struct {
	net.UDPAddr
	Addr string
}

func getDial(flags *defs.Flags, target *zgrab2.ScanTarget, aw *ArrayWriter) func(string, string, *tls.Config, *quic.Config) (quic.EarlySession, error) {
	return func(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlySession, error) {
		host, svc, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		// Use fixed IP if available and request is for target domain
		resolver := net.DefaultResolver
		if target.IP != nil && host == target.Domain {
			if r, err := zgrab2.NewFakeResolver(target.IP.String()); err != nil {
				return nil, err
			} else {
				resolver = r
			}
		}

		// See quic.dialAddrContext
		// network is always "udp" for h3
		ctx, _ := context.WithTimeout(context.Background(), flags.Timeout)
		ips, err := blocklist.LookupIP(resolver, ctx, target.IPNetwork(), host)
		if err != nil {
			return nil, err
		}
		port, err := resolver.LookupPort(ctx, network, svc)
		if err != nil {
			return nil, err
		}
		udpAddr := net.UDPAddr{IP: ips[0], Port: port}
		aw.Add("remote-addr", &ourUDPAddr{UDPAddr: udpAddr, Addr: addr})

		udpConn, err := net.DialUDP(network, &net.UDPAddr{IP: net.IPv4zero, Port: 0}, &udpAddr)
		if err != nil {
			return nil, err
		}
		//no 0RTT
		return quic.DialContextPublic(ctx, udpConn, &udpAddr, addr, tlsCfg, cfg, false, true, true)
	}
}

func getCheckRedirect(flags *defs.Flags, aw *ArrayWriter) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		aw.AddResponse("redirect", req.Response, flags)

		// flags.MaxRedirects defaults to 0, i.e., no redirects at all.
		// We mirror the behavior of the non-h3 http scanner.
		if len(via) > flags.MaxRedirects {
			return ErrTooManyRedirects
		}

		if req.URL.User != nil {
			return ErrRedirectWithCreds
		}

		return nil
	}
}

func QuicRequest(target *zgrab2.ScanTarget, addr string, flags *defs.Flags) interface{} {
	aw := NewArrayWriter()

	tracer1 := qlog.NewTracer(aw.ForConn)
	tracer2 := &customTracer{
		tprcv: func(tp *logging.TransportParameters, conn []byte) {
			aw.AddTypeConn(tp, conn)
		},
		h3rcv: func(s logging.StreamID, i interface{}, conn []byte) {
			aw.AddTypeConnStream(i, conn, s)
		},
	}

	ecnMode := quic.DisableECN
	switch strings.ToLower(flags.ECNModeH3) {
	case "ect0":
		ecnMode = quic.UseECT0
	case "ect1":
		ecnMode = quic.UseECT1
	}
	if ecnMode != quic.DisableECN && !flags.DisableECNCEH3 {
		ecnMode |= quic.TryCE
	}

	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !flags.TLSFlags.VerifyServerCertificate,
			KeyLogWriter:       KeyLogWriter{aw},
		},
		QuicConfig: &quic.Config{
			Tracer:               logging.NewMultiplexedTracer(tracer1, tracer2),
			HandshakeIdleTimeout: 5000 * time.Millisecond,
			ECNMode:              ecnMode,
		},
		Dial: getDial(flags, target, aw),
	}
	// keep this in case of panics
	defer roundTripper.Close()

	hclient := &http.Client{
		Timeout:       flags.Timeout,
		Transport:     roundTripper,
		CheckRedirect: getCheckRedirect(flags, aw),
	}

	aw.Add("url", addr)

	get := func(client *http.Client, url string) (resp *http.Response, err error) {
		req, err := http.NewRequest(flags.Method, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "*/*")
		req.Header.Add("Priority", "u=5, i")
		req.Header.Add("user-agent", flags.UserAgent)
		resp, err = client.Do(req)
		return resp, err
	}
	resp, err := get(hclient, addr)
	if err == nil {
		aw.AddResponse("*http.Response", resp, flags)
	}

	// Explicitly close connections to allow logging into aw
	// The deferred roundTripper.Close() call becomes a no-op
	if closeErr := roundTripper.Close(); closeErr != nil {
		aw.Add("close_error", fmt.Sprint(closeErr))
	}
	if err != nil {
		aw.Add("error", fmt.Sprint(err))
	}
	return aw.GetArray()
}
