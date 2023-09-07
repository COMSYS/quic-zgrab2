package h3

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/http"
	"github.com/zmap/zgrab2/modules/http/defs"
)

// Amends parent's Results by qlog data for h3
type Results struct {
	defs.Results

	// QLog maps request URLs to the return value of QuicRequest
	QLog map[string]interface{} `json:"qlog"`
}

type AltAuthority struct {
	host string
	port uint16
}

func (auth AltAuthority) RequestURL(base *url.URL) string {
	if auth.host == "" {
		auth.host = base.Hostname()
		if strings.ContainsRune(auth.host, ':') {
			// IPv6 hostname
			auth.host = "[" + auth.host + "]"
		}
	}
	return fmt.Sprintf("https://%s:%d%s", auth.host, auth.port, base.EscapedPath())
}

var SupportedProtos = map[string]bool{
	"h3-27": true, "h3-29": true, "h3-32": true, "h3-34": true, "h3": true,
}

func findH3Addrs(resp *http.Response) []string {
	altSvc := resp.Header.Get("Alt-Svc")
	authSet := map[AltAuthority]bool{}

	for _, svc := range strings.Split(altSvc, ",") {
		svc = strings.SplitN(svc, ";", 2)[0]
		kv := strings.SplitN(svc, "=", 2)
		if key := strings.TrimSpace(kv[0]); key == "clear" {
			return nil // See RFC 7838, section 3
		} else if len(kv) != 2 || !SupportedProtos[key] {
			continue
		}

		auth := strings.TrimSpace(kv[1])
		if strings.HasPrefix(auth, `"`) && strings.HasSuffix(auth, `"`) && len(auth) >= 2 {
			auth = auth[1 : len(auth)-1]
		}

		x := AltAuthority{}
		split := strings.LastIndexByte(auth, ':')
		v, err := strconv.ParseUint(auth[split+1:], 10, 16)
		if err != nil {
			// fall back to default HTTPS port
			x.port = 443
		} else {
			x.port = uint16(v)
		}

		if split != -1 {
			x.host = auth[:split]
		} else if err != nil {
			// If ':' is missing and parsing as uint16 failed, use auth as host
			x.host = auth
		}
		authSet[x] = true // add to set
	}

	if len(authSet) == 0 {
		return nil
	}

	res := make([]string, 0, len(authSet))
	for auth := range authSet {
		res = append(res, auth.RequestURL(resp.Request.URL))
	}
	return res
}

func TryGrab(target *zgrab2.ScanTarget, flags *defs.Flags, urlStr string, res *defs.Results) interface{} {
	if flags.DisableH3 {
		return res
	}

	var chain []*http.Response
	if flags.UseFirstAltSvc {
		chain = append(chain, res.RedirectResponseChain...)
	}
	if res.Response != nil {
		chain = append(chain, res.Response)
	}

	var addrs []string

	for _, r := range chain {
		if a := findH3Addrs(r); a != nil {
			addrs = a
			break
		}
	}

	if flags.AlwaysTryH3 {
		if u, err := url.Parse(urlStr); err == nil {
			add := AltAuthority{port: 443}.RequestURL(u)
			contains := false
			for _, a := range addrs {
				if a == add {
					contains = true
					break
				}
			}
			if !contains {
				addrs = append(addrs, add)
			}
		}
	}

	if addrs == nil {
		return res
	}

	h3Res := Results{Results: *res, QLog: make(map[string]interface{}, len(addrs))}
	for _, a := range addrs {
		h3Res.QLog[a] = QuicRequest(target, a, flags)
	}
	return &h3Res
}
