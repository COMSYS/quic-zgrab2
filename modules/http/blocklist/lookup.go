package blocklist

import (
	"context"
	"fmt"
	"net"

	"github.com/zmap/zgrab2"
)

func LookupIP(resolver *net.Resolver, ctx context.Context, network, host string) ([]net.IP, error) {
	if IsHostBlocked(host) || CheckLocalhost(host) {
		return nil, &zgrab2.ScanError{
			Status: zgrab2.SCAN_APPLICATION_ERROR,
			Err:    fmt.Errorf("Host blocked %v", host),
		}
	}

	ips, err := resolver.LookupIP(ctx, network, host)
	if err != nil {
		return nil, err
	}

	var targets, blockedIPs []net.IP
	for _, nip := range ips {
		if IsIPBlocked(nip) || CheckLocalhostIP(nip) {
			blockedIPs = append(blockedIPs, nip)
		} else if nip == nil {
		} else {
			targets = append(targets, nip)
		}
	}

	if len(targets) == 0 && len(blockedIPs) > 0 {
		return nil, &zgrab2.ScanError{
			Status: zgrab2.SCAN_APPLICATION_ERROR,
			Err:    fmt.Errorf("IPs blocked for %v: %v", host, blockedIPs),
		}
	}
	if len(targets) == 0 {
		return nil, &zgrab2.ScanError{
			Status: zgrab2.SCAN_APPLICATION_ERROR,
			Err:    fmt.Errorf("no %v addresses for %v", network, host),
		}
	}
	return targets, nil
}
