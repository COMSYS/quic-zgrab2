package blocklist

import "net"

func CheckLocalhost(host string) bool {
	if i := net.ParseIP(host); i != nil {
		return CheckLocalhostIP(i)
	}
	return host == "localhost"
}

func CheckLocalhostIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsUnspecified()
}
