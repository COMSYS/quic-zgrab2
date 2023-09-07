package zgrab2

import (
	//	"encoding/csv"
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

var skipLine = errors.New("line doesn't contain a target")

var validIPNetworks = map[string]bool{
	"ip": true, "ip4": true, "ip6": true,
}

var comsysTool = "http-header"
var comsysVP = os.Getenv("VANTAGE_POINT")

func init() {
	// runs after variable initializers
	if len(comsysVP) != 0 {
		comsysTool += "@" + comsysVP
	}
}

// Function type that takes an input line and parses it into
// IP/subnet, domain, network type (ip/ip4/ip6), tag, meta,
// and json components.
//
// Returns the skipLine error if there is no target to parse.
type parseTargetFunc func(string) (*net.IPNet, string, string, string, string, TargetJson, error)

// ParseCSVTarget takes a line from a CSV-format input file and
// returns the specified ipnet, domain, and tag, or an error.
//
// ZGrab2 input files have three fields:
//   IP, DOMAIN, TAG
//
// Each line specifies a target to scan by its IP address, domain
// name, or both, as well as an optional tag used to determine which
// scanners will be invoked.
//
// A CIDR block may be provided in the IP field, in which case the
// framework expands the record into targets for every address in the
// block.
//
// Trailing empty fields may be omitted.
// Comment lines begin with #, and empty lines are ignored.
//
func ParseCSVTarget(line string) (ipnet *net.IPNet, domain string, network string, tag string, meta string, more TargetJson, err error) {
	fields := strings.SplitN(line, ",", 5)
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}
	if len(fields) > 0 && fields[0] != "" {
		if ip := net.ParseIP(fields[0]); ip != nil {
			ipnet = &net.IPNet{IP: ip}
		} else if _, cidr, er := net.ParseCIDR(fields[0]); er == nil {
			ipnet = cidr
		} else if len(fields) != 1 {
			err = fmt.Errorf("can't parse %q as an IP address or CIDR block", fields[0])
			return
		}
	}
	if len(fields) > 1 {
		domain = fields[1]
	}
	// network is not exposed by CSV format (keep default value)
	if len(fields) > 2 {
		tag = fields[2]
	}
	if len(fields) > 3 {
		meta = fields[3]
	}
	if len(fields) > 4 {
		if err = json.Unmarshal([]byte(fields[4]), &more); err != nil {
			return
		}
	}
	if len(fields) > 5 {
		err = fmt.Errorf("too many fields: %q", fields)
		return
	}

	// For legacy reasons, we also allow targets of the form:
	// DOMAIN
	if ipnet == nil && len(fields) == 1 {
		domain = fields[0]
	}

	if ipnet == nil && domain == "" {
		err = fmt.Errorf("record doesn't specify an address, network, or domain: %v", fields)
		return
	}
	return
}

// ParseZDNSTarget takes a line from a JSON-format input file and
// returns the specified ipnet, domain, and tag, or an error.
func ParseZDNSTarget(line string) (ipnet *net.IPNet, domain string, network string, tag string, meta string, inp TargetJson, err error) {
	fields := strings.SplitN(line, "|", 2)
	if len(fields) > 1 {
		meta = fields[0]
		fields = fields[1:]
	}
	if err = json.Unmarshal([]byte(fields[0]), &inp); err != nil {
		return
	}
	inp["comsys-tool"] = comsysTool
	if len(comsysVP) != 0 {
		inp["comsys-vp"] = comsysVP
	}

	tmp, ok := inp["altered_name"]
	if !ok {
		tmp, ok = inp["name"]
		if !ok {
			tmp = ""
		}
	}
	domaintmp := tmp.(string)

	err = nil
	resolveTo, _ := inp["comsys-resolve-to"].(string) // default value ("") if not present
	if len(resolveTo) > 0 && validIPNetworks[resolveTo] && len(domaintmp) > 0 {
		ipnet = nil // resolve locally
		domain = domaintmp
		network = resolveTo
		tag = ""
		return
	}

	ipnet = &net.IPNet{IP: net.IPv4zero}
	tag = "unknown"
	domain = "unknown"

	tmp = inp["data"]
	if tmp == nil {
		return
	}
	tmp = tmp.(map[string]interface{})["answers"]
	if tmp == nil {
		return
	}

	for _, rr := range tmp.([]interface{}) {
		answer := rr.(map[string]interface{})
		typ := answer["type"].(string)
		if typ == "A" || typ == "AAAA" {
			if ip := net.ParseIP(answer["answer"].(string)); ip != nil {
				ipnet = &net.IPNet{IP: ip}
				domain = domaintmp
				// network is inferred from ipnet (keep default value)
				tag = ""
				return
			}
		}
	}

	return
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func duplicateIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

// InputTargetsCSV is an InputTargetsFunc that calls GetTargets with
// the CSV file provided on the command line and ParseCSVTarget.
func InputTargetsCSV(ch chan<- ScanTarget) error {
	return GetTargets(config.inputFile, ParseCSVTarget, ch)
}

// InputTargetsZDNS is an InputTargetsFunc that calls GetTargets with
// the JSON file provided on the command line and ParseZDNSTarget.
func InputTargetsZDNS(ch chan<- ScanTarget) error {
	return GetTargets(config.inputFile, ParseZDNSTarget, ch)
}

// GetTargets reads lines from the provided reader, generates ScanTargets
// using a parseTargetFunc, and delivers them to the provided channel.
func GetTargets(source io.Reader, parseFunc parseTargetFunc, ch chan<- ScanTarget) error {
	//csvreader := csv.NewReader(source)
	//csvreader.Comment = '#'
	//csvreader.FieldsPerRecord = -1 // variable
	reader := bufio.NewReader(source)
	for {
		input, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		ipnet, domain, network, tag, meta, json, err := parseFunc(input)
		if err != nil {
			if err != skipLine {
				log.Errorf("parse error, skipping: %v", err)
			}
			continue
		}
		var ip net.IP
		if ipnet != nil {
			if ipnet.Mask != nil {
				// expand CIDR block into one target for each IP
				for ip = ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
					ch <- ScanTarget{IP: duplicateIP(ip), network: network, Domain: domain, Tag: tag, Meta: meta, Json: json}
				}
				continue
			} else {
				ip = ipnet.IP
			}
		}
		ch <- ScanTarget{IP: ip, network: network, Domain: domain, Tag: tag, Meta: meta, Json: json}
	}
	return nil
}

// InputTargetsFunc is a function type for target input functions.
//
// A function of this type generates ScanTargets on the provided
// channel.  It returns nil if there are no further inputs or error.
type InputTargetsFunc func(ch chan<- ScanTarget) error
