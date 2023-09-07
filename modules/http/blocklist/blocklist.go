package blocklist

import (
	"bufio"
	"context"
	"errors"
	logold "log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/armon/go-radix"
	"github.com/asergeyev/nradix"
)

const UpdateTimeout time.Duration = 1 * time.Minute

var blocklistPath string
var ipblocklist *nradix.Tree
var reversehostblocklist *radix.Tree

func fetchBlocklistFile(file string) (*os.File, error) {
	f, err := os.Open(blocklistPath + "/" + file)
	return f, err
}

func ipBlocklistUpdate(ctx context.Context, failok bool) bool {
	logold.Printf("INFO: Reload IP Blocklist\n")
	var err error
	var errType string
	newTree := nradix.NewTree(64)

	for _, path := range []string{"ipv4", "ipv6"} {
		f, err := fetchBlocklistFile(path)
		if err != nil {
			errType = "unavailable"
			goto EXIT
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			b := scanner.Text()
			b = strings.SplitN(b, "#", 2)[0]
			b = strings.TrimSpace(b)
			if len(b) > 0 {
				err = newTree.SetCIDR(b, true)
				if err != nil {
					errType = "add error"
					goto EXIT
				}
			}
		}

		err = scanner.Err()
		if err != nil {
			errType = "download failed"
			goto EXIT
		}
	}

EXIT:
	if err != nil {
		if failok {
			logold.Printf("WARNING: IP Blocklist %v %v, reuse old list\n", errType, err)
			return false
		} else {
			logold.Fatalf("IP Blocklist %v %v\n", errType, err)
			return false
		}
	}
	ipblocklist = newTree
	return true
}

func hostBlocklistUpdate(ctx context.Context, failok bool) bool {
	logold.Printf("INFO: Reload Host Blocklist\n")
	var errType string
	r := radix.New()

	file, err := fetchBlocklistFile("domains")
	if err != nil {
		errType = "unavailable"
		goto EXIT
	}
	defer file.Close()

	{
		// new scope required for goto above
		i := 0
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			b := scanner.Text()
			b = strings.SplitN(b, "#", 2)[0]
			b = strings.TrimSpace(b)
			if len(b) > 0 {
				i++
				host := b
				r.Insert(hostTrieKey(host), true)
			}
		}

		err = scanner.Err()
		if err != nil {
			errType = "download failed"
			goto EXIT
		}
		if i < 5 {
			err = errors.New("<5 entries")
			errType = "too small"
			goto EXIT
		}
	}

EXIT:
	if err != nil {
		if failok {
			logold.Printf("WARNING: Host Blocklist %v %v, reuse old list\n", errType, err)
			return false
		} else {
			logold.Fatalf("Host Blocklist %v %v\n", errType, err)
			return false
		}
	}
	reversehostblocklist = r
	return true
}

func Update(failok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), UpdateTimeout)
	defer cancel()
	if ipBlocklistUpdate(ctx, failok) {
		hostBlocklistUpdate(ctx, failok)
	} else {
		logold.Printf("WARNING: IP Blocklist update failed, will not update Host Blocklist\n")
	}
}

func Init() {
	blocklistPath = os.Getenv("BLOCKLIST_PATH")
	if len(blocklistPath) == 0 {
		logold.Panicf("Blocklist disabled: path is not set in BLOCKLIST_PATH env var")
		ipblocklist = nradix.NewTree(0)
		reversehostblocklist = radix.New()
		return
	}

	Update(false)
	go func() {
		for {
			time.Sleep(3600 * time.Second)
			Update(true)
		}
	}()
}

// Adapted from https://stackoverflow.com/questions/1752414/how-to-reverse-a-string-in-go
func hostTrieKey(host string) string {
	n := len(host)
	runes := make([]rune, n+1)
	runes[n] = '.' // prevent matching suffixes (e.g., example.com matching ample.com)
	for _, rune := range host {
		n--
		runes[n] = rune
	}
	return string(runes[n:])
}

func IsHostBlocked(host string) bool {
	key := hostTrieKey(host)
	_, _, ok := reversehostblocklist.LongestPrefix(key)
	return ok
}

func IsIPBlocked(ip net.IP) bool {
	v, _ := ipblocklist.FindCIDR(ip.String())
	return v != nil
}
