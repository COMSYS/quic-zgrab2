package defs

import "github.com/zmap/zgrab2"

// Flags holds the command-line configuration for the HTTP scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
	Method          string `long:"method" default:"GET" description:"Set HTTP request method type"`
	Endpoint        string `long:"endpoint" default:"/" description:"Send an HTTP request to an endpoint"`
	FailHTTPToHTTPS bool   `long:"fail-http-to-https" description:"Trigger retry-https logic on known HTTP/400 protocol mismatch responses"`
	UserAgent       string `long:"user-agent" default:"Mozilla/5.0 zgrab/0.x" description:"Set a custom user agent"`
	RetryHTTPS      bool   `long:"retry-https" description:"If the initial request fails, reconnect and try with HTTPS."`
	MaxSize         int    `long:"max-size" default:"256" description:"Max kilobytes to read in response to an HTTP request"`
	MaxRedirects    int    `long:"max-redirects" default:"0" description:"Max number of redirects to follow"`

	// FollowLocalhostRedirects overrides the default behavior to return
	// ErrRedirLocalhost whenever a redirect points to localhost.
	FollowLocalhostRedirects bool `long:"follow-localhost-redirects" description:"Follow HTTP redirects to localhost"`

	// UseHTTPS causes the first request to be over TLS, without requiring a
	// redirect to HTTPS. It does not change the port used for the connection.
	UseHTTPS bool `long:"use-https" description:"Perform an HTTPS connection on the initial host"`

	// RedirectsSucceed causes the ErrTooManRedirects error to be suppressed
	RedirectsSucceed bool `long:"redirects-succeed" description:"Redirects are always a success, even if max-redirects is exceeded"`

	OverrideSH bool `long:"override-sig-hash" description:"Override the default SignatureAndHashes TLS option with more expansive default"`

	// ComputeDecodedBodyHashAlgorithm enables computing the body hash later than the default,
	// using the specified algorithm, allowing a user of the response to recompute a matching hash
	ComputeDecodedBodyHashAlgorithm string `long:"compute-decoded-body-hash-algorithm" choice:"sha256" choice:"sha1" description:"Choose algorithm for BodyHash field"`

	// WithBodyLength enables adding the body_size field to the Response
	WithBodyLength bool `long:"with-body-size" description:"Enable the body_size attribute, for how many bytes actually read"`

	DisableBPF bool `long:"disable-bpf" description:"Do not collect additional conn_infos via eBPF (lifts the CAP_SYS_ADMIN requirement on Linux)"`

	UseFirstAltSvc bool   `long:"use-first-altsvc" description:"Check the redirect chain in addition to the final response for an Alt-Svc header"`
	AlwaysTryH3    bool   `long:"always-try-h3" description:"Attempt h3 grab on :443 even without an Alt-Svc header"`
	DisableH3      bool   `long:"disable-h3" description:"Disable h3 completely"`
	ECNModeH3      string `long:"ecn-mode-h3" choice:"ect0" choice:"ect1" description:"Enable ECN support for h3 grabs with the given codepoint"`
	DisableECNCEH3 bool   `long:"disable-ecnce-h3" description:"Disable the CE codepoint test for h3 grabs"`
}

// Validate performs any needed validation on the arguments
func (flags *Flags) Validate(args []string) error {
	return nil
}

// Help returns module-specific help
func (flags *Flags) Help() string {
	return ""
}
