package runners

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/vbauerster/mpb/v8"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/tablewriter"
)

// User-Agent header used in HTTP requests to mimic a browser.
const (
	DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0"

	ModeDump   = "table"
	ModeTyping = "text"
)

var (
	// tlsConfig defines the TLS configuration for secure HTTP requests.
	tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12, // Minimum TLS version
		CipherSuites: []uint16{ // Supported cipher suites
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}, // Preferred elliptic curves
		NextProtos:       []string{"http/1.1"},                                    // Supported protocols
	}
)

// Runner defines the interface for search runners
type Runner interface {
	Name() string
	Prepare(ctx Context)
	Run(username string) Response
}

type Context struct {
	Ctx      context.Context
	Logger   *ll.Logger
	Progress *mpb.Progress
	Auth     Auth
	Login    Login
	Options  Options
}

type Auth struct {
	Key    []byte
	Secret []byte
}

type Login struct {
	Username string
	Password string
}

type Options struct {
	NoFalsePositive bool
}

// Response represents a runner's search result
type Response struct {
	Service  string
	Found    bool
	Error    error
	Count    uint32
	Data     Result
	Duration time.Duration
}

// Result defines the interface for result rendering
type Result interface {
	Table(*tablewriter.Table)
	String() string
}

// BuildDomains generates a list of potential domains using the username and common TLDs.
func BuildDomains(username string) []string {
	tlds := []string{
		".com", ".net", ".org", ".biz", ".info", ".name", ".pro", ".cat", ".co",
		".me", ".io", ".tech", ".dev", ".app", ".shop", ".fail", ".xyz", ".blog",
		".portfolio", ".store", ".online", ".about", ".space", ".lol", ".fun", ".social",
	}
	var domains []string
	for _, tld := range tlds {
		domains = append(domains, username+tld)
	}
	return domains
}

// BuildURL constructs a URL by replacing the placeholder with the username.
func BuildURL(baseURL, username string) string {
	return strings.Replace(baseURL, "{}", username, 1)
}

// CrackHash attempts to crack a password hash using the Weakpass API.
func CrackHash(hash string, logger *ll.Logger) string {
	client := &http.Client{}
	url := fmt.Sprintf("https://weakpass.com/api/v1/search/%s.json", hash)
	logger.Debugf("Sending GET request to Weakpass API: %s", url)
	start := time.Now()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		logger.Errorf("Error creating Weakpass request: %v", err)
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0")
	req.Header.Set("accept", "application/json")
	res, err := client.Do(req)
	if err != nil {
		logger.Errorf("Error fetching Weakpass response: %v", err)
		return ""
	}
	defer res.Body.Close()
	logger.Debugf("Received Weakpass response in %v, status: %s", time.Since(start), res.Status)
	jsonData, err := io.ReadAll(res.Body)
	if err != nil {
		logger.Errorf("Error reading Weakpass response JSON: %v", err)
		return ""
	}
	logger.Debugf("Weakpass response size: %d bytes", len(jsonData))
	var weakpass struct {
		Pass string `json:"pass"`
	}
	err = sonic.Unmarshal(jsonData, &weakpass)
	if err != nil {
		logger.Errorf("Error unmarshalling Weakpass JSON: %v", err)
		return ""
	}
	if weakpass.Pass != "" {
		logger.Debugf("Successfully cracked hash %s to password: %s", hash, weakpass.Pass)
	}
	return weakpass.Pass
}

// formatStealerDate formats a date string from HudsonRock API into a human-readable format.
func formatStealerDate(dateStr string) string {
	t, err := time.Parse(time.RFC3339, dateStr)
	if err != nil {
		return dateStr
	}
	now := time.Now()
	diff := now.Sub(t)
	switch {
	case diff < time.Hour:
		return "just now"
	case diff < 24*time.Hour:
		hours := int(diff.Hours())
		return fmt.Sprintf("%d hour%s ago", hours, plural(hours))
	case diff < 7*24*time.Hour:
		days := int(diff.Hours() / 24)
		return fmt.Sprintf("%d day%s ago", days, plural(days))
	default:
		return t.Format("Jan 2, 2006")
	}
}

// plural returns an empty string for singular or "s" for plural.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

var runners map[string]Runner

func Register(name string, runner Runner) {
	if runners == nil {
		runners = make(map[string]Runner)
	}
	runners[name] = runner
}

func UnRegister(name string) {
	if runners == nil {
		runners = make(map[string]Runner)
	}
	delete(runners, name)
}

func Find(name string) (Runner, bool) {
	name = strings.TrimSpace(name)
	runner, ok := runners[name]
	return runner, ok
}

func List() []Runner {
	rr := make([]Runner, 0, len(runners))
	for _, runner := range runners {
		rr = append(rr, runner)
	}
	return rr
}

func All() map[string]Runner {
	return runners
}

func Names() []string {
	names := make([]string, 0, len(runners))
	for name, _ := range runners {
		names = append(names, name)
	}
	return names
}
