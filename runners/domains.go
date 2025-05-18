package runners

import (
	"context"
	"errors"
	"fmt"
	"github.com/ibnaleem/gosearch/utils"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/olekukonko/ll"
	"github.com/olekukonko/tablewriter"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
	"golang.org/x/time/rate"
)

const (
	DomainsName = "domains"
)

func init() {
	Register(DomainsName, NewDomains())
}

// Domains implements the Runner interface for domain searches
type Domains struct {
	ctx      context.Context
	logger   *ll.Logger
	progress *mpb.Progress
	count    atomic.Uint32
}

// NewDomains creates a new Domains runner
func NewDomains() *Domains {
	return &Domains{}
}

func (r *Domains) Name() string {
	return BreachName
}

func (r *Domains) Prepare(ctx Context) {
	r.ctx = ctx.Ctx
	r.logger = ctx.Logger
	r.progress = ctx.Progress
}

// Run searches for the username across domains
func (r *Domains) Run(username string) Response {
	domains := BuildDomains(username)
	r.logger.Println(utils.Yellowf("[*] Searching %d domains with the username %s...", len(domains), username))

	// Initialize rate limiter: 5 requests per second
	limiter := rate.NewLimiter(rate.Every(time.Second/5), 5)
	client := &http.Client{
		Timeout:   120 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}
	// Initialize progress bar
	var bar *mpb.Bar
	if r.progress != nil {
		bar = r.progress.AddBar(int64(len(domains)),
			mpb.PrependDecorators(
				decor.Name(fmt.Sprintf("%s: ", r.Name()), decor.WC{W: 15}),
				decor.Percentage(decor.WCSyncWidth),
			),
			mpb.AppendDecorators(
				decor.OnComplete(decor.CurrentNoUnit(""), "Done"),
			),
		)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make([]struct{ Domain string }, 0, len(domains))
	domainCount := 0
	for _, domain := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			defer func() {
				if bar != nil {
					bar.Increment()
				}
			}()
			url := "http://" + domain
			req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, url, nil)
			if err != nil {
				r.logger.Errorf("Error creating request for %s: %v", domain, err)
				return
			}
			req.Header.Set("User-Agent", DefaultUserAgent)
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.5")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")
			req.Header.Set("Connection", "keep-alive")
			req.Header.Set("Upgrade-Insecure-Requests", "1")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "none")
			req.Header.Set("Sec-Fetch-User", "?1")
			req.Header.Set("Cache-Control", "max-age=0")
			r.logger.Debugf("Sending GET request to %s", url)
			start := time.Now()
			if err := limiter.Wait(r.ctx); err != nil {
				r.logger.Errorf("Rate limiter error for %s: %v", domain, err)
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				var netErr net.Error
				ok := errors.As(err, &netErr)
				noSuchHostError := strings.Contains(err.Error(), "no such host")
				networkTimeoutError := ok && netErr.Timeout()
				if !noSuchHostError && !networkTimeoutError {
					r.logger.Errorf("Error sending request for %s: %v", domain, err)
				}
				return
			}
			defer resp.Body.Close()
			duration := time.Since(start)
			r.logger.Debugf("Received response for %s in %v, status: %s", domain, duration, resp.Status)
			if resp.StatusCode == http.StatusOK {
				mu.Lock()
				results = append(results, struct{ Domain string }{domain})
				domainCount++
				r.count.Add(1)
				mu.Unlock()
			}
		}(domain)
	}
	wg.Wait()
	if domainCount > 0 {
		r.logger.Println(utils.Green("[+] Found %d domains with the username %s"), domainCount, username)
		return Response{
			Service: r.Name(),
			Found:   true,
			Data:    DomainsResponse{Domains: results},
			Count:   r.count.Load(),
		}
	}
	r.logger.Println(utils.Red("[-] No domains found with the username %s"), username)

	return Response{
		Service: r.Name(),
		Found:   false,
		Data:    DomainsResponse{},
		Count:   r.count.Load(),
	}
}

// DomainsResponse represents Domains search results
type DomainsResponse struct {
	Domains []struct {
		Domain string
	}
}

func (r DomainsResponse) Table(out *tablewriter.Table) {
	out.Header([]any{utils.Blue("NO"), utils.Blue("DOMAIN"), utils.Blue("STATUS")})
	for i, domain := range r.Domains {
		out.Append([]string{
			fmt.Sprintf("%d", i+1),
			domain.Domain,
			utils.Green("200 OK").String(),
		})
	}
}

func (r DomainsResponse) String() string {
	var sb strings.Builder
	for _, domain := range r.Domains {
		sb.WriteString(fmt.Sprintf("[+] 200 OK: %s\n", domain.Domain))
	}
	return sb.String()
}
