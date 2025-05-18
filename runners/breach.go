package runners

import (
	"context"
	"fmt"
	"github.com/ibnaleem/gosearch/utils"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ibnaleem/gobreach"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/tablewriter"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
	"golang.org/x/time/rate"
)

const (
	BreachName = "breach"
)

func init() {
	Register(BreachName, NewBreachDirectory())
}

// BreachDirectory implements the Runner interface for BreachDirectory searches
type BreachDirectory struct {
	ctx      context.Context
	logger   *ll.Logger
	progress *mpb.Progress
	count    atomic.Uint32
	APIKey   string
}

// NewBreachDirectory creates a new BreachDirectory runner
func NewBreachDirectory() *BreachDirectory {
	return &BreachDirectory{}
}

func (r *BreachDirectory) Name() string {
	return BreachName
}

func (r *BreachDirectory) Prepare(ctx Context) {
	r.ctx = ctx.Ctx
	r.logger = ctx.Logger
	r.progress = ctx.Progress
	r.APIKey = string(ctx.Auth.Key)
}

// Run searches for the username on BreachDirectory
func (r *BreachDirectory) Run(username string) Response {

	if r.APIKey == "" {
		return Response{
			Service: r.Name(),
			Found:   false,
			Error:   fmt.Errorf("can not run BreachDirectory search without an API key"),
		}
	}

	r.logger.Println(utils.Yellowf("[*] Searching %s on Breach Directory for any compromised passwords...", username))

	// Initialize rate limiter: 1 request per second
	limiter := rate.NewLimiter(rate.Every(time.Second), 1)
	// Initialize progress bar
	var bar *mpb.Bar
	if r.progress != nil {
		bar = r.progress.AddBar(1,
			mpb.PrependDecorators(
				decor.Name(fmt.Sprintf("%s: ", r.Name()), decor.WC{W: 15}),
				decor.Percentage(decor.WCSyncWidth),
			),
			mpb.AppendDecorators(
				decor.OnComplete(decor.CurrentNoUnit(""), "Done"),
			),
		)
	}
	client, err := gobreach.NewBreachDirectoryClient(r.APIKey)
	if err != nil {
		r.logger.Errorf("Error initializing BreachDirectory client: %v", err)
		if bar != nil {
			bar.SetTotal(0, true)
		}
		return Response{
			Service: r.Name(),
			Found:   false,
			Error:   fmt.Errorf("error initializing client: %v", err),
		}
	}
	r.logger.Debugf("Searching BreachDirectory for %s", username)
	start := time.Now()
	if err := limiter.Wait(r.ctx); err != nil {
		r.logger.Errorf("Rate limiter error: %v", err)
		if bar != nil {
			bar.SetTotal(0, true)
		}
		return Response{
			Service: r.Name(),
			Found:   false,
			Error:   fmt.Errorf("rate limiter error: %v", err),
		}
	}
	response, err := client.Search(username)
	if err != nil {
		r.logger.Errorf("Error searching BreachDirectory: %v", err)
		if bar != nil {
			bar.SetTotal(0, true)
		}
		return Response{
			Service: r.Name(),
			Found:   false,
			Error:   fmt.Errorf("error searching: %v", err),
		}
	}
	duration := time.Since(start)
	r.logger.Debugf("BreachDirectory search completed in %v", duration)
	if bar != nil {
		bar.SetTotal(0, true)
	}
	if response.Found == 0 {
		return Response{
			Service: r.Name(),
			Found:   false,
			Data:    BreachDirectoryResponse{},
		}
	}
	breaches := make([]struct{ Password, Sha1, Sources string }, 0, response.Found)
	for _, entry := range response.Result {
		pass := CrackHash(entry.Hash, r.logger)
		if pass == "" {
			pass = entry.Password
		}
		breaches = append(breaches, struct{ Password, Sha1, Sources string }{pass, entry.Sha1, entry.Sources})
	}

	r.logger.Println(utils.Greenf("[+] Found %d breaches for %s", response.Found, username))
	r.count.Add(uint32(response.Found))

	bar.SetTotal(int64(response.Found), true)
	return Response{
		Service:  r.Name(),
		Found:    true,
		Data:     BreachDirectoryResponse{Breaches: breaches},
		Count:    r.count.Load(),
		Duration: time.Since(start),
	}
}

// BreachDirectoryResponse represents BreachDirectory search results
type BreachDirectoryResponse struct {
	Breaches []struct {
		Password string
		Sha1     string
		Sources  string
	}
}

func (r BreachDirectoryResponse) Table(out *tablewriter.Table) {
	out.Header([]any{utils.Blue("NO"), utils.Blue("PASSWORD"), utils.Blue("SHA1"), utils.Blue("SOURCE")})
	for i, breach := range r.Breaches {
		out.Append([]string{
			fmt.Sprintf("%d", i+1),
			utils.Green(breach.Password).String(),
			breach.Sha1,
			breach.Sources,
		})
	}
}

func (r BreachDirectoryResponse) String() string {
	var sb strings.Builder
	for _, breach := range r.Breaches {
		sb.WriteString(fmt.Sprintf("[+] Password: %s\n", breach.Password))
		sb.WriteString(fmt.Sprintf("[+] SHA1: %s\n", breach.Sha1))
		sb.WriteString(fmt.Sprintf("[+] Source: %s\n\n", breach.Sources))
	}
	return sb.String()
}
