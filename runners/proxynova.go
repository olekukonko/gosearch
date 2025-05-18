package runners

import (
	"context"
	"fmt"
	"github.com/ibnaleem/gosearch/utils"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bytedance/sonic"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/tablewriter"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
	"golang.org/x/time/rate"
)

const (
	NovaName = "nova"
)

func init() {
	Register(NovaName, NewProxyNova())
}

// ProxyNova implements the Runner interface for ProxyNova searches
type ProxyNova struct {
	ctx      context.Context
	logger   *ll.Logger
	progress *mpb.Progress
	count    atomic.Uint32
}

// NewProxyNova creates a new ProxyNova runner
func NewProxyNova() *ProxyNova {
	return &ProxyNova{}
}

func (r *ProxyNova) Name() string {
	return NovaName
}

func (r *ProxyNova) Prepare(ctx Context) {
	r.ctx = ctx.Ctx
	r.logger = ctx.Logger
	r.progress = ctx.Progress
}

// Run searches for the username on ProxyNova
func (r *ProxyNova) Run(username string) Response {

	// Initialize rate limiter: 1 request per second
	limiter := rate.NewLimiter(rate.Every(time.Second), 1)
	client := &http.Client{
		Timeout:   120 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}
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
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, "https://api.proxynova.com/comb?query="+username, nil)
	if err != nil {
		r.logger.Errorf("Error creating ProxyNova request: %v", err)
		if bar != nil {
			bar.SetTotal(0, true)
		}
		return Response{
			Service: r.Name(),
			Found:   false,
			Error:   fmt.Errorf("error creating request: %v", err),
		}
	}
	r.logger.Debugf("Sending GET request to %s", req.URL.String())
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
	resp, err := client.Do(req)
	if err != nil {
		r.logger.Errorf("Error sending ProxyNova request: %v", err)
		if bar != nil {
			bar.SetTotal(0, true)
		}
		return Response{
			Service: r.Name(),
			Found:   false,
			Error:   fmt.Errorf("error sending request: %v", err),
		}
	}
	defer resp.Body.Close()
	duration := time.Since(start)
	r.logger.Debugf("Received response in %v, status: %s", duration, resp.Status)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		r.logger.Errorf("Error reading ProxyNova response: %v", err)
		if bar != nil {
			bar.SetTotal(0, true)
		}
		return Response{
			Service: r.Name(),
			Found:   false,
			Error:   fmt.Errorf("error reading response: %v", err),
		}
	}
	r.logger.Debugf("ProxyNova response size: %d bytes", len(body))
	var response struct {
		Count int      `json:"count"`
		Lines []string `json:"lines"`
	}
	if err := sonic.Unmarshal(body, &response); err != nil {
		r.logger.Errorf("Error parsing ProxyNova JSON: %v", err)
		if bar != nil {
			bar.SetTotal(0, true)
		}
		return Response{
			Service: r.Name(),
			Found:   false,
			Error:   fmt.Errorf("error parsing JSON: %v", err),
		}
	}
	if bar != nil {
		bar.SetTotal(0, true)
	}
	if response.Count == 0 {
		return Response{
			Service: r.Name(),
			Found:   false,
			Data:    ProxyNovaResponse{},
		}
	}
	creds := make([]struct{ Email, Password string }, 0, response.Count)
	for _, line := range response.Lines {
		parts := strings.Split(line, ":")
		if len(parts) == 2 {
			creds = append(creds, struct{ Email, Password string }{parts[0], parts[1]})
		}
	}

	bar.SetTotal(int64(response.Count), true)
	r.count.Add(uint32(response.Count))

	return Response{
		Service:  r.Name(),
		Found:    true,
		Data:     ProxyNovaResponse{Credentials: creds},
		Count:    r.count.Load(),
		Duration: time.Since(start),
	}
}

// ProxyNovaResponse represents ProxyNova search results
type ProxyNovaResponse struct {
	Credentials []struct {
		Email    string
		Password string
	}
}

func (r ProxyNovaResponse) Table(out *tablewriter.Table) {
	out.Header([]any{utils.Blue("No"), utils.Blue("Email"), utils.Blue("Password")})
	for i, cred := range r.Credentials {
		out.Append([]string{
			fmt.Sprintf("%d", i+1),
			utils.Green(cred.Email).String(),
			utils.Red(cred.Password).String(),
		})
	}
}

func (r ProxyNovaResponse) String() string {
	var sb strings.Builder
	for _, cred := range r.Credentials {
		sb.WriteString(fmt.Sprintf("[+] Email: %s\n", cred.Email))
		sb.WriteString(fmt.Sprintf("[+] Password: %s\n\n", cred.Password))
	}
	return sb.String()
}
