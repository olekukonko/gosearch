package runners

import (
	"compress/gzip"
	"compress/zlib"
	"context"
	"fmt"
	"github.com/bytedance/sonic"
	"github.com/ibnaleem/gosearch/utils"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/tablewriter"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
	"golang.org/x/time/rate"
)

const (
	WebsiteName = "websites"
)

func init() {
	Register(WebsiteName, NewWebsites())
}

// WeakpassResponse represents the response from Weakpass API for hash cracking.
type WeakpassResponse struct {
	Type string `json:"type"` // Hash type
	Hash string `json:"hash"` // Hash value
	Pass string `json:"pass"` // Cracked password
}

// Website represents a website configuration for searching usernames.
type Website struct {
	Name            string   `json:"name"`                   // Website name
	BaseURL         string   `json:"base_url"`               // Base URL template
	URLProbe        string   `json:"url_probe,omitempty"`    // Optional probe URL
	FollowRedirects bool     `json:"follow_redirects"`       // Whether to follow HTTP redirects
	UserAgent       string   `json:"user_agent,omitempty"`   // Custom User-Agent, if any
	ErrorType       string   `json:"errorType"`              // Type of error checking
	ErrorMsg        string   `json:"errorMsg,omitempty"`     // Expected error message for non-existent profiles
	ErrorCode       int      `json:"errorCode,omitempty"`    // Expected HTTP status code for non-existent profiles
	ResponseURL     string   `json:"response_url,omitempty"` // Expected response URL for existing profiles
	Cookies         []Cookie `json:"cookies,omitempty"`      // Cookies to include in requests
}

// Cookie represents an HTTP cookie.
type Cookie struct {
	Name  string `json:"name"`  // Cookie name
	Value string `json:"value"` // Cookie value
}

// Data holds the list of websites to search.
type Data struct {
	Websites []Website `json:"websites"` // List of website configurations
}

// Websites implements the Runner interface for website searches
type Websites struct {
	ctx              context.Context
	logger           *ll.Logger
	progress         *mpb.Progress
	noFalsePositives bool
	count            atomic.Uint32
}

// NewWebsites creates a new Websites runner
func NewWebsites() *Websites {
	return &Websites{}
}

func (r *Websites) Name() string {
	return WebsiteName
}

func (r *Websites) Prepare(ctx Context) {
	r.ctx = ctx.Ctx
	r.logger = ctx.Logger
	r.progress = ctx.Progress
	r.noFalsePositives = ctx.Options.NoFalsePositive
}

// Run searches for the username across websites
func (r *Websites) Run(username string) Response {
	start := time.Now()
	r.logger.Println(utils.Yellowf("[*] Searching %s across websites...", username))

	data, err := UnmarshalJSON(r.logger)
	if err != nil {
		r.logger.Errorf("Error unmarshalling JSON: %v", err)
		return Response{
			Service: r.Name(),
			Found:   false,
			Error:   fmt.Errorf("error unmarshalling JSON: %v", err),
		}
	}
	// Initialize rate limiter: 10 requests per second
	limiter := rate.NewLimiter(rate.Every(time.Second/10), 10)
	// Initialize progress bar
	var bar *mpb.Bar
	if r.progress != nil {
		bar = r.progress.AddBar(int64(len(data.Websites)),
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
	profiles := make([]struct {
		Name, URL  string
		Unverified bool
	}, 0, len(data.Websites))
	for _, website := range data.Websites {
		wg.Add(1)
		go func(website Website) {
			defer wg.Done()
			defer func() {
				if bar != nil {
					bar.Increment()
				}
			}()
			var url string
			if website.URLProbe != "" {
				url = BuildURL(website.URLProbe, username)
			} else {
				url = BuildURL(website.BaseURL, username)
			}
			r.logger.Debugf("Checking website %s at %s", website.Name, url)
			var profileURL string
			switch website.ErrorType {
			case "status_code":
				profileURL = r.makeRequestWithErrorCode(website, url, username, limiter)
			case "errorMsg":
				profileURL = r.makeRequestWithErrorMsg(website, url, username, limiter)
			case "profilePresence":
				profileURL = r.makeRequestWithProfilePresence(website, url, username, limiter)
			case "response_url":
				profileURL = r.makeRequestWithResponseURL(website, url, username, limiter)
			default:
				if !r.noFalsePositives {
					profileURL = url
					mu.Lock()
					r.count.Add(1)
					mu.Unlock()
				}
			}
			mu.Lock()
			if profileURL != "" {
				profiles = append(profiles, struct {
					Name, URL  string
					Unverified bool
				}{
					Name:       website.Name,
					URL:        profileURL,
					Unverified: website.ErrorType == "unknown",
				})
			} else {
				profiles = append(profiles, struct {
					Name, URL  string
					Unverified bool
				}{
					Name:       website.Name,
					URL:        "",
					Unverified: false,
				})
			}
			mu.Unlock()
		}(website)
	}
	wg.Wait()
	websitesResult := WebsitesResponse{
		Profiles: make([]struct {
			Name   string
			URL    string
			Status string
		}, len(profiles)),
	}
	for i, profile := range profiles {
		websitesResult.Profiles[i] = struct {
			Name   string
			URL    string
			Status string
		}{
			Name:   profile.Name,
			URL:    profile.URL,
			Status: "not_found",
		}
		if profile.URL != "" {
			websitesResult.Profiles[i].Status = "found"
		}
	}
	if len(profiles) > 0 {
		r.logger.Println(utils.Greenf("[+] Found %d website profiles for %s", len(profiles), username))

	} else {
		r.logger.Println(utils.Redf("[-] No website profiles found for %s", username))
	}
	return Response{
		Service:  r.Name(),
		Found:    len(profiles) > 0,
		Data:     websitesResult,
		Count:    r.count.Load(),
		Duration: time.Since(start),
	}
}

func (r *Websites) makeRequestWithErrorCode(website Website, url, username string, limiter *rate.Limiter) string {
	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       tlsConfig,
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Jar: nil,
	}
	if !website.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	userAgent := DefaultUserAgent
	if website.UserAgent != "" {
		userAgent = website.UserAgent
	}
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, url, nil)
	if err != nil {
		r.logger.Errorf("Error creating request for %s: %v", url, err)
		return ""
	}
	req.Header.Set("User-Agent", userAgent)
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
	if website.Cookies != nil {
		for _, cookie := range website.Cookies {
			req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
		}
	}
	r.logger.Debugf("Sending GET request to %s", url)
	start := time.Now()
	if err := limiter.Wait(r.ctx); err != nil {
		r.logger.Errorf("Rate limiter error for %s: %v", url, err)
		return ""
	}
	res, err := client.Do(req)
	if err != nil {
		r.logger.Debugf("Error sending request to %s: %v", url, err)
		return ""
	}
	defer res.Body.Close()
	duration := time.Since(start)
	r.logger.Debugf("Received response for %s in %v, status: %s", url, duration, res.Status)
	if res.StatusCode >= 400 {
		return ""
	}
	if res.StatusCode != website.ErrorCode {
		r.count.Add(1)
		return BuildURL(website.BaseURL, username)
	}
	return ""
}

func (r *Websites) makeRequestWithErrorMsg(website Website, url, username string, limiter *rate.Limiter) string {
	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       tlsConfig,
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Jar: nil,
	}
	if !website.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	userAgent := DefaultUserAgent
	if website.UserAgent != "" {
		userAgent = website.UserAgent
	}
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, url, nil)
	if err != nil {
		r.logger.Errorf("Error creating request for %s: %v", url, err)
		return ""
	}
	req.Header.Set("User-Agent", userAgent)
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
	if website.Cookies != nil {
		for _, cookie := range website.Cookies {
			req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
		}
	}
	r.logger.Debugf("Sending GET request to %s", url)
	start := time.Now()
	if err := limiter.Wait(r.ctx); err != nil {
		r.logger.Errorf("Rate limiter error for %s: %v", url, err)
		return ""
	}
	res, err := client.Do(req)
	if err != nil {
		r.logger.Debugf("Error sending request to %s: %v", url, err)
		return ""
	}
	var reader io.ReadCloser
	switch res.Header.Get("Content-Encoding") {
	case "gzip":
		gzReader, err := gzip.NewReader(res.Body)
		if err != nil {
			r.logger.Errorf("Error creating gzip reader for %s: %v", url, err)
			res.Body.Close()
			return ""
		}
		reader = gzReader
	case "deflate":
		zlibReader, err := zlib.NewReader(res.Body)
		if err != nil {
			r.logger.Errorf("Error creating deflate reader for %s: %v", url, err)
			res.Body.Close()
			return ""
		}
		reader = zlibReader
	case "br":
		reader = io.NopCloser(brotli.NewReader(res.Body))
	default:
		reader = res.Body
	}
	defer res.Body.Close()
	duration := time.Since(start)
	r.logger.Debugf("Received response for %s in %v, status: %s", url, duration, res.Status)
	body, err := io.ReadAll(reader)
	if err != nil {
		r.logger.Errorf("Error reading response body from %s: %v", url, err)
		return ""
	}
	r.logger.Debugf("Response body size for %s: %d bytes", url, len(body))
	if res.StatusCode >= 400 {
		return ""
	}
	bodyStr := string(body)
	if !strings.Contains(bodyStr, website.ErrorMsg) {
		r.count.Add(1)
		return BuildURL(website.BaseURL, username)
	}
	return ""
}

func (r *Websites) makeRequestWithProfilePresence(website Website, url, username string, limiter *rate.Limiter) string {
	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       tlsConfig,
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Jar: nil,
	}
	if !website.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	userAgent := DefaultUserAgent
	if website.UserAgent != "" {
		userAgent = website.UserAgent
	}
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, url, nil)
	if err != nil {
		r.logger.Errorf("Error creating request for %s: %v", url, err)
		return ""
	}
	req.Header.Set("User-Agent", userAgent)
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
	if website.Cookies != nil {
		for _, cookie := range website.Cookies {
			req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
		}
	}
	r.logger.Debugf("Sending GET request to %s", url)
	start := time.Now()
	if err := limiter.Wait(r.ctx); err != nil {
		r.logger.Errorf("Rate limiter error for %s: %v", url, err)
		return ""
	}
	res, err := client.Do(req)
	if err != nil {
		r.logger.Debugf("Error sending request to %s: %v", url, err)
		return ""
	}
	defer res.Body.Close()
	duration := time.Since(start)
	r.logger.Debugf("Received response for %s in %v, status: %s", url, duration, res.Status)
	body, err := io.ReadAll(res.Body)
	if err != nil {
		r.logger.Errorf("Error reading response body from %s: %v", url, err)
		return ""
	}
	r.logger.Debugf("Response body size for %s: %d bytes", url, len(body))
	if res.StatusCode >= 400 {
		return ""
	}
	bodyStr := string(body)
	if strings.Contains(bodyStr, website.ErrorMsg) {
		r.count.Add(1)
		return BuildURL(website.BaseURL, username)
	}
	return ""
}

func (r *Websites) makeRequestWithResponseURL(website Website, url, username string, limiter *rate.Limiter) string {
	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       tlsConfig,
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Jar: nil,
	}
	if !website.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	userAgent := DefaultUserAgent
	if website.UserAgent != "" {
		userAgent = website.UserAgent
	}
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, url, nil)
	if err != nil {
		r.logger.Errorf("Error creating request for %s: %v", url, err)
		return ""
	}
	req.Header.Set("User-Agent", userAgent)
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
	if website.Cookies != nil {
		for _, cookie := range website.Cookies {
			req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
		}
	}
	r.logger.Debugf("Sending GET request to %s", url)
	start := time.Now()
	if err := limiter.Wait(r.ctx); err != nil {
		r.logger.Errorf("Rate limiter error for %s: %v", url, err)
		return ""
	}
	res, err := client.Do(req)
	if err != nil {
		r.logger.Debugf("Error sending request to %s: %v", url, err)
		return ""
	}
	defer res.Body.Close()
	duration := time.Since(start)
	r.logger.Debugf("Received response for %s in %v, status: %s", url, duration, res.Status)
	if res.StatusCode >= 400 {
		return ""
	}
	formattedResponseURL := BuildURL(website.ResponseURL, username)
	if !(res.Request.URL.String() == formattedResponseURL) {
		r.count.Add(1)
		return BuildURL(website.BaseURL, username)
	}
	return ""
}

// WebsitesResponse represents website search results
type WebsitesResponse struct {
	Profiles []struct {
		Name   string
		URL    string
		Status string // "found" or "not_found"
	}
}

func (r WebsitesResponse) Table(out *tablewriter.Table) {
	out.Header([]any{utils.Blue("NO"), utils.Blue("WEBSITE"), utils.Blue("URL")})
	for i, profile := range r.Profiles {
		name := profile.Name
		if profile.Status == "found" {
			name = utils.Green(profile.Name).String()
		} else {
			name = utils.Yellow(profile.Name).String()
		}
		url := ""
		if profile.Status == "found" {
			url = utils.Green(profile.URL).String()
		}
		out.Append([]string{
			fmt.Sprintf("%d", i+1),
			name,
			url,
		})
	}
}

func (r WebsitesResponse) String() string {
	var sb strings.Builder
	for _, profile := range r.Profiles {
		prefix := "[+]"
		if profile.Status == "not_found" {
			prefix = "[?]"
		}
		url := ""
		if profile.Status == "found" {
			url = profile.URL
		}
		sb.WriteString(fmt.Sprintf("%s %s: %s\n", prefix, profile.Name, url))
	}
	return sb.String()
}

// UnmarshalJSON fetches and parses the website configuration from a remote JSON file.
func UnmarshalJSON(logger *ll.Logger) (Data, error) {
	url := "https://raw.githubusercontent.com/ibnaleem/gosearch/refs/heads/main/data.json"
	logger.Debugf("Fetching data.json from %s", url)
	start := time.Now()
	resp, err := http.Get(url)
	if err != nil {
		logger.Errorf("Error downloading data.json: %v", err)
		return Data{}, fmt.Errorf("error downloading data.json: %w", err)
	}
	defer resp.Body.Close()
	logger.Debugf("Received data.json response in %v, status: %s", time.Since(start), resp.Status)

	if resp.StatusCode != http.StatusOK {
		logger.Errorf("Failed to download data.json, status code: %d", resp.StatusCode)
		return Data{}, fmt.Errorf("failed to download data.json, status code: %d", resp.StatusCode)
	}

	jsonData, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Errorf("Error reading downloaded content: %v", err)
		return Data{}, fmt.Errorf("error reading downloaded content: %w", err)
	}
	logger.Debugf("Downloaded data.json, size: %d bytes", len(jsonData))

	var data Data
	err = sonic.Unmarshal(jsonData, &data)
	if err != nil {
		logger.Errorf("Error unmarshalling JSON: %v", err)
		return Data{}, fmt.Errorf("error unmarshalling JSON: %w", err)
	}
	logger.Debugf("Successfully loaded %d websites from data.json", len(data.Websites))
	return data, nil
}
