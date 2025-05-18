package main

import (
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/bytedance/sonic"
	"github.com/ibnaleem/gobreach"
	"github.com/olekukonko/tablewriter"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/time/rate"
)

func (r HudsonRockResult) RenderTable(out *tablewriter.Table) {
	out.Header([]any{Blue("#"), Blue("Stealer"), Blue("Date"), Blue("Computer"), Blue("Passwords")})
	for i, stealer := range r.Stealers {
		computerName := stealer.ComputerName
		if !strings.EqualFold(strings.TrimSpace(computerName), "Not Found") {
			computerName = Red(computerName).String()
		}
		out.Append([]string{
			fmt.Sprintf("%d", i+1),
			stealer.StealerFamily,
			formatStealerDate(stealer.DateCompromised),
			computerName,
			strings.Join(stealer.TopPasswords, "\n"),
		})
	}
}

func (r HudsonRockResult) String() string {
	var sb strings.Builder
	for i, stealer := range r.Stealers {
		sb.WriteString(fmt.Sprintf("[-] Stealer #%d\n", i+1))
		sb.WriteString(fmt.Sprintf(":: Family: %s\n", stealer.StealerFamily))
		sb.WriteString(fmt.Sprintf(":: Date: %s\n", stealer.DateCompromised))
		sb.WriteString(fmt.Sprintf(":: Computer: %s\n", stealer.ComputerName))
		sb.WriteString(fmt.Sprintf(":: OS: %s\n", stealer.OperatingSystem))
		sb.WriteString(fmt.Sprintf(":: Path: %s\n", stealer.MalwarePath))
		var avs string
		switch v := stealer.Antiviruses.(type) {
		case string:
			avs = v
		case []interface{}:
			parts := make([]string, len(v))
			for i, av := range v {
				parts[i] = fmt.Sprint(av)
			}
			avs = strings.Join(parts, ", ")
		}
		sb.WriteString(fmt.Sprintf(":: AV: %s\n", avs))
		sb.WriteString(fmt.Sprintf(":: IP: %s\n", stealer.IP))
		sb.WriteString(":: Passwords:\n")
		for _, p := range stealer.TopPasswords {
			sb.WriteString(fmt.Sprintf("   %s\n", p))
		}
		sb.WriteString(":: Logins:\n")
		for _, l := range stealer.TopLogins {
			sb.WriteString(fmt.Sprintf("   %s\n", l))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// ProxyNovaResult represents ProxyNova search results
type ProxyNovaResult struct {
	Credentials []struct {
		Email    string
		Password string
	}
}

func (r ProxyNovaResult) RenderTable(out *tablewriter.Table) {
	out.Header([]any{Blue("No"), Blue("Email"), Blue("Password")})
	for i, cred := range r.Credentials {
		out.Append([]string{
			fmt.Sprintf("%d", i+1),
			Green(cred.Email).String(),
			Red(cred.Password).String(),
		})
	}
}

func (r ProxyNovaResult) String() string {
	var sb strings.Builder
	for _, cred := range r.Credentials {
		sb.WriteString(fmt.Sprintf("[+] Email: %s\n", cred.Email))
		sb.WriteString(fmt.Sprintf("[+] Password: %s\n\n", cred.Password))
	}
	return sb.String()
}

// DomainsResult represents Domains search results
type DomainsResult struct {
	Domains []struct {
		Domain string
	}
}

func (r DomainsResult) RenderTable(out *tablewriter.Table) {
	out.Header([]any{Blue("NO"), Blue("DOMAIN"), Blue("STATUS")})
	for i, domain := range r.Domains {
		out.Append([]string{
			fmt.Sprintf("%d", i+1),
			domain.Domain,
			Green(http.StatusOK).String(),
		})
	}
}

func (r DomainsResult) String() string {
	var sb strings.Builder
	for _, domain := range r.Domains {
		sb.WriteString(fmt.Sprintf("[+] 200 OK: %s\n", domain.Domain))
	}
	return sb.String()
}

// WebsitesResult represents Websites search results
type WebsitesResult struct {
	Profiles []struct {
		Name   string
		URL    string
		Status string // "found" or "not_found"
	}
}

func (r WebsitesResult) RenderTable(out *tablewriter.Table) {
	out.Header([]any{Blue("NO"), Blue("WEBSITE"), Blue("URL")})
	for i, profile := range r.Profiles {
		name := profile.Name
		if profile.Status == "found" {
			name = Green(profile.Name).String()
		} else {
			name = Yellow(profile.Name).String()
		}
		url := ""
		if profile.Status == "found" {
			url = Green(profile.URL).String()
		}
		out.Append([]string{
			fmt.Sprintf("%d", i+1),
			name,
			url,
		})
	}
}

func (r WebsitesResult) String() string {
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

// BreachDirectoryResult represents BreachDirectory search results
type BreachDirectoryResult struct {
	Breaches []struct {
		Password string
		Sha1     string
		Sources  string
	}
}

func (r BreachDirectoryResult) RenderTable(out *tablewriter.Table) {
	out.Header([]any{Blue("NO"), Blue("PASSWORD"), Blue("SHA1"), Blue("SOURCE")})
	for i, breach := range r.Breaches {
		out.Append([]string{
			fmt.Sprintf("%d", i+1),
			Green(breach.Password).String(),
			breach.Sha1,
			breach.Sources,
		})
	}
}

func (r BreachDirectoryResult) String() string {
	var sb strings.Builder
	for _, breach := range r.Breaches {
		sb.WriteString(fmt.Sprintf("[+] Password: %s\n", breach.Password))
		sb.WriteString(fmt.Sprintf("[+] SHA1: %s\n", breach.Sha1))
		sb.WriteString(fmt.Sprintf("[+] Source: %s\n\n", breach.Sources))
	}
	return sb.String()
}

// HudsonRockRunner implements the Runner interface for HudsonRock searches
type HudsonRockRunner struct{}

func (r HudsonRockRunner) Run(username string) Response {
	logger.Infof(Yellow("[*] Searching %s on HudsonRock's Cybercrime Intelligence Database...").String(), username)
	// Initialize rate limiter: 1 request per second
	limiter := rate.NewLimiter(rate.Every(time.Second), 1)
	client := &http.Client{
		Timeout: 120 * time.Second,
	}
	url := fmt.Sprintf("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username=%s", username)
	logger.Debugf("Sending GET request to %s", url)
	start := time.Now()
	if err := limiter.Wait(context.Background()); err != nil {
		logger.Errorf("Rate limiter error: %v", err)
		return Response{
			Service: "HudsonRock",
			Found:   false,
			Error:   fmt.Sprintf("Rate limiter error: %v", err),
		}
	}
	resp, err := client.Get(url)
	if err != nil {
		logger.Errorf("Error fetching HudsonRock data: %v", err)
		return Response{
			Service: "HudsonRock",
			Found:   false,
			Error:   fmt.Sprintf("Error fetching data: %v", err),
		}
	}
	defer resp.Body.Close()
	duration := time.Since(start)
	logger.Debugf("Received response in %v, status: %s", duration, resp.Status)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Errorf("Error reading HudsonRock response: %v", err)
		return Response{
			Service: "HudsonRock",
			Found:   false,
			Error:   fmt.Sprintf("Error reading response: %v", err),
		}
	}
	logger.Debugf("HudsonRock response size: %d bytes", len(body))
	var response HudsonRockResponse
	if err := sonic.Unmarshal(body, &response); err != nil {
		logger.Errorf("Error parsing HudsonRock JSON: %v", err)
		return Response{
			Service: "HudsonRock",
			Found:   false,
			Error:   fmt.Sprintf("Error parsing JSON: %v", err),
		}
	}
	if response.Message == "This username is not associated with a computer infected by an info-stealer. Visit https://www.hudsonrock.com/free-tools to discover additional free tools and Infostealers related data." {
		logger.Infof(Green("✓ No info-stealer association found").String())
		return Response{
			Service: "HudsonRock",
			Found:   false,
			Data:    HudsonRockResult{},
		}
	}
	logger.Warnf(Red("‼ Info-stealer compromise detected").String())
	logger.Warnf(Yellow("  All credentials on this computer may be exposed").String())
	return Response{
		Service: "HudsonRock",
		Found:   true,
		Data:    HudsonRockResult{Stealers: response.Stealers},
	}
}

// ProxyNovaRunner implements the Runner interface for ProxyNova searches
type ProxyNovaRunner struct{}

func (r ProxyNovaRunner) Run(username string) Response {
	logger.Infof(Yellow("[*] Searching %s on ProxyNova for any compromised passwords...").String(), username)
	// Initialize rate limiter: 1 request per second
	limiter := rate.NewLimiter(rate.Every(time.Second), 1)
	client := &http.Client{
		Timeout: 120 * time.Second,
	}
	req, err := http.NewRequest(http.MethodGet, "https://api.proxynova.com/comb?query="+username, nil)
	if err != nil {
		logger.Errorf("Error creating ProxyNova request: %v", err)
		return Response{
			Service: "ProxyNova",
			Found:   false,
			Error:   fmt.Sprintf("Error creating request: %v", err),
		}
	}
	logger.Debugf("Sending GET request to %s", req.URL.String())
	start := time.Now()
	if err := limiter.Wait(context.Background()); err != nil {
		logger.Errorf("Rate limiter error: %v", err)
		return Response{
			Service: "ProxyNova",
			Found:   false,
			Error:   fmt.Sprintf("Rate limiter error: %v", err),
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		logger.Errorf("Error sending ProxyNova request: %v", err)
		return Response{
			Service: "ProxyNova",
			Found:   false,
			Error:   fmt.Sprintf("Error sending request: %v", err),
		}
	}
	defer resp.Body.Close()
	duration := time.Since(start)
	logger.Debugf("Received response in %v, status: %s", duration, resp.Status)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Errorf("Error reading ProxyNova response: %v", err)
		return Response{
			Service: "ProxyNova",
			Found:   false,
			Error:   fmt.Sprintf("Error reading response: %v", err),
		}
	}
	logger.Debugf("ProxyNova response size: %d bytes", len(body))
	var response ProxyNova
	err = sonic.Unmarshal(body, &response)
	if err != nil {
		logger.Errorf("Error parsing ProxyNova JSON: %v", err)
		return Response{
			Service: "ProxyNova",
			Found:   false,
			Error:   fmt.Sprintf("Error parsing JSON: %v", err),
		}
	}
	if response.Count == 0 {
		logger.Infof(Red("[-] No compromised passwords found for %s.").String(), username)
		return Response{
			Service: "ProxyNova",
			Found:   false,
			Data:    ProxyNovaResult{},
		}
	}
	creds := make([]struct{ Email, Password string }, 0, response.Count)
	for _, line := range response.Lines {
		parts := strings.Split(line, ":")
		if len(parts) == 2 {
			creds = append(creds, struct{ Email, Password string }{parts[0], parts[1]})
		}
	}
	logger.Infof(Green("[+] Found %d compromised passwords for %s").String(), response.Count, username)
	return Response{
		Service: "ProxyNova",
		Found:   true,
		Data:    ProxyNovaResult{Credentials: creds},
	}
}

// DomainsRunner implements the Runner interface for Domains searches
type DomainsRunner struct{}

func (r DomainsRunner) Run(username string) Response {
	domains := BuildDomains(username)
	logger.Infof(Yellow("[*] Searching %d domains with the username %s...").String(), len(domains), username)
	// Initialize rate limiter: 5 requests per second
	limiter := rate.NewLimiter(rate.Every(time.Second/5), 5)
	client := &http.Client{
		Timeout: 120 * time.Second,
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make([]struct{ Domain string }, 0, len(domains))
	domainCount := 0
	for _, domain := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			url := "http://" + domain
			req, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				logger.Errorf("Error creating request for %s: %v", domain, err)
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
			logger.Debugf("Sending GET request to %s", url)
			start := time.Now()
			if err := limiter.Wait(context.Background()); err != nil {
				logger.Errorf("Rate limiter error for %s: %v", domain, err)
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				var netErr net.Error
				ok := errors.As(err, &netErr)
				noSuchHostError := strings.Contains(err.Error(), "no such host")
				networkTimeoutError := ok && netErr.Timeout()
				if !noSuchHostError && !networkTimeoutError {
					logger.Errorf("Error sending request for %s: %v", domain, err)
				}
				return
			}
			defer resp.Body.Close()
			duration := time.Since(start)
			logger.Debugf("Received response for %s in %v, status: %s", domain, duration, resp.Status)
			if resp.StatusCode == http.StatusOK {
				mu.Lock()
				results = append(results, struct{ Domain string }{domain})
				domainCount++
				mu.Unlock()
			}
		}(domain)
	}
	wg.Wait()
	if domainCount > 0 {
		logger.Infof(Green("[+] Found %d domains with the username %s").String(), domainCount, username)
		return Response{
			Service: "Domains",
			Found:   true,
			Data:    DomainsResult{Domains: results},
		}
	}
	logger.Infof(Red("[-] No domains found with the username %s").String(), username)
	return Response{
		Service: "Domains",
		Found:   false,
		Data:    DomainsResult{},
	}
}

// WebsitesRunner implements the Runner interface for Websites searches
type WebsitesRunner struct {
	NoFalsePositives bool
}

func (r WebsitesRunner) Run(username string) Response {
	logger.Infof(Yellow("[*] Searching %s across websites...").String(), username)
	data, err := UnmarshalJSON()
	if err != nil {
		logger.Errorf("Error unmarshalling JSON: %v", err)
		return Response{
			Service: "Websites",
			Found:   false,
			Error:   fmt.Sprintf("Error unmarshalling JSON: %v", err),
		}
	}
	// Initialize rate limiter: 10 requests per second
	limiter := rate.NewLimiter(rate.Every(time.Second/10), 10)
	// Initialize progress bar
	bar := progressbar.NewOptions(len(data.Websites),
		progressbar.OptionSetDescription("Checking websites"),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(30),
		progressbar.OptionShowIts(),
		progressbar.OptionClearOnFinish(),
	)
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
			defer bar.Add(1)
			var url string
			if website.URLProbe != "" {
				url = BuildURL(website.URLProbe, username)
			} else {
				url = BuildURL(website.BaseURL, username)
			}
			logger.Debugf("Checking website %s at %s", website.Name, url)
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
				if !r.NoFalsePositives {
					profileURL = url
					mu.Lock()
					count.Add(1)
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
	bar.Finish()
	websitesResult := WebsitesResult{
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
		logger.Infof(Green("[+] Found %d website profiles for %s").String(), len(profiles), username)
	} else {
		logger.Infof(Red("[-] No website profiles found for %s").String(), username)
	}
	return Response{
		Service: "Websites",
		Found:   len(profiles) > 0,
		Data:    websitesResult,
	}
}

func (r WebsitesRunner) makeRequestWithErrorCode(website Website, url, username string, limiter *rate.Limiter) string {
	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       tlsConfig,
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, DualStack: true}).DialContext,
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
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		logger.Errorf("Error creating request for %s: %v", url, err)
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
	logger.Debugf("Sending GET request to %s", url)
	start := time.Now()
	if err := limiter.Wait(context.Background()); err != nil {
		logger.Errorf("Rate limiter error for %s: %v", url, err)
		return ""
	}
	res, err := client.Do(req)
	if err != nil {
		logger.Debugf("Error sending request to %s: %v", url, err)
		return ""
	}
	defer res.Body.Close()
	duration := time.Since(start)
	logger.Debugf("Received response for %s in %v, status: %s", url, duration, res.Status)
	if res.StatusCode >= 400 {
		return ""
	}
	if res.StatusCode != website.ErrorCode {
		count.Add(1)
		return BuildURL(website.BaseURL, username)
	}
	return ""
}

func (r WebsitesRunner) makeRequestWithErrorMsg(website Website, url, username string, limiter *rate.Limiter) string {
	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       tlsConfig,
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, DualStack: true}).DialContext,
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
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		logger.Errorf("Error creating request for %s: %v", url, err)
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
	logger.Debugf("Sending GET request to %s", url)
	start := time.Now()
	if err := limiter.Wait(context.Background()); err != nil {
		logger.Errorf("Rate limiter error for %s: %v", url, err)
		return ""
	}
	res, err := client.Do(req)
	if err != nil {
		logger.Debugf("Error sending request to %s: %v", url, err)
		return ""
	}
	var reader io.ReadCloser
	switch res.Header.Get("Content-Encoding") {
	case "gzip":
		gzReader, err := gzip.NewReader(res.Body)
		if err != nil {
			logger.Errorf("Error creating gzip reader for %s: %v", url, err)
			res.Body.Close()
			return ""
		}
		reader = gzReader
	case "deflate":
		zlibReader, err := zlib.NewReader(res.Body)
		if err != nil {
			logger.Errorf("Error creating deflate reader for %s: %v", url, err)
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
	logger.Debugf("Received response for %s in %v, status: %s", url, duration, res.Status)
	body, err := io.ReadAll(reader)
	if err != nil {
		logger.Errorf("Error reading response body from %s: %v", url, err)
		return ""
	}
	logger.Debugf("Response body size for %s: %d bytes", url, len(body))
	if res.StatusCode >= 400 {
		return ""
	}
	bodyStr := string(body)
	if !strings.Contains(bodyStr, website.ErrorMsg) {
		count.Add(1)
		return BuildURL(website.BaseURL, username)
	}
	return ""
}

func (r WebsitesRunner) makeRequestWithProfilePresence(website Website, url, username string, limiter *rate.Limiter) string {
	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       tlsConfig,
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, DualStack: true}).DialContext,
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
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		logger.Errorf("Error creating request for %s: %v", url, err)
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
	logger.Debugf("Sending GET request to %s", url)
	start := time.Now()
	if err := limiter.Wait(context.Background()); err != nil {
		logger.Errorf("Rate limiter error for %s: %v", url, err)
		return ""
	}
	res, err := client.Do(req)
	if err != nil {
		logger.Debugf("Error sending request to %s: %v", url, err)
		return ""
	}
	defer res.Body.Close()
	duration := time.Since(start)
	logger.Debugf("Received response for %s in %v, status: %s", url, duration, res.Status)
	body, err := io.ReadAll(res.Body)
	if err != nil {
		logger.Errorf("Error reading response body from %s: %v", url, err)
		return ""
	}
	logger.Debugf("Response body size for %s: %d bytes", url, len(body))
	if res.StatusCode >= 400 {
		return ""
	}
	bodyStr := string(body)
	if strings.Contains(bodyStr, website.ErrorMsg) {
		count.Add(1)
		return BuildURL(website.BaseURL, username)
	}
	return ""
}

func (r WebsitesRunner) makeRequestWithResponseURL(website Website, url, username string, limiter *rate.Limiter) string {
	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       tlsConfig,
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, DualStack: true}).DialContext,
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
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		logger.Errorf("Error creating request for %s: %v", url, err)
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
	logger.Debugf("Sending GET request to %s", url)
	start := time.Now()
	if err := limiter.Wait(context.Background()); err != nil {
		logger.Errorf("Rate limiter error for %s: %v", url, err)
		return ""
	}
	res, err := client.Do(req)
	if err != nil {
		logger.Debugf("Error sending request to %s: %v", url, err)
		return ""
	}
	defer res.Body.Close()
	duration := time.Since(start)
	logger.Debugf("Received response for %s in %v, status: %s", url, duration, res.Status)
	if res.StatusCode >= 400 {
		return ""
	}
	formattedResponseURL := BuildURL(website.ResponseURL, username)
	if !(res.Request.URL.String() == formattedResponseURL) {
		count.Add(1)
		return BuildURL(website.BaseURL, username)
	}
	return ""
}

// BreachDirectoryRunner implements the Runner interface for BreachDirectory searches
type BreachDirectoryRunner struct {
	APIKey string
}

func (r BreachDirectoryRunner) Run(username string) Response {
	logger.Infof(Yellow("[*] Searching %s on Breach Directory for any compromised passwords...").String(), username)
	// Initialize rate limiter: 1 request per second
	limiter := rate.NewLimiter(rate.Every(time.Second), 1)
	client, err := gobreach.NewBreachDirectoryClient(r.APIKey)
	if err != nil {
		logger.Errorf("Error initializing BreachDirectory client: %v", err)
		return Response{
			Service: "BreachDirectory",
			Found:   false,
			Error:   fmt.Sprintf("Error initializing client: %v", err),
		}
	}
	logger.Debugf("Searching BreachDirectory for %s", username)
	start := time.Now()
	if err := limiter.Wait(context.Background()); err != nil {
		logger.Errorf("Rate limiter error: %v", err)
		return Response{
			Service: "BreachDirectory",
			Found:   false,
			Error:   fmt.Sprintf("Rate limiter error: %v", err),
		}
	}
	response, err := client.Search(username)
	if err != nil {
		logger.Errorf("Error searching BreachDirectory: %v", err)
		return Response{
			Service: "BreachDirectory",
			Found:   false,
			Error:   fmt.Sprintf("Error searching: %v", err),
		}
	}
	duration := time.Since(start)
	logger.Debugf("BreachDirectory search completed in %v", duration)
	if response.Found == 0 {
		logger.Infof(Red("[-] No breaches found for %s.").String(), username)
		return Response{
			Service: "BreachDirectory",
			Found:   false,
			Data:    BreachDirectoryResult{},
		}
	}
	breaches := make([]struct{ Password, Sha1, Sources string }, 0, response.Found)
	for _, entry := range response.Result {
		pass := CrackHash(entry.Hash)
		if pass == "" {
			pass = entry.Password
		}
		breaches = append(breaches, struct{ Password, Sha1, Sources string }{pass, entry.Sha1, entry.Sources})
	}
	logger.Infof(Green("[+] Found %d breaches for %s").String(), response.Found, username)
	return Response{
		Service: "BreachDirectory",
		Found:   true,
		Data:    BreachDirectoryResult{Breaches: breaches},
	}
}
