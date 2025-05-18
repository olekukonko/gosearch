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
	HudsonRockName = "hudsonrock"
)

func init() {
	Register(HudsonRockName, NewHudsonRock())
}

// HudsonRock implements the Runner interface for HudsonRock searches
type HudsonRock struct {
	ctx      context.Context
	logger   *ll.Logger
	progress *mpb.Progress
	count    atomic.Uint32
}

// NewHudsonRock creates a new HudsonRock runner
func NewHudsonRock() *HudsonRock {
	return &HudsonRock{}
}

func (r *HudsonRock) Name() string {
	return HudsonRockName
}

func (r *HudsonRock) Prepare(ctx Context) {
	r.ctx = ctx.Ctx
	r.logger = ctx.Logger
	r.progress = ctx.Progress
}

// Run searches for the username on HudsonRock
func (r *HudsonRock) Run(username string) Response {
	r.logger.Println(utils.Yellowf("[*] Searching %s on HudsonRock's Cybercrime Intelligence Database...", username))

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
	url := fmt.Sprintf("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username=%s", username)
	r.logger.Debugf("Sending GET request to %s", url)
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
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, url, nil)
	if err != nil {
		r.logger.Errorf("Error creating HudsonRock request: %v", err)
		if bar != nil {
			bar.SetTotal(0, true)
		}
		return Response{
			Service: r.Name(),
			Found:   false,
			Error:   fmt.Errorf("error creating request: %v", err),
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		r.logger.Errorf("Error fetching HudsonRock data: %v", err)
		if bar != nil {
			bar.SetTotal(0, true)
		}
		return Response{
			Service: r.Name(),
			Found:   false,
			Error:   fmt.Errorf("error fetching data: %v", err),
		}
	}
	defer resp.Body.Close()
	duration := time.Since(start)
	r.logger.Debugf("Received response in %v, status: %s", duration, resp.Status)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		r.logger.Errorf("Error reading HudsonRock response: %v", err)
		if bar != nil {
			bar.SetTotal(0, true)
		}
		return Response{
			Service: r.Name(),
			Found:   false,
			Error:   fmt.Errorf("error reading response: %v", err),
		}
	}
	r.logger.Debugf("HudsonRock response size: %d bytes", len(body))

	var response HudsonRockResponse

	if err := sonic.Unmarshal(body, &response); err != nil {
		r.logger.Errorf("Error parsing HudsonRock JSON: %v", err)
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
	if response.Message == "This username is not associated with a computer infected by an info-stealer. Visit https://www.hudsonrock.com/free-tools to discover additional free tools and Infostealers related data." {

		r.logger.Println(utils.Green("✓ No info-stealer association found"))

		return Response{
			Service: r.Name(),
			Found:   false,
			Data:    HudsonRockResponse{},
		}
	}

	bar.SetTotal(int64(len(response.Stealers)), true)

	return Response{
		Service:  r.Name(),
		Found:    true,
		Data:     HudsonRockResponse{Stealers: response.Stealers},
		Duration: time.Since(start),
	}
}

type Stealer struct {
	TotalCorporateServices int         `json:"total_corporate_services"` // Number of corporate services compromised
	TotalUserServices      int         `json:"total_user_services"`      // Number of user services compromised
	DateCompromised        string      `json:"date_compromised"`         // Date of compromise
	StealerFamily          string      `json:"stealer_family"`           // Type of stealer malware
	ComputerName           string      `json:"computer_name"`            // Name of compromised computer
	OperatingSystem        string      `json:"operating_system"`         // Operating system of compromised computer
	MalwarePath            string      `json:"malware_path"`             // Path of malware on compromised system
	Antiviruses            interface{} `json:"antiviruses"`              // Antivirus software detected
	IP                     string      `json:"ip"`                       // IP address of compromised system
	TopPasswords           []string    `json:"top_passwords"`            // Commonly used passwords
	TopLogins              []string    `json:"top_logins"`               // Commonly used logins
}

// HudsonRockResponse represents HudsonRock search results
type HudsonRockResponse struct {
	Message  string `json:"message"`
	Stealers []Stealer
}

func (r HudsonRockResponse) Table(out *tablewriter.Table) {
	out.Header([]any{utils.Blue("#"), utils.Blue("Stealer"), utils.Blue("Date"), utils.Blue("Computer"), utils.Blue("Passwords")})
	for i, stealer := range r.Stealers {
		computerName := stealer.ComputerName
		if !strings.EqualFold(strings.TrimSpace(computerName), "Not Found") {
			computerName = utils.Red(computerName).String()
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

func (r HudsonRockResponse) String() string {
	var sb strings.Builder
	for i, stealer := range r.Stealers {
		sb.WriteString(fmt.Sprintf("[-] Stealer #%d\n", i+1))
		sb.WriteString(fmt.Sprintf(":: Family: %s\n", stealer.StealerFamily))
		sb.WriteString(fmt.Sprintf(":: Date: %s\n", formatStealerDate(stealer.DateCompromised)))
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
