package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bytedance/sonic"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/inancgumus/screen"
	"github.com/manifoldco/promptui"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/ll/lx"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
)

// GoSearch ASCII logo displayed at program start.
const ASCII = `
________  ________  ________  _______   ________  ________  ________  ___  ___
|\   ____\|\   __  \|\   ____\|\  ___ \ |\   __  \|\   __  \|\   ____\|\  \|\  \
\ \  \___|\ \  \|\  \ \  \___|\ \   __/|\ \  \|\  \ \  \|\  \ \  \___|\ \  \\\  \
\ \  \  __\ \  \\\  \ \_____  \ \  \_|/_\ \   __  \ \   _  _\ \  \    \ \   __  \
\ \  \|\  \ \  \\\  \|____|\  \ \  \_|\ \ \  \ \  \ \  \\  \\ \  \____\ \  \ \  \
\ \_______\ \_______\____\_\  \ \_______\ \__\ \__\ \__\\ _\\ \_______\ \__\ \__\
\|_______|\|_______|\_________\|_______|\|__|\|__|\|__|\|__|\|_______|\|__|\|__|
\|_________|

`

const (
	// GoSearch version number.
	VERSION = "v2.0.0"

	// User-Agent header used in HTTP requests to mimic a browser.
	DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0"
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

	// count tracks the number of found profiles using atomic operations for thread safety.
	count atomic.Uint32

	// CurrentTheme holds the active color theme for terminal output.
	CurrentTheme = DarkTheme

	// mu synchronizes file writes
	mu sync.Mutex

	// logger is the centralized logger
	logger *ll.Logger

	// serviceOrder defines the fixed order for service execution
	serviceOrder = []string{
		"websites",
		"hudsonrock",
		"breachdirectory",
		"proxynova",
		"domains",
	}
)

// init sets the initial theme based on terminal background detection.
func init() {
	// Override theme based on auto-detection
	CurrentTheme = detectTheme()
}

// main is the entry point of the program, handling command-line arguments and orchestrating searches.
func main() {
	// Define flags
	modeFlag := flag.String("mode", "cmd", "Run mode: cmd, web, or interactive")
	usernameFlag := flag.String("u", "", "Username to search")
	usernameFlagLong := flag.String("username", "", "Username to search")
	servicesFlag := flag.String("services", "", "Comma-separated services to run (e.g., hudsonrock,proxynova)")
	noFalsePositivesFlag := flag.Bool("no-false-positives", false, "Do not show false positives")
	breachDirectoryAPIKey := flag.String("b", "", "Search Breach Directory with an API Key")
	breachDirectoryAPIKeyLong := flag.String("breach-directory", "", "Search Breach Directory with an API Key")
	portFlag := flag.String("port", "8080", "Port for web mode")
	jsonOutput := flag.Bool("json", false, "Output results as JSON (cmd mode only)")
	debugFlag := flag.Bool("debug", false, "Enable debug logging")

	flag.Parse()

	// Initialize logger
	logger = ll.New("")
	if *debugFlag {
		logger.Level(lx.LevelDebug)
	} else {
		logger.Level(lx.LevelInfo)
	}

	// Determine API key
	apiKey := *breachDirectoryAPIKey
	if apiKey == "" {
		apiKey = *breachDirectoryAPIKeyLong
	}

	// Get runners
	runners, err := getRunners(*servicesFlag, apiKey, *noFalsePositivesFlag)
	if err != nil {
		fmt.Printf("Error selecting services: %v\n", err)
		fmt.Println("Available services:", strings.Join(AvailableServices(), ", "))
		os.Exit(1)
	}
	if len(runners) == 0 {
		fmt.Println("No services selected")
		os.Exit(1)
	}

	// Handle modes
	switch *modeFlag {
	case "web":
		r := WebServer(runners)
		fmt.Printf("Starting web server on :%s\n", *portFlag)
		if err := http.ListenAndServe(":"+*portFlag, r); err != nil {
			logger.Errorf("Web server failed: %v", err)
			fmt.Printf("Web server failed: %v\n", err)
			os.Exit(1)
		}

	case "cmd":
		var username string
		if *usernameFlag != "" {
			username = *usernameFlag
		} else if *usernameFlagLong != "" {
			username = *usernameFlagLong
		} else if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
			username = os.Args[1]
		} else {
			fmt.Println("Usage: gosearch [username] [-u <username>] [-no-false-positives] [-b <apikey>] [--breach-directory <apikey>]")
			fmt.Println("For web mode, use: gosearch -mode web [-port <port>]")
			fmt.Println("For interactive mode, use: gosearch -mode interactive")
			fmt.Println("Available services:", strings.Join(AvailableServices(), ", "))
			os.Exit(1)
		}

		DeleteOldFile(username)
		data, err := UnmarshalJSON()
		if err != nil {
			logger.Errorf("Error unmarshalling json: %v", err)
			fmt.Printf("Error unmarshalling json: %v\n", err)
			os.Exit(1)
		}

		screen.Clear()
		fmt.Print(strings.TrimSpace(ASCII))
		fmt.Println(VERSION)
		fmt.Println(strings.Repeat("⎯", 85))
		fmt.Println(":: Username                              : ", username)
		fmt.Println(":: Websites                              : ", len(data.Websites))
		if *servicesFlag != "" {
			fmt.Println(":: Services                              : ", *servicesFlag)
		}
		if *noFalsePositivesFlag {
			fmt.Println(":: No False Positives                    : ", *noFalsePositivesFlag)
		}
		fmt.Println(strings.Repeat("⎯", 85))
		fmt.Println()
		if !*noFalsePositivesFlag {
			fmt.Println("[!] A yellow link indicates that I was unable to verify whether the username exists on the platform.")
		}

		start := time.Now()
		resultsChan := runSearches(username, runners)

		if *jsonOutput {
			results := make([]Response, 0, len(runners))
			for res := range resultsChan {
				results = append(results, res)
			}
			enc := sonic.ConfigDefault.NewEncoder(os.Stdout)
			if err := enc.Encode(results); err != nil {
				logger.Errorf("Failed to encode JSON: %v", err)
				fmt.Fprintf(os.Stderr, "Failed to encode JSON: %v\n", err)
				os.Exit(1)
			}
			return
		}

		for res := range resultsChan {
			fmt.Println()
			if res.Error != "" {
				Redf("[%s] Error: %s", res.Service, res.Error).Println()
				if err := WriteToFile(username, fmt.Sprintf("[%s] Error: %s\n", res.Service, res.Error)); err != nil {
					logger.Errorf("Failed to write error to file: %v", err)
				}
				continue
			}
			if res.Found {
				Greenf("[%s] Found results", res.Service).Println()
				if res.Data != nil {
					table := tablewriter.NewTable(os.Stdout, tablewriter.WithHeaderConfig(tw.CellConfig{
						Formatting: tw.CellFormatting{AutoFormat: tw.Off},
					}),
						tablewriter.WithColumnMax(80),
					)
					res.Data.RenderTable(table)
					if err := table.Render(); err != nil {
						logger.Errorf("Table render failed: %v", err)
					}
					if err := WriteToFile(username, res.Data.String()); err != nil {
						logger.Errorf("Failed to write results to file: %v", err)
					}
				}
			} else {
				Greenf("[%s] No results found", res.Service).Println()
				if err := WriteToFile(username, fmt.Sprintf("[%s] No results found\n", res.Service)); err != nil {
					logger.Errorf("Failed to write no-results to file: %v", err)
				}
			}
			if err := WriteToFile(username, strings.Repeat("⎯", 85)+"\n"); err != nil {
				logger.Errorf("Failed to write separator to file: %v", err)
			}
		}

		fmt.Println()
		elapsed := time.Since(start)
		table := tablewriter.NewTable(os.Stdout, tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{Borders: tw.BorderNone})))
		table.Append(Bold("Number of profiles found"), Red(count.Load()))
		table.Append(Bold("Total time taken"), Green(elapsed))
		if err := table.Render(); err != nil {
			logger.Errorf("Table render failed: %v", err)
		}

		if err := WriteToFile(username, ":: Number of profiles found              : "+strconv.Itoa(int(count.Load()))+"\n"); err != nil {
			logger.Errorf("Failed to write profile count to file: %v", err)
		}
		if err := WriteToFile(username, ":: Total time taken                      : "+elapsed.String()+"\n"); err != nil {
			logger.Errorf("Failed to write elapsed time to file: %v", err)
		}

	case "interactive":
		runInteractiveMode(runners)

	default:
		fmt.Printf("Unknown mode: %s\n", *modeFlag)
		os.Exit(1)
	}
}

// AvailableServices returns the list of supported service names
func AvailableServices() []string {
	services := make([]string, 0, len(RunnerRegistry))
	for name := range RunnerRegistry {
		services = append(services, name)
	}
	sort.Strings(services)
	return services
}

// getRunners selects runners based on user input, preserving default behavior
func getRunners(servicesFlag string, apiKey string, noFalsePositives bool) ([]Runner, error) {
	runnerMap := map[string]Runner{
		"hudsonrock":      HudsonRockRunner{},
		"proxynova":       ProxyNovaRunner{},
		"breachdirectory": BreachDirectoryRunner{APIKey: apiKey},
		"domains":         DomainsRunner{},
		"websites":        WebsitesRunner{NoFalsePositives: noFalsePositives},
	}

	// Validate API key for breachdirectory
	if strings.Contains(strings.ToLower(servicesFlag), "breachdirectory") || (servicesFlag == "" && apiKey != "") {
		if apiKey == "" || len(apiKey) < 8 { // Basic length check; adjust based on actual API key format
			logger.Warnf("Invalid or missing BreachDirectory API key; skipping service")
			if servicesFlag != "" {
				servicesFlag = strings.ReplaceAll(servicesFlag, "breachdirectory", "")
				servicesFlag = strings.ReplaceAll(servicesFlag, ",,", ",")
				servicesFlag = strings.Trim(servicesFlag, ",")
			}
		}
	}

	selectedServices := serviceOrder
	if servicesFlag != "" {
		requested := strings.Split(strings.ToLower(servicesFlag), ",")
		seen := make(map[string]bool)
		selectedServices = nil
		for _, s := range requested {
			s = strings.TrimSpace(s)
			if s == "" || seen[s] {
				continue
			}
			if _, ok := runnerMap[s]; !ok {
				return nil, fmt.Errorf("unknown service: %s", s)
			}
			if s == "breachdirectory" && apiKey == "" {
				logger.Warnf("BreachDirectory skipped due to missing API key")
				continue
			}
			seen[s] = true
			// Add service in original order
			for _, ordered := range serviceOrder {
				if ordered == s && !contains(selectedServices, s) {
					selectedServices = append(selectedServices, s)
				}
			}
		}
		if len(selectedServices) == 0 {
			return nil, fmt.Errorf("no valid services selected")
		}
	} else if apiKey == "" {
		// Exclude breachdirectory if no API key
		selectedServices = []string{"websites", "hudsonrock", "proxynova", "domains"}
	}

	runners := make([]Runner, 0, len(selectedServices))
	for _, s := range selectedServices {
		runner := runnerMap[s]
		runners = append(runners, runner)
	}
	return runners, nil
}

// validateUsername checks if a username is valid for web requests
func validateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if len(username) > 50 {
		return fmt.Errorf("username too long (max 50 characters)")
	}
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("username contains invalid characters (only alphanumeric and underscores allowed)")
	}
	return nil
}

// WebServer sets up the Chi router with middleware
func WebServer(runners []Runner) *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(httprate.LimitByIP(10, time.Second)) // 10 requests per second per IP
	r.Get("/search/{username}", func(w http.ResponseWriter, r *http.Request) {
		username := chi.URLParam(r, "username")
		logger.Debugf("Received web request for username: %s", username)
		if err := validateUsername(username); err != nil {
			logger.Errorf("Invalid username: %s (%v)", username, err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resultsChan := runSearches(username, runners)
		results := make([]Response, 0, len(runners))
		for res := range resultsChan {
			results = append(results, res)
		}
		w.Header().Set("Content-Type", "application/json")
		enc := sonic.ConfigDefault.NewEncoder(w)
		if err := enc.Encode(results); err != nil {
			logger.Errorf("Failed to encode JSON response: %v", err)
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	})
	return r
}

// UnmarshalJSON fetches and parses the website configuration from a remote JSON file.
func UnmarshalJSON() (Data, error) {
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

// WriteToFile appends content to a file named after the username.
func WriteToFile(username string, content string) error {
	mu.Lock()
	defer mu.Unlock()
	filename := fmt.Sprintf("%s.txt", username)
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, os.ModePerm)
	if err != nil {
		logger.Errorf("Error opening file %s: %v", filename, err)
		return fmt.Errorf("error opening file %s: %w", filename, err)
	}
	defer f.Close()
	if _, err = f.WriteString(content); err != nil {
		logger.Errorf("Error writing to file %s: %v", filename, err)
		return fmt.Errorf("error writing to file %s: %w", filename, err)
	}
	logger.Debugf("Wrote to file %s: %s", filename, content)
	return nil
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
func CrackHash(hash string) string {
	client := &http.Client{}
	url := fmt.Sprintf("https://weakpass.com/api/v1/search/%s.json", hash)
	logger.Debugf("Sending GET request to Weakpass API: %s", url)
	start := time.Now()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		logger.Errorf("Error creating Weakpass request: %v", err)
		return ""
	}
	req.Header.Set("User-Agent", DefaultUserAgent)
	req.Header.Set("accept:", "application/json")
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
	var weakpass WeakpassResponse
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

// DeleteOldFile removes any existing output file for the username.
func DeleteOldFile(username string) {
	filename := fmt.Sprintf("%s.txt", username)
	err := os.Remove(filename)
	if err != nil && !os.IsNotExist(err) {
		logger.Errorf("Error deleting file %s: %v", filename, err)
	}
	logger.Debugf("Deleted old file %s if it existed", filename)
}

// runSearches executes all runners concurrently, streaming results through a channel
func runSearches(username string, runners []Runner) chan Response {
	resultsChan := make(chan Response, len(runners))
	var wg sync.WaitGroup
	for _, runner := range runners {
		wg.Add(1)
		go func(runner Runner) {
			defer wg.Done()
			result := runner.Run(username)
			resultsChan <- result
		}(runner)
	}
	go func() {
		wg.Wait()
		close(resultsChan)
	}()
	return resultsChan
}

// runInteractiveMode provides an interactive prompt for searching
func runInteractiveMode(runners []Runner) {
	for {
		prompt := promptui.Prompt{
			Label: "Enter username (or 'quit' to exit)",
			Validate: func(input string) error {
				input = strings.TrimSpace(input)
				if input == "" {
					return fmt.Errorf("username cannot be empty")
				}
				return nil
			},
		}
		username, err := prompt.Run()
		if err != nil || username == "quit" {
			fmt.Println("Exiting interactive mode")
			return
		}
		username = strings.TrimSpace(username)
		logger.Debugf("Interactive mode: selected username %s", username)

		services := AvailableServices()
		selectPrompt := promptui.Select{
			Label: "Select services (use arrow keys, press Enter to finish)",
			Items: append(services, "All"),
			Size:  10,
		}
		selectedServices := []string{}
		for {
			idx, result, err := selectPrompt.Run()
			if err != nil {
				break
			}
			if result == "All" {
				selectedServices = services
				break
			}
			selectedServices = append(selectedServices, services[idx])
			services = append(services[:idx], services[idx+1:]...)
			selectPrompt.Items = append(services, "All")
		}
		if len(selectedServices) == 0 {
			fmt.Println("No services selected, try again")
			continue
		}
		logger.Debugf("Interactive mode: selected services %v", selectedServices)

		selectedRunners := make([]Runner, 0, len(selectedServices))
		for _, s := range selectedServices {
			if runner, ok := RunnerRegistry[s]; ok {
				selectedRunners = append(selectedRunners, runner)
			}
		}
		if len(selectedRunners) == 0 {
			fmt.Println("No valid services selected")
			continue
		}

		fmt.Println("\nSearching for", username, "on", strings.Join(selectedServices, ", "), "...")
		start := time.Now()
		resultsChan := runSearches(username, selectedRunners)

		for res := range resultsChan {
			fmt.Println()
			if res.Error != "" {
				Redf("[%s] Error: %s", res.Service, res.Error).Println()
				continue
			}
			if res.Found {
				Greenf("[%s] Found results", res.Service).Println()
				if res.Data != nil {
					table := tablewriter.NewTable(os.Stdout, tablewriter.WithHeaderConfig(tw.CellConfig{
						Formatting: tw.CellFormatting{AutoFormat: tw.Off},
					}))
					res.Data.RenderTable(table)
					if err := table.Render(); err != nil {
						logger.Errorf("Table render failed: %v", err)
					}
				}
			} else {
				Greenf("[%s] No results found", res.Service).Println()
			}
		}

		elapsed := time.Since(start)
		fmt.Println()
		table := tablewriter.NewTable(os.Stdout, tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{Borders: tw.BorderNone})))
		table.Append(Bold("Number of profiles found"), Red(count.Load()))
		table.Append(Bold("Total time taken"), Green(elapsed))
		if err := table.Render(); err != nil {
			logger.Errorf("Table render failed: %v", err)
		}
	}
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// formatStealerDate formats a date string from HudsonRock API into a human-readable format.
func formatStealerDate(dateStr string) string {
	t, err := time.Parse(time.RFC3339, dateStr)
	if err != nil {
		logger.Errorf("Error parsing date %s: %v", dateStr, err)
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
