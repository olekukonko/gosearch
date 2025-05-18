package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"github.com/ibnaleem/gosearch/runners"
	"github.com/ibnaleem/gosearch/utils"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bytedance/sonic"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/manifoldco/promptui"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/ll/lx"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
	"github.com/vbauerster/mpb/v8"
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
)

var (
	// logger is the centralized logger
	logger *ll.Logger
)

var (
	modeFlag                  = flag.String("mode", "cmd", "Run mode: cmd, web, or interactive")
	usernameFlag              = flag.String("u", "", "Username to search")
	usernameFlagLong          = flag.String("username", "", "Username to search")
	servicesFlag              = flag.String("services", "all", "Comma-separated services to run (e.g., hudsonrock,proxynova)")
	noFalsePositivesFlag      = flag.Bool("no-false-positives", false, "Do not show false positives")
	breachDirectoryAPIKey     = flag.String("b", "", "Search Breach Directory with an API Key")
	breachDirectoryAPIKeyLong = flag.String("breach-directory", "", "Search Breach Directory with an API Key")
	portFlag                  = flag.String("port", "8080", "Port for web mode")
	jsonOutput                = flag.Bool("json", false, "Output results as JSON (cmd mode only)")
	outputMode                = flag.String("output", "dump", "Output mode: dump, typewriter (cmd mode only)")
	debugFlag                 = flag.Bool("debug", false, "Enable debug logging")
)

// main is the entry point of the program, handling command-line arguments and orchestrating searches.
func main() {
	// Define flags

	flag.Parse()

	// Initialize logger
	logger = ll.New("").Enable()
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
	var rr []runners.Runner

	// Get runners
	if *servicesFlag == "all" {
		rr = runners.List()
	} else {
		values := strings.Split(*servicesFlag, ",")
		for _, s := range values {
			res, ok := runners.Find(s)
			ll.Dbg(s)
			if ok {
				rr = append(rr, res)
				continue
			}

			ll.Errorf("Unknown service: %s", s)
			fmt.Println("Available services:", strings.Join(runners.Names(), ", "))
			os.Exit(1)
		}
	}

	if len(rr) == 0 {
		fmt.Println("No services selected")
		os.Exit(1)
	}

	// Handle modes
	switch *modeFlag {
	case "web":
		r := WebServer(rr)
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
			fmt.Println("Available services:", strings.Join(runners.Names(), ", "))
			os.Exit(1)
		}

		DeleteOldFile(username)
		fmt.Print(strings.TrimSpace(ASCII))
		fmt.Println(VERSION)
		fmt.Println(strings.Repeat("⎯", 85))
		fmt.Println(":: Username                              : ", username)
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
			fmt.Println()
		}

		start := time.Now()
		results := runSearches(username, rr)

		if *jsonOutput {
			enc := sonic.ConfigDefault.NewEncoder(os.Stdout)
			if err := enc.Encode(results); err != nil {
				logger.Errorf("Failed to encode JSON: %v", err)
				fmt.Fprintf(os.Stderr, "Failed to encode JSON: %v\n", err)
				os.Exit(1)
			}
			return
		}

		for _, res := range results {

			fmt.Println()
			if res.Error != nil {
				logger.Errorf("[%s] Error: %s", res.Service, res.Error)

				if err := WriteToFile(username, fmt.Sprintf("[%s] Error: %s\n", res.Service, res.Error)); err != nil {
					logger.Errorf("Failed to write error to file: %v", err)
				}
				continue
			}

			if res.Found {
				logger.Println(utils.Greenf("[%s] Found results", res.Service))
				if res.Data != nil {

					// render
					render(os.Stdout, res)

					// Write string representation to file
					if err := WriteToFile(username, res.Data.String()); err != nil {
						logger.Errorf("Failed to write results to file: %v", err)
					}
				}
			} else {
				logger.Print(utils.Greenf("[%s] No results found", res.Service))
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

		for name, service := range results {
			table.Append(utils.Boldf("Total %s", name), service.Count)
		}

		table.Append(utils.Bold("Total time taken"), utils.Green(elapsed.String()).String())
		if err := table.Render(); err != nil {
			logger.Errorf("Table render failed: %v", err)
		}

		if err := WriteToFile(username, ":: Total time taken                      : "+elapsed.String()+"\n"); err != nil {
			logger.Errorf("Failed to write elapsed time to file: %v", err)
		}

	case "interactive":
		runInteractiveMode()

	default:
		fmt.Printf("Unknown mode: %s\n", *modeFlag)
		os.Exit(1)
	}
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
func WebServer(rr []runners.Runner) *chi.Mux {
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
		results := runSearches(username, rr)
		// Convert map to slice for JSON output
		resultSlice := make([]runners.Response, 0, len(results))
		for _, service := range results {
			resultSlice = append(resultSlice, service)
		}
		w.Header().Set("Content-Type", "application/json")
		enc := sonic.ConfigDefault.NewEncoder(w)
		if err := enc.Encode(resultSlice); err != nil {
			logger.Errorf("Failed to encode JSON response: %v", err)
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	})
	return r
}

// WriteToFile appends content to a file named after the username.
func WriteToFile(username string, content string) error {
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

// DeleteOldFile removes any existing output file for the username.
func DeleteOldFile(username string) {
	filename := fmt.Sprintf("%s.txt", username)
	err := os.Remove(filename)
	if err != nil && !os.IsNotExist(err) {
		logger.Errorf("Error deleting file %s: %v", filename, err)
	}
	logger.Debugf("Deleted old file %s if it existed", filename)
}

// runSearches executes all runners concurrently, streaming results into a map
func runSearches(username string, rr []runners.Runner) map[string]runners.Response {
	progress := mpb.New(mpb.WithWidth(60), mpb.WithRefreshRate(100*time.Millisecond))
	results := make(map[string]runners.Response)
	var wg sync.WaitGroup
	resultsChan := make(chan runners.Response, len(rr))

	for _, runner := range rr {
		wg.Add(1)
		go func(runner runners.Runner) {
			defer wg.Done()
			runner.Prepare(runners.Context{
				Logger:   logger,
				Ctx:      context.Background(),
				Progress: progress,
				Auth:     runners.Auth{Key: []byte(*breachDirectoryAPIKey), Secret: []byte(*breachDirectoryAPIKeyLong)},
			})
			result := runner.Run(username)
			resultsChan <- result
		}(runner)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for res := range resultsChan {
		results[res.Service] = res
	}

	progress.Wait() // This call finalizes the progress instance
	return results
}

// runInteractiveMode provides an interactive prompt for searching
func runInteractiveMode() {
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

		services := runners.Names()
		var selectedServices []string
		for len(services) > 0 {
			selectPrompt := promptui.Select{
				Label: "Select a service and press Enter to proceed, or continue selecting (Ctrl+C to cancel)",
				Items: append(services, "List"),
				Size:  10,
			}
			idx, result, err := selectPrompt.Run()
			if err != nil {
				if len(selectedServices) > 0 {
					break // Proceed with selected services
				}
				fmt.Println("No services selected, try again")
				continue
			}
			if result == "List" {
				selectedServices = services
				break
			}
			selectedServices = append(selectedServices, services[idx])
			services = append(services[:idx], services[idx+1:]...)
			if len(selectedServices) > 0 {
				// Allow breaking after selecting one or more services
				fmt.Println("Selected:", strings.Join(selectedServices, ", "))
				fmt.Println("Press Enter to proceed or select another service")
				if _, _, err := selectPrompt.Run(); err != nil {
					break
				}
			}
		}
		if len(selectedServices) == 0 {
			fmt.Println("No services selected, try again")
			continue
		}
		logger.Debugf("Interactive mode: selected services %v", selectedServices)

		selectedRunners := make([]runners.Runner, 0, len(selectedServices))
		for _, s := range selectedServices {
			res, ok := runners.Find(s)
			if ok {
				selectedRunners = append(selectedRunners, res)
			}

		}
		if len(selectedRunners) == 0 {
			fmt.Println("No valid services selected")
			continue
		}

		fmt.Println("\nSearching for", username, "on", strings.Join(selectedServices, ", "), "...")
		start := time.Now()
		results := runSearches(username, selectedRunners)

		for _, service := range selectedServices {
			res, ok := results[service]
			if !ok {
				continue
			}
			fmt.Println()
			if res.Error != nil {
				logger.Print(utils.Redf("[%s] Error: %s", res.Service, res.Error))
				if err := WriteToFile(username, fmt.Sprintf("[%s] Error: %s\n", res.Service, res.Error)); err != nil {
					logger.Errorf("Failed to write error to file: %v", err)
				}
				continue
			}
			if res.Found {

				logger.Println(utils.Greenf("[%s] Found results", res.Service))

				if res.Data != nil {
					render(os.Stdout, res)
					if err := WriteToFile(username, res.Data.String()); err != nil {
						logger.Errorf("Failed to write results to file: %v", err)
					}
				}
			} else {
				logger.Println(utils.Greenf("[%s] No results found", res.Service))

				if err := WriteToFile(username, fmt.Sprintf("[%s] No results found\n", res.Service)); err != nil {
					logger.Errorf("Failed to write no-results to file: %v", err)
				}
			}
			if err := WriteToFile(username, strings.Repeat("⎯", 85)+"\n"); err != nil {
				logger.Errorf("Failed to write separator to file: %v", err)
			}
		}

		elapsed := time.Since(start)
		fmt.Println()
		table := tablewriter.NewTable(os.Stdout, tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{Borders: tw.BorderNone})))
		table.Append(utils.Bold("Total time taken"), utils.Green(elapsed.String()).String())
		if err := table.Render(); err != nil {
			logger.Errorf("Table render failed: %v", err)
		}
	}
}

func render(writer io.Writer, response runners.Response) {
	if *outputMode == "dump" {
		table := tablewriter.NewTable(writer, tablewriter.WithHeaderConfig(tw.CellConfig{
			Formatting: tw.CellFormatting{AutoFormat: tw.Off},
		}))
		response.Data.Table(table)
		table.Render()
		return
	}

	buf := bytes.Buffer{}
	table := tablewriter.NewTable(&buf, tablewriter.WithHeaderConfig(tw.CellConfig{
		Formatting: tw.CellFormatting{AutoFormat: tw.Off},
	}))
	response.Data.Table(table)
	table.Render()

	for _, char := range buf.String() {
		writer.Write([]byte{byte(char)})
		time.Sleep(10 * time.Millisecond)
	}

	fmt.Println()
}
