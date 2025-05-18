package main

import (
	"fmt"
	"github.com/olekukonko/tablewriter"
	"io"
	"os"
	"strings"
)

// Theme defines color codes for terminal output styling.
type Theme struct {
	Reset     string // Reset formatting
	Bold      string // Bold text
	Underline string // Underlined text
	Red       string // Red text
	Green     string // Green text
	Yellow    string // Yellow text
	Blue      string // Blue text
	Magenta   string // Magenta text
	Cyan      string // Cyan text
	White     string // White text
	Gray      string // Gray text
}

// LightTheme defines colors optimized for light terminal backgrounds.
var LightTheme = Theme{
	Reset:     "\033[0m",
	Bold:      "\033[1m",
	Underline: "\033[4m",
	Red:       "\033[31m", // Bright red for light background
	Green:     "\033[32m", // Forest green
	Yellow:    "\033[33m", // Dark yellow
	Blue:      "\033[34m", // Navy blue
	Magenta:   "\033[35m", // Dark magenta
	Cyan:      "\033[36m", // Dark cyan
	White:     "\033[37m", // Black for light background
	Gray:      "\033[90m", // Dark gray
}

// DarkTheme defines colors optimized for dark terminal backgrounds.
var DarkTheme = Theme{
	Reset:     "\033[0m",
	Bold:      "\033[1m",
	Underline: "\033[4m",
	Red:       "\033[91m", // Light red for dark background
	Green:     "\033[92m", // Light green
	Yellow:    "\033[93m", // Bright yellow
	Blue:      "\033[94m", // Light blue
	Magenta:   "\033[95m", // Light magenta
	Cyan:      "\033[96m", // Light cyan
	White:     "\033[97m", // White for dark background
	Gray:      "\033[37m", // Light gray
}

// init sets the initial theme based on terminal background detection.
func init() {
	// Override theme based on auto-detection
	CurrentTheme = detectTheme()
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

// Data holds the list of websites to search.
type Data struct {
	Websites []Website `json:"websites"` // List of website configurations
}

// Cookie represents an HTTP cookie.
type Cookie struct {
	Name  string `json:"name"`  // Cookie name
	Value string `json:"value"` // Cookie value
}

// Stealer represents data from an info-stealer compromise.
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

// HudsonRockResponse represents the response from HudsonRock's API.
type HudsonRockResponse struct {
	Message  string    `json:"message"`  // Response message
	Stealers []Stealer `json:"stealers"` // List of stealer data
}

// WeakpassResponse represents the response from Weakpass API for hash cracking.
type WeakpassResponse struct {
	Type string `json:"type"` // Hash type
	Hash string `json:"hash"` // Hash value
	Pass string `json:"pass"` // Cracked password
}

// ProxyNova represents the response from ProxyNova API for compromised passwords.
type ProxyNova struct {
	Count int      `json:"count"` // Number of compromised credentials
	Lines []string `json:"lines"` // List of credential pairs
}

// ResultData defines the interface for service-specific results
type ResultData interface {
	RenderTable(out *tablewriter.Table)
	String() string
}

// Response represents the standardized output from a Runner
type Response struct {
	Service string     `json:"service"`
	Found   bool       `json:"found"`
	Data    ResultData `json:"data,omitempty"`
	Error   string     `json:"error,omitempty"`
}

// Runner defines the interface for search services
type Runner interface {
	Run(username string) Response
}

// RunnerRegistry maps service names to their Runner implementations
var RunnerRegistry = map[string]Runner{
	"hudsonrock":      HudsonRockRunner{},
	"proxynova":       ProxyNovaRunner{},
	"breachdirectory": BreachDirectoryRunner{},
	"domains":         DomainsRunner{},
	"websites":        WebsitesRunner{},
}

// HudsonRockResult represents HudsonRock search results
type HudsonRockResult struct {
	Stealers []Stealer
}

// Color represents a colored string for terminal output.
type Color string

// String returns the colored string.
func (c Color) String() string {
	return string(c)
}

// Print prints the colored text without a newline.
func (c Color) Print() {
	fmt.Print(c)
}

// Println prints the colored text with a newline.
func (c Color) Println() {
	fmt.Println(c)
}

// Fprint writes the colored text to an io.Writer.
func (c Color) Fprint(w io.Writer) {
	fmt.Fprint(w, c)
}

// Fprintln writes the colored text to an io.Writer with a newline.
func (c Color) Fprintln(w io.Writer) {
	fmt.Fprintln(w, c)
}

// Text creates a colored string using the specified color code.
func Text(s string, colorCode string) Color {
	return Color(colorCode + s + CurrentTheme.Reset)
}

// Red formats text in red.
func Red(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Red)
}

// Green formats text in green.
func Green(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Green)
}

// Yellow formats text in yellow.
func Yellow(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Yellow)
}

// Blue formats text in blue.
func Blue(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Blue)
}

// Cyan formats text in cyan.
func Cyan(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Cyan)
}

// Magenta formats text in magenta.
func Magenta(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Magenta)
}

// White formats text in white.
func White(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.White)
}

// Gray formats text in gray.
func Gray(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Gray)
}

// Redf formats text in red with a format string.
func Redf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Red)
}

// Greenf formats text in green with a format string.
func Greenf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Green)
}

// Yellowf formats text in yellow with a format string.
func Yellowf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Yellow)
}

// Bluef formats text in blue with a format string.
func Bluef(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Blue)
}

// Cyanf formats text in cyan with a format string.
func Cyanf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Cyan)
}

// Magentaf formats text in magenta with a format string.
func Magentaf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Magenta)
}

// Whitef formats text in white with a format string.
func Whitef(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.White)
}

// Grayf formats text in gray with a format string.
func Grayf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Gray)
}

// Bold formats text in bold.
func Bold(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Bold)
}

// detectTheme determines the terminal color theme based on the COLORFGBG environment variable.
func detectTheme() Theme {
	colorfgbg := os.Getenv("COLORFGBG")
	if strings.Contains(colorfgbg, ";0") {
		return DarkTheme // Dark background
	} else if strings.Contains(colorfgbg, ";15") {
		return LightTheme // Light background
	}
	return DarkTheme // Default
}
