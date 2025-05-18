package utils

import (
	"fmt"
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

var CurrentTheme = Theme{}

// init sets the initial theme based on terminal background detection.
func init() {
	// Override theme based on auto-detection
	CurrentTheme = detectTheme()
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

func Bold(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Bold)
}

// Boldf formats text in bold.
func Boldf(format string, args ...interface{}) Color {
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
