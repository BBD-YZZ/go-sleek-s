package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gosleek/gosleek/internal/display"
	"github.com/pterm/pterm"
)

// ──────────────────────────────────────────────────────────────────────────
// Shared table renderer — CJK + ANSI aware column alignment
// ──────────────────────────────────────────────────────────────────────────

// TableColumn defines a single column in a styled table.
type TableColumn struct {
	Header string
	Getter func() string
	// Width hint (display cols); if 0, auto-expand to longest value
	Width int
	// If true, value width is measured after stripping ANSI (colored text)
	StripAnsi bool
}

// PrintTable renders a header + rows with uniform column widths.
// Each rowFunc supplies column values for one row.
// colWidths is optional; if nil, columns auto-size.
func PrintTable(title string, headers []string, colWidths []int, rows func() [][]string, countLabel string) {
	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  " + title))
	pterm.Println(pterm.Gray(strings.Repeat("─", 75)))

	// Compute column widths from headers and all rows
	maxWidths := make([]int, len(headers))
	for i, h := range headers {
		maxWidths[i] = display.DisplayWidth(h)
	}

	// Collect all row data to compute widths
	allRows := rows()
	for _, row := range allRows {
		for i, v := range row {
			vw := display.DisplayWidth(v)
			if i < len(maxWidths) && vw > maxWidths[i] {
				maxWidths[i] = vw
			}
		}
	}

	// Apply user-specified widths where they exceed auto-computed
	for i, w := range colWidths {
		if w > 0 && w > maxWidths[i] {
			maxWidths[i] = w
		}
	}

	// Render header
	printTableRow(headers, maxWidths)

	// Render rows
	for _, row := range allRows {
		printTableRow(row, maxWidths)
	}

	pterm.Println(pterm.Gray(strings.Repeat("─", 75)))
	if countLabel != "" {
		pterm.Println(pterm.Gray("  " + countLabel))
	}
	pterm.Println()
}

// printTableRow prints a single row with padded columns.
func printTableRow(row []string, widths []int) {
	var sb strings.Builder
	for i, v := range row {
		if i > 0 {
			sb.WriteString("  ")
		}
		vw := display.DisplayWidth(v)
		if i < len(widths) && vw < widths[i] {
			// pad to the right based on display width
			sb.WriteString(v)
			sb.WriteString(strings.Repeat(" ", widths[i]-vw))
		} else {
			sb.WriteString(v)
		}
	}
	pterm.Println(sb.String())
}

// ──────────────────────────────────────────────────────────────────────────
// Core utilities
// ──────────────────────────────────────────────────────────────────────────

func findConfig() string {
	paths := []string{
		"configs/config.yaml",
		"./config.yaml",
		filepath.Join(os.Getenv("HOME"), ".gosleek", "config.yaml"),
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func readTargetsFile(path string) ([]string, error) {
	var targets []string
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	return targets, scanner.Err()
}

func readTargetsStdin() ([]string, error) {
	var targets []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	return targets, scanner.Err()
}

func parseHeaders(headers []string) map[string]string {
	result := make(map[string]string)
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return result
}

func setupOutputDir(dir string) string {
	if dir == "" {
		dir = "results"
	}
	timestamp := time.Now().Format("20060102-150405")
	return filepath.Join(dir, "gosleek_"+timestamp)
}
