package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pterm/pterm"
)

// ──────────────────────────────────────────────────────────────────────────
// Display-width-aware helpers (mirrors internal/output/console.go logic)
// ──────────────────────────────────────────────────────────────────────────

// displayWidth returns the visual column width of s in a terminal,
// accounting for ANSI escape sequences and CJK double-width runes.
func displayWidth(s string) int {
	var n int
	inEsc := false
	for _, r := range s {
		if r == 0x1b {
			inEsc = true
			continue
		}
		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		n += runeDisplayWidth(r)
	}
	return n
}

func runeDisplayWidth(r rune) int {
	if r == 0 || r < 0x20 {
		return 0
	}
	switch {
	case r >= 0x1100 && r <= 0x115F:
		return 2
	case r >= 0x2E80 && r <= 0x303E:
		return 2
	case r >= 0x3040 && r <= 0x33BF:
		return 2
	case r >= 0x3300 && r <= 0x33FF:
		return 2
	case r >= 0x3400 && r <= 0x9FFF:
		return 2
	case r >= 0xAC00 && r <= 0xD7AF:
		return 2
	case r >= 0xF900 && r <= 0xFAFF:
		return 2
	case r >= 0xFE10 && r <= 0xFE6F:
		return 2
	case r >= 0xFF01 && r <= 0xFF60:
		return 2
	case r >= 0xFFE0 && r <= 0xFFE6:
		return 2
	}
	return 1
}

// stripAnsi strips ANSI escape sequences from s.
func stripAnsi(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inEsc := false
	for _, r := range s {
		if r == 0x1b {
			inEsc = true
			continue
		}
		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// padRight pads s with spaces to target display width n.
func padRight(s string, n int) string {
	w := displayWidth(s)
	if w >= n {
		return s
	}
	return s + strings.Repeat(" ", n-w)
}

// truncate shortens s to max display width, appending "…" if truncated.
func truncate(s string, max int) string {
	if displayWidth(s) <= max {
		return s
	}
	runes := []rune(s)
	w := 0
	for i, r := range runes {
		rw := runeDisplayWidth(r)
		if w+rw > max-1 {
			return string(runes[:i]) + "…"
		}
		w += rw
	}
	return string(runes) + "…"
}

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
		maxWidths[i] = displayWidth(h)
	}

	// Collect all row data to compute widths
	allRows := rows()
	for _, row := range allRows {
		for i, v := range row {
			vw := displayWidth(v)
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
		vw := displayWidth(v)
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
