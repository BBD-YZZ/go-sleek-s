package main

import (
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

// normalizeShortFlags maps short aliases to their long forms.
// Go's flag package doesn't support short aliases, so we pre-process args.
func normalizeShortFlags(args []string) []string {
	result := make([]string, 0, len(args))
	for i, arg := range args {
		// Skip long flags and values
		if strings.HasPrefix(arg, "--") {
			result = append(result, arg)
			continue
		}
		// Handle -X=value format
		if strings.HasPrefix(arg, "-") && !strings.Contains(arg, " ") {
			if eqIdx := strings.Index(arg, "="); eqIdx > 0 {
				key := arg[1:eqIdx]
				value := arg[eqIdx+1:]
				switch key {
				case "p":
					result = append(result, "--proxy="+value)
				case "a":
					result = append(result, "--addr="+value)
				case "c":
					result = append(result, "--concurrency="+value)
				case "r":
					result = append(result, "--rate-limit="+value)
				case "t":
					result = append(result, "--target="+value)
				case "l":
					result = append(result, "--list="+value)
				case "T":
					result = append(result, "--templates="+value)
				case "o":
					result = append(result, "--output="+value)
				case "f":
					result = append(result, "--format="+value)
				case "e":
					result = append(result, "--exclude="+value)
				case "k":
					result = append(result, "--verify-ssl")
				default:
					result = append(result, arg)
				}
				continue
			}
			// Handle -X value format
			switch arg {
			case "-p":
				result = append(result, "--proxy")
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					result = append(result, args[i+1])
				}
			case "-a":
				result = append(result, "--addr")
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					result = append(result, args[i+1])
				}
			case "-c":
				result = append(result, "--concurrency")
				if i+1 < len(args) && isInt(args[i+1]) {
					result = append(result, args[i+1])
				}
			case "-r":
				result = append(result, "--rate-limit")
				if i+1 < len(args) && isInt(args[i+1]) {
					result = append(result, args[i+1])
				}
			case "-t":
				result = append(result, "--target")
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					result = append(result, args[i+1])
				}
			case "-l":
				result = append(result, "--list")
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					result = append(result, args[i+1])
				}
			case "-T":
				result = append(result, "--templates")
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					result = append(result, args[i+1])
				}
			case "-o":
				result = append(result, "--output")
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					result = append(result, args[i+1])
				}
			case "-f":
				result = append(result, "--format")
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					result = append(result, args[i+1])
				}
			case "-e":
				result = append(result, "--exclude")
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					result = append(result, args[i+1])
				}
			case "-k":
				result = append(result, "--verify-ssl")
			case "-H":
				result = append(result, "--header")
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					result = append(result, args[i+1])
				}
			default:
				result = append(result, arg)
			}
		} else {
			result = append(result, arg)
		}
	}
	return result
}

func isInt(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

// listYAMLFiles recursively finds all .yaml/.yml files in a directory.
func listYAMLFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// typLabel returns a color-coded label for template/plugin type.
func typLabel(typ string) string {
	if typ == "Plugin" {
		return pterm.Magenta(typ)
	}
	return pterm.Gray(typ)
}

// severityBadge returns a color-coded severity badge.
func severityBadge(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return pterm.Bold.Sprint(pterm.Red(sev))
	case "high":
		return pterm.Red(sev)
	case "medium":
		return pterm.Yellow(sev)
	case "low":
		return pterm.Cyan(sev)
	case "info":
		return pterm.Gray(sev)
	default:
		return pterm.White(sev)
	}
}
