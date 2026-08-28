package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gosleek/gosleek/internal/display"
	"github.com/gosleek/gosleek/internal/output"
	"github.com/gosleek/gosleek/internal/template"
	"github.com/gosleek/gosleek/pkg/constants"
	"github.com/pterm/pterm"
)

func runValidate(args []string) {
	output.PrintBannerRaw(constants.Version)

	fs := flag.NewFlagSet("validate", flag.ExitOnError)

	// Handle -h/--help
	var showHelp bool
	fs.BoolFunc("h", "显示帮助信息", func(_ string) error {
		showHelp = true
		return nil
	})
	fs.BoolFunc("help", "显示帮助信息", func(_ string) error {
		showHelp = true
		return nil
	})

	fs.Parse(args)

	if showHelp {
		showValidateHelp()
		return
	}

	paths := fs.Args()
	if len(paths) == 0 {
		showValidateHelp()
		return
	}

	// Resolve paths: expand directories into file lists
	var targets []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			targets = append(targets, p)
			continue
		}
		if info.IsDir() {
			files, err := listYAMLFiles(p)
			if err != nil {
				pterm.Printf("  [WARN] %s: %v\n", p, err)
			} else {
				targets = append(targets, files...)
			}
		} else {
			targets = append(targets, p)
		}
	}

	if len(targets) == 0 {
		pterm.Println()
		pterm.Println(pterm.Yellow("  No YAML templates found in the specified paths"))
		pterm.Println()
		return
	}

	valid := 0
	invalid := 0

	type result struct {
		path   string
		id     string
		name   string
		status string
	}
	var results []result

	for _, path := range targets {
		if tmpl, err := template.LoadFile(path); err == nil {
			name := tmpl.Name
			if name == "" {
				name = "—"
			}
			results = append(results, result{
				path:   path,
				id:     tmpl.ID,
				name:   name,
				status: "[OK] Valid",
			})
			valid++
		} else {
			results = append(results, result{
				path:   path,
				id:     "",
				name:   "—",
				status: "[FAIL] " + err.Error(),
			})
			invalid++
		}
	}

	colWidths := []int{40, 32, 40, 0}
	rowsFn := func() [][]string {
		var rows [][]string
		for _, r := range results {
			rows = append(rows, []string{
				display.Truncate(r.path, 40),
				r.id,
				display.Truncate(r.name, 40),
				r.status,
			})
		}
		return rows
	}
	headers := []string{"Path", "ID", "Name", "Status"}
	var countStr string
	if invalid == 0 {
		countStr = fmt.Sprintf("All passed: %d templates valid", valid)
	} else {
		countStr = fmt.Sprintf("Done: %d valid, %d invalid", valid, invalid)
	}
	PrintTable("Template Validation", headers, colWidths, rowsFn, countStr)
}

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

func showValidateHelp() {
	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  Usage: gosleek validate [options] <template_file>..."))
	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  Arguments:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	pterm.Println("    <template_file>   YAML template file or directory to validate")
	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  Options:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	pterm.Println("    -h, --help        Show this help message")
	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  Examples:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	pterm.Println("    gosleek validate templates/spring-boot.yaml")
	pterm.Println("    gosleek validate templates/")
	pterm.Println("    gosleek validate a.yaml b.yaml c.yaml")
	pterm.Println()
}
