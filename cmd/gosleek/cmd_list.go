package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/gosleek/gosleek/internal/display"
	"github.com/gosleek/gosleek/internal/output"
	"github.com/gosleek/gosleek/internal/plugin"
	"github.com/gosleek/gosleek/internal/template"
	"github.com/gosleek/gosleek/pkg/constants"
	"github.com/gosleek/gosleek/pkg/types"
	"github.com/pterm/pterm"
)

func runList(args []string) {
	output.PrintBannerRaw(constants.Version)

	fs := flag.NewFlagSet("list", flag.ExitOnError)

	templatesDir := fs.String("T", "templates", "模板目录")
	pluginsOnly := fs.Bool("plugins-only", false, "仅显示 Go 插件")
	tags := fs.String("tags", "", "按标签筛选")
	severity := fs.String("severity", "", "按严重度筛选")
	exclude := fs.String("e", "", "排除指定 ID")
	id := fs.String("id", "", "筛选指定 ID")

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

	if showHelp || len(fs.Args()) > 0 {
		showListHelp()
		return
	}

	var idFilter []string
	if *id != "" {
		idFilter = []string{*id}
	}
	var sevFilter []string
	if *severity != "" {
		sevFilter = []string{*severity}
	}
	var tagFilter []string
	if *tags != "" {
		tagFilter = strings.Split(*tags, ",")
	}
	var excludeFilter []string
	if *exclude != "" {
		excludeFilter = strings.Split(*exclude, ",")
	}

	var templates []*types.Template
	if !*pluginsOnly {
		if loaded, err := template.LoadDir(*templatesDir); err == nil {
			templates = template.ExcludeByID(template.FilterBySeverity(template.FilterByTag(template.FilterByID(loaded, idFilter), tagFilter), sevFilter), excludeFilter)
		}
	}

	var pluginList []plugin.Plugin
	pluginList = plugin.Filter(plugin.All(), plugin.FilterOptions{PluginIDs: idFilter, Tags: tagFilter, Severity: sevFilter, ExcludeIDs: excludeFilter})

	type entry struct {
		typ  string
		id   string
		name string
		sev  string
		author string
		tags string
	}
	var entries []entry
	for _, t := range templates {
		entries = append(entries, entry{
			typ:    "YAML",
			id:     t.ID,
			name:   t.Name,
			sev:    t.Severity,
			author: t.Author,
			tags:   strings.Join(t.Tags, ","),
		})
	}
	for _, p := range pluginList {
		meta := p.Meta()
		entries = append(entries, entry{
			typ:    "Plugin",
			id:     meta.ID,
			name:   meta.Name,
			sev:    meta.Severity,
			author: meta.Author,
			tags:   strings.Join(meta.Tags, ","),
		})
	}

	// Print using CJK/ANSI-aware table
	colWidths := []int{8, 32, 50, 10, 10, 0} // last col auto-expand
	rowsFn := func() [][]string {
		var result [][]string
		for _, e := range entries {
			result = append(result, []string{
				typLabel(e.typ),
				e.id,
				display.Truncate(e.name, 50),
				severityBadge(e.sev),
				display.Truncate(e.author, 10),
				e.tags,
			})
		}
		return result
	}

	headers := []string{"类型", "ID", "名称", "严重度", "作者", "标签"}
	var countStr string
	if *pluginsOnly {
		countStr = fmt.Sprintf("共 %d 个 Go 插件", len(pluginList))
	} else {
		countStr = fmt.Sprintf("共 %d 个 YAML 模板, %d 个 Go 插件", len(templates), len(pluginList))
	}
	PrintTable("模板 / 插件列表", headers, colWidths, rowsFn, countStr)
}

func typLabel(typ string) string {
	if typ == "Plugin" {
		return pterm.Magenta(typ)
	}
	return pterm.Gray(typ)
}

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

func showListHelp() {
	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  用法: gosleek list [选项]"))
	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  选项:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	pterm.Println("    -T, --templates <dir>   模板目录（默认: templates）")
	pterm.Println("    --plugins-only          仅显示 Go 插件")
	pterm.Println("    --tags <t,t>            按标签筛选")
	pterm.Println("    --severity <s,s>        按严重度筛选")
	pterm.Println("    -e, --exclude <id>      排除指定 ID")
	pterm.Println("    -id, --id <id>          按 ID 筛选")
	pterm.Println("    -h, --help              显示此帮助信息")
	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  示例:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	pterm.Println("    gosleek list")
	pterm.Println("    gosleek list --plugins-only")
	pterm.Println("    gosleek list --severity critical")
	pterm.Println("    gosleek list --tags sqli")
	pterm.Println()
}
