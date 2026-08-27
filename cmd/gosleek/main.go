package main

import (
	"fmt"
	"os"

	_ "github.com/gosleek/gosleek/plugins" // 触发插件 init() 注册
	"github.com/gosleek/gosleek/internal/output"
	"github.com/gosleek/gosleek/pkg/constants"
	"github.com/pterm/pterm"
)

func main() {
	if len(os.Args) < 2 {
		output.PrintBannerRaw(constants.Version)
		printGlobalHelp()
		os.Exit(0)
	}

	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	case "list":
		runList(os.Args[2:])
	case "validate":
		runValidate(os.Args[2:])
	case "replay":
		runReplay(os.Args[2:])
	case "version":
		output.PrintBannerRaw(constants.Version)
		pterm.Println()
		pterm.Println("  " + pterm.Bold.Sprint("Go-Sleek-T") + "  " + pterm.LightCyan("v"+constants.Version))
		pterm.Println("  " + pterm.Gray("- 模板驱动的漏洞扫描器"))
		pterm.Println()
	case "help", "--help", "-h":
		output.PrintBannerRaw(constants.Version)
		printGlobalHelp()
	default:
		// Check if user typed subcommand help like "gosleek scan -h"
		output.PrintBannerRaw(constants.Version)
		fmt.Fprintln(os.Stderr, pterm.Red("未知命令: "+os.Args[1]))
		fmt.Fprintln(os.Stderr, "使用 'gosleek help' 查看帮助")
		os.Exit(1)
	}
}
