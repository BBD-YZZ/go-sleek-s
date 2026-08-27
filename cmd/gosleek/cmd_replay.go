package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/gosleek/gosleek/internal/output"
	"github.com/gosleek/gosleek/pkg/constants"
	"github.com/pterm/pterm"
)

func runReplay(args []string) {
	output.PrintBannerRaw(constants.Version)

	fs := flag.NewFlagSet("replay", flag.ExitOnError)

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

	requestFile := fs.Bool("f", false, "从文件读取请求")
	target := fs.String("t", "", "目标 URL")
	outputDir := fs.String("o", "./responses", "响应输出目录")
	verbose := fs.Int("v", 0, "详细输出")

	fs.Parse(args)

	if showHelp {
		showReplayHelp()
		return
	}

	if len(fs.Args()) == 0 && !*requestFile {
		showReplayHelp()
		os.Exit(1)
	}

	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  请求复放"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 75)))
	pterm.Println()
	pterm.Println("    " + pterm.Yellow("⚠  此功能仍在开发中，暂不可用"))
	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  配置:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 75)))
	pterm.Println("    目标 URL:      " + pterm.LightCyan(*target))
	pterm.Println("    输出目录:      " + pterm.LightCyan(*outputDir))
	pterm.Println("    详细输出级别:  " + pterm.LightCyan(fmt.Sprintf("%d", *verbose)))
	pterm.Println("    从文件读取:    " + pterm.LightCyan(fmt.Sprintf("%v", *requestFile)))
	pterm.Println()
	pterm.Println(pterm.Gray("  提示: 请保存请求到文件，然后使用 -f 指定文件路径进行复放"))
	pterm.Println()
}

func showReplayHelp() {
	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  用法: gosleek replay [选项] <请求文件>"))
	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  参数:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	pterm.Println("    <请求文件>    HTTP 请求原文文件路径")
	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  选项:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	pterm.Println("    -f, --file    从文件读取请求（默认读取命令行参数）")
	pterm.Println("    -t, --target  目标 URL（覆盖请求中的主机头）")
	pterm.Println("    -o, --output  响应输出目录（默认: ./responses/）")
	pterm.Println("    -v, --verbose 详细输出级别（0-2）")
	pterm.Println("    -h, --help    显示帮助信息")
	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  示例:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	pterm.Println("    gosleek replay request.txt -t http://target.com")
	pterm.Println("    gosleek replay -f request.txt -t http://target.com -o ./resp/")
	pterm.Println()
}
