package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/gosleek/gosleek/internal/output"
	"github.com/gosleek/gosleek/internal/replay"
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

	requestFile := fs.String("f", "", "请求文件路径（raw HTTP 格式）")
	target := fs.String("t", "", "目标 URL（如 http://example.com）")
	outputDir := fs.String("o", "./responses", "响应输出目录")
	verbose := fs.Int("v", 0, "详细输出级别（0=普通, 1=-v, 2=-vv）")
	proxy := fs.String("proxy", "", "HTTP/SOCKS5 代理")
	insecure := fs.Bool("k", false, "跳过 TLS 证书校验")
	save := fs.Bool("save", true, "保存响应到文件（默认: 启用）")
	compare := fs.Bool("compare", false, "与历史响应比对差异")
	compareWith := fs.String("with", "", "历史响应文件路径（与 -compare 配合使用）")

	fs.Parse(args)

	if showHelp {
		showReplayHelp()
		return
	}

	// 确定请求文件
	reqFile := *requestFile
	if reqFile == "" && len(fs.Args()) > 0 {
		reqFile = fs.Args()[0]
	}
	if reqFile == "" {
		fmt.Fprintln(os.Stderr, "未指定请求文件，使用 -f <file> 或作为 positional 参数")
		showReplayHelp()
		os.Exit(1)
	}

	// 验证目标
	if *target == "" {
		// 尝试从请求文件中提取 Host 或 URL
		if data, err := os.ReadFile(reqFile); err == nil {
			lines := strings.SplitN(string(data), "\r\n", 2)
			if len(lines) > 0 {
				parts := strings.Fields(lines[0])
				if len(parts) >= 2 && (strings.HasPrefix(parts[1], "http://") || strings.HasPrefix(parts[1], "https://")) {
					*target = parts[1]
				}
			}
		}
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, "未指定目标 URL，使用 -t <url> 或在请求文件中提供完整 URL")
		os.Exit(1)
	}

	console := output.NewConsole(*verbose)

	// 运行 replay
	session := &replay.Session{
		RequestFile: reqFile,
		BaseURL:     *target,
		Proxy:       *proxy,
		Insecure:    *insecure,
		OutputDir:   *outputDir,
		Save:        *save,
		Compare:     *compare,
		OldPath:     *compareWith,
		Verbose:     *verbose,
	}

	ctx := context.Background()
	result, err := session.Run(ctx)
	if err != nil {
		console.PrintError("replay 失败: %v", err)
		os.Exit(1)
	}

	// 输出结果
	console.PrintReplayResult(result)

	// 如果有对比差异
	if *compare && result.Compare.HasDiff {
		console.PrintReplayDiff(result.Compare)
	}

	// 详细输出请求和响应
	if *verbose >= 2 {
		console.PrintReplayRaw("请求", result.Raw)
		console.PrintReplayRaw("响应", result.Raw)
	}

	// 保存确认
	if *save && result.SavedPath != "" {
		console.PrintSaved(result.SavedPath, "txt")
	}
}

func showReplayHelp() {
	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  用法: gosleek replay [选项] <请求文件>"))
	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  参数:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	pterm.Println("    <请求文件>    HTTP 请求原文文件路径（raw 格式）")
	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  选项:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	pterm.Println("    -f, --file <path>   请求文件路径（可省略 positional 参数）")
	pterm.Println("    -t, --target <url>  目标 URL（覆盖请求中的 Host 头）")
	pterm.Println("    -o, --output <dir>  响应输出目录（默认: ./responses/）")
	pterm.Println("    --save              保存响应到文件（默认: 启用）")
	pterm.Println("    --compare           与历史响应比对差异")
	pterm.Println("    --with <path>       历史响应文件路径（与 --compare 配合）")
	pterm.Println("    --proxy <url>       HTTP/SOCKS5 代理")
	pterm.Println("    -k, --insecure      跳过 TLS 证书校验")
	pterm.Println("    -v, --verbose <n>   详细输出级别（0/1/2，默认: 0）")
	pterm.Println("    -h, --help          显示此帮助信息")
	pterm.Println()
	pterm.Println(pterm.Bold.Sprint("  示例:"))
	pterm.Println(pterm.Gray(strings.Repeat("─", 55)))
	pterm.Println("    gosleek replay request.txt -t http://target.com")
	pterm.Println("    gosleek replay -f request.txt -t http://target.com -o ./resp/")
	pterm.Println("    gosleek replay -f request.txt -t http://target.com --compare --with old_response.txt")
	pterm.Println("    gosleek replay request.txt -t http://target.com -v 2")
	pterm.Println()
}
