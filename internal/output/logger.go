package output

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pterm/pterm"
)

// Logger wraps slog with dual output (console via pterm + file JSON).
//
// 设计说明 (redesigned 2026-08-07):
//  1. 之前的 Logger 从来没被接入主流程, 所有日志走的是 Console 回调, 而 Console 的
//     回调在 verbose=0 时就被闸门挡住了, 用户要求的 logger.info 自然看不到。
//  2. 现在 Logger 通过自定义 ptermHandler 直接把 slog.Record 渲染成与 Console 一致
//     的彩色 "[TAG] 时间 消息" 格式, 保证层次分明。
//  3. -v / -vv 的闸门通过 SetMinLevel 动态调整: 默认只显示 warn+, -v 显示 info+,
//     -vv 显示 debug+ 。这样既能保证 "每条请求和响应在 -vv 都打印", 又不会淹没屏幕。
//  4. 文件日志仍然是 JSON 格式, 完整 debug 级别, 用于事后分析。
type Logger struct {
	slog    *slog.Logger
	file    *os.File
	mu      sync.Mutex
	verbose int
	level   *slog.LevelVar // dynamic console level
}

// NewLogger creates a structured logger with pterm-styled console output
// plus optional JSON file output.
//
// verbose:
//
//	0 → console shows WARN / ERROR only
//	1 → + INFO
//	2 → + DEBUG
func NewLogger(logFile string, level string, verbose int) *Logger {
	lvl := &slog.LevelVar{}

	switch {
	case verbose >= 2:
		lvl.Set(slog.LevelDebug)
	case verbose >= 1:
		lvl.Set(slog.LevelInfo)
	default:
		lvl.Set(slog.LevelWarn)
	}

	// allow explicit level to only lower the bar (not raise above verbose)
	switch level {
	case "debug":
		if verbose < 2 {
			lvl.Set(slog.LevelDebug)
		}
	case "info":
		if verbose < 1 && lvl.Level() > slog.LevelInfo {
			lvl.Set(slog.LevelInfo)
		}
	}

	consoleHandler := newPtermHandler(lvl)

	var logger *slog.Logger
	var file *os.File

	if logFile != "" {
		dir := filepath.Dir(logFile)
		_ = os.MkdirAll(dir, 0755)
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			file = f
			fileHandler := slog.NewJSONHandler(f, &slog.HandlerOptions{
				Level: slog.LevelDebug, // file always gets everything
			})
			logger = slog.New(&dualHandler{
				console: consoleHandler,
				file:    fileHandler,
			})
		} else {
			logger = slog.New(consoleHandler)
		}
	} else {
		logger = slog.New(consoleHandler)
	}

	return &Logger{
		slog:    logger,
		file:    file,
		verbose: verbose,
		level:   lvl,
	}
}

// SetMinLevel adjusts console verbosity at runtime.
func (l *Logger) SetMinLevel(level slog.Level) { l.level.Set(level) }

// ──────────────────────────────────────────────────────────────────────────
// ptermHandler — render slog records as colored pterm lines
// ──────────────────────────────────────────────────────────────────────────

type ptermHandler struct {
	level *slog.LevelVar
}

func newPtermHandler(level *slog.LevelVar) *ptermHandler {
	return &ptermHandler{level: level}
}

func (h *ptermHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *ptermHandler) Handle(ctx context.Context, r slog.Record) error {
	// Map slog level → Chinese tag & color (same palette as Console)
	// 所有 tag 统一 2 个中文字符
	var tag string
	var color func(a ...interface{}) string
	switch r.Level {
	case slog.LevelDebug:
		tag, color = "调试", pterm.Gray
	case slog.LevelInfo:
		tag, color = "信息", pterm.LightCyan
	case slog.LevelWarn:
		tag, color = "警告", pterm.Yellow
	case slog.LevelError:
		tag, color = "错误", pterm.Red
	}

	// Build attribute string: k1=v1 k2=v2
	attrs := make([]string, 0, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, fmt.Sprintf("%s=%v", a.Key, a.Value.Any()))
		return true
	})

	msg := r.Message
	if len(attrs) > 0 {
		msg = msg + "  " + pterm.Gray(strings.Join(attrs, " "))
	}

	// Timestamp with date + brackets, Chinese tag (2 chars = 4 display cols)
	ts := pterm.Gray("[" + time.Now().Format("2006-01-02 15:04:05.000") + "]")
	tagFmt := color("[" + tag + "]")

	// contIndent: 25 (ts) + 2 + 6 ([标签]) + 2 = 35 spaces
	const indent = "                                   "

	lines := strings.Split(msg, "\n")
	if len(lines) == 1 {
		pterm.Printf("%s %s %s\n", ts, tagFmt, lines[0])
		return nil
	}
	for i, l := range lines {
		if i == 0 {
			pterm.Printf("%s %s %s\n", ts, tagFmt, l)
		} else {
			pterm.Printf("%s %s\n", indent, l)
		}
	}
	return nil
}

func (h *ptermHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return h }
func (h *ptermHandler) WithGroup(name string) slog.Handler       { return h }

// ──────────────────────────────────────────────────────────────────────────
// dualHandler — console + file
// ──────────────────────────────────────────────────────────────────────────

type dualHandler struct {
	console slog.Handler
	file    slog.Handler
}

func (h *dualHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.console.Enabled(ctx, level) || h.file.Enabled(ctx, level)
}

func (h *dualHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.console.Enabled(ctx, r.Level) {
		_ = h.console.Handle(ctx, r.Clone())
	}
	if h.file.Enabled(ctx, r.Level) {
		if err := h.file.Handle(ctx, r.Clone()); err != nil {
			return err
		}
	}
	return nil
}

func (h *dualHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &dualHandler{
		console: h.console.WithAttrs(attrs),
		file:    h.file.WithAttrs(attrs),
	}
}

func (h *dualHandler) WithGroup(name string) slog.Handler {
	return &dualHandler{
		console: h.console.WithGroup(name),
		file:    h.file.WithGroup(name),
	}
}

// ──────────────────────────────────────────────────────────────────────────
// Convenience methods
// ──────────────────────────────────────────────────────────────────────────

// Debug logs at debug level with fmt-style formatting.
func (l *Logger) Debug(msg string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.slog.Debug(fmt.Sprintf(msg, args...))
}

// Info logs at info level.
func (l *Logger) Info(msg string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.slog.Info(fmt.Sprintf(msg, args...))
}

// Warn logs at warn level.
func (l *Logger) Warn(msg string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.slog.Warn(fmt.Sprintf(msg, args...))
}

// WarnKV logs at warn level with structured key-value pairs.
func (l *Logger) WarnKV(msg string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.slog.Warn(msg, args...)
}

// Error logs at error level.
func (l *Logger) Error(msg string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.slog.Error(fmt.Sprintf(msg, args...))
}

// InfoKV logs at info level with structured key-value pairs.
func (l *Logger) InfoKV(msg string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.slog.Info(msg, args...)
}

// DebugKV logs at debug level with structured key-value pairs.
func (l *Logger) DebugKV(msg string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.slog.Debug(msg, args...)
}

// Verbose returns the configured verbose level.
func (l *Logger) Verbose() int { return l.verbose }

// Close cleans up file handles. Safe to call multiple times.
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
}
