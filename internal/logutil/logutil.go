// Package logutil provides a minimal logging utility with global singleton
// support. It is intentionally free of dependencies on other internal packages
// to break import cycles (e.g. output ↔ replay ↔ httpclient).
//
// All modules (oob, fingerprint, template, replay, plugin, httpclient, etc.)
// use this package for log output.  The global Console or Logger is registered
// once in main.go after creating the Console — before that, logs fall back to
// fmt.Printf so they are always visible but unstyled.
package logutil

import (
	"fmt"
	"sync"
	"time"

	"github.com/pterm/pterm"
)

// TagColors maps tag names to their pterm color functions.
var TagColors = map[string]func(a ...interface{}) string{
	"信息": pterm.LightCyan,
	"详细": pterm.LightBlue,
	"调试": pterm.Gray,
	"警告": pterm.Yellow,
	"错误": pterm.Red,
	"成功": pterm.Green,
	"扫描": pterm.LightMagenta,
	"进度": pterm.Cyan,
	"请求": pterm.LightWhite,
	"响应": pterm.LightGreen,
	"匹配": pterm.LightYellow,
	"跳过": pterm.Gray,
	"流程": pterm.LightBlue,
	"外带": pterm.Magenta,
	"指纹": pterm.LightGreen,
	"限速": pterm.Yellow,
	"回放": pterm.Cyan,
}

func TagColor(tag string) func(...interface{}) string {
	if c, ok := TagColors[tag]; ok {
		return c
	}
	return pterm.White
}

// ConsoleLike is the minimal interface that a Console must implement for
// Log() to route through it.  The real Console in output/console.go satisfies
// this interface.
type ConsoleLike interface {
	PLine(tag string, levelMin int, format string, args ...interface{})
	SetMinLevel(level int)
}

// LoggerLike is deprecated — ConsoleLike now handles all output routing.
// Kept for backward compatibility with existing code.
type LoggerLike interface{}

var (
	globalConsoleMu sync.Mutex
	globalConsole   ConsoleLike
	globalLogger    LoggerLike
	// effectiveVerb is the CLI verbosity level (-1/silent, 0/default, 1/-v, 2/-vv).
	// Config log-level raises this when no CLI flags are passed.
	effectiveVerb int
)

// SetConsole registers a Console as the global output destination.
// Call this once in main.go after creating the Console.
func SetConsole(c ConsoleLike) {
	globalConsoleMu.Lock()
	defer globalConsoleMu.Unlock()
	globalConsole = c
}

// SetLogger is deprecated — all logging now goes through SetConsole.
func SetLogger(_ LoggerLike) {
	globalConsoleMu.Lock()
	defer globalConsoleMu.Unlock()
}

// SetEffectiveVerb sets the effective verbosity from CLI flags.
// Called once in main.go after parsing flags: SetEffectiveVerb(verb).
func SetEffectiveVerb(verb int) {
	globalConsoleMu.Lock()
	defer globalConsoleMu.Unlock()
	effectiveVerb = verb
}

// SetMinLevel raises the effective verbosity from config.yaml log-level
// when no CLI verbosity flags were passed (effectiveVerb == 0).
func SetMinLevel(level int) {
	globalConsoleMu.Lock()
	defer globalConsoleMu.Unlock()
	if effectiveVerb == 0 && level > 0 {
		effectiveVerb = level
	}
}

// LogLevelToVerbosity maps config.yaml log-level strings to console verbosity levels.
// Exported for use in cmd/gosleek/main.go (used to set console threshold via SetMinLevel).
func LogLevelToVerbosity(level string) int {
	return logLevelToVerbosity(level)
}

// logLevelToVerbosity maps config.yaml log-level strings to console verbosity levels.
func logLevelToVerbosity(level string) int {
	switch level {
	case "debug":
		return 2
	case "info":
		return 1
	case "warn":
		return 0
	case "error":
		return -1
	default:
		return 0
	}
}

// Log emits a timestamped log line in the unified format:
//
//	[2006-01-02 15:04:05.000] [TAG]  message
//
// level values: "debug" (requires -vv), "info" (requires -v), "warn", "error".
// tag is a 2-character Chinese label.
func Log(level, tag, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)

	// Determine minimum verbosity level for this log level
	var levelMin int
	switch level {
	case "debug":
		levelMin = 2
	case "info":
		levelMin = 1
	default:
		levelMin = 0
	}

	globalConsoleMu.Lock()
	console := globalConsole
	globalConsoleMu.Unlock()

	if console != nil {
		// Console.visible() checks c.verbose >= levelMin.
		// CLI -v/-vv sets c.verbose directly via NewConsole(verb).
		// Config log-level only raises effectiveVerb when verb==0 (no CLI flags).
		// So if CLI flag is passed, it always takes priority.
		console.PLine(tag, levelMin, "%s", msg)
		return
	}

	// Fallback: direct output
	ts := "[" + time.Now().Format("2006-01-02 15:04:05.000") + "]"
	tagFmt := TagColor(tag)("[" + tag + "]")
	pterm.Printf("%s%s %s\n", ts, tagFmt, msg)
}

// LogKV emits a log line with structured key=value attributes.
// The attrs are appended to the message in the format " k1=v1 k2=v2".
func LogKV(level, tag, msg string, attrs ...interface{}) {
	if len(attrs)%2 != 0 {
		// odd number of args — append odd elements as values
		for i := 1; i < len(attrs); i += 2 {
			msg = fmt.Sprintf("%s %s=%v", msg, attrs[i-1], attrs[i])
		}
		attrs = nil
	}
	for i := 0; i < len(attrs); i += 2 {
		msg = fmt.Sprintf("%s %s=%v", msg, attrs[i], attrs[i+1])
	}
	Log(level, tag, "%s", msg)
}
