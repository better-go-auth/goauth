package logger

import (
	"context"
	"log/slog"
	"sync/atomic"
)

// Level is a better-auth log level. Levels are ordered debug < info < success < warn < error.
type Level string

const (
	LevelDebug   Level = "debug"
	LevelInfo    Level = "info"
	LevelSuccess Level = "success"
	LevelWarn    Level = "warn"
	LevelError   Level = "error"
)

// DefaultLevel is better-auth's default log level ("warn").
const DefaultLevel = LevelWarn

// levelRank orders the levels like better-auth's `levels` array.
var levelRank = map[Level]int{LevelDebug: 0, LevelInfo: 1, LevelSuccess: 2, LevelWarn: 3, LevelError: 4}

// LogFunc is better-auth's custom `logger.log(level, message, ...args)`. It never receives LevelSuccess
// (better-auth maps it to "info").
type LogFunc func(level Level, message string, args ...any)

// Options mirrors better-auth's `logger` option (AuthConfig.Logger).
type Options struct {
	// Disabled turns every goauth log message off (better-auth's logger.disabled).
	Disabled bool
	// Level is the lowest level that is published (better-auth's logger.level, default "warn").
	Level Level
	// Log replaces the default output (better-auth's logger.log). Args are the key/value pairs of the
	// message, in slog style ("err", err, "userId", id, ...).
	Log LogFunc
	// Slog is where the default output goes (goauth only; default slog.Default() at the time of logging).
	// Ignored when Log is set.
	Slog *slog.Logger
}

// Logger is goauth's injectable logger: better-auth's createLogger(options) on top of slog.
// The zero value is not usable; build one with New.
type Logger struct {
	opts Options
}

// New builds a Logger from better-auth style options (unknown levels fall back to "warn").
func New(opts Options) *Logger {
	if _, ok := levelRank[opts.Level]; !ok {
		opts.Level = DefaultLevel
	}
	return &Logger{opts: opts}
}

// Level returns the configured level.
func (l *Logger) Level() Level { return l.opts.Level }

// Enabled reports whether a message of level would be published (better-auth's shouldPublishLog).
func (l *Logger) Enabled(level Level) bool {
	if l == nil || l.opts.Disabled {
		return false
	}
	return levelRank[level] >= levelRank[l.opts.Level]
}

// Debug logs at the debug level.
func (l *Logger) Debug(msg string, args ...any) { l.log(LevelDebug, msg, args) }

// Info logs at the info level.
func (l *Logger) Info(msg string, args ...any) { l.log(LevelInfo, msg, args) }

// Success logs at better-auth's success level (published as info).
func (l *Logger) Success(msg string, args ...any) { l.log(LevelSuccess, msg, args) }

// Warn logs at the warn level.
func (l *Logger) Warn(msg string, args ...any) { l.log(LevelWarn, msg, args) }

// Error logs at the error level.
func (l *Logger) Error(msg string, args ...any) { l.log(LevelError, msg, args) }

// log publishes one message when its level is enabled.
func (l *Logger) log(level Level, msg string, args []any) {
	// Step 1: drop messages below the configured level (or everything when disabled)
	if !l.Enabled(level) {
		return
	}
	// Step 2: a custom log function gets better-auth's level names (success is reported as info)
	if l.opts.Log != nil {
		if level == LevelSuccess {
			level = LevelInfo
		}
		l.opts.Log(level, msg, args...)
		return
	}
	// Step 3: default output through slog
	out := l.opts.Slog
	if out == nil {
		out = slog.Default()
	}
	out.Log(context.Background(), slogLevel(level), msg, args...)
}

// slogLevel maps a better-auth level to a slog level.
func slogLevel(level Level) slog.Level {
	switch level {
	case LevelDebug:
		return slog.LevelDebug
	case LevelWarn:
		return slog.LevelWarn
	case LevelError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// defaultLogger is the process-wide logger used by goauth packages that have no config at hand.
var defaultLogger atomic.Pointer[Logger]

func init() { defaultLogger.Store(New(Options{})) }

// Default returns the process-wide goauth logger. SetupGoAuth installs the one built from
// AuthConfig.Logger (the last SetupGoAuth call wins, like the ID generator).
func Default() *Logger { return defaultLogger.Load() }

// SetDefault replaces the process-wide goauth logger (nil restores the default warn-level slog logger).
func SetDefault(l *Logger) {
	if l == nil {
		l = New(Options{})
	}
	defaultLogger.Store(l)
}

// Debug logs at the debug level with the process-wide logger.
func Debug(msg string, args ...any) { Default().Debug(msg, args...) }

// Info logs at the info level with the process-wide logger.
func Info(msg string, args ...any) { Default().Info(msg, args...) }

// Warn logs at the warn level with the process-wide logger.
func Warn(msg string, args ...any) { Default().Warn(msg, args...) }

// Error logs at the error level with the process-wide logger.
func Error(msg string, args ...any) { Default().Error(msg, args...) }
