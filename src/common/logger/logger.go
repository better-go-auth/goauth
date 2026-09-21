package logger

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
)

type Opt struct {
	Ctx  context.Context
	Args []slog.Attr
}

// LogTrace logs name and output value with caller file location
func LogTrace(name string, output interface{}) {
	coloredMsg := string(ColorCyan) + name + string(ColorReset) + " " + string(ColorBlue) + fmt.Sprintf("=| %v", output) + string(ColorReset)
	pc := make([]uintptr, 15)
	n := runtime.Callers(2, pc)
	frames := runtime.CallersFrames(pc[:n])
	frame, _ := frames.Next()
	slog.Info(coloredMsg, slog.String("file", fmt.Sprintf("%s:%d", frame.File, frame.Line)))
}

func ErrorCtx(ctx context.Context, name string, output any, opt *Opt) {
	coloredMsg := string(ColorMagenta) + name + string(ColorReset) + " " + string(ColorYellow) + fmt.Sprintf("=| %v", output) + string(ColorReset)
	pc := make([]uintptr, 15)
	n := runtime.Callers(2, pc)
	frames := runtime.CallersFrames(pc[:n])
	frame, _ := frames.Next()
	slog.ErrorContext(ctx, coloredMsg, slog.String("file", fmt.Sprintf("%s:%d", frame.File, frame.Line)))
}

func LogError(name string, output any) {
	coloredMsg := string(ColorMagenta) + name + string(ColorReset) + " " + string(ColorYellow) + fmt.Sprintf("=| %v", output) + string(ColorReset)
	pc := make([]uintptr, 15)
	n := runtime.Callers(2, pc)
	frames := runtime.CallersFrames(pc[:n])
	frame, _ := frames.Next()
	slog.Error(coloredMsg, slog.String("file", fmt.Sprintf("%s:%d", frame.File, frame.Line)))
}

