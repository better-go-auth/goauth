package logger

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

type entry struct {
	level Level
	msg   string
	args  []any
}

func capture() (*[]entry, LogFunc) {
	var got []entry
	return &got, func(level Level, msg string, args ...any) { got = append(got, entry{level, msg, args}) }
}

func TestLevels(t *testing.T) {
	cases := []struct {
		level Level
		want  []Level // levels that are published
	}{
		{LevelDebug, []Level{LevelDebug, LevelInfo, LevelInfo, LevelWarn, LevelError}},
		{LevelInfo, []Level{LevelInfo, LevelInfo, LevelWarn, LevelError}},
		{LevelSuccess, []Level{LevelInfo, LevelWarn, LevelError}},
		{LevelWarn, []Level{LevelWarn, LevelError}},
		{LevelError, []Level{LevelError}},
		{"", []Level{LevelWarn, LevelError}},      // default warn
		{"bogus", []Level{LevelWarn, LevelError}}, // unknown → warn
	}
	for _, c := range cases {
		got, fn := capture()
		l := New(Options{Level: c.level, Log: fn})
		l.Debug("d")
		l.Info("i")
		l.Success("s") // published as info, like better-auth
		l.Warn("w")
		l.Error("e", "k", 1)
		var levels []Level
		for _, e := range *got {
			levels = append(levels, e.level)
		}
		if strings.Join(toStrings(levels), ",") != strings.Join(toStrings(c.want), ",") {
			t.Errorf("level %q: published %v, want %v", c.level, levels, c.want)
		}
	}
}

func toStrings(ls []Level) []string {
	out := make([]string, len(ls))
	for i, l := range ls {
		out[i] = string(l)
	}
	return out
}

func TestDisabledAndArgs(t *testing.T) {
	got, fn := capture()
	New(Options{Disabled: true, Level: LevelDebug, Log: fn}).Error("x")
	if len(*got) != 0 {
		t.Fatal("disabled logger published")
	}
	New(Options{Log: fn}).Error("boom", "err", "e1", "userId", "u1")
	if len(*got) != 1 || (*got)[0].msg != "boom" || len((*got)[0].args) != 4 || (*got)[0].args[3] != "u1" {
		t.Fatalf("entry = %+v", *got)
	}
	var nilLogger *Logger
	if nilLogger.Enabled(LevelError) {
		t.Fatal("nil logger enabled")
	}
}

func TestSlogOutput(t *testing.T) {
	var buf bytes.Buffer
	out := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	l := New(Options{Level: LevelDebug, Slog: out})
	l.Debug("dbg", "a", 1)
	l.Warn("wrn")
	l.Error("err")
	s := buf.String()
	for _, want := range []string{"level=DEBUG msg=dbg a=1", "level=WARN msg=wrn", "level=ERROR msg=err"} {
		if !strings.Contains(s, want) {
			t.Fatalf("output %q misses %q", s, want)
		}
	}
}

func TestDefault(t *testing.T) {
	t.Cleanup(func() { SetDefault(nil) })
	got, fn := capture()
	SetDefault(New(Options{Level: LevelInfo, Log: fn}))
	Info("hello")
	Debug("hidden")
	Warn("w")
	Error("e")
	if len(*got) != 3 || Default().Level() != LevelInfo {
		t.Fatalf("published %+v", *got)
	}
	SetDefault(nil)
	if Default().Level() != DefaultLevel {
		t.Fatal("SetDefault(nil) must restore the default logger")
	}
}
