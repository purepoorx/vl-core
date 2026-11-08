package core

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type Logger struct {
	mu    sync.Mutex
	out   io.Writer
	level int
}

const (
	levelDebug = iota
	levelInfo
	levelWarn
	levelError
)

func NewLogger(level string, out io.Writer) *Logger {
	if out == nil {
		out = os.Stderr
	}
	l := &Logger{out: out, level: levelInfo}
	switch strings.ToLower(level) {
	case "debug":
		l.level = levelDebug
	case "info", "":
		l.level = levelInfo
	case "warn", "warning":
		l.level = levelWarn
	case "error":
		l.level = levelError
	}
	return l
}

func (l *Logger) log(level int, tag string, format string, args ...any) {
	if level < l.level {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.out, "%s [%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), tag, fmt.Sprintf(format, args...))
}

func (l *Logger) Debug(f string, a ...any) { l.log(levelDebug, "DEBUG", f, a...) }
func (l *Logger) Info(f string, a ...any)  { l.log(levelInfo, "INFO", f, a...) }
func (l *Logger) Warn(f string, a ...any)  { l.log(levelWarn, "WARN", f, a...) }
func (l *Logger) Error(f string, a ...any) { l.log(levelError, "ERROR", f, a...) }
