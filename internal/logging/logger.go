package logging

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"authguard/internal/auth"
)

// Logger wraps slog.Logger to implement our auth.Logger interface
type Logger struct {
	slogger *slog.Logger
	attrs   []slog.Attr
}

// NewLogger creates a new logger instance using log/slog
func NewLogger(config auth.LoggingConfig) (auth.Logger, error) {
	level, err := parseLogLevel(config.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}

	var handler slog.Handler

	// Create handler based on format
	opts := &slog.HandlerOptions{
		Level: level,
	}

	switch strings.ToLower(config.Format) {
	case "json":
		handler = slog.NewJSONHandler(os.Stdout, opts)
	case "text":
		handler = slog.NewTextHandler(os.Stdout, opts)
	default:
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	slogger := slog.New(handler)

	return &Logger{
		slogger: slogger,
		attrs:   make([]slog.Attr, 0),
	}, nil
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, keysAndValues ...any) {
	attrs := l.parseKeyValues(keysAndValues...)
	l.slogger.LogAttrs(context.TODO(), slog.LevelDebug, msg, append(l.attrs, attrs...)...)
}

// Info logs an info message
func (l *Logger) Info(msg string, keysAndValues ...any) {
	attrs := l.parseKeyValues(keysAndValues...)
	l.slogger.LogAttrs(context.TODO(), slog.LevelInfo, msg, append(l.attrs, attrs...)...)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, keysAndValues ...any) {
	attrs := l.parseKeyValues(keysAndValues...)
	l.slogger.LogAttrs(context.TODO(), slog.LevelWarn, msg, append(l.attrs, attrs...)...)
}

// Error logs an error message
func (l *Logger) Error(msg string, keysAndValues ...any) {
	attrs := l.parseKeyValues(keysAndValues...)
	l.slogger.LogAttrs(context.TODO(), slog.LevelError, msg, append(l.attrs, attrs...)...)
}

// With returns a new logger with additional fields
func (l *Logger) With(keysAndValues ...any) auth.Logger {
	newAttrs := make([]slog.Attr, len(l.attrs))
	copy(newAttrs, l.attrs)

	// Add new attributes
	attrs := l.parseKeyValues(keysAndValues...)
	newAttrs = append(newAttrs, attrs...)

	return &Logger{
		slogger: l.slogger,
		attrs:   newAttrs,
	}
}

// parseKeyValues converts key-value pairs to slog attributes
func (l *Logger) parseKeyValues(keysAndValues ...any) []slog.Attr {
	var attrs []slog.Attr

	for i := 0; i < len(keysAndValues); i += 2 {
		if i+1 >= len(keysAndValues) {
			// Odd number of arguments, ignore the last one
			break
		}

		key, ok := keysAndValues[i].(string)
		if !ok {
			// Key is not a string, skip
			continue
		}

		attrs = append(attrs, slog.Any(key, keysAndValues[i+1]))
	}

	return attrs
}

// parseLogLevel parses a log level string to slog.Level
func parseLogLevel(level string) (slog.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level: %s", level)
	}
}
