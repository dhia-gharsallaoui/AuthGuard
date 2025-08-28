package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogLevel_String(t *testing.T) {
	tests := []struct {
		name     string
		level    LogLevel
		expected string
	}{
		{
			name:     "Debug level",
			level:    LogLevelDebug,
			expected: "debug",
		},
		{
			name:     "Info level",
			level:    LogLevelInfo,
			expected: "info",
		},
		{
			name:     "Warn level",
			level:    LogLevelWarn,
			expected: "warn",
		},
		{
			name:     "Error level",
			level:    LogLevelError,
			expected: "error",
		},
		{
			name:     "Unknown level (default to info)",
			level:    LogLevel(999), // Invalid log level
			expected: "info",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.level.String())
		})
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected LogLevel
	}{
		{
			name:     "Parse debug",
			input:    "debug",
			expected: LogLevelDebug,
		},
		{
			name:     "Parse info",
			input:    "info",
			expected: LogLevelInfo,
		},
		{
			name:     "Parse warn",
			input:    "warn",
			expected: LogLevelWarn,
		},
		{
			name:     "Parse warning (alias for warn)",
			input:    "warning",
			expected: LogLevelWarn,
		},
		{
			name:     "Parse error",
			input:    "error",
			expected: LogLevelError,
		},
		{
			name:     "Parse unknown (default to info)",
			input:    "unknown",
			expected: LogLevelInfo,
		},
		{
			name:     "Parse empty string (default to info)",
			input:    "",
			expected: LogLevelInfo,
		},
		{
			name:     "Parse mixed case (default to info)",
			input:    "DEBUG",
			expected: LogLevelInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ParseLogLevel(tt.input))
		})
	}
}

func TestLogFormat_String(t *testing.T) {
	tests := []struct {
		name     string
		format   LogFormat
		expected string
	}{
		{
			name:     "JSON format",
			format:   LogFormatJSON,
			expected: "json",
		},
		{
			name:     "Text format",
			format:   LogFormatText,
			expected: "text",
		},
		{
			name:     "Unknown format (default to json)",
			format:   LogFormat(999), // Invalid log format
			expected: "json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.format.String())
		})
	}
}

func TestParseLogFormat(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected LogFormat
	}{
		{
			name:     "Parse json",
			input:    "json",
			expected: LogFormatJSON,
		},
		{
			name:     "Parse text",
			input:    "text",
			expected: LogFormatText,
		},
		{
			name:     "Parse unknown (default to json)",
			input:    "unknown",
			expected: LogFormatJSON,
		},
		{
			name:     "Parse empty string (default to json)",
			input:    "",
			expected: LogFormatJSON,
		},
		{
			name:     "Parse mixed case (default to json)",
			input:    "JSON",
			expected: LogFormatJSON,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ParseLogFormat(tt.input))
		})
	}
}

// Test LogLevel constants are properly defined
func TestLogLevel_Constants(t *testing.T) {
	assert.Equal(t, LogLevel(0), LogLevelDebug)
	assert.Equal(t, LogLevel(1), LogLevelInfo)
	assert.Equal(t, LogLevel(2), LogLevelWarn)
	assert.Equal(t, LogLevel(3), LogLevelError)
}

// Test LogFormat constants are properly defined
func TestLogFormat_Constants(t *testing.T) {
	assert.Equal(t, LogFormat(0), LogFormatJSON)
	assert.Equal(t, LogFormat(1), LogFormatText)
}

// Test round-trip conversion for LogLevel
func TestLogLevel_RoundTrip(t *testing.T) {
	levels := []LogLevel{LogLevelDebug, LogLevelInfo, LogLevelWarn, LogLevelError}

	for _, level := range levels {
		str := level.String()
		parsed := ParseLogLevel(str)
		assert.Equal(t, level, parsed, "Round-trip failed for level %v", level)
	}
}

// Test round-trip conversion for LogFormat
func TestLogFormat_RoundTrip(t *testing.T) {
	formats := []LogFormat{LogFormatJSON, LogFormatText}

	for _, format := range formats {
		str := format.String()
		parsed := ParseLogFormat(str)
		assert.Equal(t, format, parsed, "Round-trip failed for format %v", format)
	}
}
