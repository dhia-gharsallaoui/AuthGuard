package auth

// LogLevel represents logging levels
type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
)

// String returns the string representation of the log level
func (l LogLevel) String() string {
	switch l {
	case LogLevelDebug:
		return "debug"
	case LogLevelInfo:
		return "info"
	case LogLevelWarn:
		return "warn"
	case LogLevelError:
		return "error"
	default:
		return "info"
	}
}

// ParseLogLevel parses a string to LogLevel
func ParseLogLevel(s string) LogLevel {
	switch s {
	case "debug":
		return LogLevelDebug
	case "info":
		return LogLevelInfo
	case "warn", "warning":
		return LogLevelWarn
	case "error":
		return LogLevelError
	default:
		return LogLevelInfo
	}
}

// LogFormat represents logging formats
type LogFormat int

const (
	LogFormatJSON LogFormat = iota
	LogFormatText
)

// String returns the string representation of the log format
func (f LogFormat) String() string {
	switch f {
	case LogFormatJSON:
		return "json"
	case LogFormatText:
		return "text"
	default:
		return "json"
	}
}

// ParseLogFormat parses a string to LogFormat
func ParseLogFormat(s string) LogFormat {
	switch s {
	case "json":
		return LogFormatJSON
	case "text":
		return LogFormatText
	default:
		return LogFormatJSON
	}
}

// Logger interface for structured logging
type Logger interface {
	Debug(msg string, keysAndValues ...any)
	Info(msg string, keysAndValues ...any)
	Warn(msg string, keysAndValues ...any)
	Error(msg string, keysAndValues ...any)
	With(keysAndValues ...any) Logger
}

// LoggingConfig represents logging configuration
type LoggingConfig struct {
	Level  string `yaml:"level" default:"info"`  // debug, info, warn, error
	Format string `yaml:"format" default:"json"` // json, text
}
