package auth

import "time"

// Config represents the main configuration structure
type Config struct {
	Server    ServerConfig   `yaml:"server"`
	Providers []ProviderType `yaml:"providers"` // List of enabled providers
	Cache     CacheConfig    `yaml:"cache"`
	Logging   LoggingConfig  `yaml:"logging"`
	Metrics   MetricsConfig  `yaml:"metrics"`
}

// ServerConfig represents HTTP server configuration
type ServerConfig struct {
	Port            string        `yaml:"port" default:"8080"`
	Host            string        `yaml:"host" default:"0.0.0.0"`
	ReadTimeout     time.Duration `yaml:"read_timeout" default:"10s"`
	WriteTimeout    time.Duration `yaml:"write_timeout" default:"10s"`
	IdleTimeout     time.Duration `yaml:"idle_timeout" default:"120s"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout" default:"30s"`
	MaxHeaderBytes  int           `yaml:"max_header_bytes" default:"1048576"` // 1MB
}

// CacheConfig represents cache configuration
type CacheConfig struct {
	Type            CacheType     `yaml:"type" default:"memory"`
	RedisURL        string        `yaml:"redis_url"`
	RedisPassword   string        `yaml:"redis_password"`
	RedisDB         int           `yaml:"redis_db" default:"0"`
	MaxKeys         int           `yaml:"max_keys" default:"1000"`
	CleanupInterval time.Duration `yaml:"cleanup_interval" default:"10m"`
	DefaultTTL      time.Duration `yaml:"default_ttl" default:"1h"`
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Server.Port == "" {
		return ErrConfigurationError
	}

	if len(c.Providers) == 0 {
		return ErrConfigurationError
	}

	return nil
}
