package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"authguard/internal/auth"

	"gopkg.in/yaml.v3"
)

// Loader handles configuration loading from YAML files and environment variables
type Loader struct {
	configPath string
	envPrefix  string
}

// NewLoader creates a new configuration loader
func NewLoader(configPath, envPrefix string) *Loader {
	return &Loader{
		configPath: configPath,
		envPrefix:  envPrefix,
	}
}

// Load loads configuration from YAML file and applies environment variable overrides
func (l *Loader) Load() (*auth.Config, error) {
	config := &auth.Config{}

	// Load from YAML file if it exists
	if l.configPath != "" {
		if err := l.loadFromYAML(config); err != nil {
			return nil, fmt.Errorf("failed to load YAML config: %w", err)
		}
	}

	// Apply defaults
	l.applyDefaults(config)

	// Apply environment variable overrides
	l.applyEnvOverrides(config)

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return config, nil
}

// loadFromYAML loads configuration from YAML file
func (l *Loader) loadFromYAML(config *auth.Config) error {
	if _, err := os.Stat(l.configPath); os.IsNotExist(err) {
		return nil // Config file is optional
	}

	data, err := os.ReadFile(l.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return fmt.Errorf("failed to parse YAML config: %w", err)
	}

	return nil
}

// applyDefaults applies default values to configuration fields
func (l *Loader) applyDefaults(config *auth.Config) {
	// Server defaults
	if config.Server.Port == "" {
		config.Server.Port = "8080"
	}
	if config.Server.Host == "" {
		config.Server.Host = "0.0.0.0"
	}
	if config.Server.ReadTimeout == 0 {
		config.Server.ReadTimeout = 10 * time.Second
	}
	if config.Server.WriteTimeout == 0 {
		config.Server.WriteTimeout = 10 * time.Second
	}
	if config.Server.IdleTimeout == 0 {
		config.Server.IdleTimeout = 120 * time.Second
	}
	if config.Server.ShutdownTimeout == 0 {
		config.Server.ShutdownTimeout = 30 * time.Second
	}
	if config.Server.MaxHeaderBytes == 0 {
		config.Server.MaxHeaderBytes = 1048576 // 1MB
	}

	// Logging defaults
	if config.Logging.Level == "" {
		config.Logging.Level = "info"
	}
	if config.Logging.Format == "" {
		config.Logging.Format = "json"
	}

	// Metrics defaults - need to handle boolean default properly
	// If neither Path nor Port is set, assume no metrics config was provided, so set default enabled
	if config.Metrics.Path == "" && config.Metrics.Port == "" {
		config.Metrics.Enabled = true
	}
	if config.Metrics.Path == "" {
		config.Metrics.Path = "/metrics"
	}
	if config.Metrics.Port == "" {
		config.Metrics.Port = "9090"
	}

	// Default providers - both firebase and ip_whitelist
	if config.Providers == nil {
		config.Providers = []auth.ProviderType{auth.ProviderTypeFirebase, auth.ProviderTypeIPWhitelist}
	}

	// Cache defaults
	if config.Cache.Type == 0 {
		config.Cache.Type = auth.CacheTypeMemory
	}
	if config.Cache.MaxKeys == 0 {
		config.Cache.MaxKeys = 1000
	}
	if config.Cache.CleanupInterval == 0 {
		config.Cache.CleanupInterval = 10 * time.Minute
	}
	if config.Cache.DefaultTTL == 0 {
		config.Cache.DefaultTTL = time.Hour
	}
}

// applyEnvOverrides applies environment variable overrides to configuration
func (l *Loader) applyEnvOverrides(config *auth.Config) {
	// Server overrides
	if port := os.Getenv(l.envPrefix + "_SERVER_PORT"); port != "" {
		config.Server.Port = port
	}
	if host := os.Getenv(l.envPrefix + "_SERVER_HOST"); host != "" {
		config.Server.Host = host
	}
	if timeout := os.Getenv(l.envPrefix + "_SERVER_READ_TIMEOUT"); timeout != "" {
		if duration, err := time.ParseDuration(timeout); err == nil {
			config.Server.ReadTimeout = duration
		}
	}
	if timeout := os.Getenv(l.envPrefix + "_SERVER_WRITE_TIMEOUT"); timeout != "" {
		if duration, err := time.ParseDuration(timeout); err == nil {
			config.Server.WriteTimeout = duration
		}
	}

	// Logging overrides
	if level := os.Getenv(l.envPrefix + "_LOG_LEVEL"); level != "" {
		config.Logging.Level = level
	}
	if format := os.Getenv(l.envPrefix + "_LOG_FORMAT"); format != "" {
		config.Logging.Format = format
	}

	// Metrics overrides
	if enabled := os.Getenv(l.envPrefix + "_METRICS_ENABLED"); enabled != "" {
		config.Metrics.Enabled = strings.ToLower(enabled) == "true"
	}

	// Providers override
	if providers := os.Getenv(l.envPrefix + "_PROVIDERS"); providers != "" {
		var providerTypes []auth.ProviderType
		for providerStr := range strings.SplitSeq(providers, ",") {
			providerStr = strings.TrimSpace(providerStr)
			if providerType := auth.ParseProviderType(providerStr); providerType != auth.ProviderTypeUnknown {
				providerTypes = append(providerTypes, providerType)
			}
		}
		if len(providerTypes) > 0 {
			config.Providers = providerTypes
		}
	}

	// Cache overrides
	if cacheType := os.Getenv(l.envPrefix + "_CACHE_TYPE"); cacheType != "" {
		config.Cache.Type = auth.ParseCacheType(cacheType)
	}
	if redisURL := os.Getenv(l.envPrefix + "_REDIS_URL"); redisURL != "" {
		config.Cache.RedisURL = redisURL
	}
	if redisPassword := os.Getenv(l.envPrefix + "_REDIS_PASSWORD"); redisPassword != "" {
		config.Cache.RedisPassword = redisPassword
	}
	if redisDB := os.Getenv(l.envPrefix + "_REDIS_DB"); redisDB != "" {
		if db, err := strconv.Atoi(redisDB); err == nil {
			config.Cache.RedisDB = db
		}
	}
}
