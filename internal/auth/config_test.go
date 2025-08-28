package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConfig_Validate(t *testing.T) {
	t.Run("Valid configuration", func(t *testing.T) {
		config := &Config{
			Server: ServerConfig{
				Port: "8080",
				Host: "0.0.0.0",
			},
			Providers: []ProviderType{ProviderTypeFirebase},
		}

		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("Empty server port", func(t *testing.T) {
		config := &Config{
			Server: ServerConfig{
				Port: "", // Empty port should cause validation error
				Host: "0.0.0.0",
			},
			Providers: []ProviderType{ProviderTypeFirebase},
		}

		err := config.Validate()
		assert.Error(t, err)
		assert.Equal(t, ErrConfigurationError, err)
	})

	t.Run("No providers configured", func(t *testing.T) {
		config := &Config{
			Server: ServerConfig{
				Port: "8080",
				Host: "0.0.0.0",
			},
			Providers: []ProviderType{}, // Empty providers should cause validation error
		}

		err := config.Validate()
		assert.Error(t, err)
		assert.Equal(t, ErrConfigurationError, err)
	})

	t.Run("Nil providers", func(t *testing.T) {
		config := &Config{
			Server: ServerConfig{
				Port: "8080",
				Host: "0.0.0.0",
			},
			Providers: nil, // Nil providers should cause validation error
		}

		err := config.Validate()
		assert.Error(t, err)
		assert.Equal(t, ErrConfigurationError, err)
	})

	t.Run("Valid configuration with multiple providers", func(t *testing.T) {
		config := &Config{
			Server: ServerConfig{
				Port: "9090",
				Host: "localhost",
			},
			Providers: []ProviderType{ProviderTypeFirebase, ProviderTypeIPWhitelist},
		}

		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("Valid configuration with all fields populated", func(t *testing.T) {
		config := &Config{
			Server: ServerConfig{
				Port:            "8443",
				Host:            "0.0.0.0",
				ReadTimeout:     10 * time.Second,
				WriteTimeout:    10 * time.Second,
				IdleTimeout:     120 * time.Second,
				ShutdownTimeout: 30 * time.Second,
				MaxHeaderBytes:  1048576,
			},
			Providers: []ProviderType{ProviderTypeFirebase},
			Cache: CacheConfig{
				Type:            CacheTypeMemory,
				RedisURL:        "redis://localhost:6379",
				RedisPassword:   "password",
				RedisDB:         0,
				MaxKeys:         1000,
				CleanupInterval: 10 * time.Minute,
				DefaultTTL:      1 * time.Hour,
			},
			Logging: LoggingConfig{
				Level:  "info",
				Format: "json",
			},
			Metrics: MetricsConfig{
				Enabled: true,
				Path:    "/metrics",
				Port:    "9090",
			},
		}

		err := config.Validate()
		assert.NoError(t, err)
	})
}