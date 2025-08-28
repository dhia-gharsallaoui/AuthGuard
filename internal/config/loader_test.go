package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"authguard/internal/auth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLoader(t *testing.T) {
	loader := NewLoader("/path/to/config.yml", "APP")

	assert.Equal(t, "/path/to/config.yml", loader.configPath)
	assert.Equal(t, "APP", loader.envPrefix)
}

func TestLoader_Load_WithYAMLFile(t *testing.T) {
	// Create a temporary config file
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yml")

	yamlContent := `
server:
  port: "9000"
  host: "localhost"
  read_timeout: 15s
  write_timeout: 20s
  idle_timeout: 180s
  shutdown_timeout: 45s
  max_header_bytes: 2097152

logging:
  level: "debug"
  format: "text"

metrics:
  enabled: false
  path: "/custom-metrics"
  port: "8080"

providers:
  - 1  # firebase
  - 2  # ip_whitelist

cache:
  type: 1  # redis
  redis_url: "redis://localhost:6379"
  redis_password: "secret"
  redis_db: 1
  max_keys: 2000
  cleanup_interval: 15m
  default_ttl: 2h
`

	err := os.WriteFile(configPath, []byte(yamlContent), 0o644)
	require.NoError(t, err)

	loader := NewLoader(configPath, "TEST")
	config, err := loader.Load()

	require.NoError(t, err)
	assert.Equal(t, "9000", config.Server.Port)
	assert.Equal(t, "localhost", config.Server.Host)
	assert.Equal(t, 15*time.Second, config.Server.ReadTimeout)
	assert.Equal(t, 20*time.Second, config.Server.WriteTimeout)
	assert.Equal(t, 180*time.Second, config.Server.IdleTimeout)
	assert.Equal(t, 45*time.Second, config.Server.ShutdownTimeout)
	assert.Equal(t, 2097152, config.Server.MaxHeaderBytes)

	assert.Equal(t, "debug", config.Logging.Level)
	assert.Equal(t, "text", config.Logging.Format)

	assert.False(t, config.Metrics.Enabled)
	assert.Equal(t, "/custom-metrics", config.Metrics.Path)
	assert.Equal(t, "8080", config.Metrics.Port)

	assert.Equal(t, []auth.ProviderType{auth.ProviderTypeFirebase, auth.ProviderTypeIPWhitelist}, config.Providers)

	assert.Equal(t, auth.CacheTypeRedis, config.Cache.Type)
	assert.Equal(t, "redis://localhost:6379", config.Cache.RedisURL)
	assert.Equal(t, "secret", config.Cache.RedisPassword)
	assert.Equal(t, 1, config.Cache.RedisDB)
	assert.Equal(t, 2000, config.Cache.MaxKeys)
	assert.Equal(t, 15*time.Minute, config.Cache.CleanupInterval)
	assert.Equal(t, 2*time.Hour, config.Cache.DefaultTTL)
}

func TestLoader_Load_WithoutYAMLFile(t *testing.T) {
	loader := NewLoader("", "TEST")
	config, err := loader.Load()

	require.NoError(t, err)

	// Should have defaults applied
	assert.Equal(t, "8080", config.Server.Port)
	assert.Equal(t, "0.0.0.0", config.Server.Host)
	assert.Equal(t, 10*time.Second, config.Server.ReadTimeout)
	assert.Equal(t, 10*time.Second, config.Server.WriteTimeout)
	assert.Equal(t, 120*time.Second, config.Server.IdleTimeout)
	assert.Equal(t, 30*time.Second, config.Server.ShutdownTimeout)
	assert.Equal(t, 1048576, config.Server.MaxHeaderBytes)

	assert.Equal(t, "info", config.Logging.Level)
	assert.Equal(t, "json", config.Logging.Format)

	assert.True(t, config.Metrics.Enabled)
	assert.Equal(t, "/metrics", config.Metrics.Path)
	assert.Equal(t, "9090", config.Metrics.Port)

	assert.Equal(t, []auth.ProviderType{auth.ProviderTypeFirebase, auth.ProviderTypeIPWhitelist}, config.Providers)

	assert.Equal(t, auth.CacheTypeMemory, config.Cache.Type)
	assert.Equal(t, 1000, config.Cache.MaxKeys)
	assert.Equal(t, 10*time.Minute, config.Cache.CleanupInterval)
	assert.Equal(t, time.Hour, config.Cache.DefaultTTL)
}

func TestLoader_Load_WithEnvironmentOverrides(t *testing.T) {
	cleanup := setupLoaderTestEnv()
	defer cleanup()

	// Set environment variables
	envVars := map[string]string{
		"TEST_SERVER_PORT":          "3000",
		"TEST_SERVER_HOST":          "127.0.0.1",
		"TEST_SERVER_READ_TIMEOUT":  "5s",
		"TEST_SERVER_WRITE_TIMEOUT": "7s",
		"TEST_LOG_LEVEL":            "error",
		"TEST_LOG_FORMAT":           "text",
		"TEST_METRICS_ENABLED":      "false",
		"TEST_PROVIDERS":            "firebase,ip_whitelist",
		"TEST_CACHE_TYPE":           "redis",
		"TEST_REDIS_URL":            "redis://localhost:6379/2",
		"TEST_REDIS_PASSWORD":       "testpass",
		"TEST_REDIS_DB":             "3",
	}

	for key, value := range envVars {
		err := os.Setenv(key, value)
		require.NoError(t, err)
	}

	loader := NewLoader("", "TEST")
	config, err := loader.Load()

	require.NoError(t, err)

	// Check environment overrides
	assert.Equal(t, "3000", config.Server.Port)
	assert.Equal(t, "127.0.0.1", config.Server.Host)
	assert.Equal(t, 5*time.Second, config.Server.ReadTimeout)
	assert.Equal(t, 7*time.Second, config.Server.WriteTimeout)
	assert.Equal(t, "error", config.Logging.Level)
	assert.Equal(t, "text", config.Logging.Format)
	assert.False(t, config.Metrics.Enabled)
	assert.Equal(t, []auth.ProviderType{auth.ProviderTypeFirebase, auth.ProviderTypeIPWhitelist}, config.Providers)
	assert.Equal(t, auth.CacheTypeRedis, config.Cache.Type)
	assert.Equal(t, "redis://localhost:6379/2", config.Cache.RedisURL)
	assert.Equal(t, "testpass", config.Cache.RedisPassword)
	assert.Equal(t, 3, config.Cache.RedisDB)
}

func TestLoader_Load_InvalidYAMLFile(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "invalid.yml")

	invalidYAML := `
server:
  port: "8080"
  invalid_yaml: [unclosed
`

	err := os.WriteFile(configPath, []byte(invalidYAML), 0o644)
	require.NoError(t, err)

	loader := NewLoader(configPath, "TEST")
	_, err = loader.Load()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse YAML config")
}

func TestLoader_Load_ValidationFailure(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "invalid-config.yml")

	// Create config that will fail validation (empty providers)
	invalidConfig := `
server:
  port: ""  # Empty port should cause validation failure
providers: []  # Empty providers should cause validation failure
`

	err := os.WriteFile(configPath, []byte(invalidConfig), 0o644)
	require.NoError(t, err)

	loader := NewLoader(configPath, "TEST")
	_, err = loader.Load()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "configuration validation failed")
}

func TestLoader_loadFromYAML_NonExistentFile(t *testing.T) {
	loader := NewLoader("/path/to/nonexistent/file.yml", "TEST")
	config := &auth.Config{}

	// Should not error for non-existent file (it's optional)
	err := loader.loadFromYAML(config)
	assert.NoError(t, err)
}

func TestLoader_loadFromYAML_UnreadableFile(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "unreadable.yml")

	// Create file and make it unreadable
	err := os.WriteFile(configPath, []byte("content"), 0o644)
	require.NoError(t, err)

	err = os.Chmod(configPath, 0o000) // No permissions
	require.NoError(t, err)
	defer func() {
		err := os.Chmod(configPath, 0o644) // Restore permissions for cleanup
		require.NoError(t, err)
	}()

	loader := NewLoader(configPath, "TEST")
	config := &auth.Config{}

	err = loader.loadFromYAML(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read config file")
}

func TestLoader_applyDefaults(t *testing.T) {
	loader := NewLoader("", "TEST")
	config := &auth.Config{}

	loader.applyDefaults(config)

	// Test server defaults
	assert.Equal(t, "8080", config.Server.Port)
	assert.Equal(t, "0.0.0.0", config.Server.Host)
	assert.Equal(t, 10*time.Second, config.Server.ReadTimeout)
	assert.Equal(t, 10*time.Second, config.Server.WriteTimeout)
	assert.Equal(t, 120*time.Second, config.Server.IdleTimeout)
	assert.Equal(t, 30*time.Second, config.Server.ShutdownTimeout)
	assert.Equal(t, 1048576, config.Server.MaxHeaderBytes)

	// Test logging defaults
	assert.Equal(t, "info", config.Logging.Level)
	assert.Equal(t, "json", config.Logging.Format)

	// Test metrics defaults
	assert.True(t, config.Metrics.Enabled)
	assert.Equal(t, "/metrics", config.Metrics.Path)
	assert.Equal(t, "9090", config.Metrics.Port)

	// Test provider defaults
	assert.Equal(t, []auth.ProviderType{auth.ProviderTypeFirebase, auth.ProviderTypeIPWhitelist}, config.Providers)

	// Test cache defaults
	assert.Equal(t, auth.CacheTypeMemory, config.Cache.Type)
	assert.Equal(t, 1000, config.Cache.MaxKeys)
	assert.Equal(t, 10*time.Minute, config.Cache.CleanupInterval)
	assert.Equal(t, time.Hour, config.Cache.DefaultTTL)
}

func TestLoader_applyDefaults_PreservesExistingValues(t *testing.T) {
	loader := NewLoader("", "TEST")
	config := &auth.Config{
		Server: auth.ServerConfig{
			Port: "9000",
			Host: "custom-host",
		},
		Logging: auth.LoggingConfig{
			Level:  "debug",
			Format: "text",
		},
		Providers: []auth.ProviderType{auth.ProviderTypeFirebase},
		Cache: auth.CacheConfig{
			Type:    auth.CacheTypeRedis,
			MaxKeys: 5000,
		},
	}

	loader.applyDefaults(config)

	// Should preserve existing values
	assert.Equal(t, "9000", config.Server.Port)
	assert.Equal(t, "custom-host", config.Server.Host)
	assert.Equal(t, "debug", config.Logging.Level)
	assert.Equal(t, "text", config.Logging.Format)
	assert.Equal(t, []auth.ProviderType{auth.ProviderTypeFirebase}, config.Providers)
	assert.Equal(t, auth.CacheTypeRedis, config.Cache.Type)
	assert.Equal(t, 5000, config.Cache.MaxKeys)

	// Should still apply defaults for unset values
	assert.Equal(t, 10*time.Second, config.Server.ReadTimeout)
	assert.Equal(t, "/metrics", config.Metrics.Path)
}

func TestLoader_applyEnvOverrides_InvalidDurations(t *testing.T) {
	cleanup := setupLoaderTestEnv()
	defer cleanup()

	// Set invalid duration values
	err := os.Setenv("TEST_SERVER_READ_TIMEOUT", "invalid-duration")
	require.NoError(t, err)
	err = os.Setenv("TEST_SERVER_WRITE_TIMEOUT", "also-invalid")
	require.NoError(t, err)

	loader := NewLoader("", "TEST")
	config := &auth.Config{}
	loader.applyDefaults(config)

	originalReadTimeout := config.Server.ReadTimeout
	originalWriteTimeout := config.Server.WriteTimeout

	loader.applyEnvOverrides(config)

	// Should preserve original values when env var is invalid
	assert.Equal(t, originalReadTimeout, config.Server.ReadTimeout)
	assert.Equal(t, originalWriteTimeout, config.Server.WriteTimeout)
}

func TestLoader_applyEnvOverrides_InvalidIntValues(t *testing.T) {
	cleanup := setupLoaderTestEnv()
	defer cleanup()

	err := os.Setenv("TEST_REDIS_DB", "not-a-number")
	require.NoError(t, err)

	loader := NewLoader("", "TEST")
	config := &auth.Config{}
	loader.applyDefaults(config)

	originalRedisDB := config.Cache.RedisDB

	loader.applyEnvOverrides(config)

	// Should preserve original value when env var is invalid
	assert.Equal(t, originalRedisDB, config.Cache.RedisDB)
}

func TestLoader_applyEnvOverrides_ProvidersEnvironment(t *testing.T) {
	cleanup := setupLoaderTestEnv()
	defer cleanup()

	tests := []struct {
		name        string
		envValue    string
		expected    []auth.ProviderType
		description string
	}{
		{
			name:        "single provider",
			envValue:    "firebase",
			expected:    []auth.ProviderType{auth.ProviderTypeFirebase},
			description: "should parse single provider",
		},
		{
			name:        "multiple providers",
			envValue:    "firebase,ip_whitelist",
			expected:    []auth.ProviderType{auth.ProviderTypeFirebase, auth.ProviderTypeIPWhitelist},
			description: "should parse multiple providers",
		},
		{
			name:        "providers with spaces",
			envValue:    " firebase , ip_whitelist ",
			expected:    []auth.ProviderType{auth.ProviderTypeFirebase, auth.ProviderTypeIPWhitelist},
			description: "should handle spaces around provider names",
		},
		{
			name:        "invalid provider mixed with valid",
			envValue:    "firebase,invalid,ip_whitelist",
			expected:    []auth.ProviderType{auth.ProviderTypeFirebase, auth.ProviderTypeIPWhitelist},
			description: "should skip invalid providers but keep valid ones",
		},
		{
			name:        "empty providers",
			envValue:    "",
			expected:    []auth.ProviderType{auth.ProviderTypeFirebase, auth.ProviderTypeIPWhitelist},
			description: "should keep defaults when env is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				err := os.Setenv("TEST_PROVIDERS", tt.envValue)
				require.NoError(t, err)
				defer func() {
					err := os.Unsetenv("TEST_PROVIDERS")
					require.NoError(t, err)
				}()
			}

			loader := NewLoader("", "TEST")
			config := &auth.Config{}
			loader.applyDefaults(config)

			loader.applyEnvOverrides(config)

			assert.Equal(t, tt.expected, config.Providers, tt.description)
		})
	}
}

// Helper function to clean up environment variables for loader tests
func setupLoaderTestEnv() func() {
	// Store original values
	originalVars := make(map[string]string)
	for _, env := range os.Environ() {
		if len(env) > 0 {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 && strings.HasPrefix(parts[0], "TEST_") {
				originalVars[parts[0]] = parts[1]
			}
		}
	}

	// Clear test variables
	for key := range originalVars {
		_ = os.Unsetenv(key)
	}

	// Return cleanup function
	return func() {
		// Clear any test vars that might have been set
		for _, env := range os.Environ() {
			if len(env) > 0 {
				parts := strings.SplitN(env, "=", 2)
				if len(parts) >= 1 && strings.HasPrefix(parts[0], "TEST_") {
					_ = os.Unsetenv(parts[0])
				}
			}
		}

		// Restore original values
		for key, value := range originalVars {
			_ = os.Setenv(key, value)
		}
	}
}
